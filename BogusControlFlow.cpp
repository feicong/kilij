//===- BogusControlFlow.cpp - Bogus control flow obfuscation -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE for details.
//
// Modifications Copyright (c) 2026 Danny Mundy
//
//===----------------------------------------------------------------------===//
//
// Inserts fake conditional branches guarded by opaque predicates. The "false"
// path executes a cloned block with junked instructions, while the "true" path
// preserves the original semantics.
//
// Flags:
//   -bcf            enable bogus control flow
//   -bcf_prob=0-100 probability per block (default 30)
//   -bcf_loop=N     number of iterations per function (N >= 1, default 1)
//
// Debugging: build with LLVM_DEBUG and use -debug-only=bcf.
//
//===----------------------------------------------------------------------===//

#include "BogusControlFlow.h"
#include "CryptoUtils.h"
#include "OpaquePredicates.h"
#include "Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/ISDOpcodes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <list>

using namespace std;
using namespace llvm;

#define DEBUG_TYPE "bcf"

STATISTIC(NumFunction, "a. Number of functions in this module");
STATISTIC(NumTimesOnFunctions, "b. Number of times we run on each function");
STATISTIC(InitNumBasicBlocks,
          "c. Initial number of basic blocks in this module");
STATISTIC(NumModifiedBasicBlocks, "d. Number of modified basic blocks");
STATISTIC(NumAddedBasicBlocks,
          "e. Number of added basic blocks in this module");
STATISTIC(FinalNumBasicBlocks,
          "f. Final number of basic blocks in this module");

namespace {
const int defaultObfRate = 30, defaultObfTime = 1;

cl::opt<bool> BogusControlFlow("bcf", cl::init(false),
                               cl::desc("Enable bogus control flow"));
cl::opt<int>
    ObfProbRate("bcf_prob",
                cl::desc("Choose the probability [%] each basic blocks will be "
                         "obfuscated by the -bcf pass"),
                cl::value_desc("probability rate"), cl::init(defaultObfRate),
                cl::Optional);

cl::opt<int>
    ObfTimes("bcf_loop",
             cl::desc("Choose how many time the -bcf pass loop on a function"),
             cl::value_desc("number of times"), cl::init(defaultObfTime),
             cl::Optional);

void bogus(Function &F, int Prob, int Times);
void addBogusFlow(BasicBlock *basicBlock, Function &F);
BasicBlock *createAlteredBasicBlock(BasicBlock *basicBlock,
                                    const Twine &Name = "",
                                    Function *F = nullptr);

static bool isUnsupportedTerminator(const Instruction *Term) {
  return isa<InvokeInst>(Term) || isa<CallBrInst>(Term) ||
         isa<CatchSwitchInst>(Term) || isa<CatchReturnInst>(Term) ||
         isa<CleanupReturnInst>(Term) || isa<ResumeInst>(Term);
}

static BasicBlock::iterator getSplitPoint(BasicBlock &BB) {
  auto It = BB.begin();
  while (It != BB.end()) {
    if (isa<PHINode>(It) || It->isDebugOrPseudoInst() ||
        It->isLifetimeStartOrEnd() || isa<AllocaInst>(It)) {
      // Keep prologue-only instructions in place to preserve SSA and debug info.
      ++It;
      continue;
    }
    break;
  }
  return It;
}

void bogus(Function &F, int Prob, int Times) {
  ++NumFunction;
  std::size_t origBBs = countBasicBlocks(F);
  std::size_t origInsts = countInstructions(F);
  int NumBasicBlocks = 0;
  bool firstTime = true;
  bool hasBeenModified = false;
  LLVM_DEBUG(dbgs() << "bcf: Started on function " << F.getName() << "\n");
  LLVM_DEBUG(dbgs() << "bcf: Probability rate: " << Prob << "\n");
  LLVM_DEBUG(dbgs() << "bcf: How many times: " << Times << "\n");
  NumTimesOnFunctions = Times;
  int NumObfTimes = Times;

  do {
    LLVM_DEBUG(dbgs() << "bcf: Function " << F.getName()
                                  << ", before the pass:\n");
    LLVM_DEBUG(F.viewCFG());
    // Snapshot blocks first so transformations don't invalidate traversal.
    std::list<BasicBlock *> basicBlocks;
    for (Function::iterator i = F.begin(); i != F.end(); ++i) {
      basicBlocks.push_back(&*i);
    }
    LLVM_DEBUG(dbgs() << "bcf: Iterating on the Function's Basic Blocks\n");

    while (!basicBlocks.empty()) {
      NumBasicBlocks++;
      BasicBlock *basicBlock = basicBlocks.front();
      if (shouldSkipBlock(basicBlock)) {
        LLVM_DEBUG(dbgs() << "bcf: Block " << NumBasicBlocks
                                      << " skipped (unsupported).\n");
        basicBlocks.pop_front();
        continue;
      }
      if ((int)llvm::cryptoutils->get_range(100) < Prob) {
        LLVM_DEBUG(dbgs() << "bcf: Block " << NumBasicBlocks
                                      << " selected. \n");
        hasBeenModified = true;
        ++NumModifiedBasicBlocks;
        NumAddedBasicBlocks += 3;
        FinalNumBasicBlocks += 3;
        addBogusFlow(basicBlock, F);
      } else {
        LLVM_DEBUG(dbgs() << "bcf: Block " << NumBasicBlocks
                                      << " not selected.\n");
      }
      basicBlocks.pop_front();

      if (firstTime) {
        ++InitNumBasicBlocks;
        ++FinalNumBasicBlocks;
      }
    }
    LLVM_DEBUG(dbgs() << "bcf: End of function " << F.getName() << "\n");
    if (hasBeenModified) {
      LLVM_DEBUG(dbgs() << "bcf: Function " << F.getName()
                                    << ", after the pass: \n");
      LLVM_DEBUG(F.viewCFG());
    } else {
      LLVM_DEBUG(dbgs() << "bcf: Function has not been modified \n");
    }
    if (!checkObfuscationBudget(F, origBBs, origInsts, "bcf")) {
      break;
    }
    firstTime = false;
  } while (--NumObfTimes > 0);
}

void addBogusFlow(BasicBlock *basicBlock, Function &F) {
  if (!basicBlock || !basicBlock->getTerminator())
    return;
  if (shouldSkipBlock(basicBlock))
    return;
  if (basicBlock->isEHPad() ||
      isUnsupportedTerminator(basicBlock->getTerminator())) {
    return;
  }
  // Split after phi/debug prologue so we don't have to remap incoming values.
  BasicBlock::iterator i1 = basicBlock->begin();
  auto firstRealIt = getSplitPoint(*basicBlock);
  if (firstRealIt != basicBlock->end())
    i1 = firstRealIt;
  if (firstRealIt == basicBlock->end() || firstRealIt->isEHPad())
    return;
  BasicBlock *originalBB = basicBlock->splitBasicBlock(i1, "originalBB");
  LLVM_DEBUG(dbgs()
                             << "bcf: First and original basic blocks: ok\n");

  BasicBlock *alteredBB = createAlteredBasicBlock(originalBB, "alteredBB", &F);
  LLVM_DEBUG(dbgs() << "bcf: Altered basic block: ok\n");

  alteredBB->getTerminator()->eraseFromParent();
  basicBlock->getTerminator()->eraseFromParent();
  LLVM_DEBUG(dbgs() << "bcf: Terminator removed from the altered"
                                << " and first basic blocks\n");

  // Placeholder FCMP_TRUE predicate; doF() replaces these with opaque
  // predicates after the structural transform is complete.
  Value *LHS = ConstantFP::get(Type::getFloatTy(F.getContext()), 1.0);
  Value *RHS = ConstantFP::get(Type::getFloatTy(F.getContext()), 1.0);
  LLVM_DEBUG(dbgs() << "bcf: Value LHS and RHS created\n");

  FCmpInst *condition = cast<FCmpInst>(CmpInst::Create(
      Instruction::FCmp, FCmpInst::FCMP_TRUE, LHS, RHS, "condition",
      InsertPosition(basicBlock->end())));
  LLVM_DEBUG(dbgs() << "bcf: Always true condition created\n");

  BranchInst::Create(originalBB, alteredBB, (Value *)condition, basicBlock);
  LLVM_DEBUG(
      "gen",
      dbgs() << "bcf: Terminator instruction in first basic block: ok\n");

  // Altered block unconditionally falls through to original, creating a
  // diamond that looks like a real branch to static analysis.
  BranchInst::Create(originalBB, alteredBB);
  LLVM_DEBUG(dbgs() << "bcf: Terminator instruction in altered block: ok\n");

  // Add a second opaque branch at the end of originalBB so the CFG has a
  // back-edge to alteredBB, further confusing dominance analysis.
  BasicBlock::iterator i = originalBB->end();
  BasicBlock *originalBBpart2 =
      originalBB->splitBasicBlock(--i, "originalBBpart2");
  LLVM_DEBUG(dbgs() << "bcf: Terminator part of the original basic block"
                         << " is isolated\n");
  originalBB->getTerminator()->eraseFromParent();
  FCmpInst *condition2 = cast<FCmpInst>(CmpInst::Create(
      Instruction::FCmp, CmpInst::FCMP_TRUE, LHS, RHS, "condition2",
      InsertPosition(originalBB->end())));
  BranchInst::Create(originalBBpart2, alteredBB, (Value *)condition2,
                     originalBB);
  LLVM_DEBUG(dbgs()
                             << "bcf: Terminator original basic block: ok\n");
  LLVM_DEBUG(dbgs() << "bcf: End of addBogusFlow().\n");

}


// Clone a block and inject junk arithmetic so decompilers can't trivially
// identify it as dead code by structure alone.
BasicBlock *createAlteredBasicBlock(BasicBlock *basicBlock, const Twine &Name,
                                    Function *F) {
  ValueToValueMapTy VMap;
  BasicBlock *alteredBB = llvm::CloneBasicBlock(basicBlock, VMap, Name, F);
  LLVM_DEBUG(dbgs() << "bcf: Original basic block cloned\n");
  BasicBlock::iterator ji = basicBlock->begin();
  for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end();
       i != e; ++i) {
    for (User::op_iterator opi = i->op_begin(), ope = i->op_end(); opi != ope;
         ++opi) {
      Value *v = MapValue(*opi, VMap, RF_None, 0);
      if (v != 0) {
        *opi = v;
        LLVM_DEBUG(dbgs()
                                   << "bcf: Value's operand has been set\n");
      }
    }
    LLVM_DEBUG(dbgs() << "bcf: Operands remapped\n");
    if (PHINode *pn = dyn_cast<PHINode>(i)) {
      for (unsigned j = 0, e = pn->getNumIncomingValues(); j != e; ++j) {
        Value *v = MapValue(pn->getIncomingBlock(j), VMap, RF_None, 0);
        if (v != 0) {
          pn->setIncomingBlock(j, cast<BasicBlock>(v));
        }
      }
    }
    LLVM_DEBUG(dbgs() << "bcf: PHINodes remapped\n");
    SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
    i->getAllMetadata(MDs);
    LLVM_DEBUG(dbgs() << "bcf: Metadata remapped\n");
    // Carry debug locs from original so DWARF doesn't reference stale scopes.
    i->setDebugLoc(ji->getDebugLoc());
    ji++;
    LLVM_DEBUG(dbgs()
                               << "bcf: Debug information location set\n");

  }

  // Strip debug intrinsics to avoid "mismatched subprogram" verifier errors
  // since the cloned block lives in a different control-flow context.
  for (auto I = alteredBB->begin(), E = alteredBB->end(); I != E;) {
    Instruction *Instr = &*I++;
    if (isa<DbgInfoIntrinsic>(Instr))
      Instr->eraseFromParent();
  }

  LLVM_DEBUG(dbgs()
                             << "bcf: The cloned basic block is now correct\n");
  LLVM_DEBUG(
      "gen",
      dbgs() << "bcf: Starting to add junk code in the cloned block...\n");

  // Inject junk arithmetic around existing binary ops to make the dead block
  // look plausible to decompilers and pattern matchers.
  for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end();
       i != e; ++i) {
    if (i->isBinaryOp()) {
      unsigned opcode = i->getOpcode();
      Instruction *op, *op1 = nullptr;
      if (opcode == Instruction::Add || opcode == Instruction::Sub ||
          opcode == Instruction::Mul || opcode == Instruction::UDiv ||
          opcode == Instruction::SDiv || opcode == Instruction::URem ||
          opcode == Instruction::SRem || opcode == Instruction::Shl ||
          opcode == Instruction::LShr || opcode == Instruction::AShr ||
          opcode == Instruction::And || opcode == Instruction::Or ||
          opcode == Instruction::Xor) {
        for (int random = (int)llvm::cryptoutils->get_range(10); random < 10;
             ++random) {
          switch (llvm::cryptoutils->get_range(4)) {
          case 0:
            break;
          case 1:
            op = BinaryOperator::CreateNeg(i->getOperand(0), "", i);
            op1 = BinaryOperator::Create(Instruction::Add, op,
                                         i->getOperand(1), "", i);
            break;
          case 2:
            op1 = BinaryOperator::Create(Instruction::Sub, i->getOperand(0),
                                         i->getOperand(1), "", i);
            op = BinaryOperator::Create(Instruction::Mul, op1,
                                        i->getOperand(1), "", i);
            break;
          case 3:
            if (i->getOperand(1)->getType()->isIntegerTy()) {
              unsigned Bits =
                  i->getOperand(1)->getType()->getIntegerBitWidth();
              Value *Mask =
                  ConstantInt::get(i->getOperand(1)->getType(), Bits - 1);
              Value *Amt =
                  BinaryOperator::CreateAnd(i->getOperand(1), Mask, "", i);
              op = BinaryOperator::Create(Instruction::Shl, i->getOperand(0),
                                          Amt, "", i);
            }
            break;
          }
        }
      }
      if (opcode == Instruction::FAdd || opcode == Instruction::FSub ||
          opcode == Instruction::FMul || opcode == Instruction::FDiv ||
          opcode == Instruction::FRem) {
        for (int random = (int)llvm::cryptoutils->get_range(10); random < 10;
             ++random) {
          switch (llvm::cryptoutils->get_range(3)) {
          case 0:
            break;
          case 1:
            op = UnaryOperator::CreateFNeg(i->getOperand(0), "", i);
            op1 = BinaryOperator::Create(Instruction::FAdd, op,
                                         i->getOperand(1), "", i);
            break;
          case 2:
            op = BinaryOperator::Create(Instruction::FSub, i->getOperand(0),
                                        i->getOperand(1), "", i);
            op1 = BinaryOperator::Create(Instruction::FMul, op,
                                         i->getOperand(1), "", i);
            break;
          }
        }
      }
    }
  }
  return alteredBB;
}

// Second phase: replace placeholder FCMP_TRUE branches with a mix of
// call-free and helper-call opaque predicates.
bool doF(Module &M, Function &F, TaggedFunctionCache &TagCache) {
  LLVM_DEBUG(dbgs() << "bcf: Starting doFinalization...\n");

  OpaquePredContext PredCtx;
  PredCtx.TagCache = &TagCache;
  std::vector<Instruction *> toEdit, toDelete;

  for (Function::iterator fi = F.begin(), fe = F.end(); fi != fe; ++fi) {
    // fi->setName("");
    Instruction *tbb = fi->getTerminator();
    if (tbb->getOpcode() == Instruction::Br) {
      BranchInst *br = (BranchInst *)(tbb);
      if (br->isConditional()) {
        auto *cond = dyn_cast<FCmpInst>(br->getCondition());
        if (!cond)
          continue;
        if (cond->getPredicate() == FCmpInst::FCMP_TRUE) {
          LLVM_DEBUG(dbgs() << "bcf: an always true predicate !\n");
          toDelete.push_back(cond);
          toEdit.push_back(tbb);
        }
      }
    }
  }

  for (std::vector<Instruction *>::iterator i = toEdit.begin();
       i != toEdit.end(); ++i) {
    BranchInst *br = cast<BranchInst>(*i);
    IRBuilder<> B(br);
    B.SetCurrentDebugLocation(br->getDebugLoc());
    OpaquePredResult R =
        createOpaquePredicate(B, *br->getFunction(), br, PredCtx);
    BasicBlock *SuccTrue = br->getSuccessor(0);
    BasicBlock *SuccFalse = br->getSuccessor(1);
    if (!R.ExpectedTrue)
      std::swap(SuccTrue, SuccFalse);

    BranchInst::Create(SuccTrue, SuccFalse, R.Cond, br->getIterator());
    LLVM_DEBUG(dbgs() << "bcf: Erase branch instruction:"
                                  << *br << "\n");
    (*i)->eraseFromParent();
  }
  for (std::vector<Instruction *>::iterator i = toDelete.begin();
       i != toDelete.end(); ++i) {
    LLVM_DEBUG(dbgs() << "bcf: Erase condition instruction:"
                                  << *((Instruction *)*i) << "\n");
    if ((*i)->use_empty())
      (*i)->eraseFromParent();
  }

  LLVM_DEBUG(dbgs() << "bcf: End of the pass, here are the "
                                   "graphs after doFinalization\n");
  return true;
}
} // namespace

PreservedAnalyses BogusControlFlowPass::run(Function &F,
                                            FunctionAnalysisManager &AM) {
  if (ObfTimes <= 0) {
    errs() << "BogusControlFlow application number -bcf_loop=x must be x > 0";
    return PreservedAnalyses::all();
  }

  if (ObfProbRate < 0 || ObfProbRate > 100) {
    errs() << "BogusControlFlow application basic blocks percentage "
              "-bcf_prob=x must be 0 <= x <= 100";
    return PreservedAnalyses::all();
  }
  int Times = ObfTimes.getValue();
  int Prob = ObfProbRate.getValue();
  if (Prob == 0)
    return PreservedAnalyses::all();
  if (toObfuscate(BogusControlFlow, &F, "bcf")) {
    recordObfuscationSeed(*F.getParent());
    maybeDumpIR(F, "bcf.before");
    bogus(F, Prob, Times);
    Module &M = *F.getParent();
    if (CachedModule != &M) {
      CachedModule = &M;
      TagCache.rebuild(M);
    }
    doF(M, F, TagCache);
    verifyFunctionOrDie(F, "bcf");
    maybeDumpIR(F, "bcf.after");
    return PreservedAnalyses::none();
  }

  return PreservedAnalyses::all();
}
