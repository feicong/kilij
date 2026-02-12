//===- Flattening.cpp - Flattening Obfuscation pass------------------------===//
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
// This file implements the flattening pass
//
//===----------------------------------------------------------------------===//

#include "Flattening.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h" // For DemoteRegToStack and DemotePHIToStack
#include "llvm/Transforms/Utils/LowerSwitch.h"
#include <cassert>

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "flattening"

STATISTIC(Flattened, "Functions flattened");

namespace {
cl::opt<bool> Flattening("fla", cl::init(false),
                         cl::desc("Enable the flattening pass"));

// Adapted from LLVM's RegToMem utility.
bool valueEscapes(const Instruction &Inst) {
  if (!Inst.getType()->isSized())
    return false;

  const BasicBlock *BB = Inst.getParent();
  for (const User *U : Inst.users()) {
    const Instruction *UI = cast<Instruction>(U);
    if (UI->getParent() != BB || isa<PHINode>(UI))
      return true;
  }
  return false;
}

void fixStack(Function &F) {
  // Flattening breaks SSA dominance; demote everything to stack so the
  // dispatch loop can re-load values regardless of which case ran last.
  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*F.begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = F.begin(); i != F.end(); ++i) {

      for (BasicBlock::iterator j = i->begin(); j != i->end(); ++j) {

        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); ++i) {
      DemoteRegToStack(*tmpReg.at(i));
    }

    for (unsigned int i = 0; i != tmpPhi.size(); ++i) {
      DemotePHIToStack(tmpPhi.at(i));
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}

// Feistel network encodes switch case IDs so a static analyst can't map
// encoded dispatch values to basic blocks without recovering the keys.
static uint32_t rotl32(uint32_t v, unsigned r) {
  r &= 31u;
  return (v << r) | (v >> ((32u - r) & 31u));
}

static uint32_t feistelF32(uint32_t r, uint32_t k) {
  uint32_t ko = k | 1u;
  uint32_t x = r ^ k;
  x = (x + ko) ^ rotl32(x, 5);
  x *= ko;
  x ^= (x >> 11);
  return x & 0xFFFFu;
}

static uint32_t feistelEncode32(uint32_t v, ArrayRef<uint32_t> keys) {
  uint32_t l = v >> 16;
  uint32_t r = v & 0xFFFFu;
  for (uint32_t k : keys) {
    uint32_t f = feistelF32(r, k);
    uint32_t nl = r;
    uint32_t nr = l ^ f;
    l = nl;
    r = nr;
  }
  return (l << 16) | (r & 0xFFFFu);
}

static uint32_t feistelDecode32(uint32_t v, ArrayRef<uint32_t> keys) {
  uint32_t l = v >> 16;
  uint32_t r = v & 0xFFFFu;
  for (size_t i = keys.size(); i > 0; --i) {
    uint32_t k = keys[i - 1];
    uint32_t f = feistelF32(l, k);
    uint32_t nr = l;
    uint32_t nl = r ^ f;
    l = nl;
    r = nr;
  }
  return (l << 16) | (r & 0xFFFFu);
}

// IR-level Feistel round emitted inline so the decoder runs at dispatch time.
static Value *feistelF32IR(IRBuilder<> &B, Value *R, uint32_t K) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Value *KC = ConstantInt::get(I32Ty, K);
  Value *KO = B.CreateOr(KC, ConstantInt::get(I32Ty, 1));
  Value *X = B.CreateXor(R, KC);
  Value *Rot = B.CreateOr(B.CreateShl(X, ConstantInt::get(I32Ty, 5)),
                          B.CreateLShr(X, ConstantInt::get(I32Ty, 27)));
  Value *Mix = B.CreateXor(B.CreateAdd(X, KO), Rot);
  Value *Mul = B.CreateMul(Mix, KO);
  Value *Out = B.CreateXor(Mul, B.CreateLShr(Mul, ConstantInt::get(I32Ty, 11)));
  // Keep the round function bounded to 16 bits for stable case IDs.
  return B.CreateAnd(Out, ConstantInt::get(I32Ty, 0xFFFFu));
}

static Value *feistelDecodeIR(IRBuilder<> &B, Value *V,
                              ArrayRef<uint32_t> Keys) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Value *L = B.CreateLShr(V, ConstantInt::get(I32Ty, 16));
  Value *R = B.CreateAnd(V, ConstantInt::get(I32Ty, 0xFFFFu));
  for (size_t i = Keys.size(); i > 0; --i) {
    uint32_t K = Keys[i - 1];
    Value *F = feistelF32IR(B, L, K);
    Value *NewR = L;
    Value *NewL = B.CreateXor(R, F);
    L = NewL;
    R = NewR;
  }
  Value *Hi = B.CreateShl(L, ConstantInt::get(I32Ty, 16));
  Value *Lo = B.CreateAnd(R, ConstantInt::get(I32Ty, 0xFFFFu));
  return B.CreateOr(Hi, Lo);
}

bool flatten(Function &F) {
  vector<BasicBlock *> origBB;
  BasicBlock *loopEntry;
  BasicBlock *loopEnd;
  LoadInst *load;
  SwitchInst *switchI;
  AllocaInst *switchVar;
  DenseMap<BasicBlock *, ConstantInt *> caseScrambled;
  DenseMap<BasicBlock *, ConstantInt *> caseEncoded;
  BasicBlock *firstCase = nullptr;

  // Skip functions with unsupported blocks/instructions to avoid invalid IR.
  for (Function::iterator i = F.begin(); i != F.end(); ++i) {
    if (shouldSkipBlock(&*i)) {
      return false;
    }
  }

  for (Function::iterator i = F.begin(); i != F.end(); ++i) {
    BasicBlock *tmp = &*i;
    origBB.push_back(tmp);

    BasicBlock *bb = &*i;
    Instruction *Term = bb->getTerminator();
    if (!Term)
      return false;
    if (!isa<BranchInst>(Term) && !isa<ReturnInst>(Term))
      return false;
    if (Term->getNumSuccessors() > 2)
      return false;
    if (isa<InvokeInst>(Term)) {
      return false;
    }
  }

  if (origBB.size() <= 1) {
    return false;
  }

  // Entry block stays outside the dispatch loop as the single entry point.
  origBB.erase(origBB.begin());

  Function::iterator tmp = F.begin();
  BasicBlock *insert = &*tmp;
  BranchInst *br = nullptr;
  if (isa<BranchInst>(insert->getTerminator())) {
    br = cast<BranchInst>(insert->getTerminator());
  }

  if ((br != nullptr && br->isConditional()) ||
      insert->getTerminator()->getNumSuccessors() > 1) {
    // Split early so the dispatcher has a single-entry landing block.
    BasicBlock::iterator i = insert->end();
    --i;

    if (insert->size() > 1) {
      --i;
    }

    BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
    origBB.insert(origBB.begin(), tmpBB);
  }

  Instruction *EntryTerm = insert->getTerminator();
  unsigned EntrySuccs = EntryTerm->getNumSuccessors();
  if (EntrySuccs != 1) {
    return false;
  }
  firstCase = EntryTerm->getSuccessor(0);

  IntegerType *I32Ty = Type::getInt32Ty(F.getContext());
  SmallVector<uint32_t, 4> FeistelKeys;
  FeistelKeys.reserve(4);
  for (unsigned i = 0; i < 4; ++i) {
    uint32_t K = llvm::cryptoutils->get_uint32_t() | 1u;
    FeistelKeys.push_back(K);
  }
#ifndef NDEBUG
  for (uint32_t v = 0; v < 1024; ++v) {
    uint32_t enc = feistelEncode32(v, FeistelKeys);
    uint32_t dec = feistelDecode32(enc, FeistelKeys);
    assert(dec == v && "feistel encode/decode mismatch");
  }
#endif

  // Fisher-Yates shuffle so case IDs aren't correlated with BB order.
  vector<uint32_t> caseIds;
  caseIds.reserve(origBB.size());
  for (uint32_t i = 0; i < origBB.size(); ++i) {
    caseIds.push_back(i);
  }
  for (size_t i = caseIds.size(); i > 1; --i) {
    size_t j = llvm::cryptoutils->get_range(i);
    std::swap(caseIds[i - 1], caseIds[j]);
  }

  for (size_t i = 0; i < origBB.size(); ++i) {
    uint32_t id = caseIds[i];
    uint32_t encoded = feistelEncode32(id, FeistelKeys);
    caseScrambled[origBB[i]] =
        cast<ConstantInt>(ConstantInt::get(I32Ty, id));
    caseEncoded[origBB[i]] = cast<ConstantInt>(ConstantInt::get(I32Ty, encoded));
  }

  if (!caseEncoded.count(firstCase)) {
    return false;
  }
  for (BasicBlock *BB : origBB) {
    Instruction *Term = BB->getTerminator();
    unsigned NSucc = Term->getNumSuccessors();
    for (unsigned i = 0; i < NSucc; ++i) {
      if (!caseEncoded.count(Term->getSuccessor(i))) {
        return false;
      }
    }
  }

  insert->getTerminator()->eraseFromParent();

  // Store the Feistel-encoded case ID; the switch decodes it each iteration.
  switchVar = new AllocaInst(I32Ty, 0, "switchVar", insert);
  new StoreInst(caseEncoded[firstCase], switchVar, insert);

  loopEntry = BasicBlock::Create(F.getContext(), "loopEntry", &F, insert);
  loopEnd = BasicBlock::Create(F.getContext(), "loopEnd", &F, insert);

  load = new LoadInst(I32Ty, switchVar, "switchVar", loopEntry);
  // Decode the Feistel-encoded state before branching; the non-linearity
  // prevents pattern-matching the dispatch variable to block order.
  IRBuilder<> DecB(loopEntry);
  Value *decVal = feistelDecodeIR(DecB, load, FeistelKeys);

  insert->moveBefore(loopEntry);
  BranchInst::Create(loopEntry, insert);
  BranchInst::Create(loopEntry, loopEnd);

  BasicBlock *swDefault =
      BasicBlock::Create(F.getContext(), "switchDefault", &F, loopEnd);
  BranchInst::Create(loopEnd, swDefault);

  switchI = SwitchInst::Create(decVal, swDefault, origBB.size(), loopEntry);

  F.begin()->getTerminator()->eraseFromParent();
  BranchInst::Create(loopEntry, &*F.begin());
  for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
       ++b) {
    BasicBlock *i = *b;
    ConstantInt *numCase = nullptr;

    i->moveBefore(loopEnd);
    numCase = caseScrambled.lookup(i);
    switchI->addCase(numCase, i);
  }

  // Rewrite each block's terminator to store the next encoded case ID and
  // branch back into the dispatch loop instead of jumping directly.
  for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
       ++b) {
    BasicBlock *i = *b;
    ConstantInt *numCase = nullptr;

    if (i->getTerminator()->getNumSuccessors() == 0) {
      continue;
    }

    if (i->getTerminator()->getNumSuccessors() == 1) {
      BasicBlock *succ = i->getTerminator()->getSuccessor(0);
      i->getTerminator()->eraseFromParent();

      numCase = caseEncoded.lookup(succ);
      if (numCase == nullptr)
        return false;

      new StoreInst(numCase, load->getPointerOperand(), i);
      BranchInst::Create(loopEnd, i);
      continue;
    }

    if (i->getTerminator()->getNumSuccessors() == 2) {
      ConstantInt *numCaseTrue =
          caseEncoded.lookup(i->getTerminator()->getSuccessor(0));
      ConstantInt *numCaseFalse =
          caseEncoded.lookup(i->getTerminator()->getSuccessor(1));

      if (numCaseTrue == nullptr || numCaseFalse == nullptr)
        return false;

      // Select preserves the original branch condition in the flattened form.
      BranchInst *br = cast<BranchInst>(i->getTerminator());
      SelectInst *sel =
          SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "",
                             i->getTerminator()->getIterator());

      i->getTerminator()->eraseFromParent();
      new StoreInst(sel, load->getPointerOperand(), i);
      BranchInst::Create(loopEnd, i);
      continue;
    }
  }

  fixStack(F);

  return true;
}
} // namespace

PreservedAnalyses FlatteningPass::run(Function &F,
                                      FunctionAnalysisManager &AM) {
  if (toObfuscate(Flattening, &F, "fla")) {
    ObfPassContext Ctx = beginFunctionObfuscation(F, "fla");

    // Lower existing switches to if/else chains first; the flattener only
    // handles branch/return terminators.
    LowerSwitchPass lower;
    PreservedAnalyses LowerPA = lower.run(F, AM);
    bool Changed = !LowerPA.areAllPreserved();

    if (flatten(F)) {
      ++Flattened;
      Changed = true;
    }
    finishFunctionObfuscation(F, "fla", Ctx, Changed);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
  return PreservedAnalyses::all();
}
