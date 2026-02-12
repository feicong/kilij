//===- SplitBasicBlock.cpp - Split basic block obfuscation ----------------===//
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
// This file implements the split basic block pass
//
//===----------------------------------------------------------------------===//

#include "SplitBasicBlock.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils/Local.h" // For DemoteRegToStack and DemotePHIToStack

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "split"

STATISTIC(Split, "Basicblock splitted");

namespace {
cl::opt<bool> SplitEnabled("split", cl::init(false),
                           cl::desc("Enable basic block splitting"));

cl::opt<int> SplitNum("split_num", cl::init(2),
                      cl::desc("Split <split_num> time each BB"));

bool containsPHI(BasicBlock *b) {
  for (BasicBlock::iterator I = b->begin(), IE = b->end(); I != IE; ++I) {
    if (isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

// Splitting around alloca/stacksave can violate dominance for lifetime
// markers or push the alloca out of the entry block where it's expected.
bool hasStackRelatedInst(BasicBlock *b) {
  for (Instruction &I : *b) {
    if (isa<AllocaInst>(&I)) {
      return true;
    }
    if (auto *II = dyn_cast<IntrinsicInst>(&I)) {
      switch (II->getIntrinsicID()) {
      case Intrinsic::lifetime_start:
      case Intrinsic::lifetime_end:
      case Intrinsic::stacksave:
      case Intrinsic::stackrestore:
        return true;
      default:
        break;
      }
    }
  }
  return false;
}

bool doSplit(Function &F, std::size_t OrigBBs, std::size_t OrigInsts) {
  std::vector<BasicBlock *> origBB;
  bool Changed = false;

  for (Function::iterator I = F.begin(), IE = F.end(); I != IE; ++I) {
    origBB.push_back(&*I);
  }

  for (std::vector<BasicBlock *>::iterator I = origBB.begin(),
                                           IE = origBB.end();
       I != IE; ++I) {
    BasicBlock *curr = *I;
    int splitN = SplitNum;
    if (shouldSkipBlock(curr)) {
      continue;
    }

    // PHI blocks can't be split without remapping incoming edges.
    if (curr->size() < 3 || containsPHI(curr) || hasStackRelatedInst(curr)) {
      continue;
    }

    // Clamp to avoid degenerate single-instruction blocks.
    if ((size_t)splitN >= curr->size()) {
      splitN = curr->size() - 1;
    }

    // Split iteratively within the current block to avoid degenerate splits.
    BasicBlock *toSplit = curr;
    for (int i = 0; i < splitN; ++i) {
      if (toSplit->size() < 3)
        break; // need at least 2 non-terminator instructions
      unsigned maxIdx = static_cast<unsigned>(toSplit->size() - 2);
      unsigned splitIdx = 1 + cryptoutils->get_range(maxIdx);
      BasicBlock::iterator it = toSplit->begin();
      std::advance(it, splitIdx);
      if (it == toSplit->end())
        continue;
      toSplit = toSplit->splitBasicBlock(it, toSplit->getName() + ".split");
      ++Split;
      Changed = true;
      if (!checkObfuscationBudget(F, OrigBBs, OrigInsts, "split"))
        return Changed;
    }
  }
  return Changed;
}
} // namespace

PreservedAnalyses SplitBasicBlockPass::run(Function &F,
                                           FunctionAnalysisManager &AM) {
  if (!((SplitNum > 1) && (SplitNum <= 10))) {
    errs() << "Split application basic block percentage\
            -split_num=x must be 1 < x <= 10";
    return PreservedAnalyses::all();
  }

  if (toObfuscate(SplitEnabled, &F, "split")) {
    // Capture baseline sizes to enforce growth caps across passes.
    ObfPassContext Ctx = beginFunctionObfuscation(F, "split");
    bool Changed = doSplit(F, Ctx.OrigBBs, Ctx.OrigInsts);
    finishFunctionObfuscation(F, "split", Ctx, Changed);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  return PreservedAnalyses::all();
}
