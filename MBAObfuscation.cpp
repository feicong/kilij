//===- MBAObfuscation.cpp - MBA obfuscation ------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE for details.
//
// Copyright (c) 2026 Danny Mundy
//
//===----------------------------------------------------------------------===//
//
// Implements MBA rewrite patterns and the MBA pass driver.
//
//===----------------------------------------------------------------------===//
#include "MBAObfuscation.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "mba"

static cl::opt<bool> MBAEnabled("mba", cl::init(false),
                               cl::desc("Enable MBA obfuscation"));
static cl::opt<int> MBAIterations("mba_loop", cl::init(1),
                                  cl::desc("MBA transformation iterations"));
static cl::opt<unsigned>
    MBAMaxIRInsts("mba-max-ir-insts", cl::init(0),
                  cl::desc("Max IR instruction count per function eligible "
                           "for MBA (0 = unlimited)"));

static bool isSupportedType(const Type *Ty) {
  return Ty && Ty->isIntegerTy() && !Ty->isVectorTy();
}

static Value *mbaAdd(IRBuilder<> &B, Value *X, Value *Y) {
  // Algebraic identities expand add into boolean ops to obscure intent.
  switch (cryptoutils->get_range(3)) {
  case 0: {
    Value *Xor = B.CreateXor(X, Y);
    Value *And = B.CreateAnd(X, Y);
    Value *And2 = B.CreateShl(And, 1);
    return B.CreateAdd(Xor, And2);
  }
  case 1: {
    Value *Or = B.CreateOr(X, Y);
    Value *And = B.CreateAnd(X, Y);
    return B.CreateAdd(Or, And);
  }
  default: {
    Value *Or = B.CreateOr(X, Y);
    Value *Or2 = B.CreateShl(Or, 1);
    Value *Xor = B.CreateXor(X, Y);
    return B.CreateSub(Or2, Xor);
  }
  }
}

static Value *mbaSub(IRBuilder<> &B, Value *X, Value *Y) {
  Value *NegY = B.CreateNeg(Y);
  Value *Xor = B.CreateXor(X, NegY);
  Value *And = B.CreateAnd(X, NegY);
  Value *And2 = B.CreateShl(And, 1);
  return B.CreateAdd(Xor, And2);
}

static Value *mbaXor(IRBuilder<> &B, Value *X, Value *Y) {
  if (cryptoutils->get_range(2) == 0) {
    Value *Or = B.CreateOr(X, Y);
    Value *And = B.CreateAnd(X, Y);
    return B.CreateSub(Or, And);
  }
  Value *NotY = B.CreateNot(Y);
  Value *NotX = B.CreateNot(X);
  Value *A = B.CreateAnd(X, NotY);
  Value *Bv = B.CreateAnd(NotX, Y);
  return B.CreateOr(A, Bv);
}

static Value *mbaAnd(IRBuilder<> &B, Value *X, Value *Y) {
  if (cryptoutils->get_range(2) == 0) {
    Value *Add = B.CreateAdd(X, Y);
    Value *Or = B.CreateOr(X, Y);
    return B.CreateSub(Add, Or);
  }
  Value *NotX = B.CreateNot(X);
  Value *NotY = B.CreateNot(Y);
  Value *Or = B.CreateOr(NotX, NotY);
  return B.CreateNot(Or);
}

static Value *mbaOr(IRBuilder<> &B, Value *X, Value *Y) {
  if (cryptoutils->get_range(2) == 0) {
    Value *And = B.CreateAnd(X, Y);
    Value *Xor = B.CreateXor(X, Y);
    return B.CreateAdd(And, Xor);
  }
  Value *And = B.CreateAnd(X, Y);
  Value *Add = B.CreateAdd(X, Y);
  return B.CreateSub(Add, And);
}

static bool applyMBA(BinaryOperator *BO) {
  if (!BO)
    return false;
  if (!isSupportedType(BO->getType()))
    return false;
  auto *Ty = dyn_cast<IntegerType>(BO->getType());
  if (!Ty)
    return false;
  if (Ty->getBitWidth() <= 1)
    return false;
  if (BO->getOperand(0)->getType() != BO->getType() ||
      BO->getOperand(1)->getType() != BO->getType())
    return false;
  if (shouldSkipInstruction(BO))
    return false;
  // Skip instructions already rewritten by sub/mba to prevent exponential
  // expansion on re-obfuscation.
  if (isArithObf(*BO))
    return false;
  // nsw/nuw/exact flags constrain optimization; our rewrite can't preserve
  // them, so bail rather than silently miscompile.
  if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(BO)) {
    if (OBO->hasNoSignedWrap() || OBO->hasNoUnsignedWrap())
      return false;
  }
  if (auto *PE = dyn_cast<PossiblyExactOperator>(BO)) {
    if (PE->isExact())
      return false;
  }

  Instruction *Prev = BO->getPrevNode();
  IRBuilder<> B(BO);
  B.SetCurrentDebugLocation(BO->getDebugLoc());

  Value *X = BO->getOperand(0);
  Value *Y = BO->getOperand(1);
  Value *NewVal = nullptr;

  switch (BO->getOpcode()) {
  case Instruction::Add:
    NewVal = mbaAdd(B, X, Y);
    break;
  case Instruction::Sub:
    NewVal = mbaSub(B, X, Y);
    break;
  case Instruction::Xor:
    NewVal = mbaXor(B, X, Y);
    break;
  case Instruction::And:
    NewVal = mbaAnd(B, X, Y);
    break;
  case Instruction::Or:
    NewVal = mbaOr(B, X, Y);
    break;
  default:
    return false;
  }

  if (!NewVal)
    return false;

  markInsertedRange(*BO->getParent(), Prev, BO, "mba");
  BO->replaceAllUsesWith(NewVal);
  BO->eraseFromParent();
  return true;
}

PreservedAnalyses MBAObfuscationPass::run(Function &F,
                                          FunctionAnalysisManager &AM) {
  if (MBAIterations <= 0) {
    return PreservedAnalyses::all();
  }

  LLVM_DEBUG(dbgs() << "mba: " << F.getName() << "\n");

  if (!toObfuscate(MBAEnabled, &F, "mba")) {
    return PreservedAnalyses::all();
  }
  if (MBAMaxIRInsts > 0 && countInstructions(F) > MBAMaxIRInsts) {
    return PreservedAnalyses::all();
  }

  ObfPassContext Ctx = beginFunctionObfuscation(F, "mba");

  bool changed = false;
  for (int iter = 0; iter < MBAIterations; ++iter) {
    SmallVector<BinaryOperator *, 16> work;
    for (BasicBlock &BB : F) {
      if (shouldSkipBlock(&BB))
        continue;
      for (Instruction &I : BB) {
        if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
          if (isSupportedType(BO->getType())) {
            if (isArithObf(*BO))
              continue;
            work.push_back(BO);
          }
        }
      }
    }

    // Build the worklist first to avoid iterator invalidation on rewrite.
    for (BinaryOperator *BO : work) {
      if (applyMBA(BO))
        changed = true;
    }

    if (!checkObfuscationBudget(F, Ctx.OrigBBs, Ctx.OrigInsts, "mba")) {
      break;
    }
  }

  if (changed) {
    finishFunctionObfuscation(F, "mba", Ctx, true, false);
    return PreservedAnalyses::none();
  }

  return PreservedAnalyses::all();
}
