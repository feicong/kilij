//===- Substitution.cpp - Instruction substitution obfuscation -----------===//
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
// Implements instruction substitution patterns and the pass driver.
//
//===----------------------------------------------------------------------===//

#include "Substitution.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO.h"

using namespace llvm;

#define DEBUG_TYPE "substitution"

STATISTIC(Add, "Add substituted");
STATISTIC(Sub, "Sub substituted");
STATISTIC(And, "And substituted");
STATISTIC(Or, "Or substituted");
STATISTIC(Xor, "Xor substituted");

namespace {
cl::opt<bool> Substitution("sub", cl::init(false),
                           cl::desc("Enable instruction substitutions"));

cl::opt<int>
    ObfTimes("sub_loop",
             cl::desc("Choose how many time the -sub pass loops on a function"),
             cl::value_desc("number of times"), cl::init(1), cl::Optional);

bool substitute(Function *f, std::size_t origBBs, std::size_t origInsts);

void addNeg(BinaryOperator *bo);
void addDoubleNeg(BinaryOperator *bo);
void addRand(BinaryOperator *bo);
void addRand2(BinaryOperator *bo);

void subNeg(BinaryOperator *bo);
void subRand(BinaryOperator *bo);
void subRand2(BinaryOperator *bo);

void andSubstitution(BinaryOperator *bo);
void andSubstitutionRand(BinaryOperator *bo);

void orSubstitution(BinaryOperator *bo);
void orSubstitutionRand(BinaryOperator *bo);

void xorSubstitution(BinaryOperator *bo);
void xorSubstitutionRand(BinaryOperator *bo);

// Each opcode has a table of algebraically equivalent rewrites; the pass
// picks one at random per instruction to diversify output across builds.
#define NUMBER_ADD_SUBST 4
#define NUMBER_SUB_SUBST 3
#define NUMBER_AND_SUBST 2
#define NUMBER_OR_SUBST 2
#define NUMBER_XOR_SUBST 2

void (*funcAdd[NUMBER_ADD_SUBST])(BinaryOperator *bo) = {&addNeg, &addDoubleNeg,
                                                         &addRand, &addRand2};
void (*funcSub[NUMBER_SUB_SUBST])(BinaryOperator *bo) = {&subNeg, &subRand,
                                                         &subRand2};
void (*funcAnd[NUMBER_AND_SUBST])(BinaryOperator *bo) = {&andSubstitution,
                                                         &andSubstitutionRand};
void (*funcOr[NUMBER_OR_SUBST])(BinaryOperator *bo) = {&orSubstitution,
                                                       &orSubstitutionRand};
void (*funcXor[NUMBER_XOR_SUBST])(BinaryOperator *bo) = {&xorSubstitution,
                                                         &xorSubstitutionRand};

bool substitute(Function *f, std::size_t origBBs, std::size_t origInsts) {
  Function *tmp = f;
  bool Changed = false;

  int times = ObfTimes;
  do {
    for (Function::iterator bb = tmp->begin(); bb != tmp->end(); ++bb) {
      if (shouldSkipBlock(&*bb)) {
        continue;
      }
      for (BasicBlock::iterator inst = bb->begin(); inst != bb->end();) {
        Instruction *Cur = &*inst++;
        if (shouldSkipInstruction(Cur)) {
          continue;
        }
        if (isArithObf(*Cur)) {
          continue;
        }
        if (auto *BO = dyn_cast<BinaryOperator>(Cur)) {
          Type *Ty = BO->getType();
          if (!Ty->isIntegerTy() || Ty->isVectorTy()) {
            continue;
          }
          // nsw/nuw/exact flags can't be preserved through substitution.
          if (auto *OBO = dyn_cast<OverflowingBinaryOperator>(BO)) {
            if (OBO->hasNoSignedWrap() || OBO->hasNoUnsignedWrap())
              continue;
          }
          if (auto *PE = dyn_cast<PossiblyExactOperator>(BO)) {
            if (PE->isExact())
              continue;
          }
          Instruction *Prev = BO->getPrevNode();
          bool Replaced = false;
          switch (BO->getOpcode()) {
          case BinaryOperator::Add:
            (funcAdd[llvm::cryptoutils->get_range(NUMBER_ADD_SUBST)])(BO);
            ++Add;
            Replaced = true;
            break;
          case BinaryOperator::Sub:
            (funcSub[llvm::cryptoutils->get_range(NUMBER_SUB_SUBST)])(BO);
            ++Sub;
            Replaced = true;
            break;
          // No substitution patterns for mul/div/rem/shift yet.
          case Instruction::And:
            (funcAnd[llvm::cryptoutils->get_range(2)])(BO);
            ++And;
            Replaced = true;
            break;
          case Instruction::Or:
            (funcOr[llvm::cryptoutils->get_range(2)])(BO);
            ++Or;
            Replaced = true;
            break;
          case Instruction::Xor:
            (funcXor[llvm::cryptoutils->get_range(2)])(BO);
            ++Xor;
            Replaced = true;
            break;
          default:
            break;
          }
          if (Replaced) {
            // Tag the inserted range to avoid re-obfuscating our own ops.
            markInsertedRange(*bb, Prev, BO, "sub");
            Changed = true;
          }
          if (Replaced && BO->use_empty())
            BO->eraseFromParent();
        }
      }
    }
  } while (--times > 0 && checkObfuscationBudget(*tmp, origBBs, origInsts, "sub"));
  return Changed;
}

// Implementation of a = b - (-c)
void addNeg(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  if (bo->getOpcode() == Instruction::Add) {
    op = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op, "", bo->getIterator());


    bo->replaceAllUsesWith(op);
  }
}

// Implementation of a = -(-b + (-c))
void addDoubleNeg(BinaryOperator *bo) {
  Instruction *op, *op2 = nullptr;

  if (bo->getOpcode() == Instruction::Add) {
    op = BinaryOperator::CreateNeg(bo->getOperand(0), "", bo->getIterator());
    op2 = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::Add, op, op2, "", bo->getIterator());
    op = BinaryOperator::CreateNeg(op, "", bo->getIterator());

    // Check signed wrap
    // op->setHasNoSignedWrap(bo->hasNoSignedWrap());
    // op->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
  } else {
    op = UnaryOperator::CreateFNeg(bo->getOperand(0), "", bo->getIterator());
    op2 = UnaryOperator::CreateFNeg(bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::FAdd, op, op2, "", bo->getIterator());
    op = UnaryOperator::CreateFNeg(op, "", bo->getIterator());
  }

  bo->replaceAllUsesWith(op);
}

// Implementation of  r = rand (); a = b + r; a = a + c; a = a - r
void addRand(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  if (bo->getOpcode() == Instruction::Add) {
    Type *ty = bo->getType();
    ConstantInt *co =
        (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());
    op =
        BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo->getIterator());


    bo->replaceAllUsesWith(op);
  }
}

// Implementation of r = rand (); a = b - r; a = a + b; a = a + r
void addRand2(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  if (bo->getOpcode() == Instruction::Add) {
    Type *ty = bo->getType();
    ConstantInt *co =
        (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());
    op =
        BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::Add, op, co, "", bo->getIterator());


    bo->replaceAllUsesWith(op);
  }
}

// Implementation of a = b + (-c)
void subNeg(BinaryOperator *bo) {
  Instruction *op = nullptr;

  if (bo->getOpcode() == Instruction::Sub) {
    op = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo->getIterator());

    // Check signed wrap
    // op->setHasNoSignedWrap(bo->hasNoSignedWrap());
    // op->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
  } else {
    op = UnaryOperator::CreateFNeg(bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::FAdd, bo->getOperand(0), op, "", bo->getIterator());
  }

  bo->replaceAllUsesWith(op);
}

// Implementation of  r = rand (); a = b + r; a = a - c; a = a - r
void subRand(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  if (bo->getOpcode() == Instruction::Sub) {
    Type *ty = bo->getType();
    ConstantInt *co =
        (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());
    op =
        BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo->getIterator());


    bo->replaceAllUsesWith(op);
  }
}

// Implementation of  r = rand (); a = b - r; a = a - c; a = a + r
void subRand2(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  if (bo->getOpcode() == Instruction::Sub) {
    Type *ty = bo->getType();
    ConstantInt *co =
        (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());
    op =
        BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo->getIterator());
    op =
        BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo->getIterator());
    op = BinaryOperator::Create(Instruction::Add, op, co, "", bo->getIterator());

    bo->replaceAllUsesWith(op);
  }
}

// a = b & c => a = (b ^ ~c) & b
void andSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo->getIterator());
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::Xor, bo->getOperand(0), op, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::And, op1, bo->getOperand(0), "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}

// a = a & b <=> !(!a | !b) & (r | !r)
// The (r | !r) tautology adds junk ops without changing the result.
void andSubstitutionRand(BinaryOperator *bo) {
  Type *ty = bo->getType();
  ConstantInt *co =
      (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());

  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo->getIterator());
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo->getIterator());
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo->getIterator());
  BinaryOperator *opa =
      BinaryOperator::Create(Instruction::Or, op, op1, "", bo->getIterator());
  opr = BinaryOperator::Create(Instruction::Or, co, opr, "", bo->getIterator());
  op = BinaryOperator::CreateNot(opa, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::And, op, opr, "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}

// a = b | c via (a ^ r) ^ (b ^ r) | (a & b), randomized with tautology terms.
void orSubstitutionRand(BinaryOperator *bo) {
  Type *ty = bo->getType();
  ConstantInt *co =
      (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());

  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo->getIterator());
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo->getIterator());
  BinaryOperator *op2 = BinaryOperator::CreateNot(co, "", bo->getIterator());
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, op, co, "", bo->getIterator());
  BinaryOperator *op4 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op2, "", bo->getIterator());
  BinaryOperator *op5 =
      BinaryOperator::Create(Instruction::And, op1, co, "", bo->getIterator());
  BinaryOperator *op6 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op2, "", bo->getIterator());
  op3 = BinaryOperator::Create(Instruction::Or, op3, op4, "", bo->getIterator());
  op4 = BinaryOperator::Create(Instruction::Or, op5, op6, "", bo->getIterator());
  op5 = BinaryOperator::Create(Instruction::Xor, op3, op4, "", bo->getIterator());
  op3 = BinaryOperator::Create(Instruction::Or, op, op1, "", bo->getIterator());
  op3 = BinaryOperator::CreateNot(op3, "", bo->getIterator());
  op4 = BinaryOperator::Create(Instruction::Or, co, op2, "", bo->getIterator());
  op4 = BinaryOperator::Create(Instruction::And, op3, op4, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::Or, op5, op4, "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}

// a = b | c => (b & c) | (b ^ c)
void orSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  op = BinaryOperator::Create(Instruction::And, bo->getOperand(0),
                              bo->getOperand(1), "", bo->getIterator());
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo->getIterator());

  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}

// a = a ^ b => (!a & b) | (a & !b)
void xorSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::And, bo->getOperand(1), op, "", bo->getIterator());
  BinaryOperator *op1 =
      BinaryOperator::CreateNot(bo->getOperand(1), "", bo->getIterator());
  op1 = BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}

// a = a ^ b <=> (a ^ r) ^ (b ^ r), expanded through boolean ops with random r.
void xorSubstitutionRand(BinaryOperator *bo) {
  BinaryOperator *op = nullptr;

  Type *ty = bo->getType();
  ConstantInt *co =
      (ConstantInt *)ConstantInt::get(ty, llvm::cryptoutils->get_uint64_t());

  op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::And, co, op, "", bo->getIterator());
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo->getIterator());
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), opr, "", bo->getIterator());
  BinaryOperator *op2 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo->getIterator());
  op2 = BinaryOperator::Create(Instruction::And, op2, co, "", bo->getIterator());
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), opr, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo->getIterator());
  op1 = BinaryOperator::Create(Instruction::Or, op2, op3, "", bo->getIterator());
  op = BinaryOperator::Create(Instruction::Xor, op, op1, "", bo->getIterator());
  bo->replaceAllUsesWith(op);
}
} // namespace

PreservedAnalyses SubstitutionPass::run(Function &F,
                                        FunctionAnalysisManager &AM) {
  if (ObfTimes <= 0) {
    errs() << "Substitution application number -sub_loop=x must be x > 0";
    return PreservedAnalyses::all();
  }

  if (toObfuscate(Substitution, &F, "sub")) {
    ObfPassContext Ctx = beginFunctionObfuscation(F, "sub");
    bool Changed = substitute(&F, Ctx.OrigBBs, Ctx.OrigInsts);
    finishFunctionObfuscation(F, "sub", Ctx, Changed, false);
    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }

  return PreservedAnalyses::all();
}
