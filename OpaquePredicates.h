//===- OpaquePredicates.h - Opaque predicate helpers ---------------------===//
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
// Declares opaque predicate helpers used by other passes.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_OPAQUEPREDICATES_H
#define LLVM_OBFUSCATION_OPAQUEPREDICATES_H

#include "Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include <cstdint>
#include <string>

namespace llvm {
class AllocaInst;
class Instruction;
class Value;
}

struct OpaquePredContext {
  const llvm::Function *Owner = nullptr;
  llvm::DenseMap<const llvm::Instruction *, uint64_t> InstIndex;
  std::string ModuleSeedHex;
  // Mixed constants keep predicates stable per-module without embedding seeds.
  uint64_t MixConst = 0;
  bool MixConstInit = false;
  FuncletBundleContext Funclets;
  TaggedFunctionCache *TagCache = nullptr;
  llvm::AllocaInst *SeedSlot = nullptr;
  llvm::Value *FuncSeed = nullptr;
};

struct OpaquePredResult {
  llvm::Value *Cond = nullptr;
  bool ExpectedTrue = true;
  // 0=Collatz, 1=Powmod, 2=DiffSquares, 3=XorEq, 4=CheapIdentity,
  // 5=MinorQuadric, 6=QSeries, 7=Composite.
  uint8_t AlgoId = 0;
};

llvm::Function *getOrCreateCollatzPredicate(llvm::Module &M,
                                            unsigned variant);
OpaquePredResult createOpaquePredicate(llvm::IRBuilder<> &B, llvm::Function &F,
                                       llvm::Instruction *Site,
                                       OpaquePredContext &Ctx);

#endif
