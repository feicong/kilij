//===- Utils.h - Obfuscation utilities -----------------------------------===//
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
// Shared utilities and helpers used across obfuscation passes.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_UTILS_H
#define LLVM_OBFUSCATION_UTILS_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include <cstdint>
#include <cstddef>
#include <string>

// Parse LLVM global annotations for per-function obfuscation controls.
std::string readAnnotate(const llvm::Function *f);
bool hasAnnotation(const llvm::Function *f, llvm::StringRef token);
bool toObfuscate(bool flag, llvm::Function *f, llvm::StringRef attribute);
std::string normalizePath(llvm::StringRef Path);
bool pathMatchesAny(llvm::StringRef Path,
                    llvm::ArrayRef<std::string> Patterns);
bool pathMatchesPatternList(llvm::StringRef Path,
                            llvm::StringRef Patterns);

// Allow pass plugins to force-enable a pass when it's explicitly requested in a
// textual pipeline (e.g. opt -passes='fla,bcf'), even if the corresponding
// -mllvm flag was not provided.
void forceObfuscationPass(llvm::StringRef PassToken);
bool isForcedObfuscationPass(llvm::StringRef PassToken);

// Skip helpers for IR that is fragile or unsafe to transform.
bool shouldSkipInstruction(const llvm::Instruction *I);
bool shouldSkipBlock(const llvm::BasicBlock *BB);
bool shouldSkipFunction(const llvm::Function *F);

// Record baseline sizes once so growth limits stay consistent across passes.
void ensureObfBaseline(llvm::Function &F);

std::size_t countInstructions(const llvm::Function &F);
std::size_t countBasicBlocks(const llvm::Function &F);
// Enforce configured size budgets to avoid pathological blowups.
bool checkObfuscationBudget(llvm::Function &F, std::size_t origBBs,
                            std::size_t origInsts, llvm::StringRef passName);
int clampInt(int v, int lo, int hi);
unsigned clampProb(int v);

// Captures pre-pass sizes so finish can check the growth budget.
struct ObfPassContext {
  std::size_t OrigBBs = 0;
  std::size_t OrigInsts = 0;
};


ObfPassContext beginFunctionObfuscation(llvm::Function &F,
                                        llvm::StringRef Tag,
                                        bool DumpBefore = true,
                                        bool EnsureBaseline = true);
void finishFunctionObfuscation(llvm::Function &F, llvm::StringRef Tag,
                               const ObfPassContext &Ctx, bool Changed,
                               bool CheckBudget = true, bool Verify = true,
                               bool DumpAfter = true);

// Mark injected arithmetic so later passes can avoid double-encoding it.
void markArithObf(llvm::Instruction &I, llvm::StringRef Tag);
bool isArithObf(const llvm::Instruction &I);
void markInsertedRange(llvm::BasicBlock &BB, llvm::Instruction *Prev,
                       llvm::Instruction *End, llvm::StringRef Tag);

// Common SplitMix64 bit-mixer used for deterministic diffusion.
uint64_t splitmix64(uint64_t &x);

// Cache of obfuscation-tagged helper functions within a module.
// Build once per module/pass run to avoid repeated O(N) scans.
struct TaggedFunctionCache {
  llvm::DenseMap<llvm::StringRef, llvm::Function *> Map;
  const llvm::Module *Owner = nullptr;

  TaggedFunctionCache() = default;
  explicit TaggedFunctionCache(llvm::Module &M) { rebuild(M); }

  void rebuild(llvm::Module &M);
  llvm::Function *lookup(llvm::StringRef Tag) const;
  void insert(llvm::Function &F);
  void clear();
};

// Shared funclet (Windows EH) operand bundle handling.
struct FuncletBundleContext {
  llvm::DenseMap<llvm::BasicBlock *, llvm::SmallVector<llvm::BasicBlock *, 1>>
      FuncletPads;
  const llvm::Function *Owner = nullptr;
  bool Built = false;
};

void ensureFuncletMap(llvm::Function &F, FuncletBundleContext &Ctx);
llvm::SmallVector<llvm::OperandBundleDef, 1>
getFuncletBundleFor(llvm::Instruction *Site, FuncletBundleContext &Ctx);
bool hasAmbiguousFunclet(llvm::Instruction *Site, FuncletBundleContext &Ctx);

llvm::Function *getOrCreateObfFail(llvm::Module &M);
llvm::Function *getOrCreateObfFail(llvm::Module &M,
                                   TaggedFunctionCache *TagCache);

void maybeDumpIR(const llvm::Function &F, llvm::StringRef tag);
void maybeDumpIR(const llvm::Module &M, llvm::StringRef tag);
void recordObfuscationSeed(llvm::Module &M);
void verifyFunctionOrDie(const llvm::Function &F, llvm::StringRef passName);
void verifyModuleOrDie(const llvm::Module &M, llvm::StringRef passName);

// Symbol obfuscation helpers (internal/private globals/functions).
llvm::Function *findTaggedFunction(llvm::Module &M, llvm::StringRef Tag);
llvm::GlobalVariable *findTaggedGlobal(llvm::Module &M, llvm::StringRef Tag);
void obfuscateSymbolName(llvm::GlobalObject &GO, llvm::Module &M,
                         llvm::StringRef Tag, llvm::StringRef Base);
llvm::GlobalVariable *getOrCreateObfFailCode(llvm::Module &M);

#endif
