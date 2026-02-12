//===- IndirectBranch.h - Indirect branch obfuscation --------------------===//
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
// Declares indirect-branch obfuscation helpers.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_INDIRECTBRANCH_H
#define LLVM_OBFUSCATION_INDIRECTBRANCH_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class IndirectBranchPass : public PassInfoMixin<IndirectBranchPass> {
public:
  // Converts direct calls/branches to indirect to blur control-flow edges.
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};
} // namespace llvm

#endif
