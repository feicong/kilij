//===- Substitution.h - Substitution obfuscation pass ---------------------===//
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
// This file declares the substitution obfuscation pass.
//
//===----------------------------------------------------------------------===//


#ifndef LLVM_OBFUSCATION_SUBSTITUTION_H
#define LLVM_OBFUSCATION_SUBSTITUTION_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class SubstitutionPass : public PassInfoMixin<SubstitutionPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  // Preserve availability under optnone; obfuscation is opt-in.
  static bool isRequired() { return true; }
};
} // namespace llvm

#endif
