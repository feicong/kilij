//===- BogusControlFlow.h - Bogus control flow obfuscation ---------------===//
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
// Declares the bogus control flow obfuscation pass.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBFUSCATION_BOGUSCONTROLFLOW_H
#define LLVM_OBFUSCATION_BOGUSCONTROLFLOW_H

#include "Utils.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
class BogusControlFlowPass : public PassInfoMixin<BogusControlFlowPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  // Keep pass available even under optnone; obfuscation is opt-in.
  static bool isRequired() { return true; }

private:
  const Module *CachedModule = nullptr;
  ::TaggedFunctionCache TagCache;
};
} // namespace llvm
#endif
