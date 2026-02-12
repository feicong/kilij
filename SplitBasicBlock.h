//===- SplitBasicBlock.h - Split basic block obfuscation ------------------===//
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
// This file declares the split basic block obfuscation pass.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBFUSCATION_SPLITBASICBLOCK_H
#define LLVM_OBFUSCATION_SPLITBASICBLOCK_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class SplitBasicBlockPass : public PassInfoMixin<SplitBasicBlockPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  // Force availability under optnone; obfuscation is opt-in.
  static bool isRequired() { return true; }
};
} // namespace llvm

#endif
