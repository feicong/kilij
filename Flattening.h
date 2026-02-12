//===- Flattening.h - Flattening obfuscation pass -------------------------===//
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
// This file declares the flattening obfuscation pass.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBFUSCATION_FLATTENING_H
#define LLVM_OBFUSCATION_FLATTENING_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class FlatteningPass : public PassInfoMixin<FlatteningPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
  // Preserve availability under optnone; obfuscation is explicitly enabled.
  static bool isRequired() { return true; }
};
} // namespace llvm

#endif
