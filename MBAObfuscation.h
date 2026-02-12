//===- MBAObfuscation.h - MBA obfuscation --------------------------------===//
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
// Declares the MBA pass.
//
//===----------------------------------------------------------------------===//
#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class MBAObfuscationPass : public PassInfoMixin<MBAObfuscationPass> {
public:
  // Rewrites arithmetic into mixed boolean/arithmetic identities.
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};
} // namespace llvm
