//===- ConstObfuscation.h - Constant obfuscation -------------------------===//
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
// Declares the constant obfuscation pass.
//
//===----------------------------------------------------------------------===//
#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class ConstObfuscationPass : public PassInfoMixin<ConstObfuscationPass> {
public:
  // Encodes integer immediates so they don't appear verbatim in IR/ASM.
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
};
} // namespace llvm
