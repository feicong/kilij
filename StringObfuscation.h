//===- StringObfuscation.h - String obfuscation --------------------------===//
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
// Declares string obfuscation helpers and configuration.
//
//===----------------------------------------------------------------------===//
#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class StringObfuscationPass : public PassInfoMixin<StringObfuscationPass> {
public:
  // Obfuscates constant C-strings with a decode-on-use helper.
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};
} // namespace llvm
