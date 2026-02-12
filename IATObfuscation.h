//===- IATObfuscation.h - IAT obfuscation and resolver -------------------===//
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
// Declares import obfuscation and resolver helpers.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_IATOBFUSCATION_H
#define LLVM_OBFUSCATION_IATOBFUSCATION_H

#include "llvm/IR/PassManager.h"

namespace llvm {

class IATObfuscationPass : public PassInfoMixin<IATObfuscationPass> {
public:
  // Rewrites imports to make API usage harder to recover statically.
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif
