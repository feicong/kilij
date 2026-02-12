//===- VMPass.h - VM pass orchestration ----------------------------------===//
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
// Declares the VM pass and shared options.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMPASS_H
#define LLVM_OBFUSCATION_VMPASS_H

#include "llvm/IR/PassManager.h"

namespace llvm {
namespace obfvm {

class VMPass : public PassInfoMixin<VMPass> {
public:
  // Orchestrates VM lowering, encoding, and emission for marked functions.
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
};

} // namespace obfvm
} // namespace llvm

#endif
