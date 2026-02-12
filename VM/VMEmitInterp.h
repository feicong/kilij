//===- VMEmitInterp.h - Emit opcode-mode VM interpreter ------------------===//
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
// Declares helpers for emitting the opcode-mode VM interpreter.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMEMITINTERP_H
#define LLVM_OBFUSCATION_VMEMITINTERP_H

#include "VMBytecode.h"
#include "VMConfig.h"
#include "VMIR.h"
#include "llvm/IR/Function.h"

namespace llvm {
namespace obfvm {

// Emit a bytecode interpreter tailored to the current layout/encoding.
Function *emitVMInterpreter(Module &M, const VMFunction &F,
                            const VMBytecode &BC,
                            const VMBytecodeGlobals &Globals,
                            const VMBCLayout &Layout,
                            const VMBCEncodingInfo &EncInfo,
                            const VMConfig &Cfg, uint64_t BCKey);

} // namespace obfvm
} // namespace llvm

#endif
