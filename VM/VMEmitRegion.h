//===- VMEmitRegion.h - Emit region VM executors -------------------------===//
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
// Declares helpers for emitting region-mode executors and dispatcher.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMEMITREGION_H
#define LLVM_OBFUSCATION_VMEMITREGION_H

#include "VMConfig.h"
#include "VMIR.h"
#include "llvm/IR/Function.h"
#include <string>

namespace llvm {
namespace obfvm {

// Emit region executors plus the runtime dispatcher for region-based VM mode.
Function *emitVMRegions(Module &M, const VMFunction &F, const VMConfig &Cfg,
                        std::string &Err, uint32_t &EntrySlot);

} // namespace obfvm
} // namespace llvm

#endif
