//===- VMInterpreter.h - Reference VM interpreter ------------------------===//
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
// Declares the reference VM interpreter used for validation.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMINTERPRETER_H
#define LLVM_OBFUSCATION_VMINTERPRETER_H

#include "VMIR.h"
#include "llvm/ADT/SmallVector.h"
#include <cstdint>
#include <string>

namespace llvm {
namespace obfvm {

struct VMRuntimeState {
  SmallVector<uint64_t, 16> Regs;
  uint32_t PC = 0;
};

class VMInterpreter {
public:
  // Debug-only reference interpreter; used for validation and testing.
  bool run(const VMFunction &F, VMRuntimeState &State, uint64_t &RetVal,
           std::string *Err = nullptr) const;
};

} // namespace obfvm
} // namespace llvm

#endif
