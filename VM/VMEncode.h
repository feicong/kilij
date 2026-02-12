//===- VMEncode.h - VM register encoding and MBA -------------------------===//
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
// Declares the VM encoding pipeline (register encoding plus MBA
// expansion).
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMENCODE_H
#define LLVM_OBFUSCATION_VMENCODE_H

#include "VMConfig.h"
#include "VMLowering.h"
#include <string>

namespace llvm {
namespace obfvm {

// Affine encoding rewrites VM IR so register values are stored as A*x+B;
// optional Feistel adds non-linearity. Must run before MBA to avoid MBA
// seeing already-expanded decode/encode sequences.
bool applyAffineEncoding(VMLoweringResult &Res, bool EnableFeistel,
                         bool FeistelAllRegs, unsigned FeistelRounds,
                         unsigned EncodePercent, std::string &Err);
// MBA replaces simple ops with equivalent multi-term expressions.
bool applyMBAObfuscation(VMFunction &F, std::string &Err);

} // namespace obfvm
} // namespace llvm

#endif
