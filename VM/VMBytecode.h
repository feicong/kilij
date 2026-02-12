//===- VMBytecode.h - VM bytecode definitions ----------------------------===//
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
// Defines the opcode layout, operand encoding, and validation constants
// for VM bytecode.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMBYTECODE_H
#define LLVM_OBFUSCATION_VMBYTECODE_H

#include "VMIR.h"
#include <array>
#include <cstdint>
#include <vector>

namespace llvm {
class Constant;
class ConstantArray;
class ConstantInt;
class LLVMContext;
class Module;
class StructType;
class Type;
class raw_ostream;

namespace obfvm {

// Pad byte encodes side-channel flags that survive encoding; low bits are
// semantic (ImmRaw, Volatile, Align), high bits are randomized noise.
static constexpr uint8_t VMBCPadImmRaw = 0x1;
static constexpr uint8_t VMBCPadVolatile = 0x2;
static constexpr uint8_t VMBCPadAlignShift = 2;
static constexpr uint8_t VMBCPadAlignMask = 0x3C;

enum class VMBCField : uint8_t {
  Op = 0,
  Type = 1,
  Aux = 2,
  Pad = 3,
  Dst = 4,
  A = 5,
  B = 6,
  Imm = 7,
  TTrue = 8,
  TFalse = 9,
  CallIndex = 10,
  Count = 11
};

static constexpr unsigned VMBCFieldCount =
    static_cast<unsigned>(VMBCField::Count);

struct VMBCLayout {
  uint8_t Stride = 36;
  uint8_t PadBytes = 0;
  // FieldIndex maps logical fields to physical order for layout shuffling.
  std::array<uint8_t, VMBCFieldCount> FieldIndex{};
};

struct VMBCEncodingInfo {
  uint64_t MixConst = 0;
  uint64_t MulConst1 = 0;
  uint64_t MulConst2 = 0;
  uint64_t SaltInstr = 0;
  uint64_t SaltOff = 0;
  uint64_t SaltSwitchVal = 0;
  uint64_t SaltSwitchTgt = 0;
  uint64_t PermSeedMix = 0;
  uint8_t Rot8 = 0;
};

// Fixed-width instruction; all fields always present so the stride is constant
// and layout shuffling doesn't need per-opcode format tables.
struct VMBCInstr {
  uint8_t Op = 0;
  uint8_t Type = 0;
  uint8_t Aux = 0;
  uint8_t Pad = 0;
  uint32_t Dst = 0;
  uint32_t A = 0;
  uint32_t B = 0;
  uint64_t Imm = 0;
  Constant *ImmConst = nullptr;
  uint32_t TTrue = 0;
  uint32_t TFalse = 0;
  uint32_t CallIndex = 0;
};

struct VMBytecode {
  std::vector<VMBCInstr> Instrs;
  std::vector<uint32_t> BlockOffsets;
  std::vector<uint64_t> SwitchValues;
  std::vector<uint32_t> SwitchTargets;
};

VMBytecode buildBytecode(const VMFunction &F);

void dumpVMBytecode(const VMBytecode &BC, raw_ostream &OS);

struct VMBytecodeGlobals {
  Constant *InstrArray = nullptr;
  Constant *BlockOffsets = nullptr;
  Constant *SwitchValues = nullptr;
  Constant *SwitchTargets = nullptr;
  Constant *OpDecode = nullptr;
  // Hash constants used to validate encoded bytecode at runtime.
  uint64_t HashKey = 0;
  uint64_t HashMul = 0;
};

VMBCLayout buildVMBCLayout(bool Hard, uint64_t Seed = 0);
VMBCEncodingInfo buildVMBCEncodingInfo(uint64_t Seed, bool Hard);
StructType *getOrCreateBCInstrType(LLVMContext &Ctx,
                                   const VMBCLayout &Layout);

inline unsigned getBCFieldIndex(const VMBCLayout &Layout, VMBCField Field) {
  return Layout.FieldIndex[static_cast<unsigned>(Field)];
}

VMBytecodeGlobals emitBytecodeGlobals(Module &M, const VMBytecode &BC,
                                      StringRef BaseName,
                                      const VMBCLayout &Layout,
                                      const VMBCEncodingInfo &EncInfo,
                                      uint64_t EncodeKey = 0,
                                      bool Encode = false,
                                      uint64_t HashKey = 0,
                                      uint64_t HashMul = 0);

} // namespace obfvm
} // namespace llvm

#endif
