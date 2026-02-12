//===- VMIR.h - VM IR definitions ----------------------------------------===//
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
// Defines the VM IR types, opcodes, and register model.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMIR_H
#define LLVM_OBFUSCATION_VMIR_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include <cstdint>

namespace llvm {
class Function;
class FunctionType;
class Constant;
class Type;
class raw_ostream;

namespace obfvm {

// Flat type system: no vectors, aggregates, or wide integers.  Everything
// that survives lowering fits in a single 64-bit VM register.
enum class VMTypeKind : uint8_t {
  I1,
  I8,
  I16,
  I32,
  I64,
  F32,
  F64,
  Ptr
};

struct VMType {
  VMTypeKind Kind;
  explicit VMType(VMTypeKind K = VMTypeKind::I64) : Kind(K) {}
};

unsigned getTypeBitWidth(VMTypeKind K, unsigned PtrBits);
const char *getTypeName(VMTypeKind K);

struct VMValue {
  enum class Kind : uint8_t { Reg, Imm, Const };
  Kind K = Kind::Imm;
  uint32_t Reg = 0;
  uint64_t Imm = 0;
  Constant *C = nullptr;

  // VM operands are small and self-describing to keep bytecode compact.
  static VMValue reg(uint32_t R) {
    VMValue V;
    V.K = Kind::Reg;
    V.Reg = R;
    return V;
  }

  static VMValue imm(uint64_t V) {
    VMValue Val;
    Val.K = Kind::Imm;
    Val.Imm = V;
    return Val;
  }

  static VMValue constant(Constant *Cst) {
    VMValue Val;
    Val.K = Kind::Const;
    Val.C = Cst;
    return Val;
  }
};

enum class VMBinOp : uint8_t {
  Add,
  Sub,
  Mul,
  UDiv,
  SDiv,
  URem,
  SRem,
  And,
  Or,
  Xor,
  Shl,
  LShr,
  AShr,
  FAdd,
  FSub,
  FMul,
  FDiv,
  FRem
};

enum class VMCmpPred : uint8_t {
  EQ,
  NE,
  ULT,
  ULE,
  UGT,
  UGE,
  SLT,
  SLE,
  SGT,
  SGE,
  FEQ,
  FNE,
  FLT,
  FLE,
  FGT,
  FGE
};

// Minimal ISA; calls go through CallHost stubs to avoid re-implementing
// calling conventions inside the interpreter.
enum class VMOpcode : uint8_t {
  Mov,
  BinOp,
  FNeg,
  ICmp,
  FCmp,
  Cast,
  Load,
  Store,
  MemFence,
  Br,
  CondBr,
  Switch,
  Select,
  Ret,
  CallHost,
  CallHostIndirect,
  Trap
};

enum class VMFenceKind : uint8_t {
  Acquire,
  Release,
  AcquireRelease,
  SeqCst
};

enum class VMCastKind : uint8_t {
  ZExt,
  SExt,
  Trunc,
  Bitcast,
  PtrToInt,
  IntToPtr,
  FPToUI,
  FPToSI,
  UIToFP,
  SIToFP,
  FPTrunc,
  FPExt
};

struct VMInstr {
  VMOpcode Op = VMOpcode::Mov;
  VMType Ty;
  VMType SrcTy;
  uint8_t Pad = 0;
  // Destination is a virtual register index, not tied to LLVM SSA.
  uint32_t Dst = UINT32_MAX;
  VMBinOp Bin = VMBinOp::Add;
  VMCmpPred Pred = VMCmpPred::EQ;
  VMCastKind Cast = VMCastKind::Bitcast;
  VMFenceKind Fence = VMFenceKind::SeqCst;
  SmallVector<VMValue, 3> Ops;
  SmallVector<uint64_t, 4> SwitchValues;
  SmallVector<uint32_t, 4> SwitchTargets;
  uint32_t SwitchDefault = UINT32_MAX;
  uint32_t TargetTrue = UINT32_MAX;
  uint32_t TargetFalse = UINT32_MAX;
  uint32_t CallIndex = UINT32_MAX;
};

struct VMBlock {
  uint32_t Id = 0;
  SmallVector<VMInstr, 16> Instrs;
};

// CallInfo captures everything needed to emit a native call stub: the VM
// packs/unpacks args from registers and jumps to host code, avoiding the
// need for a full ABI model inside the VM.
struct VMCallInfo {
  StringRef Name;
  Function *Callee = nullptr;
  FunctionType *CalleeTy = nullptr;
  unsigned CalleeAddrSpace = 0;
  SmallVector<uint32_t, 8> ArgRegs;
  SmallVector<Type *, 8> ArgTypes;
  VMType RetTy;
  uint32_t RetReg = UINT32_MAX;
  bool IsVoid = false;
  bool IsIndirect = false;
  uint32_t CalleeReg = UINT32_MAX;
  unsigned CallConv = 0;
  AttributeList CallAttrs;
};

struct VMFunction {
  StringRef Name;
  unsigned PtrBits = 0;
  // RegCount is a dense VM register file; indices are stable within a function.
  unsigned RegCount = 0;
  SmallVector<VMBlock, 8> Blocks;
  SmallVector<VMCallInfo, 8> Calls;
};

void dumpVMFunction(const VMFunction &F, raw_ostream &OS);

} // namespace obfvm
} // namespace llvm

#endif
