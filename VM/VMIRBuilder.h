//===- VMIRBuilder.h - VM IR builder helpers -----------------------------===//
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
// Provides a small builder API for constructing VM IR consistently.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMIRBUILDER_H
#define LLVM_OBFUSCATION_VMIRBUILDER_H

#include "VMIR.h"
#include <cassert>

namespace llvm {
namespace obfvm {

class VMIRBuilder {
public:
  explicit VMIRBuilder(VMFunction &Func) : F(Func) {}

  // Blocks are created with monotonically assigned IDs for stable ordering.
  VMBlock &createBlock() {
    VMBlock B;
    B.Id = static_cast<uint32_t>(F.Blocks.size());
    F.Blocks.push_back(B);
    return F.Blocks.back();
  }

  VMBlock &createBlock(uint32_t Id) {
    VMBlock B;
    B.Id = Id;
    F.Blocks.push_back(B);
    return F.Blocks.back();
  }

  void setInsertPoint(VMBlock &B) { Cur = &B; }

  VMInstr &append(const VMInstr &I) {
    assert(Cur && "vmir: insert point not set");
    Cur->Instrs.push_back(I);
    return Cur->Instrs.back();
  }

  VMInstr &mov(VMType Ty, uint32_t Dst, VMValue Src) {
    VMInstr I;
    I.Op = VMOpcode::Mov;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Ops = {Src};
    return append(I);
  }

  VMInstr &binOp(VMBinOp Op, VMType Ty, uint32_t Dst, uint32_t A, uint32_t B) {
    VMInstr I;
    I.Op = VMOpcode::BinOp;
    I.Ty = Ty;
    I.Bin = Op;
    I.Dst = Dst;
    I.Ops = {VMValue::reg(A), VMValue::reg(B)};
    return append(I);
  }

  VMInstr &fneg(VMType Ty, uint32_t Dst, uint32_t Src) {
    VMInstr I;
    I.Op = VMOpcode::FNeg;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Ops = {VMValue::reg(Src)};
    return append(I);
  }

  VMInstr &icmp(VMCmpPred Pred, VMType Ty, uint32_t Dst, uint32_t A,
                uint32_t B) {
    VMInstr I;
    I.Op = VMOpcode::ICmp;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Pred = Pred;
    I.Ops = {VMValue::reg(A), VMValue::reg(B)};
    return append(I);
  }

  VMInstr &fcmp(VMCmpPred Pred, VMType Ty, uint32_t Dst, uint32_t A,
                uint32_t B) {
    VMInstr I;
    I.Op = VMOpcode::FCmp;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Pred = Pred;
    I.Ops = {VMValue::reg(A), VMValue::reg(B)};
    return append(I);
  }

  VMInstr &cast(VMCastKind K, VMType SrcTy, VMType DstTy, uint32_t Dst,
                uint32_t Src) {
    VMInstr I;
    I.Op = VMOpcode::Cast;
    I.Ty = DstTy;
    I.SrcTy = SrcTy;
    I.Dst = Dst;
    I.Cast = K;
    I.Ops = {VMValue::reg(Src)};
    return append(I);
  }

  VMInstr &load(VMType Ty, uint32_t Dst, uint32_t Addr) {
    VMInstr I;
    I.Op = VMOpcode::Load;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Ops = {VMValue::reg(Addr)};
    return append(I);
  }

  // Store operand order is (value, address), not LLVM's (address, value).
  VMInstr &store(VMType Ty, uint32_t Val, uint32_t Addr) {
    VMInstr I;
    I.Op = VMOpcode::Store;
    I.Ty = Ty;
    I.Ops = {VMValue::reg(Val), VMValue::reg(Addr)};
    return append(I);
  }

  VMInstr &memFence(VMFenceKind K = VMFenceKind::SeqCst) {
    VMInstr I;
    I.Op = VMOpcode::MemFence;
    I.Fence = K;
    return append(I);
  }

  VMInstr &br(uint32_t Target) {
    VMInstr I;
    I.Op = VMOpcode::Br;
    I.TargetTrue = Target;
    return append(I);
  }

  VMInstr &condBr(uint32_t Cond, uint32_t TrueT, uint32_t FalseT) {
    VMInstr I;
    I.Op = VMOpcode::CondBr;
    I.Ops = {VMValue::reg(Cond)};
    I.TargetTrue = TrueT;
    I.TargetFalse = FalseT;
    return append(I);
  }

  VMInstr &select(VMType Ty, uint32_t Dst, uint32_t Cond, uint32_t TVal,
                  uint32_t FVal) {
    VMInstr I;
    I.Op = VMOpcode::Select;
    I.Ty = Ty;
    I.Dst = Dst;
    I.Ops = {VMValue::reg(Cond), VMValue::reg(TVal), VMValue::reg(FVal)};
    return append(I);
  }

  VMInstr &switchInst(VMType Ty, uint32_t CondReg, uint32_t DefaultT,
                      const SmallVectorImpl<uint64_t> &Vals,
                      const SmallVectorImpl<uint32_t> &Tgts) {
    // Switch values/targets are stored explicitly to preserve VM control flow.
    VMInstr I;
    I.Op = VMOpcode::Switch;
    I.Ty = Ty;
    I.Ops = {VMValue::reg(CondReg)};
    I.SwitchDefault = DefaultT;
    I.SwitchValues.assign(Vals.begin(), Vals.end());
    I.SwitchTargets.assign(Tgts.begin(), Tgts.end());
    return append(I);
  }

  VMInstr &retVoid() {
    VMInstr I;
    I.Op = VMOpcode::Ret;
    return append(I);
  }

  VMInstr &retReg(uint32_t Reg) {
    VMInstr I;
    I.Op = VMOpcode::Ret;
    I.Ops = {VMValue::reg(Reg)};
    return append(I);
  }

  VMInstr &callHost(uint32_t CallIndex) {
    VMInstr I;
    I.Op = VMOpcode::CallHost;
    I.CallIndex = CallIndex;
    return append(I);
  }

  VMInstr &trap() {
    VMInstr I;
    I.Op = VMOpcode::Trap;
    return append(I);
  }

private:
  VMFunction &F;
  VMBlock *Cur = nullptr;
};

} // namespace obfvm
} // namespace llvm

#endif
