//===- VMEmitUtils.h - Shared VM emitter helpers -------------------------===//
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
// Shared helpers for VM IR emitters (opcode and region backends).
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMEMITUTILS_H
#define LLVM_OBFUSCATION_VMEMITUTILS_H

#include "VMConfig.h"
#include "VMIR.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/ErrorHandling.h"
#include <cstdint>

namespace llvm {
class Constant;
class FunctionType;
class GlobalVariable;
class Module;
class StructType;
class Type;

namespace obfvm {

enum class VMStateField : unsigned;

// Maps between power-of-two slot indices and logical handler IDs.
// Unused slots route to bogus handlers for hardening.
struct DispatchLayout {
  SmallVector<uint32_t, 16> SlotToId;
  SmallVector<uint32_t, 16> IdToSlot;
};

struct VMCounters {
  GlobalVariable *Dispatch = nullptr;
  GlobalVariable *RegLoad = nullptr;
  GlobalVariable *RegStore = nullptr;
  GlobalVariable *Instr = nullptr;
  GlobalVariable *HostCall = nullptr;
  GlobalVariable *HostCycles = nullptr;
  GlobalVariable *VmCycles = nullptr;
};

// Parameters for opaque-predicate junk insertion at dispatch sites.
struct OpaqueJunkContext {
  Module &M;
  Value *KeyPtr = nullptr;
  Value *OpaqueTmp = nullptr;
  uint32_t JunkSeed = 0;
  uint32_t PredMul = 0;
  uint32_t PredAdd = 0;
  uint32_t PredMask = 0;
  uint32_t PredTarget = 0;
  bool Hard = false;
};

Type *getLLVMType(VMTypeKind K, LLVMContext &Ctx, unsigned PtrBits);
uint64_t maskForType(VMTypeKind K, unsigned PtrBits);
uint64_t signMaskForType(VMTypeKind K, unsigned PtrBits);

inline bool isPowerOf2(unsigned V) { return V != 0 && (V & (V - 1)) == 0; }
unsigned nextPow2(unsigned V);
unsigned log2Exact(unsigned V);
void shuffleDispatchOrder(SmallVectorImpl<uint32_t> &Order,
                          unsigned FixedPrefix, VMHandlers H);

Value *rotl32(IRBuilder<> &B, Value *V, unsigned Amt);
Value *rotl8(IRBuilder<> &B, Value *V, unsigned Amt);
Value *rotr8(IRBuilder<> &B, Value *V, unsigned Amt);
void bumpCounter(IRBuilder<> &B, Value *CounterPtr);
void addCounter(IRBuilder<> &B, Value *CounterPtr, Value *Delta);

Constant *asI64(Constant *C, Type *I64Ty);

Value *encodeNextPc(IRBuilder<> &IB, Value *Next, bool Hard, Value *KeyPtr,
                    unsigned RotAmt);
Value *slotFromPc(IRBuilder<> &IB, Value *Pc, bool Hard, uint32_t PcMask,
                  uint32_t PcBits, uint32_t PcMul);
Value *pcFromSlot(IRBuilder<> &IB, Value *Slot, bool Hard, uint32_t PcMask,
                  uint32_t PcBits, uint32_t PcInvMul);
Value *permuteSlot(IRBuilder<> &IB, Value *Slot, Value *Key32, bool Hard,
                   uint32_t DispatchMask, uint32_t SlotMixConst);
uint32_t permuteSlotConst(uint32_t Slot, uint32_t Key32, uint32_t Mask,
                          uint32_t SlotMixConst, bool Enable);

AtomicOrdering fenceOrdering(VMFenceKind K);
void emitFence(IRBuilder<> &B, VMFenceKind K);

VMCounters maybeCreateCounters(Module &M, StringRef BaseName, bool Enabled);

void emitOpaqueJunk(IRBuilder<> &IB, const OpaqueJunkContext &Ctx,
                    unsigned Variant = 0);

Value *getStateFieldPtr(IRBuilder<> &B, Module &M, StructType *StateTy,
                        Value *State, VMStateField Field);
Value *castValueToParam(IRBuilder<> &B, Value *V, Type *Ty,
                        unsigned PtrBits);
void checkCallSignature(FunctionType *FTy, ArrayRef<Value *> Args,
                        StringRef Where);

Value *loadReg(IRBuilder<> &B, Value *RegsPtr, Value *Idx,
               Value *CounterPtr = nullptr);
void storeReg(IRBuilder<> &B, Value *RegsPtr, Value *Idx, Value *Val,
              Value *CounterPtr = nullptr);

Value *unpackValue(IRBuilder<> &B, Value *RegVal, VMTypeKind K,
                   unsigned PtrBits);
Value *packValue(IRBuilder<> &B, Value *Val, VMTypeKind K, unsigned PtrBits);
Value *maskValue(IRBuilder<> &B, Value *Val, VMTypeKind K, unsigned PtrBits);
Value *signExtendToI64(IRBuilder<> &B, Value *Val, VMTypeKind K,
                       unsigned PtrBits);

Value *emitIntAdd(IRBuilder<> &B, Value *A, Value *Bv, VMHandlers H,
                  bool AllowExpand);
Value *emitIntSub(IRBuilder<> &B, Value *A, Value *Bv, VMHandlers H,
                  bool AllowExpand);
Value *emitIntXor(IRBuilder<> &B, Value *A, Value *Bv, VMHandlers H,
                  bool AllowExpand);
Value *emitIntAnd(IRBuilder<> &B, Value *A, Value *Bv, VMHandlers H,
                  bool AllowExpand);
Value *emitIntOr(IRBuilder<> &B, Value *A, Value *Bv, VMHandlers H,
                 bool AllowExpand);

DispatchLayout buildDispatchLayout(unsigned NumIds, unsigned Extra,
                                   VMHandlers H);

[[noreturn]] inline void vmFatal(const Twine &Msg) {
  report_fatal_error(Msg);
}

} // namespace obfvm
} // namespace llvm

#endif
