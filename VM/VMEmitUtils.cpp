//===- VMEmitUtils.cpp - Shared VM emitter helpers -----------------------===//
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
#include "VMEmitUtils.h"
#include "CryptoUtils.h"
#include "VMMath.h"
#include "VMRuntime.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cassert>

using namespace llvm;
using namespace llvm::obfvm;

Type *llvm::obfvm::getLLVMType(VMTypeKind K, LLVMContext &Ctx,
                               unsigned PtrBits) {
  switch (K) {
  case VMTypeKind::I1:
    return Type::getInt1Ty(Ctx);
  case VMTypeKind::I8:
    return Type::getInt8Ty(Ctx);
  case VMTypeKind::I16:
    return Type::getInt16Ty(Ctx);
  case VMTypeKind::I32:
    return Type::getInt32Ty(Ctx);
  case VMTypeKind::I64:
    return Type::getInt64Ty(Ctx);
  case VMTypeKind::F32:
    return Type::getFloatTy(Ctx);
  case VMTypeKind::F64:
    return Type::getDoubleTy(Ctx);
  case VMTypeKind::Ptr:
    return Type::getIntNTy(Ctx, PtrBits);
  }
  return Type::getInt64Ty(Ctx);
}

uint64_t llvm::obfvm::maskForType(VMTypeKind K, unsigned PtrBits) {
  unsigned Bits = getTypeBitWidth(K, PtrBits);
  return maskForBits(Bits);
}

uint64_t llvm::obfvm::signMaskForType(VMTypeKind K, unsigned PtrBits) {
  unsigned Bits = getTypeBitWidth(K, PtrBits);
  if (Bits == 0)
    return 0;
  if (Bits >= 64)
    return 1ULL << 63;
  return 1ULL << (Bits - 1);
}

unsigned llvm::obfvm::nextPow2(unsigned V) {
  if (V == 0)
    return 1;
  unsigned P = 1;
  while (P < V)
    P <<= 1;
  return P;
}

unsigned llvm::obfvm::log2Exact(unsigned V) {
  assert(V != 0 && isPowerOf2(V));
  unsigned Bits = 0;
  while (V > 1) {
    V >>= 1;
    ++Bits;
  }
  return Bits;
}

void llvm::obfvm::shuffleDispatchOrder(SmallVectorImpl<uint32_t> &Order,
                                       unsigned FixedPrefix, VMHandlers H) {
  if (H != VMHandlers::Random)
    return;
  if (Order.size() <= FixedPrefix + 1)
    return;
  // Randomize handler order to decouple opcode numbers from dispatch indices.
  for (size_t i = Order.size() - 1; i > FixedPrefix; --i) {
    unsigned Range = static_cast<unsigned>(i - FixedPrefix + 1);
    size_t J = FixedPrefix + cryptoutils->get_range(Range);
    std::swap(Order[i], Order[J]);
  }
}

Value *llvm::obfvm::rotl32(IRBuilder<> &B, Value *V, unsigned Amt) {
  if (Amt == 0)
    return V;
  LLVMContext &Ctx = B.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Value *Shl = B.CreateShl(V, ConstantInt::get(I32Ty, Amt));
  Value *Shr = B.CreateLShr(V, ConstantInt::get(I32Ty, 32 - Amt));
  return B.CreateOr(Shl, Shr);
}

Value *llvm::obfvm::rotl8(IRBuilder<> &B, Value *V, unsigned Amt) {
  unsigned Rot = Amt & 7u;
  if (Rot == 0)
    return V;
  LLVMContext &Ctx = B.getContext();
  IntegerType *I8Ty = Type::getInt8Ty(Ctx);
  Value *Shl = B.CreateShl(V, ConstantInt::get(I8Ty, Rot));
  Value *Shr = B.CreateLShr(V, ConstantInt::get(I8Ty, 8 - Rot));
  return B.CreateOr(Shl, Shr);
}

Value *llvm::obfvm::rotr8(IRBuilder<> &B, Value *V, unsigned Amt) {
  unsigned Rot = Amt & 7u;
  if (Rot == 0)
    return V;
  LLVMContext &Ctx = B.getContext();
  IntegerType *I8Ty = Type::getInt8Ty(Ctx);
  Value *Shr = B.CreateLShr(V, ConstantInt::get(I8Ty, Rot));
  Value *Shl = B.CreateShl(V, ConstantInt::get(I8Ty, 8 - Rot));
  return B.CreateOr(Shl, Shr);
}

void llvm::obfvm::bumpCounter(IRBuilder<> &B, Value *CounterPtr) {
  if (!CounterPtr)
    return;
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Old = B.CreateLoad(I64Ty, CounterPtr);
  Value *New = B.CreateAdd(Old, ConstantInt::get(I64Ty, 1));
  B.CreateStore(New, CounterPtr);
}

void llvm::obfvm::addCounter(IRBuilder<> &B, Value *CounterPtr,
                             Value *Delta) {
  if (!CounterPtr)
    return;
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Delta64 = Delta;
  if (Delta->getType() != I64Ty)
    Delta64 = B.CreateZExtOrTrunc(Delta, I64Ty);
  Value *Old = B.CreateLoad(I64Ty, CounterPtr);
  Value *New = B.CreateAdd(Old, Delta64);
  B.CreateStore(New, CounterPtr);
}

// XOR + add with rotated key prevents static PC prediction across builds.
Value *llvm::obfvm::encodeNextPc(IRBuilder<> &IB, Value *Next, bool Hard,
                                 Value *KeyPtr, unsigned RotAmt) {
  if (!Hard)
    return Next;
  LLVMContext &Ctx = IB.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *KeyVal = IB.CreateLoad(I64Ty, KeyPtr);
  Value *Key32 = IB.CreateTrunc(KeyVal, I32Ty);
  Value *Rot = rotl32(IB, Key32, RotAmt);
  Value *NextI32 = IB.CreateTruncOrBitCast(Next, I32Ty);
  return IB.CreateAdd(IB.CreateXor(NextI32, Rot), Key32);
}

// Affine PC-to-slot mapping; PcMul is odd so it's bijective mod 2^PcBits.
Value *llvm::obfvm::slotFromPc(IRBuilder<> &IB, Value *Pc, bool Hard,
                               uint32_t PcMask, uint32_t PcBits,
                               uint32_t PcMul) {
  LLVMContext &Ctx = IB.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *MaskC = ConstantInt::get(I32Ty, PcMask);
  Value *PcMasked = IB.CreateAnd(Pc, MaskC);
  if (!Hard || PcBits == 0)
    return PcMasked;
  Value *MulC = ConstantInt::get(I32Ty, PcMul);
  Value *MulV = IB.CreateMul(PcMasked, MulC);
  return IB.CreateAnd(MulV, MaskC);
}

Value *llvm::obfvm::pcFromSlot(IRBuilder<> &IB, Value *Slot, bool Hard,
                               uint32_t PcMask, uint32_t PcBits,
                               uint32_t PcInvMul) {
  LLVMContext &Ctx = IB.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *MaskC = ConstantInt::get(I32Ty, PcMask);
  Value *SlotMasked = IB.CreateAnd(Slot, MaskC);
  if (!Hard || PcBits == 0)
    return SlotMasked;
  Value *InvC = ConstantInt::get(I32Ty, PcInvMul);
  Value *MulV = IB.CreateMul(SlotMasked, InvC);
  return IB.CreateAnd(MulV, MaskC);
}

// Permute slot index via key-derived odd multiplier so dispatch table
// order is unpredictable without the runtime key.
Value *llvm::obfvm::permuteSlot(IRBuilder<> &IB, Value *Slot, Value *Key32,
                                bool Hard, uint32_t DispatchMask,
                                uint32_t SlotMixConst) {
  LLVMContext &Ctx = IB.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *MaskC = ConstantInt::get(I32Ty, DispatchMask);
  Value *SlotMasked = IB.CreateAnd(Slot, MaskC);
  if (!Hard || DispatchMask == 0)
    return SlotMasked;
  Value *Mix =
      IB.CreateXor(Key32, IB.CreateLShr(Key32, ConstantInt::get(I32Ty, 16)));
  Value *Mul = IB.CreateOr(Mix, ConstantInt::get(I32Ty, 1));
  Value *Add = IB.CreateXor(Key32, ConstantInt::get(I32Ty, SlotMixConst));
  Value *MulRes = IB.CreateMul(SlotMasked, Mul);
  Value *Sum = IB.CreateAdd(MulRes, Add);
  return IB.CreateAnd(Sum, MaskC);
}

uint32_t llvm::obfvm::permuteSlotConst(uint32_t Slot, uint32_t Key32,
                                       uint32_t Mask, uint32_t SlotMixConst,
                                       bool Enable) {
  uint32_t SlotMasked = Slot & Mask;
  if (!Enable || Mask == 0)
    return SlotMasked;
  uint32_t Mix = Key32 ^ (Key32 >> 16);
  uint32_t Mul = Mix | 1u;
  uint32_t Add = Key32 ^ SlotMixConst;
  uint32_t MulRes = SlotMasked * Mul;
  uint32_t Sum = MulRes + Add;
  return Sum & Mask;
}

Constant *llvm::obfvm::asI64(Constant *C, Type *I64Ty) {
  if (!C)
    return ConstantInt::get(I64Ty, 0);
  if (C->getType() == I64Ty)
    return C;
  if (C->getType()->isPointerTy())
    return ConstantExpr::getPtrToInt(C, I64Ty);
  if (auto *ITy = dyn_cast<IntegerType>(C->getType())) {
    unsigned Bits = ITy->getBitWidth();
    if (Bits < 64)
      return ConstantExpr::getCast(Instruction::ZExt, C, I64Ty);
    if (Bits > 64)
      return ConstantExpr::getCast(Instruction::Trunc, C, I64Ty);
    return ConstantExpr::getBitCast(C, I64Ty);
  }
  return ConstantInt::get(I64Ty, 0);
}

AtomicOrdering llvm::obfvm::fenceOrdering(VMFenceKind K) {
  switch (K) {
  case VMFenceKind::Acquire:
    return AtomicOrdering::Acquire;
  case VMFenceKind::Release:
    return AtomicOrdering::Release;
  case VMFenceKind::AcquireRelease:
    return AtomicOrdering::AcquireRelease;
  case VMFenceKind::SeqCst:
    return AtomicOrdering::SequentiallyConsistent;
  }
  return AtomicOrdering::SequentiallyConsistent;
}

void llvm::obfvm::emitFence(IRBuilder<> &B, VMFenceKind K) {
  B.CreateFence(fenceOrdering(K), SyncScope::System);
}

static GlobalVariable *getOrCreateCounter(Module &M, StringRef Tag,
                                          StringRef Base) {
  if (auto *GV = findTaggedGlobal(M, Tag))
    return GV;
  LLVMContext &Ctx = M.getContext();
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  auto *GV = new GlobalVariable(M, I64Ty, false, GlobalValue::PrivateLinkage,
                                ConstantInt::get(I64Ty, 0), Base);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*GV, M, Tag, Base);
  return GV;
}

VMCounters llvm::obfvm::maybeCreateCounters(Module &M, StringRef BaseName,
                                            bool Enabled) {
  VMCounters C;
  if (!Enabled)
    return C;
  std::string Prefix = ("vm_ctr_" + BaseName).str();
  std::string DispatchTag = ("vm.ctr.dispatch." + BaseName).str();
  std::string RegLoadTag = ("vm.ctr.regload." + BaseName).str();
  std::string RegStoreTag = ("vm.ctr.regstore." + BaseName).str();
  std::string InstrTag = ("vm.ctr.instr." + BaseName).str();
  std::string HostCallTag = ("vm.ctr.hostcall." + BaseName).str();
  std::string HostCyclesTag = ("vm.ctr.hostcycles." + BaseName).str();
  std::string VmCyclesTag = ("vm.ctr.vmcycles." + BaseName).str();
  C.Dispatch =
      getOrCreateCounter(M, DispatchTag, Prefix + "_dispatch");
  C.RegLoad =
      getOrCreateCounter(M, RegLoadTag, Prefix + "_regload");
  C.RegStore =
      getOrCreateCounter(M, RegStoreTag, Prefix + "_regstore");
  C.Instr =
      getOrCreateCounter(M, InstrTag, Prefix + "_instr");
  C.HostCall =
      getOrCreateCounter(M, HostCallTag, Prefix + "_hostcall");
  C.HostCycles =
      getOrCreateCounter(M, HostCyclesTag, Prefix + "_hostcycles");
  C.VmCycles =
      getOrCreateCounter(M, VmCyclesTag, Prefix + "_vmcycles");
  return C;
}

// Insert dead-but-plausible code behind opaque predicates to confuse
// decompilers. The predicate is never true at runtime but is hard to prove
// statically because it mixes cycle counter entropy with the runtime key.
void llvm::obfvm::emitOpaqueJunk(IRBuilder<> &IB,
                                 const OpaqueJunkContext &Ctx,
                                 unsigned Variant) {
  if (!Ctx.Hard || !Ctx.OpaqueTmp || !Ctx.KeyPtr)
    return;
  LLVMContext &LLVMCtx = IB.getContext();
  Type *I64Ty = Type::getInt64Ty(LLVMCtx);
  BasicBlock *Cur = IB.GetInsertBlock();
  Function *Fn = Cur->getParent();
  BasicBlock *Junk = BasicBlock::Create(LLVMCtx, "opaque.junk", Fn);
  BasicBlock *Cont = BasicBlock::Create(LLVMCtx, "opaque.cont", Fn);
  Value *KeyVal = IB.CreateLoad(I64Ty, Ctx.KeyPtr);
  FunctionCallee Rd =
      Intrinsic::getOrInsertDeclaration(&Ctx.M, Intrinsic::readcyclecounter);
  Value *Cycle = IB.CreateCall(Rd);
  // Vary the mix pattern per site to avoid a stable predicate shape.
  unsigned MixMode = (Ctx.JunkSeed + Variant) % 3;
  // Use odd, non-zero shifts to keep low bits from collapsing.
  unsigned MixShift = 1 + ((Ctx.JunkSeed >> 3) + Variant) % 31;
  constexpr unsigned kMixFoldShift = 7;
  constexpr unsigned kMixFoldShiftAlt = 5;
  constexpr unsigned kMixFinalShift = 17;
  Value *Mix = nullptr;
  switch (MixMode) {
  case 0:
    Mix = IB.CreateXor(KeyVal, Cycle);
    break;
  case 1: {
    Value *Sum = IB.CreateAdd(KeyVal, Cycle);
    Value *Shr = IB.CreateLShr(KeyVal, ConstantInt::get(I64Ty, MixShift));
    Mix = IB.CreateXor(Sum, Shr);
    break;
  }
  default: {
    Value *Shl = IB.CreateShl(Cycle, ConstantInt::get(I64Ty, MixShift));
    Mix = IB.CreateAdd(KeyVal, Shl);
    break;
  }
  }
  // Fold some high bits into the low region before masking.
  if (Variant & 1u) {
    Mix = IB.CreateXor(Mix, IB.CreateLShr(Mix, ConstantInt::get(I64Ty, kMixFoldShift)));
  } else {
    Mix = IB.CreateAdd(Mix, IB.CreateShl(Mix, ConstantInt::get(I64Ty, kMixFoldShiftAlt)));
  }
  Value *Fold =
      IB.CreateXor(Mix, IB.CreateLShr(Mix, ConstantInt::get(I64Ty, kMixFinalShift)));
  Fold = IB.CreateMul(
      Fold, ConstantInt::get(I64Ty, static_cast<uint64_t>(Ctx.PredMul)));
  Fold = IB.CreateAdd(
      Fold, ConstantInt::get(I64Ty, static_cast<uint64_t>(Ctx.PredAdd)));
  Value *Masked = IB.CreateAnd(
      Fold, ConstantInt::get(I64Ty, static_cast<uint64_t>(Ctx.PredMask)));
  Value *Cond = IB.CreateICmpEQ(
      Masked, ConstantInt::get(I64Ty, static_cast<uint64_t>(Ctx.PredTarget)));
  IB.CreateCondBr(Cond, Junk, Cont);
  IRBuilder<> JunkIR(Junk);
  LoadInst *Old = JunkIR.CreateLoad(I64Ty, Ctx.OpaqueTmp);
  Old->setVolatile(true);
  // Keep the junk update data-dependent without a fixed shift signature.
  unsigned JunkShift = 1 + ((Ctx.JunkSeed >> 9) + Variant) % 31;
  Value *J = JunkIR.CreateXor(
      Old, JunkIR.CreateLShr(Mix, ConstantInt::get(I64Ty, JunkShift)));
  StoreInst *St = JunkIR.CreateStore(J, Ctx.OpaqueTmp);
  St->setVolatile(true);
  JunkIR.CreateBr(Cont);
  IB.SetInsertPoint(Cont);
}

Value *llvm::obfvm::getStateFieldPtr(IRBuilder<> &B, Module &M,
                                     StructType *StateTy, Value *State,
                                     VMStateField Field) {
  return B.CreateStructGEP(StateTy, State, getVMStateFieldIndex(M, Field));
}

Value *llvm::obfvm::castValueToParam(IRBuilder<> &B, Value *V, Type *Ty,
                                     unsigned PtrBits) {
  if (!Ty || V->getType() == Ty)
    return V;
  LLVMContext &Ctx = B.getContext();
  auto intPtrTy = [&]() -> Type * { return Type::getIntNTy(Ctx, PtrBits); };
  if (Ty->isPointerTy()) {
    if (V->getType()->isPointerTy()) {
      unsigned SrcAS = V->getType()->getPointerAddressSpace();
      unsigned DstAS = Ty->getPointerAddressSpace();
      if (SrcAS != DstAS)
        return B.CreateAddrSpaceCast(V, Ty);
      return B.CreateBitCast(V, Ty);
    }
    if (V->getType()->isIntegerTy()) {
      Type *IntPtrTy = intPtrTy();
      Value *IntV =
          (V->getType() == IntPtrTy) ? V : B.CreateZExtOrTrunc(V, IntPtrTy);
      return B.CreateIntToPtr(IntV, Ty);
    }
    if (V->getType()->isFloatingPointTy()) {
      unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
      Type *IntSrcTy = Type::getIntNTy(Ctx, SrcBits);
      Value *IntV = B.CreateBitCast(V, IntSrcTy);
      Type *IntPtrTy = intPtrTy();
      if (IntSrcTy != IntPtrTy)
        IntV = B.CreateZExtOrTrunc(IntV, IntPtrTy);
      return B.CreateIntToPtr(IntV, Ty);
    }
  } else if (Ty->isIntegerTy()) {
    if (V->getType()->isPointerTy()) {
      Type *IntPtrTy = intPtrTy();
      Value *IntV = B.CreatePtrToInt(V, IntPtrTy);
      return B.CreateZExtOrTrunc(IntV, Ty);
    }
    if (V->getType()->isIntegerTy())
      return B.CreateZExtOrTrunc(V, Ty);
    if (V->getType()->isFloatingPointTy()) {
      unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
      if (SrcBits == Ty->getIntegerBitWidth())
        return B.CreateBitCast(V, Ty);
      return B.CreateFPToSI(V, Ty);
    }
  } else if (Ty->isFloatingPointTy()) {
    if (V->getType()->isFloatingPointTy()) {
      unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
      unsigned DstBits = Ty->getPrimitiveSizeInBits();
      if (SrcBits == DstBits)
        return B.CreateBitCast(V, Ty);
      if (SrcBits < DstBits)
        return B.CreateFPExt(V, Ty);
      return B.CreateFPTrunc(V, Ty);
    }
    if (V->getType()->isIntegerTy()) {
      if (V->getType()->getIntegerBitWidth() == Ty->getPrimitiveSizeInBits())
        return B.CreateBitCast(V, Ty);
      return B.CreateSIToFP(V, Ty);
    }
    if (V->getType()->isPointerTy()) {
      Type *IntPtrTy = intPtrTy();
      Value *IntV = B.CreatePtrToInt(V, IntPtrTy);
      if (IntPtrTy->getIntegerBitWidth() == Ty->getPrimitiveSizeInBits())
        return B.CreateBitCast(IntV, Ty);
      return B.CreateSIToFP(IntV, Ty);
    }
  }
  return V;
}

void llvm::obfvm::checkCallSignature(FunctionType *FTy,
                                     ArrayRef<Value *> Args,
                                     StringRef Where) {
  if (!FTy)
    return;
  if (Args.size() < FTy->getNumParams()) {
    errs() << "vm: call arg count " << Args.size() << " < params "
           << FTy->getNumParams() << " at " << Where << "\n";
    vmFatal("vm: call arg count mismatch");
  }
  unsigned Limit = std::min<unsigned>(Args.size(), FTy->getNumParams());
  for (unsigned i = 0; i < Limit; ++i) {
    Type *ParamTy = FTy->getParamType(i);
    if (Args[i]->getType() != ParamTy) {
      errs() << "vm: call arg type mismatch at " << Where << " idx " << i
             << " arg=" << *Args[i]->getType()
             << " param=" << *ParamTy << "\n";
      vmFatal("vm: call arg type mismatch");
    }
  }
}

Value *llvm::obfvm::loadReg(IRBuilder<> &B, Value *RegsPtr, Value *Idx,
                            Value *CounterPtr) {
  bumpCounter(B, CounterPtr);
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Idx64 = B.CreateZExt(Idx, I64Ty);
  Value *Ptr = B.CreateInBoundsGEP(I64Ty, RegsPtr, Idx64);
  return B.CreateLoad(I64Ty, Ptr);
}

void llvm::obfvm::storeReg(IRBuilder<> &B, Value *RegsPtr, Value *Idx,
                           Value *Val, Value *CounterPtr) {
  bumpCounter(B, CounterPtr);
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Idx64 = B.CreateZExt(Idx, I64Ty);
  Value *Ptr = B.CreateInBoundsGEP(I64Ty, RegsPtr, Idx64);
  B.CreateStore(Val, Ptr);
}

Value *llvm::obfvm::unpackValue(IRBuilder<> &B, Value *RegVal, VMTypeKind K,
                                unsigned PtrBits) {
  LLVMContext &Ctx = B.getContext();
  Type *Ty = getLLVMType(K, Ctx, PtrBits);
  if (K == VMTypeKind::F32) {
    Value *Tr = B.CreateTrunc(RegVal, Type::getInt32Ty(Ctx));
    return B.CreateBitCast(Tr, Ty);
  }
  if (K == VMTypeKind::F64) {
    return B.CreateBitCast(RegVal, Ty);
  }
  if (Ty->isIntegerTy(64))
    return RegVal;
  return B.CreateTrunc(RegVal, Ty);
}

Value *llvm::obfvm::packValue(IRBuilder<> &B, Value *Val, VMTypeKind K,
                              unsigned PtrBits) {
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  if (K == VMTypeKind::F32) {
    Value *I32 = B.CreateBitCast(Val, Type::getInt32Ty(Ctx));
    return B.CreateZExt(I32, I64Ty);
  }
  if (K == VMTypeKind::F64) {
    return B.CreateBitCast(Val, I64Ty);
  }
  if (Val->getType()->isIntegerTy(64))
    return Val;
  return B.CreateZExt(Val, I64Ty);
}

Value *llvm::obfvm::maskValue(IRBuilder<> &B, Value *Val, VMTypeKind K,
                              unsigned PtrBits) {
  uint64_t Mask = maskForType(K, PtrBits);
  if (Mask == ~0ULL)
    return Val;
  return B.CreateAnd(Val, ConstantInt::get(Val->getType(), Mask));
}

Value *llvm::obfvm::signExtendToI64(IRBuilder<> &B, Value *Val, VMTypeKind K,
                                    unsigned PtrBits) {
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  uint64_t Mask = maskForType(K, PtrBits);
  uint64_t Sign = signMaskForType(K, PtrBits);
  Value *MaskV = ConstantInt::get(I64Ty, Mask);
  Value *SignV = ConstantInt::get(I64Ty, Sign);
  Value *Masked = B.CreateAnd(Val, MaskV);
  Value *SignSet =
      B.CreateICmpNE(B.CreateAnd(Masked, SignV), ConstantInt::get(I64Ty, 0));
  Value *ExtMask = ConstantInt::get(I64Ty, ~Mask);
  Value *Signed = B.CreateSelect(SignSet, B.CreateOr(Masked, ExtMask), Masked);
  return Signed;
}

// Randomly pick an algebraic identity for integer ops to vary the IR shape
// across builds, defeating pattern-based deobfuscation.
static unsigned pickVariant(VMHandlers H, unsigned Variants, bool AllowExpand) {
  if (!AllowExpand)
    return 0;
  if (H != VMHandlers::Random || Variants <= 1)
    return 0;
  return cryptoutils->get_range(Variants);
}

// MBA variants: a+b == (a^b)+2*(a&b) == (a|b)+(a&b).
Value *llvm::obfvm::emitIntAdd(IRBuilder<> &B, Value *A, Value *Bv,
                               VMHandlers H, bool AllowExpand) {
  unsigned Choice = pickVariant(H, 3, AllowExpand);
  if (Choice == 0)
    return B.CreateAdd(A, Bv);
  if (Choice == 1) {
    Value *Tmp = B.CreateXor(A, Bv);
    return B.CreateAdd(Tmp, B.CreateShl(B.CreateAnd(A, Bv), 1));
  }
  Value *OrV = B.CreateOr(A, Bv);
  Value *AndV = B.CreateAnd(A, Bv);
  return B.CreateAdd(OrV, AndV);
}

Value *llvm::obfvm::emitIntSub(IRBuilder<> &B, Value *A, Value *Bv,
                               VMHandlers H, bool AllowExpand) {
  unsigned Choice = pickVariant(H, 3, AllowExpand);
  if (Choice == 0)
    return B.CreateSub(A, Bv);
  if (Choice == 1) {
    Value *Tmp = B.CreateXor(A, Bv);
    return B.CreateSub(Tmp, B.CreateShl(B.CreateAnd(B.CreateNot(A), Bv), 1));
  }
  Value *Sum = B.CreateAdd(A, B.CreateNot(Bv));
  return B.CreateAdd(Sum, ConstantInt::get(A->getType(), 1));
}

// MBA variants: a^b == (a|b)&~(a&b) == (a+b)-2*(a&b).
Value *llvm::obfvm::emitIntXor(IRBuilder<> &B, Value *A, Value *Bv,
                               VMHandlers H, bool AllowExpand) {
  unsigned Choice = pickVariant(H, 3, AllowExpand);
  if (Choice == 0)
    return B.CreateXor(A, Bv);
  if (Choice == 1) {
    Value *Tmp = B.CreateOr(A, Bv);
    return B.CreateAnd(Tmp, B.CreateNot(B.CreateAnd(A, Bv)));
  }
  Value *Tmp = B.CreateAdd(A, Bv);
  return B.CreateSub(Tmp, B.CreateShl(B.CreateAnd(A, Bv), 1));
}

// De Morgan variant: a&b == ~(~a|~b).
Value *llvm::obfvm::emitIntAnd(IRBuilder<> &B, Value *A, Value *Bv,
                               VMHandlers H, bool AllowExpand) {
  unsigned Choice = pickVariant(H, 2, AllowExpand);
  if (Choice == 0)
    return B.CreateAnd(A, Bv);
  return B.CreateNot(B.CreateOr(B.CreateNot(A), B.CreateNot(Bv)));
}

Value *llvm::obfvm::emitIntOr(IRBuilder<> &B, Value *A, Value *Bv,
                              VMHandlers H, bool AllowExpand) {
  unsigned Choice = pickVariant(H, 2, AllowExpand);
  if (Choice == 0)
    return B.CreateOr(A, Bv);
  return B.CreateNot(B.CreateAnd(B.CreateNot(A), B.CreateNot(Bv)));
}

// Power-of-two slot count so dispatch uses mask instead of mod; unused
// entries become bogus handler slots.
DispatchLayout llvm::obfvm::buildDispatchLayout(unsigned NumIds,
                                                unsigned Extra,
                                                VMHandlers H) {
  DispatchLayout L;
  unsigned Need = NumIds + Extra;
  unsigned Size = nextPow2(Need == 0 ? 1 : Need);
  assert(isPowerOf2(Size));
  L.SlotToId.assign(Size, UINT32_MAX);
  L.IdToSlot.assign(NumIds, 0);

  SmallVector<unsigned, 32> Slots;
  Slots.reserve(Size);
  for (unsigned I = 0; I < Size; ++I)
    Slots.push_back(I);

  // Reserve slot 0 for dispatch id 0 so the entry region stays anchored.
  if (NumIds > 0) {
    L.SlotToId[0] = 0;
    L.IdToSlot[0] = 0;
    Slots[0] = Slots.back();
    Slots.pop_back();
  }

  auto takeSlot = [&](unsigned Index) -> unsigned {
    unsigned Slot = Slots[Index];
    Slots[Index] = Slots.back();
    Slots.pop_back();
    return Slot;
  };

  for (unsigned Id = 1; Id < NumIds; ++Id) {
    unsigned Slot = 0;
    if (H == VMHandlers::Random && !Slots.empty()) {
      unsigned Pick =
          cryptoutils->get_range(static_cast<uint32_t>(Slots.size()));
      Slot = takeSlot(Pick);
    } else {
      Slot = takeSlot(0);
    }
    L.SlotToId[Slot] = Id;
    L.IdToSlot[Id] = Slot;
  }
  return L;
}
