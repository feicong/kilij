//===- VMEmitInterp.cpp - Emit opcode-mode VM interpreter ----------------===//
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
// Builds the opcode-mode interpreter: dispatch loop, opcode decode, and
// hard runtime checks.
//
//===----------------------------------------------------------------------===//
#include "VMEmitInterp.h"
#include "VMEmitUtils.h"
#include "CryptoUtils.h"
#include "VMMath.h"
#include "VMRuntime.h"
#include "Utils.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <functional>
#include <utility>

using namespace llvm;
using namespace llvm::obfvm;

#ifndef OBF_VM_RUNTIME_DEBUG
#define OBF_VM_RUNTIME_DEBUG 0
#endif

// Compile-time gate to avoid shipping debug-output signatures by accident.
static constexpr bool kVMRuntimeDebug = (OBF_VM_RUNTIME_DEBUG != 0);
// Junk constants chosen to be small odd primes for opaque predicate mixing.
static constexpr unsigned kJunkMulOp = 131u;
static constexpr unsigned kJunkMulVar = 17u;
static constexpr unsigned kJunkAddTramp = 7u;
static constexpr unsigned kBitsToBytesRound = 7u;

namespace {
static bool shouldUseWinX86StdCall(const Module &M) {
  Triple TT(M.getTargetTriple());
  if (!TT.isOSWindows() || !TT.isOSBinFormatCOFF())
    return false;
  // stdcall is only relevant on 32-bit x86 Windows.
  if (!TT.isX86())
    return false;
  return M.getDataLayout().getPointerSizeInBits() == 32;
}

static void setWinX86StdCall(Module &M, FunctionCallee Callee) {
  if (!shouldUseWinX86StdCall(M))
    return;
  Value *CalleeV = Callee.getCallee();
  if (!CalleeV)
    return;
  if (Function *Fn = dyn_cast<Function>(CalleeV->stripPointerCasts()))
    Fn->setCallingConv(CallingConv::X86_StdCall);
}

static void setWinX86StdCall(Module &M, CallInst *CI) {
  if (!CI)
    return;
  if (shouldUseWinX86StdCall(M))
    CI->setCallingConv(CallingConv::X86_StdCall);
}

struct DispTableInfo {
  GlobalVariable *Table = nullptr;
  Constant *Bias = nullptr;
  Constant *Stride = nullptr;
  Constant *Xor = nullptr;
  Constant *PermKey = nullptr;
  unsigned Scheme = 0;
};

struct BCDecodeContext {
  bool EncodeBC = false;
  uint64_t BCKey = 0;
  const VMBCEncodingInfo &EncInfo;
  Type *I8Ty = nullptr;
  Type *I32Ty = nullptr;
  Type *I64Ty = nullptr;
  Value *Key64V = nullptr;
  Value *Key8V = nullptr;
  Value *Key32V = nullptr;
  Value *Key32BV = nullptr;

  BCDecodeContext(uint64_t Key, const VMBCEncodingInfo &Info, Type *I8,
                  Type *I32, Type *I64)
      : EncodeBC(Key != 0), BCKey(Key), EncInfo(Info), I8Ty(I8), I32Ty(I32),
        I64Ty(I64) {}

  // Adapted from splitmix64; cheap avalanche to derive per-instruction keys.
  Value *mix64(IRBuilder<> &IB, Value *X) const {
    Value *T = IB.CreateXor(X, IB.CreateLShr(X, ConstantInt::get(I64Ty, 30)));
    T = IB.CreateMul(T, ConstantInt::get(I64Ty, EncInfo.MulConst1));
    T = IB.CreateXor(T, IB.CreateLShr(T, ConstantInt::get(I64Ty, 27)));
    T = IB.CreateMul(T, ConstantInt::get(I64Ty, EncInfo.MulConst2));
    T = IB.CreateXor(T, IB.CreateLShr(T, ConstantInt::get(I64Ty, 31)));
    return T;
  }

  // Per-instruction key derivation prevents bulk XOR decryption of bytecode.
  Value *deriveBCKey(IRBuilder<> &IB, Value *Index, uint64_t Salt) const {
    Value *Idx64 = IB.CreateZExt(Index, I64Ty);
    Value *Mul = IB.CreateMul(Idx64, ConstantInt::get(I64Ty, EncInfo.MixConst));
    Value *Mix = IB.CreateAdd(ConstantInt::get(I64Ty, Salt), Mul);
    Value *Base = IB.CreateXor(ConstantInt::get(I64Ty, BCKey), Mix);
    return mix64(IB, Base);
  }

  void initKeys(IRBuilder<> &IB, Value *PcIdx) {
    if (!EncodeBC)
      return;
    Key64V = deriveBCKey(IB, PcIdx, EncInfo.SaltInstr);
    Key8V = IB.CreateTrunc(Key64V, I8Ty);
    Key32V = IB.CreateTrunc(Key64V, I32Ty);
    Value *KeyShift = IB.CreateLShr(Key64V, ConstantInt::get(I64Ty, 32));
    Key32BV = IB.CreateTrunc(KeyShift, I32Ty);
  }

  Value *decode8(IRBuilder<> &IB, Value *V) const {
    if (!EncodeBC)
      return V;
    Value *T = V;
    if (EncInfo.Rot8 != 0)
      T = rotr8(IB, T, EncInfo.Rot8);
    return IB.CreateXor(T, Key8V);
  }

  Value *decode32(IRBuilder<> &IB, Value *V) const {
    if (!EncodeBC)
      return V;
    return IB.CreateXor(V, Key32V);
  }

  Value *decode32B(IRBuilder<> &IB, Value *V) const {
    if (!EncodeBC)
      return V;
    return IB.CreateXor(V, Key32BV);
  }

  Value *decode64(IRBuilder<> &IB, Value *V) const {
    if (!EncodeBC)
      return V;
    return IB.CreateXor(V, Key64V);
  }

  Value *decodeOffset(IRBuilder<> &IB, Value *Idx, Value *Enc) const {
    if (!EncodeBC)
      return Enc;
    Value *Key = deriveBCKey(IB, Idx, EncInfo.SaltOff);
    Value *KeyShift = IB.CreateLShr(Key, ConstantInt::get(I64Ty, 32));
    Value *Key32B = IB.CreateTrunc(KeyShift, I32Ty);
    return IB.CreateXor(Enc, Key32B);
  }

  Value *decodeSwitchVal(IRBuilder<> &IB, Value *Idx, Value *Enc) const {
    if (!EncodeBC)
      return Enc;
    Value *Key = deriveBCKey(IB, Idx, EncInfo.SaltSwitchVal);
    return IB.CreateXor(Enc, Key);
  }

  Value *decodeSwitchTgt(IRBuilder<> &IB, Value *Idx, Value *Enc) const {
    if (!EncodeBC)
      return Enc;
    Value *Key = deriveBCKey(IB, Idx, EncInfo.SaltSwitchTgt);
    Value *KeyShift = IB.CreateLShr(Key, ConstantInt::get(I64Ty, 32));
    Value *Key32B = IB.CreateTrunc(KeyShift, I32Ty);
    return IB.CreateXor(Enc, Key32B);
  }
};

// Encapsulates next-PC encoding so dispatch targets are key-dependent.
struct NextPcHelper {
  bool Hard = false;
  uint32_t PcMask = 0;
  uint32_t PcBits = 0;
  uint32_t PcMul = 0;
  unsigned RotAmt = 0;
  Value *KeyPtr = nullptr;
  Value *NextPcVar = nullptr;
  Value *CurPcVar = nullptr;
  BasicBlock *Update = nullptr;
  Type *I32Ty = nullptr;

  void storeNextPcVal(IRBuilder<> &IB, Value *Next) const {
    Value *Slot = slotFromPc(IB, Next, Hard, PcMask, PcBits, PcMul);
    Value *Enc = encodeNextPc(IB, Slot, Hard, KeyPtr, RotAmt);
    IB.CreateStore(Enc, NextPcVar);
    IB.CreateBr(Update);
  }

  void storeNextPcInc(IRBuilder<> &IB) const {
    Value *Cur = IB.CreateLoad(I32Ty, CurPcVar);
    Value *Next = IB.CreateAdd(Cur, ConstantInt::get(I32Ty, 1));
    storeNextPcVal(IB, Next);
  }
};

static Value *signExtendMasked(IRBuilder<> &IB, Value *V, Value *Mask,
                               Value *Sign) {
  LLVMContext &Ctx = IB.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Masked = IB.CreateAnd(V, Mask);
  Value *SignSet =
      IB.CreateICmpNE(IB.CreateAnd(Masked, Sign), ConstantInt::get(I64Ty, 0));
  Value *ExtMask = IB.CreateNot(Mask);
  return IB.CreateSelect(SignSet, IB.CreateOr(Masked, ExtMask), Masked);
}

static Value *computeByteCount(IRBuilder<> &IB, Value *BitsVar) {
  LLVMContext &Ctx = IB.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *Bits = IB.CreateLoad(I32Ty, BitsVar);
  // Round bit count up to bytes for memcpy/memcmp sizes.
  Value *Add = IB.CreateAdd(Bits, ConstantInt::get(I32Ty, kBitsToBytesRound));
  Value *Bytes = IB.CreateLShr(Add, ConstantInt::get(I32Ty, 3));
  return IB.CreateZExt(Bytes, I64Ty);
}

static void emitDispatchBlock(BasicBlock *DispBB, const DispTableInfo &DT,
                              Value *SlotVar, BasicBlock *Bogus,
                              ArrayRef<BasicBlock *> SlotTargets,
                              unsigned DispatchCount, uint32_t DispatchMask,
                              VMDispatch DispatchMode, bool Hard,
                              uint32_t SlotMixConst, IntegerType *I32Ty,
                              Type *IntPtrTy, Type *I8PtrTy) {
  IRBuilder<> DispatchIR(DispBB);
  Value *SlotIdx = DispatchIR.CreateLoad(I32Ty, SlotVar);
  SlotIdx = DispatchIR.CreateAnd(SlotIdx, ConstantInt::get(I32Ty, DispatchMask));
  if (DispatchMode == VMDispatch::Indirect && Hard && DT.PermKey) {
    // Keyed permutation prevents simple slot->handler correspondence.
    SlotIdx = permuteSlot(DispatchIR, SlotIdx, DT.PermKey, Hard, DispatchMask,
                          SlotMixConst);
  }
  if (DispatchMode == VMDispatch::Indirect) {
    if (DT.Table) {
      Value *Ptr = DispatchIR.CreateInBoundsGEP(
          DT.Table->getValueType(), DT.Table,
          {ConstantInt::get(I32Ty, 0), SlotIdx});
      Value *EncVal = DispatchIR.CreateLoad(IntPtrTy, Ptr);
      Value *DecVal = EncVal;
      if (Hard && DT.Bias && DT.Stride) {
        Value *SlotExt = DispatchIR.CreateZExt(SlotIdx, IntPtrTy);
        Value *IdxMul = DispatchIR.CreateMul(SlotExt, DT.Stride);
        Value *Offset = DispatchIR.CreateAdd(DT.Bias, IdxMul);
        if (DT.Scheme == 0) {
          DecVal = DispatchIR.CreateSub(EncVal, Offset);
        } else {
          DecVal = DispatchIR.CreateAdd(EncVal, Offset);
        }
      }
      Value *Target = DispatchIR.CreateIntToPtr(DecVal, I8PtrTy);
      IndirectBrInst *IB =
          DispatchIR.CreateIndirectBr(Target, DispatchCount);
      for (unsigned Slot = 0; Slot < DispatchCount; ++Slot)
        IB->addDestination(SlotTargets[Slot]);
    }
  } else {
    SwitchInst *Sw = DispatchIR.CreateSwitch(SlotIdx, Bogus, DispatchCount);
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot)
      Sw->addCase(ConstantInt::get(I32Ty, Slot), SlotTargets[Slot]);
  }
}
} // namespace

static GlobalVariable *getOrCreateVMDebugGV(Module &M, StringRef Name,
                                            Type *Ty) {
  if (GlobalVariable *GV = M.getGlobalVariable(Name))
    return GV;
  auto *Init = Constant::getNullValue(Ty);
  auto *GV = new GlobalVariable(M, Ty, false, GlobalValue::ExternalLinkage,
                                Init, Name);
  GV->setDLLStorageClass(GlobalValue::DLLExportStorageClass);
  return GV;
}

// Hash helper used by hard runtime integrity checks (per-build variant).
static Function *getOrCreateVMHashFunc(Module &M, unsigned Style) {
  LLVMContext &Ctx = M.getContext();
  unsigned Sel = Style % 3u;
  std::string Tag = "vm.hash64." + std::to_string(Sel);
  if (Function *F = findTaggedFunction(M, Tag))
    return F;
  IntegerType *I8Ty = Type::getInt8Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  PointerType *I8PtrTy = PointerType::getUnqual(I8Ty);
  FunctionType *FTy =
      FunctionType::get(I64Ty, {I8PtrTy, I64Ty, I64Ty, I64Ty}, false);
  std::string Base = "vm_hash64_" + std::to_string(Sel);
  Function *Fn =
      Function::Create(FTy, GlobalValue::InternalLinkage, Base, &M);
  obfuscateSymbolName(*Fn, M, Tag, Base);
  Fn->addFnAttr("vm_runtime");
  Fn->addFnAttr("no_obfuscate");
  Fn->addFnAttr(Attribute::NoInline);
  Fn->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Fn);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Fn);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", Fn);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", Fn);
  IRBuilder<> EntryIR(Entry);
  Argument *Data = Fn->getArg(0);
  Argument *Len = Fn->getArg(1);
  Argument *Key = Fn->getArg(2);
  Argument *Mul = Fn->getArg(3);
  AllocaInst *Idx = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *Hash = EntryIR.CreateAlloca(I64Ty);
  EntryIR.CreateStore(ConstantInt::get(I64Ty, 0), Idx);
  EntryIR.CreateStore(Key, Hash);
  EntryIR.CreateBr(Loop);

  IRBuilder<> LoopIR(Loop);
  Value *Cur = LoopIR.CreateLoad(I64Ty, Idx);
  Value *Cond = LoopIR.CreateICmpULT(Cur, Len);
  LoopIR.CreateCondBr(Cond, Body, Exit);

  IRBuilder<> BodyIR(Body);
  Value *Ptr = BodyIR.CreateInBoundsGEP(I8Ty, Data, Cur);
  Value *Byte = BodyIR.CreateLoad(I8Ty, Ptr);
  Value *HashVal = BodyIR.CreateLoad(I64Ty, Hash);
  Value *Byte64 = BodyIR.CreateZExt(Byte, I64Ty);
  Value *NewHash = nullptr;
  constexpr unsigned kHashRotate = 7;
  constexpr unsigned kHashRotateInv = 64 - kHashRotate;
  if (Sel == 0) {
    Value *Xor = BodyIR.CreateXor(HashVal, Byte64);
    NewHash = BodyIR.CreateMul(Xor, Mul);
  } else if (Sel == 1) {
    Value *Add = BodyIR.CreateAdd(HashVal, Byte64);
    Value *Mix =
        BodyIR.CreateXor(Add, BodyIR.CreateLShr(Add, ConstantInt::get(I64Ty, 29)));
    NewHash = BodyIR.CreateMul(Mix, Mul);
  } else {
    Value *Xor = BodyIR.CreateXor(HashVal, Byte64);
    // Rotate by a fixed odd amount to spread entropy across bits.
    Value *RotL = BodyIR.CreateShl(Xor, ConstantInt::get(I64Ty, kHashRotate));
    Value *RotR =
        BodyIR.CreateLShr(Xor, ConstantInt::get(I64Ty, kHashRotateInv));
    Value *Rot = BodyIR.CreateOr(RotL, RotR);
    NewHash = BodyIR.CreateMul(Rot, Mul);
  }
  BodyIR.CreateStore(NewHash, Hash);
  Value *Next = BodyIR.CreateAdd(Cur, ConstantInt::get(I64Ty, 1));
  BodyIR.CreateStore(Next, Idx);
  BodyIR.CreateBr(Loop);

  IRBuilder<> ExitIR(Exit);
  Value *Out = ExitIR.CreateLoad(I64Ty, Hash);
  ExitIR.CreateRet(Out);
  return Fn;
}

struct AntiDebugConfig {
  bool UseRemote = true;
  bool UseTiming = true;
  uint32_t SpinIters = 64;
  uint32_t TimeDiv = 20;
  uint64_t LcgMul = 0;
  uint64_t LcgAdd = 0;
};

// Randomize anti-debug knobs to avoid a fixed timing signature.
static AntiDebugConfig buildAntiDebugConfig() {
  AntiDebugConfig Cfg;
  uint64_t R = cryptoutils->get_uint64_t();
  Cfg.UseRemote = (R & 1u) != 0;
  Cfg.UseTiming = (R & 2u) != 0;
  if (!Cfg.UseRemote && !Cfg.UseTiming)
    Cfg.UseRemote = true;
  Cfg.SpinIters = 32u + static_cast<uint32_t>(cryptoutils->get_range(64));
  Cfg.TimeDiv = 12u + static_cast<uint32_t>(cryptoutils->get_range(24));
  Cfg.LcgMul = cryptoutils->get_uint64_t() | 1ULL;
  Cfg.LcgAdd = cryptoutils->get_uint64_t();
  return Cfg;
}

struct AntiDebugResult {
  Value *Flag = nullptr;
  BasicBlock *Tail = nullptr;
};

static AntiDebugResult emitInlineAntiDebug(IRBuilder<> &B, Module &M,
                                           const AntiDebugConfig &Cfg) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I1Ty = Type::getInt1Ty(Ctx);
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  PointerType *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
  PointerType *I32PtrTy = PointerType::getUnqual(I32Ty);
  PointerType *I64PtrTy = PointerType::getUnqual(I64Ty);
  Triple TT(M.getTargetTriple());
  // Anti-debug helpers are Windows-only; other targets skip the checks.
  if (!TT.isOSWindows() || !TT.isOSBinFormatCOFF())
    return {ConstantInt::getFalse(Ctx), B.GetInsertBlock()};

  FunctionCallee IsDbg =
      M.getOrInsertFunction("IsDebuggerPresent",
                            FunctionType::get(I32Ty, {}, false));
  FunctionCallee GetCur =
      M.getOrInsertFunction("GetCurrentProcess",
                            FunctionType::get(I8PtrTy, {}, false));
  FunctionCallee CRDP = M.getOrInsertFunction(
      "CheckRemoteDebuggerPresent",
      FunctionType::get(I32Ty, {I8PtrTy, I32PtrTy}, false));
  FunctionCallee QPC = M.getOrInsertFunction(
      "QueryPerformanceCounter", FunctionType::get(I32Ty, {I64PtrTy}, false));
  FunctionCallee QPF = M.getOrInsertFunction(
      "QueryPerformanceFrequency", FunctionType::get(I32Ty, {I64PtrTy}, false));

  // WinAPI is stdcall on 32-bit Windows (cdecl on x64).
  setWinX86StdCall(M, IsDbg);
  setWinX86StdCall(M, GetCur);
  setWinX86StdCall(M, CRDP);
  setWinX86StdCall(M, QPC);
  setWinX86StdCall(M, QPF);

  AllocaInst *SuspectVar = B.CreateAlloca(I1Ty);
  CallInst *DbgCall = B.CreateCall(IsDbg);
  setWinX86StdCall(M, DbgCall);
  Value *Dbg = DbgCall;
  Value *IsDbgV = B.CreateICmpNE(Dbg, ConstantInt::get(I32Ty, 0));
  B.CreateStore(IsDbgV, SuspectVar);

  if (Cfg.UseRemote) {
    CallInst *ProcCall = B.CreateCall(GetCur);
    setWinX86StdCall(M, ProcCall);
    Value *Proc = ProcCall;
    AllocaInst *Remote = B.CreateAlloca(I32Ty);
    B.CreateStore(ConstantInt::get(I32Ty, 0), Remote);
    CallInst *CRDPCall = B.CreateCall(CRDP, {Proc, Remote});
    setWinX86StdCall(M, CRDPCall);
    Value *RemoteVal = B.CreateLoad(I32Ty, Remote);
    Value *IsRemote = B.CreateICmpNE(RemoteVal, ConstantInt::get(I32Ty, 0));
    Value *Cur = B.CreateLoad(I1Ty, SuspectVar);
    B.CreateStore(B.CreateOr(Cur, IsRemote), SuspectVar);
  }

  if (Cfg.UseTiming) {
    AllocaInst *Freq = B.CreateAlloca(I64Ty);
    AllocaInst *T0 = B.CreateAlloca(I64Ty);
    AllocaInst *T1 = B.CreateAlloca(I64Ty);
    B.CreateStore(ConstantInt::get(I64Ty, 0), Freq);
    B.CreateStore(ConstantInt::get(I64Ty, 0), T0);
    B.CreateStore(ConstantInt::get(I64Ty, 0), T1);
    CallInst *QPFCall = B.CreateCall(QPF, {Freq});
    setWinX86StdCall(M, QPFCall);
    CallInst *QPC0 = B.CreateCall(QPC, {T0});
    setWinX86StdCall(M, QPC0);

    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Seed = B.CreateCall(Rd);
    BasicBlock *Loop =
        BasicBlock::Create(Ctx, "spin", B.GetInsertBlock()->getParent());
    BasicBlock *After =
        BasicBlock::Create(Ctx, "spin.after", B.GetInsertBlock()->getParent());
    B.CreateBr(Loop);

    IRBuilder<> SpinIR(Loop);
    PHINode *Idx = SpinIR.CreatePHI(I32Ty, 2);
    PHINode *Acc = SpinIR.CreatePHI(I64Ty, 2);
    Idx->addIncoming(ConstantInt::get(I32Ty, 0), B.GetInsertBlock());
    Acc->addIncoming(Seed, B.GetInsertBlock());
    Value *AccMul =
        SpinIR.CreateMul(Acc, ConstantInt::get(I64Ty, Cfg.LcgMul));
    Value *AccNext =
        SpinIR.CreateAdd(AccMul, ConstantInt::get(I64Ty, Cfg.LcgAdd));
    Value *IdxNext = SpinIR.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
    Value *Cond =
        SpinIR.CreateICmpULT(IdxNext, ConstantInt::get(I32Ty, Cfg.SpinIters));
    Idx->addIncoming(IdxNext, Loop);
    Acc->addIncoming(AccNext, Loop);
    SpinIR.CreateCondBr(Cond, Loop, After);

    IRBuilder<> AfterIR(After);
    CallInst *QPC1 = AfterIR.CreateCall(QPC, {T1});
    setWinX86StdCall(M, QPC1);
    Value *F = AfterIR.CreateLoad(I64Ty, Freq);
    Value *S0 = AfterIR.CreateLoad(I64Ty, T0);
    Value *S1 = AfterIR.CreateLoad(I64Ty, T1);
    Value *Delta = AfterIR.CreateSub(S1, S0);
    Value *FreqOk = AfterIR.CreateICmpNE(F, ConstantInt::get(I64Ty, 0));
    Value *Div = ConstantInt::get(I64Ty, Cfg.TimeDiv);
    Value *Thresh = AfterIR.CreateUDiv(F, Div);
    Value *Slow = AfterIR.CreateICmpUGT(Delta, Thresh);
    Value *TimeSus = AfterIR.CreateAnd(FreqOk, Slow);
    Value *Cur = AfterIR.CreateLoad(I1Ty, SuspectVar);
    AfterIR.CreateStore(AfterIR.CreateOr(Cur, TimeSus), SuspectVar);
    Value *Flag = AfterIR.CreateLoad(I1Ty, SuspectVar);
    return {Flag, After};
  }

  Value *Flag = B.CreateLoad(I1Ty, SuspectVar);
  return {Flag, B.GetInsertBlock()};
}

static void emitRuntimeDebug(IRBuilder<> &B, Module &M, StringRef Msg,
                             bool Enabled) {
  if (!Enabled || !kVMRuntimeDebug)
    return;
  Triple TT(M.getTargetTriple());
  if (!TT.isOSWindows() || !TT.isOSBinFormatCOFF())
    return;
  LLVMContext &Ctx = M.getContext();
  Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {I8PtrTy}, false);
  FunctionCallee ODS = M.getOrInsertFunction("OutputDebugStringA", FT);
  setWinX86StdCall(M, ODS);
  GlobalVariable *StrGV = B.CreateGlobalString(Msg);
  Value *Str =
      B.CreateInBoundsGEP(StrGV->getValueType(), StrGV,
                          {B.getInt32(0), B.getInt32(0)});
  CallInst *Call = B.CreateCall(ODS, {Str});
  setWinX86StdCall(M, Call);
}

static BasicBlock *emitRuntimeDebugIf(IRBuilder<> &B, Module &M, Value *Cond,
                                      StringRef Msg, bool Enabled) {
  if (!Enabled || !kVMRuntimeDebug)
    return B.GetInsertBlock();
  BasicBlock *Cur = B.GetInsertBlock();
  if (!Cur)
    return nullptr;
  Function *Fn = Cur->getParent();
  LLVMContext &Ctx = M.getContext();
  BasicBlock *LogBB = BasicBlock::Create(Ctx, "vm.dbg", Fn);
  BasicBlock *ContBB = BasicBlock::Create(Ctx, "vm.dbg.cont", Fn);
  B.CreateCondBr(Cond, LogBB, ContBB);
  IRBuilder<> LogIR(LogBB);
  emitRuntimeDebug(LogIR, M, Msg, true);
  LogIR.CreateBr(ContBB);
  B.SetInsertPoint(ContBB);
  return ContBB;
}

// ============================================================================
// VM Tracing and Bounds Checking Infrastructure
// ============================================================================

static constexpr unsigned kVmTraceBufSize = 64;

static FunctionCallee getOrCreateVMTraceFn(Module &M) {
  LLVMContext &Ctx = M.getContext();
  const DataLayout &DL = M.getDataLayout();
  Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *VoidTy = Type::getVoidTy(Ctx);
  FunctionType *FT = FunctionType::get(VoidTy, {I8PtrTy, I64Ty, I64Ty, I64Ty}, false);
  Function *F = findTaggedFunction(M, "vm.trace.fn");
  if (!F) {
    F = Function::Create(FT, GlobalValue::InternalLinkage, "vm_trace_impl", &M);
    // Avoid shipping a stable debug symbol when obf-symbols is enabled.
    obfuscateSymbolName(*F, M, "vm.trace.fn", "vm_trace_impl");
  }
  if (F->empty()) {
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> EntryIR(Entry);

    auto ArgIt = F->arg_begin();
    Value *Fmt = &*ArgIt++;
    Value *A = &*ArgIt++;
    Value *B_ = &*ArgIt++;
    Value *C = &*ArgIt++;

    Type *I8Ty = Type::getInt8Ty(Ctx);
    Value *Buf =
        EntryIR.CreateAlloca(I8Ty, ConstantInt::get(Type::getInt32Ty(Ctx), 256));

    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *SizeTy = DL.getIntPtrType(Ctx);
    FunctionType *SnprintfTy = FunctionType::get(
        I32Ty, {I8PtrTy, SizeTy, I8PtrTy}, true);
    FunctionCallee Snprintf = M.getOrInsertFunction("snprintf", SnprintfTy);
    EntryIR.CreateCall(
        Snprintf,
        {Buf, ConstantInt::get(SizeTy, 255), Fmt, A, B_, C});
    Value *BufEnd =
        EntryIR.CreateInBoundsGEP(I8Ty, Buf, ConstantInt::get(I32Ty, 255));
    EntryIR.CreateStore(ConstantInt::get(I8Ty, 0), BufEnd);

    FunctionType *ODSTy = FunctionType::get(VoidTy, {I8PtrTy}, false);
    FunctionCallee ODS = M.getOrInsertFunction("OutputDebugStringA", ODSTy);
    setWinX86StdCall(M, ODS);
    CallInst *ODSCall = EntryIR.CreateCall(ODS, {Buf});
    setWinX86StdCall(M, ODSCall);
    FunctionType *PutsTy = FunctionType::get(I32Ty, {I8PtrTy}, false);
    FunctionCallee Puts = M.getOrInsertFunction("puts", PutsTy);
    EntryIR.CreateCall(Puts, {Buf});

    EntryIR.CreateRetVoid();

    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr("vm_runtime");
  }
  return FunctionCallee(FT, F);
}

static FunctionCallee getOrCreateVMDumpTraceFn(Module &M) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I8Ty = Type::getInt8Ty(Ctx);
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  PointerType *I8PtrTy = PointerType::getUnqual(I8Ty);
  PointerType *I32PtrTy = PointerType::getUnqual(I32Ty);
  Type *VoidTy = Type::getVoidTy(Ctx);

  FunctionType *FT = FunctionType::get(
      VoidTy,
      {I32PtrTy, I32Ty, I32Ty, I8PtrTy, I32Ty, I64Ty, I64Ty, I64Ty, I64Ty,
       I64Ty, I64Ty},
      false);
  Function *F = findTaggedFunction(M, "vm.trace.dump");
  if (!F) {
    F = Function::Create(FT, GlobalValue::InternalLinkage, "vm_trace_dump_impl",
                         &M);
    obfuscateSymbolName(*F, M, "vm.trace.dump", "vm_trace_dump_impl");
  }
  if (F->empty()) {
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(Entry);

    auto ArgIt = F->arg_begin();
    Value *Buf = &*ArgIt++;
    Value *Count = &*ArgIt++;
    Value *Pc = &*ArgIt++;
    Value *NamePtr = &*ArgIt++;
    Value *NameLen = &*ArgIt++;
    Value *RegA = &*ArgIt++;
    Value *RegB = &*ArgIt++;
    Value *RegC = &*ArgIt++;
    Value *RegD = &*ArgIt++;
    Value *RegE = &*ArgIt++;
    Value *RegF = &*ArgIt++;

    Value *Path =
        B.CreateGlobalString("C:\\\\kilij-llvm20\\\\tmp_repro\\\\vm_trace.bin");

    FunctionType *CreateFileTy =
        FunctionType::get(I8PtrTy,
                          {I8PtrTy, I32Ty, I32Ty, I8PtrTy, I32Ty, I32Ty, I8PtrTy},
                          false);
    FunctionCallee CreateFile = M.getOrInsertFunction("CreateFileA",
                                                      CreateFileTy);
    setWinX86StdCall(M, CreateFile);
    const uint32_t kFileAppendData = 0x0004;
    const uint32_t kFileShareRead = 0x0001;
    const uint32_t kFileShareWrite = 0x0002;
    const uint32_t kOpenAlways = 0x00000004;
    const uint32_t kFileAttrNormal = 0x00000080;
    CallInst *CreateCall = B.CreateCall(
        CreateFile,
        {Path,
         ConstantInt::get(I32Ty, kFileAppendData),
         ConstantInt::get(I32Ty, kFileShareRead | kFileShareWrite),
         ConstantPointerNull::get(I8PtrTy),
         ConstantInt::get(I32Ty, kOpenAlways),
         ConstantInt::get(I32Ty, kFileAttrNormal),
         ConstantPointerNull::get(I8PtrTy)});
    setWinX86StdCall(M, CreateCall);
    Value *Handle = CreateCall;

    FunctionType *WriteFileTy =
        FunctionType::get(I32Ty, {I8PtrTy, I8PtrTy, I32Ty, I32PtrTy, I8PtrTy},
                          false);
    FunctionCallee WriteFile = M.getOrInsertFunction("WriteFile", WriteFileTy);
    setWinX86StdCall(M, WriteFile);
    FunctionType *CloseTy =
        FunctionType::get(I32Ty, {I8PtrTy}, false);
    FunctionCallee CloseHandle = M.getOrInsertFunction("CloseHandle", CloseTy);
    setWinX86StdCall(M, CloseHandle);

    Value *Bytes = B.CreateMul(Count, ConstantInt::get(I32Ty, 4));
    AllocaInst *Written = B.CreateAlloca(I32Ty);
    B.CreateStore(ConstantInt::get(I32Ty, 0), Written);
    Value *BufPtr = B.CreateBitCast(Buf, I8PtrTy);
    CallInst *Write0 = B.CreateCall(WriteFile,
                 {Handle, BufPtr, Bytes, Written,
                  ConstantPointerNull::get(I8PtrTy)});
    setWinX86StdCall(M, Write0);

    AllocaInst *PcTmp = B.CreateAlloca(I32Ty);
    B.CreateStore(Pc, PcTmp);
    Value *PcPtr = B.CreateBitCast(PcTmp, I8PtrTy);
    CallInst *Write1 = B.CreateCall(WriteFile,
                 {Handle, PcPtr, ConstantInt::get(I32Ty, 4), Written,
                  ConstantPointerNull::get(I8PtrTy)});
    setWinX86StdCall(M, Write1);

    AllocaInst *LenTmp = B.CreateAlloca(I32Ty);
    B.CreateStore(NameLen, LenTmp);
    Value *LenPtr = B.CreateBitCast(LenTmp, I8PtrTy);
    CallInst *Write2 = B.CreateCall(WriteFile,
                 {Handle, LenPtr, ConstantInt::get(I32Ty, 4), Written,
                  ConstantPointerNull::get(I8PtrTy)});
    setWinX86StdCall(M, Write2);
    CallInst *Write3 = B.CreateCall(WriteFile,
                 {Handle, NamePtr, NameLen, Written,
                  ConstantPointerNull::get(I8PtrTy)});
    setWinX86StdCall(M, Write3);

    auto writeI64 = [&](Value *Val) {
      AllocaInst *Tmp = B.CreateAlloca(I64Ty);
      B.CreateStore(Val, Tmp);
      Value *TmpPtr = B.CreateBitCast(Tmp, I8PtrTy);
      CallInst *WriteX = B.CreateCall(WriteFile,
                   {Handle, TmpPtr, ConstantInt::get(I32Ty, 8), Written,
                    ConstantPointerNull::get(I8PtrTy)});
      setWinX86StdCall(M, WriteX);
    };
    writeI64(RegA);
    writeI64(RegB);
    writeI64(RegC);
    writeI64(RegD);
    writeI64(RegE);
    writeI64(RegF);

    CallInst *CloseCall = B.CreateCall(CloseHandle, {Handle});
    setWinX86StdCall(M, CloseCall);
    B.CreateRetVoid();

    F->addFnAttr(Attribute::NoInline);
    F->addFnAttr("vm_runtime");
  }
  return FunctionCallee(FT, F);
}

static void emitVMTrace(IRBuilder<> &B, Module &M, StringRef Fmt,
                        Value *A, Value *B_, Value *C, bool Enabled) {
  if (!Enabled || !kVMRuntimeDebug)
    return;
  Triple TT(M.getTargetTriple());
  if (!TT.isOSWindows() || !TT.isOSBinFormatCOFF())
    return;
  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionCallee TraceFn = getOrCreateVMTraceFn(M);
  GlobalVariable *FmtGV = B.CreateGlobalString(Fmt);
  Value *FmtStr =
      B.CreateInBoundsGEP(FmtGV->getValueType(), FmtGV,
                          {B.getInt32(0), B.getInt32(0)});
  Value *A64 = A ? B.CreateZExtOrTrunc(A, I64Ty) : ConstantInt::get(I64Ty, 0);
  Value *B64 = B_ ? B.CreateZExtOrTrunc(B_, I64Ty) : ConstantInt::get(I64Ty, 0);
  Value *C64 = C ? B.CreateZExtOrTrunc(C, I64Ty) : ConstantInt::get(I64Ty, 0);
  B.CreateCall(TraceFn, {FmtStr, A64, B64, C64});
}

static Function *emitVMInterpreterBB(Module &M, const VMFunction &F,
                                     const VMConfig &Cfg);
static Function *emitVMInterpreterOpcodeBC(Module &M, const VMFunction &F,
                                           const VMBytecode &BC,
                                           const VMBytecodeGlobals &Globals,
                                           const VMBCLayout &Layout,
                                           const VMBCEncodingInfo &EncInfo,
                                           const VMConfig &Cfg,
                                           uint64_t BCKey);

static Function *emitCallHelper(Module &M, const VMFunction &F,
                                const VMCallInfo &CI, unsigned Index,
                                GlobalVariable *LoadCounter,
                                GlobalVariable *StoreCounter,
                                GlobalVariable *HostCallCounter,
                                GlobalVariable *HostCyclesCounter) {
  LLVMContext &Ctx = M.getContext();
  StructType *StateTy = getOrCreateVMStateType(M);
  PointerType *StatePtrTy = PointerType::getUnqual(StateTy);
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {StatePtrTy}, false);
  std::string Name =
      ("vm_call_" + F.Name + "_" + std::to_string(Index)).str();
  Function *Helper =
      Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  Helper->addFnAttr("vm_runtime");
  std::string Tag =
      ("vm.call." + F.Name + "." + std::to_string(Index)).str();
  obfuscateSymbolName(*Helper, M, Tag, Name);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Helper);
  IRBuilder<> CallIR(Entry);
  Value *State = Helper->arg_begin();
  Value *RegsPtr =
      CallIR.CreateLoad(PointerType::getUnqual(Type::getInt64Ty(Ctx)),
                   getStateFieldPtr(CallIR, M, StateTy, State, VMStateField::Regs));

  SmallVector<Value *, 8> Args;
  Args.reserve(CI.ArgRegs.size());
  for (unsigned i = 0; i < CI.ArgRegs.size(); ++i) {
    uint32_t Reg = CI.ArgRegs[i];
    Type *CallTy =
        (CI.CalleeTy && i < CI.CalleeTy->getNumParams())
            ? CI.CalleeTy->getParamType(i)
            : nullptr;
    Type *DecodeTy = CallTy;
    if (!DecodeTy) {
      DecodeTy = (i < CI.ArgTypes.size() && CI.ArgTypes[i]) ? CI.ArgTypes[i]
                                                            : nullptr;
    }
    VMTypeKind VMK = VMTypeKind::I64;
    if (DecodeTy && DecodeTy->isIntegerTy(1))
      VMK = VMTypeKind::I1;
    else if (DecodeTy && DecodeTy->isIntegerTy(8))
      VMK = VMTypeKind::I8;
    else if (DecodeTy && DecodeTy->isIntegerTy(16))
      VMK = VMTypeKind::I16;
    else if (DecodeTy && DecodeTy->isIntegerTy(32))
      VMK = VMTypeKind::I32;
    else if (DecodeTy && DecodeTy->isIntegerTy(64))
      VMK = VMTypeKind::I64;
    else if (DecodeTy && DecodeTy->isFloatTy())
      VMK = VMTypeKind::F32;
    else if (DecodeTy && DecodeTy->isDoubleTy())
      VMK = VMTypeKind::F64;
    else if (DecodeTy && DecodeTy->isPointerTy())
      VMK = VMTypeKind::Ptr;

    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), Reg);
    Value *RegVal = loadReg(CallIR, RegsPtr, Idx, LoadCounter);
    Value *ArgVal = unpackValue(
        CallIR, RegVal, VMK, M.getDataLayout().getPointerSizeInBits());
    if (DecodeTy) {
      if (DecodeTy->isPointerTy()) {
        ArgVal = CallIR.CreateIntToPtr(ArgVal, DecodeTy);
        if (ArgVal->getType() != DecodeTy)
          ArgVal = CallIR.CreateBitCast(ArgVal, DecodeTy);
      } else if (ArgVal->getType() != DecodeTy) {
        if (DecodeTy->isIntegerTy()) {
          ArgVal = CallIR.CreateZExtOrTrunc(ArgVal, DecodeTy);
        } else if (DecodeTy->isFloatingPointTy()) {
          ArgVal = CallIR.CreateBitCast(ArgVal, DecodeTy);
        }
      }
    }
    if (CallTy && ArgVal->getType() != CallTy) {
      ArgVal = castValueToParam(
          CallIR, ArgVal, CallTy, M.getDataLayout().getPointerSizeInBits());
    }
    Args.push_back(ArgVal);
  }
  if (CI.CalleeTy) {
    for (unsigned i = 0; i < Args.size() && i < CI.CalleeTy->getNumParams();
         ++i) {
      Type *ParamTy = CI.CalleeTy->getParamType(i);
      if (Args[i]->getType() != ParamTy) {
        errs() << "vm: call arg type mismatch in " << F.Name << " call "
               << (CI.Name.empty() ? "<anon>" : CI.Name) << " idx " << i
               << " arg=" << *Args[i]->getType()
               << " param=" << *ParamTy << "\n";
        vmFatal("vm: call arg type mismatch");
      }
    }
  }

  Value *HostStart = nullptr;
  if (HostCyclesCounter) {
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    HostStart = CallIR.CreateCall(Rd);
  }
  bumpCounter(CallIR, HostCallCounter);
  PointerType *CalleePtrTy =
      CI.CalleeTy ? PointerType::get(CI.CalleeTy, CI.CalleeAddrSpace) : nullptr;
  Value *CalleeVal = nullptr;
  if (CI.IsIndirect) {
    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), CI.CalleeReg);
    Value *RegVal = loadReg(CallIR, RegsPtr, Idx, LoadCounter);
    if (M.getDataLayout().getPointerSizeInBits() < 64) {
      RegVal =
          CallIR.CreateTrunc(RegVal,
                        Type::getIntNTy(Ctx, M.getDataLayout().getPointerSizeInBits()));
    }
    CalleeVal = CallIR.CreateIntToPtr(
        RegVal,
        CalleePtrTy ? CalleePtrTy : PointerType::getUnqual(CI.CalleeTy));
  } else {
    CalleeVal = CI.Callee;
    if (CalleeVal && CalleePtrTy && CalleeVal->getType() != CalleePtrTy) {
      if (auto *PT = dyn_cast<PointerType>(CalleeVal->getType())) {
        if (PT->getAddressSpace() != CI.CalleeAddrSpace) {
          CalleeVal = CallIR.CreateAddrSpaceCast(CalleeVal, CalleePtrTy);
        } else {
          CalleeVal = CallIR.CreateBitCast(CalleeVal, CalleePtrTy);
        }
      } else {
        CalleeVal = CallIR.CreateBitCast(CalleeVal, CalleePtrTy);
      }
    }
  }
  FunctionType *CallFTy = CI.CalleeTy;
  bool IsVarArg = CallFTy && CallFTy->isVarArg();
  bool NeedsCast = false;
  if (CallFTy) {
    if (Args.size() < CallFTy->getNumParams()) {
      vmFatal("vm: call args fewer than callee params");
    }
    for (unsigned i = 0; i < Args.size() && i < CallFTy->getNumParams(); ++i) {
      if (Args[i]->getType() != CallFTy->getParamType(i)) {
        NeedsCast = true;
        break;
      }
    }
  }
  if (!CallFTy || NeedsCast) {
    SmallVector<Type *, 8> CallArgTys;
    CallArgTys.reserve(Args.size());
    for (Value *V : Args)
      CallArgTys.push_back(V->getType());
    Type *RetTy = CallFTy ? CallFTy->getReturnType()
                          : (CI.IsVoid ? Type::getVoidTy(Ctx)
                                       : getLLVMType(CI.RetTy.Kind, Ctx,
                                                     M.getDataLayout()
                                                         .getPointerSizeInBits()));
    if (!CallFTy || !IsVarArg) {
      CallFTy = FunctionType::get(RetTy, CallArgTys, IsVarArg);
    }
    PointerType *CallPtrTy = PointerType::get(CallFTy, CI.CalleeAddrSpace);
    if (CalleeVal->getType() != CallPtrTy) {
      if (auto *PT = dyn_cast<PointerType>(CalleeVal->getType())) {
        if (PT->getAddressSpace() != CI.CalleeAddrSpace) {
          CalleeVal = CallIR.CreateAddrSpaceCast(CalleeVal, CallPtrTy);
        } else {
          CalleeVal = CallIR.CreateBitCast(CalleeVal, CallPtrTy);
        }
      } else {
        CalleeVal = CallIR.CreateBitCast(CalleeVal, CallPtrTy);
      }
    }
  }
  CallInst *Call = CallIR.CreateCall(CallFTy, CalleeVal, Args);
  Call->setCallingConv(static_cast<CallingConv::ID>(CI.CallConv));
  if (!CI.CallAttrs.isEmpty())
    Call->setAttributes(CI.CallAttrs);
  if (HostCyclesCounter && HostStart) {
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *HostEnd = CallIR.CreateCall(Rd);
    Value *Delta = CallIR.CreateSub(HostEnd, HostStart);
    addCounter(CallIR, HostCyclesCounter, Delta);
  }
  if (!CI.IsVoid) {
    Value *RetVal = Call;
    VMTypeKind VMK = CI.RetTy.Kind;
    Value *Packed;
    if (CI.CalleeTy->getReturnType()->isPointerTy()) {
      Value *PtrAsInt = CallIR.CreatePtrToInt(
          RetVal,
          Type::getIntNTy(Ctx, M.getDataLayout().getPointerSizeInBits()));
      Packed =
          packValue(CallIR, PtrAsInt, VMK, M.getDataLayout().getPointerSizeInBits());
    } else {
      Packed =
          packValue(CallIR, RetVal, VMK, M.getDataLayout().getPointerSizeInBits());
    }
    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), CI.RetReg);
    storeReg(CallIR, RegsPtr, Idx, Packed, StoreCounter);
  }

  CallIR.CreateRetVoid();
  return Helper;
}

static Function *emitVMInterpreterBB(Module &M, const VMFunction &F,
                                     const VMConfig &Cfg) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  StructType *StateTy = getOrCreateVMStateType(M);
  PointerType *StatePtrTy = PointerType::getUnqual(StateTy);
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {StatePtrTy}, false);
  std::string RunName = ("vm_run_" + F.Name).str();
  Function *Run =
      Function::Create(FT, GlobalValue::PrivateLinkage, RunName, &M);
  Run->addFnAttr("vm_runtime");
  obfuscateSymbolName(*Run, M, ("vm.run." + F.Name).str(), RunName);
  Run->addFnAttr(Attribute::NoInline);

  VMHandlers Handlers = Cfg.Handlers;
  bool Counters = Cfg.Counters;
  VMDispatch DispatchMode = Cfg.Dispatch;
  bool Hard = Cfg.Hard;
  bool HardRt = Cfg.HardRuntime;
  bool RtDebug = Cfg.RuntimeDebug;
  bool Trace = Cfg.Trace;
  bool BoundsCheck = Cfg.BoundsCheck;
  (void)BoundsCheck; // BogusIR mode uses compile-time constant indices
  bool AllowArithExpand =
      (Handlers == VMHandlers::Random) && (Cfg.Encode != VMEncode::MBA);

  VMCounters Ctrs = maybeCreateCounters(M, F.Name, Counters);
  uint64_t KeyMul = cryptoutils->get_uint64_t() | 1ULL;
  uint64_t KeyAdd = cryptoutils->get_uint64_t();
  unsigned RotAmt = Hard ? (1u + cryptoutils->get_range(31)) : 0u;
  assert(!Hard || (RotAmt > 0 && RotAmt < 32));
  uint32_t PredBits = Hard ? (3u + cryptoutils->get_range(4)) : 0u;
  uint32_t PredMask = Hard ? ((1u << PredBits) - 1u) : 0u;
  uint32_t PredTarget =
      Hard ? (cryptoutils->get_uint32_t() & PredMask) : 0u;
  uint32_t PredMul = Hard ? (cryptoutils->get_uint32_t() | 1u) : 0u;
  uint32_t PredAdd = Hard ? cryptoutils->get_uint32_t() : 0u;
  assert(!Hard || PredMask != 0);
  uint32_t SlotMixConst = cryptoutils->get_uint32_t() | 1u;
  uint32_t JunkSeed = cryptoutils->get_uint32_t();
  unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();
  if (PtrBits == 0)
    vmFatal("vm: invalid pointer size");
  IntegerType *IntPtrTy = Type::getIntNTy(Ctx, PtrBits);
  Constant *DispBiasConst = nullptr;
  Constant *DispStrideConst = nullptr;
  Constant *DispXorConst = nullptr;
  Constant *DispPermKeyConst = nullptr;
  GlobalVariable *DispTableGV = nullptr;

  /* Build call helpers */
  SmallVector<Function *, 8> Helpers;
  Helpers.reserve(F.Calls.size());
  for (unsigned i = 0; i < F.Calls.size(); ++i)
    Helpers.push_back(emitCallHelper(M, F, F.Calls[i], i, Ctrs.RegLoad,
                                     Ctrs.RegStore, Ctrs.HostCall,
                                     Ctrs.HostCycles));

  SmallVector<const VMBlock *, 16> BlockMap;
  BlockMap.resize(F.Blocks.size(), nullptr);
  for (const VMBlock &Block : F.Blocks) {
    if (Block.Id >= BlockMap.size())
      vmFatal("vm: block id out of range in bb emit");
    if (BlockMap[Block.Id])
      vmFatal("vm: duplicate block id in bb emit");
    BlockMap[Block.Id] = &Block;
  }
  for (const VMBlock *Block : BlockMap) {
    if (!Block)
      vmFatal("vm: block map not contiguous in bb emit");
  }

  uint32_t EntryId = F.Blocks.front().Id;
  if (EntryId >= BlockMap.size())
    vmFatal("vm: entry block id out of range in bb emit");

  SmallVector<uint32_t, 16> DispatchOrder;
  DispatchOrder.reserve(BlockMap.size());
  DispatchOrder.push_back(EntryId);
  for (uint32_t Idx = 0; Idx < BlockMap.size(); ++Idx) {
    if (Idx == EntryId)
      continue;
    DispatchOrder.push_back(Idx);
  }
  shuffleDispatchOrder(DispatchOrder, 1, Handlers);

  SmallVector<uint32_t, 16> DispatchId(BlockMap.size(), 0);
  for (size_t I = 0; I < DispatchOrder.size(); ++I)
    DispatchId[DispatchOrder[I]] = static_cast<uint32_t>(I);

  unsigned BogusExtra = 0;
  if (Hard && Cfg.BogusCount > 0) {
    BogusExtra = Cfg.Debug
                     ? Cfg.BogusCount
                     : cryptoutils->get_range(Cfg.BogusCount + 1);
  }
  DispatchLayout Layout = buildDispatchLayout(
      static_cast<unsigned>(DispatchOrder.size()), BogusExtra, Handlers);
  unsigned DispatchCount = static_cast<unsigned>(Layout.SlotToId.size());
  unsigned DispatchBits = log2Exact(DispatchCount);
  uint32_t DispatchMask = DispatchCount - 1;
  uint32_t PcMul = 1;
  uint32_t PcInvMul = 1;
  if (Hard && DispatchBits > 0) {
    uint64_t Inv = 1;
    // Pick a reversible multiplier so PC->slot mapping is opaque but invertible.
    for (unsigned Attempt = 0; Attempt < 16; ++Attempt) {
      uint32_t Cand =
          static_cast<uint32_t>(cryptoutils->get_uint64_t()) & DispatchMask;
      Cand |= 1u;
      if (Cand == 1 && DispatchMask != 1)
        continue;
      if (!modInversePow2(Cand, DispatchBits, Inv))
        continue;
      uint64_t Check = (static_cast<uint64_t>(Cand) * Inv) & DispatchMask;
      if (Check != 1)
        continue;
      PcMul = Cand;
      PcInvMul = static_cast<uint32_t>(Inv) & DispatchMask;
      break;
    }
    uint64_t Check = (static_cast<uint64_t>(PcMul) * PcInvMul) & DispatchMask;
    if (Check != 1) {
      PcMul = 1;
      PcInvMul = 1;
    }
  }
  SmallVector<BasicBlock *, 16> CaseBlocks;
  CaseBlocks.resize(DispatchOrder.size(), nullptr);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Run);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Run);
  BasicBlock *Update = BasicBlock::Create(Ctx, "update", Run);
  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", Run);
  BasicBlock *BogusEntry = BasicBlock::Create(Ctx, "bogus.entry", Run);
  BasicBlock *Bogus = BasicBlock::Create(Ctx, "bogus", Run);
  // Bogus blocks are reachable from dispatch to blur the real handler set.
  BasicBlock *Trap = BasicBlock::Create(Ctx, "trap", Run);
  BasicBlock *Ret = BasicBlock::Create(Ctx, "ret", Run);

  IRBuilder<> EntryIR(Entry);
  Value *State = Run->arg_begin();
  Value *RegsPtr = EntryIR.CreateLoad(
      PointerType::getUnqual(Type::getInt64Ty(Ctx)),
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Regs));
  Value *PcPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::PC);
  Value *KeyPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Key);
  AllocaInst *NextPcVar = EntryIR.CreateAlloca(Type::getInt32Ty(Ctx));
  NextPcVar->setAlignment(Align(4));
  AllocaInst *SlotVar = EntryIR.CreateAlloca(Type::getInt32Ty(Ctx));
  SlotVar->setAlignment(Align(4));
  AllocaInst *RealSlotVar = EntryIR.CreateAlloca(Type::getInt32Ty(Ctx));
  RealSlotVar->setAlignment(Align(4));
  AllocaInst *OpaqueTmp = EntryIR.CreateAlloca(I64Ty);
  OpaqueTmp->setAlignment(Align(8));
  AllocaInst *VmStartVar = nullptr;
  if (Ctrs.VmCycles) {
    VmStartVar = EntryIR.CreateAlloca(I64Ty);
    VmStartVar->setAlignment(Align(8));
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Start = EntryIR.CreateCall(Rd);
    EntryIR.CreateStore(Start, VmStartVar);
  }
  if (RtDebug) {
    std::string EnterMsg = ("vm.rt.enter." + F.Name).str();
    emitRuntimeDebug(EntryIR, M, EnterMsg, true);
  }
  EntryIR.CreateBr(Loop);

  std::string TrapMsg = ("vm.rt.trap." + F.Name).str();
  std::string AdMsg = ("vm.rt.ad." + F.Name).str();

  EntryIR.SetInsertPoint(Trap);
  emitRuntimeDebug(EntryIR, M, TrapMsg, RtDebug);
  FunctionCallee TrapFn = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  EntryIR.CreateCall(TrapFn);
  EntryIR.CreateUnreachable();

  EntryIR.SetInsertPoint(Ret);
  if (Ctrs.VmCycles && VmStartVar) {
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *End = EntryIR.CreateCall(Rd);
    Value *Start = EntryIR.CreateLoad(I64Ty, VmStartVar);
    Value *Delta = EntryIR.CreateSub(End, Start);
    addCounter(EntryIR, Ctrs.VmCycles, Delta);
  }
  EntryIR.CreateRetVoid();

  EntryIR.SetInsertPoint(Loop);

  OpaqueJunkContext JunkCtx{M, KeyPtr, OpaqueTmp, JunkSeed, PredMul,
                            PredAdd, PredMask, PredTarget, Hard};

  for (uint32_t Disp = 0; Disp < DispatchOrder.size(); ++Disp) {
    uint32_t Idx = DispatchOrder[Disp];
    const VMBlock &VB = *BlockMap[Idx];
    BasicBlock *Case = BasicBlock::Create(Ctx, "bb" + std::to_string(Idx), Run);
    CaseBlocks[Disp] = Case;
    IRBuilder<> CaseIR(Case);
    bumpCounter(CaseIR, Ctrs.Dispatch);
    if (Trace) {
      std::string BBTraceMsg = "[VM-BogusIR] Block=" + std::to_string(Idx) + " " + F.Name.str() + "\n";
      emitVMTrace(CaseIR, M, BBTraceMsg, nullptr, nullptr, nullptr, true);
    }
    // Per-block variant seed to avoid repeating opaque predicates.
    emitOpaqueJunk(CaseIR, JunkCtx, static_cast<unsigned>(Idx * kJunkMulOp));
    bool Terminated = false;

    auto BranchToLoop = [&](uint32_t Target) {
      uint32_t Did = DispatchId[Target];
      uint32_t Dslot = Layout.IdToSlot[Did];
      Value *PcVal = pcFromSlot(CaseIR, ConstantInt::get(I32Ty, Dslot), Hard,
                                DispatchMask, DispatchBits, PcInvMul);
      Value *EncNext = encodeNextPc(CaseIR, PcVal, Hard, KeyPtr, RotAmt);
      CaseIR.CreateStore(EncNext, NextPcVar);
      CaseIR.CreateBr(Update);
      Terminated = true;
    };

    for (const VMInstr &I : VB.Instrs) {
      if (Terminated)
        break;
      bumpCounter(CaseIR, Ctrs.Instr);
      switch (I.Op) {
      case VMOpcode::Mov: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *SrcVal = nullptr;
        if (!I.Ops.empty()) {
          if (I.Ops[0].K == VMValue::Kind::Reg) {
            Value *SrcIdx =
                ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
            SrcVal = loadReg(CaseIR, RegsPtr, SrcIdx, Ctrs.RegLoad);
          } else if (I.Ops[0].K == VMValue::Kind::Const) {
            SrcVal = asI64(I.Ops[0].C, Type::getInt64Ty(Ctx));
          } else {
            SrcVal = ConstantInt::get(Type::getInt64Ty(Ctx), I.Ops[0].Imm);
          }
        }
        SrcVal = maskValue(CaseIR, SrcVal, I.Ty.Kind, PtrBits);
        storeReg(CaseIR, RegsPtr, DstIdx, SrcVal, Ctrs.RegStore);
        break;
      }
      case VMOpcode::BinOp: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *AIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *BIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[1].Reg);
        Value *AVal = loadReg(CaseIR, RegsPtr, AIdx, Ctrs.RegLoad);
        Value *BVal = loadReg(CaseIR, RegsPtr, BIdx, Ctrs.RegLoad);
        Value *Res = nullptr;
        if (I.Ty.Kind == VMTypeKind::F32 || I.Ty.Kind == VMTypeKind::F64) {
          Value *FA = unpackValue(CaseIR, AVal, I.Ty.Kind, PtrBits);
          Value *FB = unpackValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
          Value *FR = nullptr;
          switch (I.Bin) {
          case VMBinOp::Add:
          case VMBinOp::FAdd:
            FR = CaseIR.CreateFAdd(FA, FB);
            break;
          case VMBinOp::Sub:
          case VMBinOp::FSub:
            FR = CaseIR.CreateFSub(FA, FB);
            break;
          case VMBinOp::Mul:
          case VMBinOp::FMul:
            FR = CaseIR.CreateFMul(FA, FB);
            break;
          case VMBinOp::FDiv:
            FR = CaseIR.CreateFDiv(FA, FB);
            break;
          case VMBinOp::FRem:
            FR = CaseIR.CreateFRem(FA, FB);
            break;
          default:
            CaseIR.CreateBr(Trap);
            Terminated = true;
            continue;
          }
          Res = packValue(CaseIR, FR, I.Ty.Kind, PtrBits);
        } else {
          switch (I.Bin) {
          case VMBinOp::Add:
            Res = emitIntAdd(CaseIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Sub:
            Res = emitIntSub(CaseIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Mul:
            Res = CaseIR.CreateMul(AVal, BVal);
            break;
          case VMBinOp::UDiv: {
            Value *BMask = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
            Value *IsZero = CaseIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "udiv.ok", Run);
            CaseIR.CreateCondBr(IsZero, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Res = CaseIR.CreateUDiv(maskValue(CaseIR, AVal, I.Ty.Kind, PtrBits), BMask);
            break;
          }
          case VMBinOp::SDiv: {
            Value *BMask = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
            Value *IsZero = CaseIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "sdiv.ok", Run);
            CaseIR.CreateCondBr(IsZero, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits);
            Value *BS = signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Res = CaseIR.CreateSDiv(AS, BS);
            break;
          }
          case VMBinOp::URem: {
            Value *BMask = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
            Value *IsZero = CaseIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "urem.ok", Run);
            CaseIR.CreateCondBr(IsZero, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Res = CaseIR.CreateURem(maskValue(CaseIR, AVal, I.Ty.Kind, PtrBits), BMask);
            break;
          }
          case VMBinOp::SRem: {
            Value *BMask = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
            Value *IsZero = CaseIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "srem.ok", Run);
            CaseIR.CreateCondBr(IsZero, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits);
            Value *BS = signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Res = CaseIR.CreateSRem(AS, BS);
            break;
          }
          case VMBinOp::And:
            Res = emitIntAnd(CaseIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Or:
            Res = emitIntOr(CaseIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Xor:
            Res = emitIntXor(CaseIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Shl: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                CaseIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "shl.ok", Run);
            CaseIR.CreateCondBr(TooBig, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Value *AV = maskValue(CaseIR, AVal, I.Ty.Kind, PtrBits);
            Res = CaseIR.CreateShl(AV, Sh);
            break;
          }
          case VMBinOp::LShr: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                CaseIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "lshr.ok", Run);
            CaseIR.CreateCondBr(TooBig, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Value *AV = maskValue(CaseIR, AVal, I.Ty.Kind, PtrBits);
            Res = CaseIR.CreateLShr(AV, Sh);
            break;
          }
          case VMBinOp::AShr: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                CaseIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "ashr.ok", Run);
            CaseIR.CreateCondBr(TooBig, Trap, Ok);
            CaseIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits);
            Res = CaseIR.CreateAShr(AS, Sh);
            break;
          }
          default:
            CaseIR.CreateBr(Trap);
            Terminated = true;
            continue;
          }
          Res = maskValue(CaseIR, Res, I.Ty.Kind, PtrBits);
        }
        storeReg(CaseIR, RegsPtr, DstIdx, Res, Ctrs.RegStore);
        break;
      }
      case VMOpcode::FNeg: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *SrcIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *SrcVal = loadReg(CaseIR, RegsPtr, SrcIdx, Ctrs.RegLoad);
        Value *Src = unpackValue(CaseIR, SrcVal, I.Ty.Kind, PtrBits);
        Value *Neg = CaseIR.CreateFNeg(Src);
        Value *Packed = packValue(CaseIR, Neg, I.Ty.Kind, PtrBits);
        storeReg(CaseIR, RegsPtr, DstIdx, Packed, Ctrs.RegStore);
        break;
      }
      case VMOpcode::ICmp: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *AIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *BIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[1].Reg);
        Value *AVal = loadReg(CaseIR, RegsPtr, AIdx, Ctrs.RegLoad);
        Value *BVal = loadReg(CaseIR, RegsPtr, BIdx, Ctrs.RegLoad);
        Value *AMask = maskValue(CaseIR, AVal, I.Ty.Kind, PtrBits);
        Value *BMask = maskValue(CaseIR, BVal, I.Ty.Kind, PtrBits);
        Value *Res = nullptr;
        switch (I.Pred) {
        case VMCmpPred::EQ:
          Res = CaseIR.CreateICmpEQ(AMask, BMask);
          break;
        case VMCmpPred::NE:
          Res = CaseIR.CreateICmpNE(AMask, BMask);
          break;
        case VMCmpPred::ULT:
          Res = CaseIR.CreateICmpULT(AMask, BMask);
          break;
        case VMCmpPred::ULE:
          Res = CaseIR.CreateICmpULE(AMask, BMask);
          break;
        case VMCmpPred::UGT:
          Res = CaseIR.CreateICmpUGT(AMask, BMask);
          break;
        case VMCmpPred::UGE:
          Res = CaseIR.CreateICmpUGE(AMask, BMask);
          break;
        case VMCmpPred::SLT:
          Res = CaseIR.CreateICmpSLT(signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SLE:
          Res = CaseIR.CreateICmpSLE(signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SGT:
          Res = CaseIR.CreateICmpSGT(signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SGE:
          Res = CaseIR.CreateICmpSGE(signExtendToI64(CaseIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(CaseIR, BVal, I.Ty.Kind, PtrBits));
          break;
        default:
          CaseIR.CreateBr(Trap);
          Terminated = true;
          continue;
        }
        Value *Ext = CaseIR.CreateZExt(Res, Type::getInt64Ty(Ctx));
        storeReg(CaseIR, RegsPtr, DstIdx, Ext, Ctrs.RegStore);
        break;
      }
      case VMOpcode::FCmp: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *AIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *BIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[1].Reg);
        Value *AVal = unpackValue(CaseIR, loadReg(CaseIR, RegsPtr, AIdx, Ctrs.RegLoad),
                                  I.Ty.Kind, PtrBits);
        Value *BVal = unpackValue(CaseIR, loadReg(CaseIR, RegsPtr, BIdx, Ctrs.RegLoad),
                                  I.Ty.Kind, PtrBits);
        Value *Res = nullptr;
        switch (I.Pred) {
        case VMCmpPred::FEQ:
          Res = CaseIR.CreateFCmpOEQ(AVal, BVal);
          break;
        case VMCmpPred::FNE:
          Res = CaseIR.CreateFCmpONE(AVal, BVal);
          break;
        case VMCmpPred::FLT:
          Res = CaseIR.CreateFCmpOLT(AVal, BVal);
          break;
        case VMCmpPred::FLE:
          Res = CaseIR.CreateFCmpOLE(AVal, BVal);
          break;
        case VMCmpPred::FGT:
          Res = CaseIR.CreateFCmpOGT(AVal, BVal);
          break;
        case VMCmpPred::FGE:
          Res = CaseIR.CreateFCmpOGE(AVal, BVal);
          break;
        default:
          CaseIR.CreateBr(Trap);
          Terminated = true;
          continue;
        }
        Value *Ext = CaseIR.CreateZExt(Res, Type::getInt64Ty(Ctx));
        storeReg(CaseIR, RegsPtr, DstIdx, Ext, Ctrs.RegStore);
        break;
      }
      case VMOpcode::Cast: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *SrcIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *SrcVal = loadReg(CaseIR, RegsPtr, SrcIdx, Ctrs.RegLoad);
        VMTypeKind SrcK = I.SrcTy.Kind;
        VMTypeKind DstK = I.Ty.Kind;
        Value *Src = unpackValue(CaseIR, SrcVal, SrcK, PtrBits);
        Value *Dst = nullptr;
        Type *DstTy = getLLVMType(DstK, Ctx, PtrBits);
        switch (I.Cast) {
        case VMCastKind::ZExt:
          Dst = CaseIR.CreateZExt(Src, DstTy);
          break;
        case VMCastKind::SExt:
          Dst = CaseIR.CreateSExt(Src, DstTy);
          break;
        case VMCastKind::Trunc:
          Dst = CaseIR.CreateTrunc(Src, DstTy);
          break;
        case VMCastKind::Bitcast:
          Dst = CaseIR.CreateBitCast(Src, DstTy);
          break;
        case VMCastKind::PtrToInt:
        case VMCastKind::IntToPtr:
          Dst = CaseIR.CreateZExtOrTrunc(Src, DstTy);
          break;
        case VMCastKind::FPToUI:
          Dst = CaseIR.CreateFPToUI(Src, DstTy);
          break;
        case VMCastKind::FPToSI:
          Dst = CaseIR.CreateFPToSI(Src, DstTy);
          break;
        case VMCastKind::UIToFP:
          Dst = CaseIR.CreateUIToFP(Src, DstTy);
          break;
        case VMCastKind::SIToFP:
          Dst = CaseIR.CreateSIToFP(Src, DstTy);
          break;
        case VMCastKind::FPTrunc:
          Dst = CaseIR.CreateFPTrunc(Src, DstTy);
          break;
        case VMCastKind::FPExt:
          Dst = CaseIR.CreateFPExt(Src, DstTy);
          break;
        }
        Value *Packed = packValue(CaseIR, Dst, DstK, PtrBits);
        storeReg(CaseIR, RegsPtr, DstIdx, Packed, Ctrs.RegStore);
        break;
      }
      case VMOpcode::Load: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *AddrIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *AddrVal = loadReg(CaseIR, RegsPtr, AddrIdx, Ctrs.RegLoad);
        Type *Ty = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        Value *Ptr = CaseIR.CreateIntToPtr(AddrVal, PointerType::getUnqual(Ty));
        LoadInst *Ld = CaseIR.CreateLoad(Ty, Ptr);
        Ld->setAlignment(Align(1));
        Value *Packed = packValue(CaseIR, Ld, I.Ty.Kind, PtrBits);
        storeReg(CaseIR, RegsPtr, DstIdx, Packed, Ctrs.RegStore);
        break;
      }
      case VMOpcode::Store: {
        Value *ValIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *AddrIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[1].Reg);
        Value *AddrVal = loadReg(CaseIR, RegsPtr, AddrIdx, Ctrs.RegLoad);
        Value *Val = loadReg(CaseIR, RegsPtr, ValIdx, Ctrs.RegLoad);
        Type *Ty = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        Value *Ptr = CaseIR.CreateIntToPtr(AddrVal, PointerType::getUnqual(Ty));
        Value *Unpacked = unpackValue(CaseIR, Val, I.Ty.Kind, PtrBits);
        StoreInst *St = CaseIR.CreateStore(Unpacked, Ptr);
        St->setAlignment(Align(1));
        break;
      }
      case VMOpcode::MemFence: {
        emitFence(CaseIR, I.Fence);
        break;
      }
      case VMOpcode::CondBr: {
        Value *CondIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
        Value *CondMasked =
            maskValue(CaseIR, CondVal, VMTypeKind::I1, PtrBits);
        Value *Cond = CaseIR.CreateICmpNE(
            CondMasked, ConstantInt::get(Type::getInt64Ty(Ctx), 0));
        if (I.TargetTrue >= BlockMap.size() ||
            I.TargetFalse >= BlockMap.size()) {
          CaseIR.CreateBr(Trap);
          Terminated = true;
          break;
        }
        uint32_t Tpc = DispatchId[I.TargetTrue];
        uint32_t Fpc = DispatchId[I.TargetFalse];
        uint32_t Tslot = Layout.IdToSlot[Tpc];
        uint32_t Fslot = Layout.IdToSlot[Fpc];
        Value *TPc =
            pcFromSlot(CaseIR, ConstantInt::get(Type::getInt32Ty(Ctx), Tslot),
                       Hard, DispatchMask, DispatchBits, PcInvMul);
        Value *FPc =
            pcFromSlot(CaseIR, ConstantInt::get(Type::getInt32Ty(Ctx), Fslot),
                       Hard, DispatchMask, DispatchBits, PcInvMul);
        Value *Next = CaseIR.CreateSelect(Cond, TPc, FPc);
        Value *EncNext = encodeNextPc(CaseIR, Next, Hard, KeyPtr, RotAmt);
        CaseIR.CreateStore(EncNext, NextPcVar);
        CaseIR.CreateBr(Update);
        Terminated = true;
        break;
      }
      case VMOpcode::Br: {
        if (I.TargetTrue >= BlockMap.size()) {
          CaseIR.CreateBr(Trap);
          Terminated = true;
          break;
        }
        BranchToLoop(I.TargetTrue);
        break;
      }
      case VMOpcode::Switch: {
        Value *CondIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
        Type *CondTy = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        auto *CondITy = cast<IntegerType>(CondTy);
        Value *Masked = maskValue(CaseIR, CondVal, I.Ty.Kind, PtrBits);
        Value *Cond = CaseIR.CreateTruncOrBitCast(Masked, CondTy);
        if (I.SwitchDefault >= BlockMap.size()) {
          CaseIR.CreateBr(Trap);
          Terminated = true;
          break;
        }
        BasicBlock *DefaultBB = BasicBlock::Create(Ctx, "switch.default", Run);
        SwitchInst *Sw = CaseIR.CreateSwitch(
            Cond, DefaultBB, static_cast<unsigned>(I.SwitchValues.size()));
        auto storeNextSwitch = [&](IRBuilder<> &SB, uint32_t Disp) {
          Value *PcVal =
              pcFromSlot(SB, ConstantInt::get(Type::getInt32Ty(Ctx), Disp),
                         Hard, DispatchMask, DispatchBits, PcInvMul);
          Value *EncNext = encodeNextPc(SB, PcVal, Hard, KeyPtr, RotAmt);
          SB.CreateStore(EncNext, NextPcVar);
          SB.CreateBr(Update);
        };
        for (size_t i = 0; i < I.SwitchValues.size(); ++i) {
          uint64_t Mask = maskForType(I.Ty.Kind, PtrBits);
          uint64_t CV = I.SwitchValues[i] & Mask;
          BasicBlock *CaseBB = BasicBlock::Create(Ctx, "switch.case", Run);
          Sw->addCase(ConstantInt::get(CondITy, CV), CaseBB);
          IRBuilder<> CaseB(CaseBB);
          if (I.SwitchTargets[i] >= BlockMap.size()) {
            CaseB.CreateBr(Trap);
            continue;
          }
          uint32_t Tdisp = Layout.IdToSlot[DispatchId[I.SwitchTargets[i]]];
          storeNextSwitch(CaseB, Tdisp);
        }
        IRBuilder<> DefB(DefaultBB);
        uint32_t Ddisp = Layout.IdToSlot[DispatchId[I.SwitchDefault]];
        storeNextSwitch(DefB, Ddisp);
        Terminated = true;
        break;
      }
      case VMOpcode::Select: {
        Value *DstIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Dst);
        Value *CondIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[0].Reg);
        Value *TrueIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[1].Reg);
        Value *FalseIdx = ConstantInt::get(Type::getInt32Ty(Ctx), I.Ops[2].Reg);
        Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
        Value *CondMasked =
            maskValue(CaseIR, CondVal, VMTypeKind::I1, PtrBits);
        Value *Cond = CaseIR.CreateICmpNE(
            CondMasked, ConstantInt::get(Type::getInt64Ty(Ctx), 0));
        Value *TV = loadReg(CaseIR, RegsPtr, TrueIdx, Ctrs.RegLoad);
        Value *FV = loadReg(CaseIR, RegsPtr, FalseIdx, Ctrs.RegLoad);
        Value *Sel = CaseIR.CreateSelect(Cond, TV, FV);
        Sel = maskValue(CaseIR, Sel, I.Ty.Kind, PtrBits);
        storeReg(CaseIR, RegsPtr, DstIdx, Sel, Ctrs.RegStore);
        break;
      }
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect: {
        if (I.CallIndex < Helpers.size()) {
          checkCallSignature(Helpers[I.CallIndex]->getFunctionType(), {State},
                             "vm:callhost:bb");
          CaseIR.CreateCall(Helpers[I.CallIndex], {State});
        } else {
          CaseIR.CreateBr(Trap);
          Terminated = true;
        }
        break;
      }
      case VMOpcode::Ret:
        CaseIR.CreateBr(Ret);
        Terminated = true;
        break;
      case VMOpcode::Trap:
        CaseIR.CreateBr(Trap);
        Terminated = true;
        break;
      }
    }
    if (!Terminated)
      CaseIR.CreateBr(Trap);
  }

  SmallVector<BasicBlock *, 16> SlotTargets;
  SlotTargets.resize(DispatchCount, Bogus);
  for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
    uint32_t Id = Layout.SlotToId[Slot];
    if (Id != UINT32_MAX && Id < CaseBlocks.size() && CaseBlocks[Id])
      SlotTargets[Slot] = CaseBlocks[Id];
  }

  if (Hard) {
    SmallVector<BasicBlock *, 16> RealTargets(SlotTargets.begin(),
                                              SlotTargets.end());
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      BasicBlock *Dest = RealTargets[Slot];
      BasicBlock *Tramp =
          BasicBlock::Create(Ctx, "slot.tramp" + std::to_string(Slot), Run);
      IRBuilder<> TrampIR(Tramp);
      // Seed the trampoline with a per-slot mix to avoid shared predicates.
      emitOpaqueJunk(TrampIR, JunkCtx,
                     static_cast<unsigned>(Slot * kJunkMulOp + kJunkAddTramp));
      TrampIR.CreateBr(Dest);
      SlotTargets[Slot] = Tramp;
    }
  }

  if (DispatchMode == VMDispatch::Indirect) {
    uint64_t DispBias = 0;
    uint64_t DispStride = 0;
    uint64_t DispXor = 0;
    uint32_t DispPermKey = 0;
    bool UsePermute = Hard && DispatchBits > 0;
    if (Hard) {
      DispBias = cryptoutils->get_uint64_t();
      DispStride = cryptoutils->get_uint64_t() | 1ULL;
      DispXor = cryptoutils->get_uint64_t();
      DispPermKey = cryptoutils->get_uint32_t();
    }
    DispBiasConst = ConstantInt::get(IntPtrTy, DispBias);
    DispStrideConst = ConstantInt::get(IntPtrTy, DispStride);
    DispXorConst = ConstantInt::get(IntPtrTy, DispXor);
    DispPermKeyConst = ConstantInt::get(I32Ty, DispPermKey);
    SmallVector<Constant *, 16> DispEntries(DispatchCount, nullptr);
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      BasicBlock *Dest = SlotTargets[Slot];
      Constant *Addr =
          ConstantExpr::getPtrToInt(BlockAddress::get(Run, Dest), IntPtrTy);
      Constant *Enc = Addr;
      unsigned Idx =
          permuteSlotConst(static_cast<uint32_t>(Slot), DispPermKey,
                           DispatchMask, SlotMixConst, UsePermute);
    if (Hard && DispBiasConst && DispStrideConst) {
      Constant *IdxC = ConstantInt::get(IntPtrTy, Idx);
      Constant *Offset =
          ConstantExpr::getAdd(DispBiasConst,
                               ConstantExpr::getMul(IdxC, DispStrideConst));
      Enc = ConstantExpr::getAdd(Addr, Offset);
    }
      DispEntries[Idx] = Enc;
    }
    ArrayType *DispTy = ArrayType::get(IntPtrTy, DispatchCount);
    Constant *DispInit = ConstantArray::get(DispTy, DispEntries);
    std::string DispName = ("vm_disp_table_" + F.Name).str();
    DispTableGV =
        new GlobalVariable(M, DispTy, true, GlobalValue::PrivateLinkage,
                           DispInit, DispName);
    DispTableGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    obfuscateSymbolName(*DispTableGV, M,
                        ("vm.disp.table." + F.Name).str(), DispName);
  }

  EntryIR.SetInsertPoint(Update);
  Value *EncNext = EntryIR.CreateLoad(I32Ty, NextPcVar);
  Value *NextPcVal = EncNext;
  if (Hard) {
    Value *KeyVal = EntryIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = EntryIR.CreateTrunc(KeyVal, I32Ty);
    Value *Rot = rotl32(EntryIR, Key32, RotAmt);
    NextPcVal = EntryIR.CreateXor(EntryIR.CreateSub(EncNext, Key32), Rot);
    Value *KeyMulC = ConstantInt::get(I64Ty, KeyMul);
    Value *KeyAddC = ConstantInt::get(I64Ty, KeyAdd);
    Value *NextPc64 = EntryIR.CreateZExt(NextPcVal, I64Ty);
    Value *NewKey = EntryIR.CreateMul(KeyVal, KeyMulC);
    NewKey = EntryIR.CreateAdd(NewKey, KeyAddC);
    NewKey = EntryIR.CreateAdd(NewKey, NextPc64);
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = EntryIR.CreateCall(Rd);
    NewKey = EntryIR.CreateXor(NewKey, Cycle);
    EntryIR.CreateStore(NewKey, KeyPtr);
    Value *NewKey32 = EntryIR.CreateTrunc(NewKey, I32Ty);
    Value *EncPc = EntryIR.CreateXor(NextPcVal, NewKey32);
    EntryIR.CreateStore(EncPc, PcPtr);
  } else {
    EntryIR.CreateStore(NextPcVal, PcPtr);
  }
  EntryIR.CreateBr(Loop);

  SmallVector<uint32_t, 16> BogusSlots;
  BogusSlots.reserve(DispatchCount);
  for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
    if (Layout.SlotToId[Slot] == UINT32_MAX)
      BogusSlots.push_back(Slot);
  }
  GlobalVariable *BogusGV = nullptr;
  if (!BogusSlots.empty()) {
    SmallVector<Constant *, 16> BogusConsts;
    BogusConsts.reserve(BogusSlots.size());
    for (uint32_t Slot : BogusSlots)
      BogusConsts.push_back(ConstantInt::get(I32Ty, Slot));
    ArrayType *BogusTy = ArrayType::get(I32Ty, BogusConsts.size());
    Constant *BogusInit = ConstantArray::get(BogusTy, BogusConsts);
    std::string BogusName = ("vm_bogus_slots_" + F.Name).str();
    BogusGV = new GlobalVariable(M, BogusTy, true,
                                 GlobalValue::PrivateLinkage, BogusInit,
                                 BogusName);
    std::string BogusTag = ("vm.bogus.slots." + F.Name).str();
    obfuscateSymbolName(*BogusGV, M, BogusTag, BogusName);
    BogusGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  }

  IRBuilder<> BogusIR(Bogus);
  if (Hard) {
    Value *KeyVal = BogusIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *Key32 = BogusIR.CreateTrunc(KeyVal, I32Ty);
    (void)BogusIR.CreateXor(Key32, BogusIR.CreateLShr(Key32, ConstantInt::get(I32Ty, 5)));
  }
  Value *RealSlot = BogusIR.CreateLoad(I32Ty, RealSlotVar);
  BogusIR.CreateStore(RealSlot, SlotVar);
  BogusIR.CreateBr(Dispatch);

  IRBuilder<> LoopIR(Loop);

  Value *EncPc = LoopIR.CreateLoad(Type::getInt32Ty(Ctx), PcPtr);
  Value *DecPc = EncPc;
  Value *KeyValLoop = nullptr;
  if (Hard) {
    KeyValLoop = LoopIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *Key32 = LoopIR.CreateTrunc(KeyValLoop, Type::getInt32Ty(Ctx));
    DecPc = LoopIR.CreateXor(EncPc, Key32);
  }
  Value *SlotVal =
      slotFromPc(LoopIR, DecPc, Hard, DispatchMask, DispatchBits, PcMul);
  LoopIR.CreateStore(SlotVal, SlotVar);
  LoopIR.CreateStore(SlotVal, RealSlotVar);
  if (Hard && BogusGV) {
    Value *Key32 = LoopIR.CreateTrunc(KeyValLoop, I32Ty);
    Value *Mix = rotl32(LoopIR, Key32, RotAmt);
    Mix = LoopIR.CreateXor(Mix, Key32);
    Mix = LoopIR.CreateXor(Mix, DecPc);
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = LoopIR.CreateCall(Rd);
    Value *Cycle32 = LoopIR.CreateTrunc(Cycle, I32Ty);
    Mix = LoopIR.CreateXor(Mix, Cycle32);
    Value *Fold =
        LoopIR.CreateXor(Mix, LoopIR.CreateLShr(Mix, ConstantInt::get(I32Ty, 11)));
    Fold = LoopIR.CreateMul(Fold, ConstantInt::get(I32Ty, PredMul));
    Fold = LoopIR.CreateAdd(Fold, ConstantInt::get(I32Ty, PredAdd));
    Value *Masked =
        LoopIR.CreateAnd(Fold, ConstantInt::get(I32Ty, PredMask));
    Value *Cond = LoopIR.CreateICmpEQ(
        Masked, ConstantInt::get(I32Ty, PredTarget));
    LoopIR.CreateCondBr(Cond, Dispatch, BogusEntry);
  } else {
    LoopIR.CreateBr(Dispatch);
  }

  IRBuilder<> BogusEntryIR(BogusEntry);
  if (BogusGV) {
    Value *KeyVal = BogusEntryIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *Key32 = BogusEntryIR.CreateTrunc(KeyVal, I32Ty);
    Value *Mix =
        BogusEntryIR.CreateXor(Key32, BogusEntryIR.CreateLShr(Key32, ConstantInt::get(I32Ty, 13)));
    Value *Idx = BogusEntryIR.CreateURem(
        Mix, ConstantInt::get(I32Ty, static_cast<uint32_t>(BogusSlots.size())));
    Value *Ptr = BogusEntryIR.CreateInBoundsGEP(BogusGV->getValueType(), BogusGV,
                                      {ConstantInt::get(I32Ty, 0), Idx});
    Value *BogusSlot = BogusEntryIR.CreateLoad(I32Ty, Ptr);
    BogusEntryIR.CreateStore(BogusSlot, SlotVar);
  }
  BogusEntryIR.CreateBr(Dispatch);

  IRBuilder<> DispatchIR(Dispatch);
  Value *SlotIdx = DispatchIR.CreateLoad(Type::getInt32Ty(Ctx), SlotVar);
  SlotIdx = DispatchIR.CreateAnd(SlotIdx,
                         ConstantInt::get(Type::getInt32Ty(Ctx), DispatchMask));
  if (DispatchMode == VMDispatch::Indirect && Hard && DispPermKeyConst) {
    SlotIdx =
        permuteSlot(DispatchIR, SlotIdx, DispPermKeyConst, Hard, DispatchMask,
                    SlotMixConst);
  }
  if (DispatchMode == VMDispatch::Indirect) {
    Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
    unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();
    IntegerType *IntPtrTy = Type::getIntNTy(Ctx, PtrBits);
    if (DispTableGV) {
      Value *Ptr = DispatchIR.CreateInBoundsGEP(
          DispTableGV->getValueType(), DispTableGV,
          {ConstantInt::get(I32Ty, 0), SlotIdx});
      Value *EncVal = DispatchIR.CreateLoad(IntPtrTy, Ptr);
      Value *DecVal = EncVal;
      if (Hard && DispBiasConst && DispStrideConst) {
        Value *SlotExt = DispatchIR.CreateZExt(SlotIdx, IntPtrTy);
        Value *Offset =
            DispatchIR.CreateAdd(DispBiasConst, DispatchIR.CreateMul(SlotExt, DispStrideConst));
        DecVal = DispatchIR.CreateSub(EncVal, Offset);
      }
      Value *Target = DispatchIR.CreateIntToPtr(DecVal, I8PtrTy);
      IndirectBrInst *IB = DispatchIR.CreateIndirectBr(Target, DispatchCount);
      for (unsigned Slot = 0; Slot < DispatchCount; ++Slot)
        IB->addDestination(SlotTargets[Slot]);
    }
  } else {
    SwitchInst *Sw = DispatchIR.CreateSwitch(SlotIdx, Bogus, DispatchCount);
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      Sw->addCase(ConstantInt::get(Type::getInt32Ty(Ctx), Slot),
                  SlotTargets[Slot]);
    }
  }

  if (HardRt) {
    AntiDebugConfig AD = buildAntiDebugConfig();
    uint64_t MixC1 = cryptoutils->get_uint64_t() | 1ULL;
    uint64_t MixC2 = cryptoutils->get_uint64_t() | 1ULL;
    uint64_t MixC3 = cryptoutils->get_uint64_t();
    uint32_t TripTag = cryptoutils->get_uint32_t() | 1u;
    BasicBlock *RtCheck = BasicBlock::Create(Ctx, "hard.rt", Run, Loop);
    BasicBlock *RtOk = BasicBlock::Create(Ctx, "hard.rt.ok", Run, Loop);
    if (auto *Term = Entry->getTerminator())
      Term->eraseFromParent();
    IRBuilder<> BogusEntryIR(Entry);
    BogusEntryIR.CreateBr(RtCheck);

    IRBuilder<> RtCheckIR(RtCheck);
    AntiDebugResult ADRes = emitInlineAntiDebug(RtCheckIR, M, AD);
    IRBuilder<> RtTailIR(ADRes.Tail);
    Value *Dbg = ADRes.Flag;
    BasicBlock *DbgTail = emitRuntimeDebugIf(RtTailIR, M, Dbg, AdMsg, RtDebug);
    IRBuilder<> RtMixIR(DbgTail ? DbgTail : RtTailIR.GetInsertBlock());
    if (GlobalVariable *TripGV = getOrCreateObfFailCode(M)) {
      Value *Cur = RtMixIR.CreateLoad(I32Ty, TripGV);
      Value *Tag = ConstantInt::get(I32Ty, TripTag);
      Value *Next = RtMixIR.CreateSelect(Dbg, Tag, Cur);
      RtMixIR.CreateStore(Next, TripGV);
    }
    Value *KeyVal = RtMixIR.CreateLoad(I64Ty, KeyPtr);
    Value *PcVal = RtMixIR.CreateLoad(I32Ty, PcPtr);
    Value *Mix = RtMixIR.CreateZExt(PcVal, I64Ty);
    Mix = RtMixIR.CreateXor(Mix, ConstantInt::get(I64Ty, MixC1));
    Mix = RtMixIR.CreateMul(Mix, ConstantInt::get(I64Ty, MixC2));
    Mix = RtMixIR.CreateAdd(Mix, ConstantInt::get(I64Ty, MixC3));
    Value *Dbg64 = RtMixIR.CreateZExt(Dbg, I64Ty);
    Value *Delta = RtMixIR.CreateMul(Dbg64, Mix);
    Value *NewKey = RtMixIR.CreateXor(KeyVal, Delta);
    RtMixIR.CreateStore(NewKey, KeyPtr);
    RtMixIR.CreateBr(RtOk);

    IRBuilder<> RtOkIR(RtOk);
    RtOkIR.CreateBr(Loop);
  }

  return Run;
}
static Function *emitVMInterpreterOpcodeBC(Module &M, const VMFunction &F,
                                           const VMBytecode &BC,
                                           const VMBytecodeGlobals &Globals,
                                           const VMBCLayout &Layout,
                                           const VMBCEncodingInfo &EncInfo,
                                           const VMConfig &Cfg,
                                           uint64_t BCKey) {
  (void)Globals;
  if (Cfg.Mode != VMMode::Opcode)
    return nullptr;
  LLVMContext &Ctx = M.getContext();
  StructType *StateTy = getOrCreateVMStateType(M);
  PointerType *StatePtrTy = PointerType::getUnqual(StateTy);
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {StatePtrTy}, false);
  std::string RunName = ("vm_run_" + F.Name).str();
  Function *Run =
      Function::Create(FT, GlobalValue::PrivateLinkage, RunName, &M);
  Run->addFnAttr("vm_runtime");
  obfuscateSymbolName(*Run, M, ("vm.run." + F.Name).str(), RunName);
  Run->addFnAttr(Attribute::NoInline);
  VMHandlers Handlers = Cfg.Handlers;
  bool Counters = Cfg.Counters;
  VMDispatch DispatchMode = Cfg.Dispatch;
  bool Hard = Cfg.Hard;
  bool HardRt = Cfg.HardRuntime;
  bool RtDebug = Cfg.RuntimeDebug && kVMRuntimeDebug;
  bool Debug = RtDebug;
  bool Trace = Cfg.Trace && kVMRuntimeDebug;
  bool BoundsCheck = Cfg.BoundsCheck;
  uint32_t RegCount = F.RegCount;
  bool AllowArithExpand =
      (Handlers == VMHandlers::Random) && (Cfg.Encode != VMEncode::MBA);
  VMCounters Ctrs = maybeCreateCounters(M, F.Name, Counters);
  uint64_t KeyMul = cryptoutils->get_uint64_t() | 1ULL;
  uint64_t KeyAdd = cryptoutils->get_uint64_t();
  unsigned RotAmt = Hard ? (1u + cryptoutils->get_range(31)) : 0u;
  assert(!Hard || (RotAmt > 0 && RotAmt < 32));
  uint32_t PredBits = Hard ? (3u + cryptoutils->get_range(4)) : 0u;
  uint32_t PredMask = Hard ? ((1u << PredBits) - 1u) : 0u;
  uint32_t PredTarget =
      Hard ? (cryptoutils->get_uint32_t() & PredMask) : 0u;
  uint32_t PredMul = Hard ? (cryptoutils->get_uint32_t() | 1u) : 0u;
  uint32_t PredAdd = Hard ? cryptoutils->get_uint32_t() : 0u;
  assert(!Hard || PredMask != 0); /* Build call helpers */
  uint32_t SlotMixConst = cryptoutils->get_uint32_t() | 1u;
  uint32_t JunkSeed = cryptoutils->get_uint32_t();
  SmallVector<Function *, 8> Helpers;
  Helpers.reserve(F.Calls.size());
  for (unsigned i = 0; i < F.Calls.size(); ++i)
    Helpers.push_back(emitCallHelper(M, F, F.Calls[i], i, Ctrs.RegLoad,
                                     Ctrs.RegStore, Ctrs.HostCall,
                                     Ctrs.HostCycles));
  IntegerType *I1Ty = Type::getInt1Ty(Ctx);
  IntegerType *I8Ty = Type::getInt8Ty(Ctx);
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);
  unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();
  if (PtrBits == 0)
    vmFatal("vm: invalid pointer size");
  IntegerType *IntPtrTy = Type::getIntNTy(Ctx, PtrBits);
  StructType *InstrTy = getOrCreateBCInstrType(Ctx, Layout);
  unsigned OpFieldIdx = getBCFieldIndex(Layout, VMBCField::Op);
  unsigned TyIdx = getBCFieldIndex(Layout, VMBCField::Type);
  unsigned AuxIdx = getBCFieldIndex(Layout, VMBCField::Aux);
  unsigned PadIdx = getBCFieldIndex(Layout, VMBCField::Pad);
  unsigned DstIdx = getBCFieldIndex(Layout, VMBCField::Dst);
  unsigned AIdx = getBCFieldIndex(Layout, VMBCField::A);
  unsigned BIdx = getBCFieldIndex(Layout, VMBCField::B);
  unsigned ImmIdx = getBCFieldIndex(Layout, VMBCField::Imm);
  unsigned TTrueIdx = getBCFieldIndex(Layout, VMBCField::TTrue);
  unsigned TFalseIdx = getBCFieldIndex(Layout, VMBCField::TFalse);
  unsigned CallIdx = getBCFieldIndex(Layout, VMBCField::CallIndex);
  GlobalVariable *DbgPcGV = nullptr;
  GlobalVariable *DbgOpGV = nullptr;
  GlobalVariable *DbgTyGV = nullptr;
  GlobalVariable *DbgAuxGV = nullptr;
  GlobalVariable *DbgADGV = nullptr;
  if (Debug) {
    DbgPcGV = getOrCreateVMDebugGV(M, "__vm_dbg_pc", I32Ty);
    DbgOpGV = getOrCreateVMDebugGV(M, "__vm_dbg_op", I32Ty);
    DbgTyGV = getOrCreateVMDebugGV(M, "__vm_dbg_ty", I32Ty);
    DbgAuxGV = getOrCreateVMDebugGV(M, "__vm_dbg_aux", I32Ty);
    DbgADGV = getOrCreateVMDebugGV(M, "__vm_dbg_ad", I32Ty);
  }
  PointerType *InstrPtrTy = PointerType::getUnqual(InstrTy);
  uint32_t InstrCount = static_cast<uint32_t>(BC.Instrs.size());
  uint32_t PcSlotCount = nextPow2(InstrCount == 0 ? 1 : InstrCount);
  unsigned PcBits = log2Exact(PcSlotCount);
  uint32_t PcMask = PcSlotCount - 1;
  uint32_t PcMul = 1;
  uint32_t PcInvMul = 1;
  if (Hard && PcBits > 0) {
    uint64_t Inv = 1;
    for (unsigned Attempt = 0; Attempt < 16; ++Attempt) {
      uint32_t Cand =
          static_cast<uint32_t>(cryptoutils->get_uint64_t()) & PcMask;
      Cand |= 1u;
      if (Cand == 1 && PcMask != 1)
        continue;
      if (!modInversePow2(Cand, PcBits, Inv))
        continue;
      uint64_t Check = (static_cast<uint64_t>(Cand) * Inv) & PcMask;
      if (Check != 1)
        continue;
      PcMul = Cand;
      PcInvMul = static_cast<uint32_t>(Inv) & PcMask;
      break;
    }
    uint64_t Check = (static_cast<uint64_t>(PcMul) * PcInvMul) & PcMask;
    if (Check != 1) {
      PcMul = 1;
      PcInvMul = 1;
    }
  }
  uint32_t BlockCount = static_cast<uint32_t>(BC.BlockOffsets.size());
  uint32_t SwitchValsCount = static_cast<uint32_t>(BC.SwitchValues.size());
  uint32_t SwitchTgtsCount = static_cast<uint32_t>(BC.SwitchTargets.size());
  unsigned OpCount = static_cast<unsigned>(VMOpcode::Trap) + 1;
  unsigned HandlerVariants = 1u;
  if (Handlers == VMHandlers::Random && Hard) {
    unsigned Pow = 1 + cryptoutils->get_range(2);
    HandlerVariants = 1u << Pow;
  }
  unsigned OpSlots = OpCount * HandlerVariants;
  unsigned BogusExtra = 0;
  if (Hard && Cfg.BogusCount > 0) {
    BogusExtra = Cfg.Debug
                     ? Cfg.BogusCount
                     : cryptoutils->get_range(Cfg.BogusCount + 1);
  }
  DispatchLayout DispLayout = buildDispatchLayout(OpSlots, BogusExtra, Handlers);
  unsigned DispatchCount = static_cast<unsigned>(DispLayout.SlotToId.size());
  uint32_t DispatchMask = DispatchCount - 1;
  GlobalVariable *OpSlotGV = nullptr;
  GlobalVariable *OpSlotEncGV = nullptr;
  Constant *OpSlotKeyConst = nullptr;
  Constant *OpSlotMixConst = nullptr;
    GlobalVariable *OpDecodeGV =
        dyn_cast_or_null<GlobalVariable>(Globals.OpDecode);
    unsigned DispatchPoints =
        (DispatchMode == VMDispatch::Indirect && Hard) ? 2u : 1u;
    if (DispatchPoints > 1 && DispatchCount < 2)
      DispatchPoints = 1;
    SmallVector<DispTableInfo, 2> DispTables;
    DispTables.resize(DispatchPoints);
  {
    SmallVector<Constant *, 16> Slots;
    Slots.reserve(OpSlots);
    for (unsigned Op = 0; Op < OpSlots; ++Op)
      Slots.push_back(ConstantInt::get(I32Ty, DispLayout.IdToSlot[Op]));
    ArrayType *SlotTy = ArrayType::get(I32Ty, Slots.size());
    Constant *Init = ConstantArray::get(SlotTy, Slots);
    std::string SlotName = ("vm_op_slots_" + F.Name).str();
    OpSlotGV = new GlobalVariable(M, SlotTy, true,
                                  GlobalValue::PrivateLinkage, Init,
                                  SlotName);
    std::string SlotTag = ("vm.op.slots." + F.Name).str();
    obfuscateSymbolName(*OpSlotGV, M, SlotTag, SlotName);
    OpSlotGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    if (Hard) {
      uint32_t OpSlotKey = cryptoutils->get_uint32_t();
      uint32_t OpSlotMix = cryptoutils->get_uint32_t() | 1u;
      OpSlotKeyConst = ConstantInt::get(I32Ty, OpSlotKey);
      OpSlotMixConst = ConstantInt::get(I32Ty, OpSlotMix);
      SmallVector<Constant *, 16> EncSlots;
      EncSlots.reserve(OpSlots);
      for (unsigned Op = 0; Op < OpSlots; ++Op) {
        uint32_t Slot = DispLayout.IdToSlot[Op];
        uint32_t Key = static_cast<uint32_t>(OpSlotKey +
                                             (OpSlotMix * static_cast<uint32_t>(Op)));
        uint32_t Enc = Slot ^ Key;
        EncSlots.push_back(ConstantInt::get(I32Ty, Enc));
      }
      Constant *EncInit = ConstantArray::get(SlotTy, EncSlots);
      std::string EncName = ("vm_op_slots_enc_" + F.Name).str();
      OpSlotEncGV = new GlobalVariable(
          M, SlotTy, true, GlobalValue::PrivateLinkage, EncInit, EncName);
      std::string EncTag = ("vm.op.slots.enc." + F.Name).str();
      obfuscateSymbolName(*OpSlotEncGV, M, EncTag, EncName);
      OpSlotEncGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    }
  }
  SmallVector<uint32_t, 16> BogusSlots;
  BogusSlots.reserve(DispatchCount);
  for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
    if (DispLayout.SlotToId[Slot] == UINT32_MAX)
      BogusSlots.push_back(Slot);
  }
  GlobalVariable *BogusGV = nullptr;
  if (!BogusSlots.empty()) {
    SmallVector<Constant *, 16> BogusConsts;
    BogusConsts.reserve(BogusSlots.size());
    for (uint32_t Slot : BogusSlots)
      BogusConsts.push_back(ConstantInt::get(I32Ty, Slot));
    ArrayType *BogusTy = ArrayType::get(I32Ty, BogusConsts.size());
    Constant *BogusInit = ConstantArray::get(BogusTy, BogusConsts);
    std::string BogusName = ("vm_bogus_slots_" + F.Name).str();
    BogusGV =
        new GlobalVariable(M, BogusTy, true, GlobalValue::PrivateLinkage,
                           BogusInit, BogusName);
    std::string BogusTag = ("vm.bogus.slots." + F.Name).str();
    obfuscateSymbolName(*BogusGV, M, BogusTag, BogusName);
    BogusGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  }
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Run);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Run);
  BasicBlock *Decode = BasicBlock::Create(Ctx, "decode", Run);
  BasicBlock *TraceCheck = nullptr;
  BasicBlock *TraceDump = nullptr;
  if (Cfg.TraceLimit > 0) {
    TraceCheck = BasicBlock::Create(Ctx, "trace.check", Run);
    TraceDump = BasicBlock::Create(Ctx, "trace.dump", Run);
  }
  BasicBlock *TypeDecode = BasicBlock::Create(Ctx, "typedecode", Run);
  BasicBlock *DispatchPrep = BasicBlock::Create(Ctx, "dispatch.prep", Run);
  BasicBlock *Update = BasicBlock::Create(Ctx, "update", Run);
  BasicBlock *DispatchSel = BasicBlock::Create(Ctx, "dispatch.sel", Run);
  BasicBlock *Dispatch0 = BasicBlock::Create(Ctx, "dispatch.0", Run);
  BasicBlock *Dispatch1 =
      (DispatchPoints > 1 && DispatchMode == VMDispatch::Indirect)
          ? BasicBlock::Create(Ctx, "dispatch.1", Run)
          : nullptr;
  BasicBlock *BogusEntry = BasicBlock::Create(Ctx, "bogus.entry", Run);
  BasicBlock *Bogus = BasicBlock::Create(Ctx, "bogus", Run);
  BasicBlock *Trap = BasicBlock::Create(Ctx, "trap", Run);
  BasicBlock *Ret = BasicBlock::Create(Ctx, "ret", Run);
  std::string TrapMsg = ("vm.rt.trap." + F.Name).str();
  std::string AdMsg = ("vm.rt.ad." + F.Name).str();
  SmallVector<BasicBlock *, 16> CaseBlocks;
  CaseBlocks.resize(OpSlots, nullptr);
  for (unsigned Op = 0; Op < OpSlots; ++Op)
    CaseBlocks[Op] = BasicBlock::Create(Ctx, "op" + std::to_string(Op), Run);
  SmallVector<BasicBlock *, 16> SlotTargets;
  SlotTargets.resize(DispatchCount, Bogus);
  for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
    uint32_t Id = DispLayout.SlotToId[Slot];
    if (Id != UINT32_MAX && Id < CaseBlocks.size() && CaseBlocks[Id])
      SlotTargets[Slot] = CaseBlocks[Id];
  }
  IRBuilder<> EntryIR(Entry);
  Value *State = Run->arg_begin();
  Value *RegsPtr = EntryIR.CreateLoad(
      PointerType::getUnqual(I64Ty),
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Regs));
  Value *PcPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::PC);
  Value *KeyPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Key);
  Value *BCField =
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Bytecode);
  Value *OffField =
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Offsets);
  Value *SVField =
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::SwitchValues);
  Value *STField =
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::SwitchTargets);
  Value *BCPtr = EntryIR.CreateLoad(I8PtrTy, BCField);
  Value *InstrPtr = EntryIR.CreateBitCast(BCPtr, InstrPtrTy);
  Value *OffsetsPtr = EntryIR.CreateLoad(PointerType::getUnqual(I32Ty), OffField);
  Value *SwitchValsPtr = EntryIR.CreateLoad(PointerType::getUnqual(I64Ty), SVField);
  Value *SwitchTgtsPtr = EntryIR.CreateLoad(PointerType::getUnqual(I32Ty), STField);
  AllocaInst *OpVar = EntryIR.CreateAlloca(I8Ty);
  AllocaInst *TyVar = EntryIR.CreateAlloca(I8Ty);
  AllocaInst *AuxVar = EntryIR.CreateAlloca(I8Ty);
  AllocaInst *PadVar = EntryIR.CreateAlloca(I8Ty);
  AllocaInst *DstVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *AVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *BVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *ImmVar = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *TTrueVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *TFalseVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *CallVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *CurPcVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *NextPcVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *SlotVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *RealSlotVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *BitsVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *MaskVar = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *SignVar = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *IsFloatVar = EntryIR.CreateAlloca(I1Ty);
  AllocaInst *IsDoubleVar = EntryIR.CreateAlloca(I1Ty);
  AllocaInst *SrcBitsVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *SrcMaskVar = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *SrcSignVar = EntryIR.CreateAlloca(I64Ty);
  AllocaInst *SrcIsFloatVar = EntryIR.CreateAlloca(I1Ty);
  AllocaInst *SrcIsDoubleVar = EntryIR.CreateAlloca(I1Ty);
  AllocaInst *MemTmp = EntryIR.CreateAlloca(I64Ty);
  MemTmp->setAlignment(Align(8));
  AllocaInst *OpaqueTmp = EntryIR.CreateAlloca(I64Ty);
  OpaqueTmp->setAlignment(Align(8));
  // Switch handler temporaries - hoisted to entry to avoid stack leak in loops
  AllocaInst *SwTgtVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *SwIdxVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *SwLowVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *SwHighVar = EntryIR.CreateAlloca(I32Ty);
  AllocaInst *VmStartVar = nullptr;
  ArrayType *TraceBufTy = nullptr;
  AllocaInst *TraceBufVar = nullptr;
  AllocaInst *TraceIdxVar = nullptr;
  if (Ctrs.VmCycles) {
    VmStartVar = EntryIR.CreateAlloca(I64Ty);
    VmStartVar->setAlignment(Align(8));
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Start = EntryIR.CreateCall(Rd);
    EntryIR.CreateStore(Start, VmStartVar);
  }
  if (Cfg.TraceLimit > 0) {
    TraceBufTy = ArrayType::get(I32Ty, kVmTraceBufSize);
    TraceBufVar = EntryIR.CreateAlloca(TraceBufTy);
    TraceIdxVar = EntryIR.CreateAlloca(I32Ty);
    EntryIR.CreateStore(ConstantInt::get(I32Ty, 0), TraceIdxVar);
  }
  if (RtDebug) {
    std::string EnterMsg = ("vm.rt.enter." + F.Name).str();
    emitRuntimeDebug(EntryIR, M, EnterMsg, true);
  }
  EntryIR.CreateBr(Loop);

  EntryIR.SetInsertPoint(Trap);
  emitRuntimeDebug(EntryIR, M, TrapMsg, RtDebug);
  FunctionCallee TrapFn = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  EntryIR.CreateCall(TrapFn);
  EntryIR.CreateUnreachable();

  EntryIR.SetInsertPoint(Ret);
  if (Ctrs.VmCycles && VmStartVar) {
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *End = EntryIR.CreateCall(Rd);
    Value *Start = EntryIR.CreateLoad(I64Ty, VmStartVar);
    Value *Delta = EntryIR.CreateSub(End, Start);
    addCounter(EntryIR, Ctrs.VmCycles, Delta);
  }
  EntryIR.CreateRetVoid();
  OpaqueJunkContext JunkCtx{M, KeyPtr, OpaqueTmp, JunkSeed, PredMul,
                            PredAdd, PredMask, PredTarget, Hard};

  if (Hard) {
    SmallVector<BasicBlock *, 16> RealTargets(SlotTargets.begin(),
                                              SlotTargets.end());
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      BasicBlock *Dest = RealTargets[Slot];
      BasicBlock *Tramp =
          BasicBlock::Create(Ctx, "slot.tramp" + std::to_string(Slot), Run);
      IRBuilder<> TrampIR(Tramp);
      // Seed the trampoline with a per-slot mix to avoid shared predicates.
      emitOpaqueJunk(TrampIR, JunkCtx,
                     static_cast<unsigned>(Slot * kJunkMulOp + kJunkAddTramp));
      TrampIR.CreateBr(Dest);
      SlotTargets[Slot] = Tramp;
    }
  }

  if (DispatchMode == VMDispatch::Indirect) {
    for (unsigned Tbl = 0; Tbl < DispatchPoints; ++Tbl) {
      uint64_t DispBias = 0;
      uint64_t DispStride = 0;
      uint64_t DispXor = 0;
      uint32_t DispPermKey = 0;
      unsigned Scheme = 0;
      bool UsePermute = Hard && DispatchMask != 0;
      if (Hard) {
        DispBias = cryptoutils->get_uint64_t();
        DispStride = cryptoutils->get_uint64_t() | 1ULL;
        DispPermKey = cryptoutils->get_uint32_t();
        Scheme = cryptoutils->get_range(2); // add/sub only (no XOR on const addrs)
      }
      DispTables[Tbl].Bias = ConstantInt::get(IntPtrTy, DispBias);
      DispTables[Tbl].Stride = ConstantInt::get(IntPtrTy, DispStride);
      DispTables[Tbl].Xor = ConstantInt::get(IntPtrTy, DispXor);
      DispTables[Tbl].PermKey = ConstantInt::get(I32Ty, DispPermKey);
      DispTables[Tbl].Scheme = Scheme;

      SmallVector<Constant *, 16> DispEntries(DispatchCount, nullptr);
      for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
        BasicBlock *Dest = SlotTargets[Slot];
        Constant *Addr =
            ConstantExpr::getPtrToInt(BlockAddress::get(Run, Dest), IntPtrTy);
        Constant *Enc = Addr;
        unsigned Idx =
            permuteSlotConst(static_cast<uint32_t>(Slot), DispPermKey,
                             DispatchMask, SlotMixConst, UsePermute);
        if (Hard && DispTables[Tbl].Bias && DispTables[Tbl].Stride) {
          Constant *IdxC = ConstantInt::get(IntPtrTy, Idx);
          Constant *IdxMul =
              ConstantExpr::getMul(IdxC, DispTables[Tbl].Stride);
          Constant *Offset =
              ConstantExpr::getAdd(DispTables[Tbl].Bias, IdxMul);
          if (Scheme == 0) {
            Enc = ConstantExpr::getAdd(Addr, Offset);
          } else {
            Enc = ConstantExpr::getSub(Addr, Offset);
          }
        }
        DispEntries[Idx] = Enc;
      }
      ArrayType *DispTy = ArrayType::get(IntPtrTy, DispatchCount);
      Constant *DispInit = ConstantArray::get(DispTy, DispEntries);
      std::string Name =
          ("vm_disp_table_" + F.Name + "_" + std::to_string(Tbl)).str();
      DispTables[Tbl].Table =
          new GlobalVariable(M, DispTy, true, GlobalValue::PrivateLinkage,
                             DispInit, Name);
      std::string Tag =
          ("vm.disp.table." + F.Name + "." + std::to_string(Tbl)).str();
      obfuscateSymbolName(*DispTables[Tbl].Table, M, Tag, Name);
      DispTables[Tbl].Table->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    }
  }

  IRBuilder<> UpdateIR(Update);
  Value *EncNext = UpdateIR.CreateLoad(I32Ty, NextPcVar);
  Value *NextPcVal = EncNext;
  if (Hard) {
    Value *KeyVal = UpdateIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = UpdateIR.CreateTrunc(KeyVal, I32Ty);
    Value *Rot = rotl32(UpdateIR, Key32, RotAmt);
    NextPcVal = UpdateIR.CreateXor(UpdateIR.CreateSub(EncNext, Key32), Rot);
    Value *KeyMulC = ConstantInt::get(I64Ty, KeyMul);
    Value *KeyAddC = ConstantInt::get(I64Ty, KeyAdd);
    Value *NextPc64 = UpdateIR.CreateZExt(NextPcVal, I64Ty);
    Value *NewKey = UpdateIR.CreateMul(KeyVal, KeyMulC);
    NewKey = UpdateIR.CreateAdd(NewKey, KeyAddC);
    NewKey = UpdateIR.CreateAdd(NewKey, NextPc64);
    FunctionCallee Rd =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = UpdateIR.CreateCall(Rd);
    NewKey = UpdateIR.CreateXor(NewKey, Cycle);
    UpdateIR.CreateStore(NewKey, KeyPtr);
    Value *NewKey32 = UpdateIR.CreateTrunc(NewKey, I32Ty);
    Value *EncPc = UpdateIR.CreateXor(NextPcVal, NewKey32);
    UpdateIR.CreateStore(EncPc, PcPtr);
  } else {
    UpdateIR.CreateStore(NextPcVal, PcPtr);
  }
  UpdateIR.CreateBr(Loop);

  auto emitTypeInfo = [&](IRBuilder<> &IB, Value *Ty, Value *BitsOut,
                          Value *MaskOut, Value *SignOut, Value *IsFloatOut,
                          Value *IsDoubleOut, BasicBlock *Cont) {
    SwitchInst *Sw = IB.CreateSwitch(Ty, Trap, 8);
    auto addCase = [&](VMTypeKind K, unsigned Bits, uint64_t Mask,
                       uint64_t Sign, bool IsFloat, bool IsDouble) {
      BasicBlock *Case = BasicBlock::Create(Ctx, "ty.case", Run);
      IRBuilder<> CaseIR(Case);
      CaseIR.CreateStore(ConstantInt::get(I32Ty, Bits), BitsOut);
      CaseIR.CreateStore(ConstantInt::get(I64Ty, Mask), MaskOut);
      CaseIR.CreateStore(ConstantInt::get(I64Ty, Sign), SignOut);
      CaseIR.CreateStore(ConstantInt::get(I1Ty, IsFloat), IsFloatOut);
      CaseIR.CreateStore(ConstantInt::get(I1Ty, IsDouble), IsDoubleOut);
      CaseIR.CreateBr(Cont);
      Sw->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(K)), Case);
    };
    addCase(VMTypeKind::I1, 1, maskForBits(1),
            signMaskForType(VMTypeKind::I1, PtrBits), false, false);
    addCase(VMTypeKind::I8, 8, maskForBits(8),
            signMaskForType(VMTypeKind::I8, PtrBits), false, false);
    addCase(VMTypeKind::I16, 16, maskForBits(16),
            signMaskForType(VMTypeKind::I16, PtrBits), false, false);
    addCase(VMTypeKind::I32, 32, maskForBits(32),
            signMaskForType(VMTypeKind::I32, PtrBits), false, false);
    addCase(VMTypeKind::I64, 64, maskForBits(64),
            signMaskForType(VMTypeKind::I64, PtrBits), false, false);
    addCase(VMTypeKind::Ptr, PtrBits, maskForBits(PtrBits),
            signMaskForType(VMTypeKind::Ptr, PtrBits), false, false);
    addCase(VMTypeKind::F32, 32, maskForBits(32),
            signMaskForType(VMTypeKind::I32, PtrBits), true, false);
    addCase(VMTypeKind::F64, 64, maskForBits(64),
            signMaskForType(VMTypeKind::I64, PtrBits), true, true);
  };
  IRBuilder<> LoopIR(Loop);
  Value *EncPc = LoopIR.CreateLoad(I32Ty, PcPtr);
  Value *DecPc = EncPc;
  if (Hard) {
    Value *KeyValLoop = LoopIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = LoopIR.CreateTrunc(KeyValLoop, I32Ty);
    DecPc = LoopIR.CreateXor(EncPc, Key32);
  }
  Value *PcIdx =
      pcFromSlot(LoopIR, DecPc, Hard, PcMask, PcBits, PcInvMul);
  LoopIR.CreateStore(PcIdx, CurPcVar);
  if (Debug && DbgPcGV)
    LoopIR.CreateStore(PcIdx, DbgPcGV);
  Value *InRange =
      LoopIR.CreateICmpULT(PcIdx, ConstantInt::get(I32Ty, InstrCount));
  if (TraceCheck) {
    LoopIR.CreateCondBr(InRange, TraceCheck, Trap);
  } else {
    LoopIR.CreateCondBr(InRange, Decode, Trap);
  }
  if (TraceCheck) {
    IRBuilder<> TraceIR(TraceCheck);
    Value *Idx = TraceIR.CreateLoad(I32Ty, TraceIdxVar);
    Value *Slot = TraceIR.CreateAnd(
        Idx, ConstantInt::get(I32Ty, kVmTraceBufSize - 1));
    Value *BufPtr = TraceIR.CreateInBoundsGEP(
        TraceBufTy, TraceBufVar,
        {ConstantInt::get(I32Ty, 0), Slot});
    Value *PcVal = TraceIR.CreateLoad(I32Ty, CurPcVar);
    TraceIR.CreateStore(PcVal, BufPtr);
    Value *Next = TraceIR.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
    TraceIR.CreateStore(Next, TraceIdxVar);
    Value *Hit = TraceIR.CreateICmpEQ(
        Next, ConstantInt::get(I32Ty, Cfg.TraceLimit));
    TraceIR.CreateCondBr(Hit, TraceDump, Decode);
  }
  if (TraceDump) {
    IRBuilder<> DumpIR(TraceDump);
    FunctionCallee DumpFn = getOrCreateVMDumpTraceFn(M);
    Value *BufBase = DumpIR.CreateInBoundsGEP(
        TraceBufTy, TraceBufVar,
        {ConstantInt::get(I32Ty, 0), ConstantInt::get(I32Ty, 0)});
    Value *PcVal = DumpIR.CreateLoad(I32Ty, CurPcVar);
    GlobalVariable *NameGV = DumpIR.CreateGlobalString(F.Name);
    Value *NamePtr = DumpIR.CreateInBoundsGEP(
        NameGV->getValueType(), NameGV,
        {ConstantInt::get(I32Ty, 0), ConstantInt::get(I32Ty, 0)});
    Value *NameLen =
        ConstantInt::get(I32Ty, static_cast<uint32_t>(F.Name.size()));
    Value *RegA = ConstantInt::get(I64Ty, 0);
    Value *RegB = ConstantInt::get(I64Ty, 0);
    Value *RegC = ConstantInt::get(I64Ty, 0);
    Value *RegD = ConstantInt::get(I64Ty, 0);
    Value *RegE = ConstantInt::get(I64Ty, 0);
    Value *RegF = ConstantInt::get(I64Ty, 0);
    if (F.RegCount > 96 && F.Name.contains("json_value")) {
      RegA = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 83),
                     Ctrs.RegLoad);
      RegB = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 84),
                     Ctrs.RegLoad);
      RegC = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 89),
                     Ctrs.RegLoad);
      RegD = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 93),
                     Ctrs.RegLoad);
      RegE = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 94),
                     Ctrs.RegLoad);
      RegF = loadReg(DumpIR, RegsPtr, ConstantInt::get(I32Ty, 96),
                     Ctrs.RegLoad);
    }
    DumpIR.CreateCall(
        DumpFn,
        {BufBase, ConstantInt::get(I32Ty, kVmTraceBufSize), PcVal, NamePtr,
         NameLen, RegA, RegB, RegC, RegD, RegE, RegF});
    DumpIR.CreateBr(Trap);
  }
  IRBuilder<> DecodeIR(Decode);
  BCDecodeContext BCDecode(BCKey, EncInfo, I8Ty, I32Ty, I64Ty);
  BCDecode.initKeys(DecodeIR, PcIdx);
  Value *InstrP = DecodeIR.CreateInBoundsGEP(InstrTy, InstrPtr, PcIdx);
  auto loadInstrField = [&](Type *Ty, unsigned FieldIdx) -> Value * {
    Value *Ptr = DecodeIR.CreateStructGEP(InstrTy, InstrP, FieldIdx);
    return DecodeIR.CreateAlignedLoad(Ty, Ptr, Align(1));
  };
  Value *OpEnc = loadInstrField(I8Ty, OpFieldIdx);
  Value *TyEnc = loadInstrField(I8Ty, TyIdx);
  Value *AuxEnc = loadInstrField(I8Ty, AuxIdx);
  Value *PadEnc = loadInstrField(I8Ty, PadIdx);
  Value *DstEnc = loadInstrField(I32Ty, DstIdx);
  Value *AEnc = loadInstrField(I32Ty, AIdx);
  Value *BEnc = loadInstrField(I32Ty, BIdx);
  Value *ImmEnc = loadInstrField(I64Ty, ImmIdx);
  Value *TTrueEnc = loadInstrField(I32Ty, TTrueIdx);
  Value *TFalseEnc = loadInstrField(I32Ty, TFalseIdx);
  Value *CallEnc = loadInstrField(I32Ty, CallIdx);
  DecodeIR.CreateStore(BCDecode.decode8(DecodeIR, OpEnc), OpVar);
  DecodeIR.CreateStore(BCDecode.decode8(DecodeIR, TyEnc), TyVar);
  DecodeIR.CreateStore(BCDecode.decode8(DecodeIR, AuxEnc), AuxVar);
  DecodeIR.CreateStore(BCDecode.decode8(DecodeIR, PadEnc), PadVar);
  DecodeIR.CreateStore(BCDecode.decode32(DecodeIR, DstEnc), DstVar);
  DecodeIR.CreateStore(BCDecode.decode32(DecodeIR, AEnc), AVar);
  DecodeIR.CreateStore(BCDecode.decode32(DecodeIR, BEnc), BVar);
  Value *ImmDec = BCDecode.decode64(DecodeIR, ImmEnc);
  Value *ImmFinal = ImmDec;
  if (BCDecode.EncodeBC) {
    Value *PadVal = DecodeIR.CreateLoad(I8Ty, PadVar);
    Value *IsRaw = DecodeIR.CreateICmpNE(
        DecodeIR.CreateAnd(PadVal, ConstantInt::get(I8Ty, VMBCPadImmRaw)),
        ConstantInt::get(I8Ty, 0));
    ImmFinal = DecodeIR.CreateSelect(IsRaw, ImmEnc, ImmDec);
  }
  DecodeIR.CreateStore(ImmFinal, ImmVar);
  DecodeIR.CreateStore(BCDecode.decode32B(DecodeIR, TTrueEnc), TTrueVar);
  DecodeIR.CreateStore(BCDecode.decode32B(DecodeIR, TFalseEnc), TFalseVar);
  DecodeIR.CreateStore(BCDecode.decode32B(DecodeIR, CallEnc), CallVar);
  DecodeIR.CreateBr(TypeDecode);
  IRBuilder<> TypeDecodeIR(TypeDecode);
  Value *TyVal = TypeDecodeIR.CreateLoad(I8Ty, TyVar);
  emitTypeInfo(TypeDecodeIR, TyVal, BitsVar, MaskVar, SignVar, IsFloatVar,
               IsDoubleVar,
               DispatchPrep);
  IRBuilder<> DispatchPrepIR(DispatchPrep);
  Value *OpVal = DispatchPrepIR.CreateLoad(I8Ty, OpVar);
  if (Debug && DbgPcGV && DbgOpGV && DbgTyGV && DbgAuxGV) {
    Value *CurPcDbg = DispatchPrepIR.CreateLoad(I32Ty, CurPcVar);
    DispatchPrepIR.CreateStore(CurPcDbg, DbgPcGV);
    DispatchPrepIR.CreateStore(DispatchPrepIR.CreateZExt(OpVal, I32Ty),
                               DbgOpGV);
    DispatchPrepIR.CreateStore(
        DispatchPrepIR.CreateZExt(DispatchPrepIR.CreateLoad(I8Ty, TyVar),
                                  I32Ty),
        DbgTyGV);
    DispatchPrepIR.CreateStore(
        DispatchPrepIR.CreateZExt(DispatchPrepIR.CreateLoad(I8Ty, AuxVar),
                                  I32Ty),
        DbgAuxGV);
  }
  if (Trace) {
    Value *CurPcTrace = DispatchPrepIR.CreateLoad(I32Ty, CurPcVar);
    Value *DstTrace = DispatchPrepIR.CreateLoad(I32Ty, DstVar);
    std::string TraceMsg = "[VM] PC=%llu Op=%llu Dst=%llu " + F.Name.str() + "\n";
    emitVMTrace(DispatchPrepIR, M, TraceMsg, CurPcTrace,
                DispatchPrepIR.CreateZExt(OpVal, I64Ty), DstTrace, true);
  }
  if (BoundsCheck && RegCount > 0) {
    Value *DstCheck = DispatchPrepIR.CreateLoad(I32Ty, DstVar);
    Value *ACheck = DispatchPrepIR.CreateLoad(I32Ty, AVar);
    Value *BCheck = DispatchPrepIR.CreateLoad(I32Ty, BVar);
    Value *MaxReg = ConstantInt::get(I32Ty, RegCount);
    Value *DstUsed =
        DispatchPrepIR.CreateICmpNE(DstCheck,
                                    ConstantInt::get(I32Ty, UINT32_MAX));
    Value *DstOOB =
        DispatchPrepIR.CreateAnd(DstUsed,
                                 DispatchPrepIR.CreateICmpUGE(DstCheck, MaxReg));
    Value *AUsed =
        DispatchPrepIR.CreateICmpNE(ACheck,
                                    ConstantInt::get(I32Ty, UINT32_MAX));
    Value *AOOB =
        DispatchPrepIR.CreateAnd(AUsed,
                                 DispatchPrepIR.CreateICmpUGE(ACheck, MaxReg));
    Value *BUsed =
        DispatchPrepIR.CreateICmpNE(BCheck,
                                    ConstantInt::get(I32Ty, UINT32_MAX));
    Value *BOOB =
        DispatchPrepIR.CreateAnd(BUsed,
                                 DispatchPrepIR.CreateICmpUGE(BCheck, MaxReg));
    Value *AnyOOB =
        DispatchPrepIR.CreateOr(DispatchPrepIR.CreateOr(DstOOB, AOOB), BOOB);
    BasicBlock *BoundsOk = BasicBlock::Create(Ctx, "bounds.ok", Run);
    BasicBlock *BoundsFail = BasicBlock::Create(Ctx, "bounds.fail", Run);
    DispatchPrepIR.CreateCondBr(AnyOOB, BoundsFail, BoundsOk);
    IRBuilder<> BoundsFailIR(BoundsFail);
    Value *CurPcFail = BoundsFailIR.CreateLoad(I32Ty, CurPcVar);
    std::string FailMsg1 = "[VM BOUNDS FAIL] PC=%llu Dst=%llu A=%llu " + F.Name.str() + "\n";
    emitVMTrace(BoundsFailIR, M, FailMsg1, CurPcFail, DstCheck, ACheck,
                true);
    std::string FailMsg2 = "[VM BOUNDS FAIL] EntryIR=%llu RegCount=" + std::to_string(RegCount) + "\n";
    emitVMTrace(BoundsFailIR, M, FailMsg2, BCheck, nullptr, nullptr, true);
    FunctionCallee TrapFnBC = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
    BoundsFailIR.CreateCall(TrapFnBC);
    BoundsFailIR.CreateUnreachable();
    DispatchPrepIR.SetInsertPoint(BoundsOk);
  }
  Value *OpIdxRaw = DispatchPrepIR.CreateZExt(OpVal, I32Ty);
  Value *OpOk =
      DispatchPrepIR.CreateICmpULT(OpIdxRaw, ConstantInt::get(I32Ty, OpCount));
  BasicBlock *OpRangeOk = BasicBlock::Create(Ctx, "op.ok", Run);
  DispatchPrepIR.CreateCondBr(OpOk, OpRangeOk, Trap);
  IRBuilder<> OpRangeOkIR(OpRangeOk);
  Value *OpIdx = OpIdxRaw;
  if (OpDecodeGV) {
    Value *OpPtr =
        OpRangeOkIR.CreateInBoundsGEP(OpDecodeGV->getValueType(), OpDecodeGV,
                                      {ConstantInt::get(I32Ty, 0), OpIdxRaw});
    Value *OpDec = OpRangeOkIR.CreateLoad(I8Ty, OpPtr);
    OpIdx = OpRangeOkIR.CreateZExt(OpDec, I32Ty);
  }
  Value *OpId = OpIdx;
  if (HandlerVariants > 1) {
    Value *KeyVal = OpRangeOkIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = OpRangeOkIR.CreateTrunc(KeyVal, I32Ty);
    Value *CurPc = OpRangeOkIR.CreateLoad(I32Ty, CurPcVar);
    Value *Mix = rotl32(OpRangeOkIR, Key32, RotAmt);
    Mix = OpRangeOkIR.CreateXor(Mix, CurPc);
    Value *Var =
        OpRangeOkIR.CreateAnd(Mix, ConstantInt::get(I32Ty, HandlerVariants - 1));
    OpId = OpRangeOkIR.CreateAdd(
        OpRangeOkIR.CreateMul(OpIdx, ConstantInt::get(I32Ty, HandlerVariants)), Var);
  }
  Value *SlotVal = nullptr;
  if (Hard && OpSlotEncGV && OpSlotKeyConst && OpSlotMixConst) {
    Value *OpSlotPtr = OpRangeOkIR.CreateInBoundsGEP(
        OpSlotEncGV->getValueType(), OpSlotEncGV,
        {ConstantInt::get(I32Ty, 0), OpId});
    Value *EncSlot = OpRangeOkIR.CreateLoad(I32Ty, OpSlotPtr);
    Value *OpKey = OpRangeOkIR.CreateAdd(OpSlotKeyConst,
                                OpRangeOkIR.CreateMul(OpId, OpSlotMixConst));
    SlotVal = OpRangeOkIR.CreateXor(EncSlot, OpKey);
  } else {
    Value *OpSlotPtr = OpRangeOkIR.CreateInBoundsGEP(OpSlotGV->getValueType(), OpSlotGV,
                                            {ConstantInt::get(I32Ty, 0), OpId});
    SlotVal = OpRangeOkIR.CreateLoad(I32Ty, OpSlotPtr);
  }
  OpRangeOkIR.CreateStore(SlotVal, SlotVar);
  OpRangeOkIR.CreateStore(SlotVal, RealSlotVar);
  if (Hard && BogusGV) {
    Value *KeyVal = OpRangeOkIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = OpRangeOkIR.CreateTrunc(KeyVal, I32Ty);
    Value *CurPc = OpRangeOkIR.CreateLoad(I32Ty, CurPcVar);
    Value *Mix = rotl32(OpRangeOkIR, Key32, RotAmt);
    Mix = OpRangeOkIR.CreateXor(Mix, Key32);
    Mix = OpRangeOkIR.CreateXor(Mix, CurPc);
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = OpRangeOkIR.CreateCall(Rd);
    Value *Cycle32 = OpRangeOkIR.CreateTrunc(Cycle, I32Ty);
    Mix = OpRangeOkIR.CreateXor(Mix, Cycle32);
    Value *Fold =
        OpRangeOkIR.CreateXor(Mix, OpRangeOkIR.CreateLShr(Mix, ConstantInt::get(I32Ty, 11)));
    Fold = OpRangeOkIR.CreateMul(Fold, ConstantInt::get(I32Ty, PredMul));
    Fold = OpRangeOkIR.CreateAdd(Fold, ConstantInt::get(I32Ty, PredAdd));
    Value *Masked = OpRangeOkIR.CreateAnd(Fold, ConstantInt::get(I32Ty, PredMask));
    Value *Cond = OpRangeOkIR.CreateICmpEQ(
        Masked, ConstantInt::get(I32Ty, PredTarget));
    OpRangeOkIR.CreateCondBr(Cond, DispatchSel, BogusEntry);
  } else {
    OpRangeOkIR.CreateBr(DispatchSel);
  }
  IRBuilder<> BogusEntryIR(BogusEntry);
  if (BogusGV) {
    Value *KeyVal = BogusEntryIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = BogusEntryIR.CreateTrunc(KeyVal, I32Ty);
    Value *Mix = BogusEntryIR.CreateXor(
        Key32, BogusEntryIR.CreateLShr(Key32, ConstantInt::get(I32Ty, 13)));
    Value *Idx = BogusEntryIR.CreateURem(
        Mix, ConstantInt::get(I32Ty, static_cast<uint32_t>(BogusSlots.size())));
    Value *Ptr =
        BogusEntryIR.CreateInBoundsGEP(BogusGV->getValueType(), BogusGV,
                                       {ConstantInt::get(I32Ty, 0), Idx});
    Value *BogusSlot = BogusEntryIR.CreateLoad(I32Ty, Ptr);
    BogusEntryIR.CreateStore(BogusSlot, SlotVar);
  }
  BogusEntryIR.CreateBr(DispatchSel);
  IRBuilder<> BogusIR(Bogus);
  if (Hard) {
    Value *KeyVal = BogusIR.CreateLoad(I64Ty, KeyPtr);
    Value *Key32 = BogusIR.CreateTrunc(KeyVal, I32Ty);
    (void)BogusIR.CreateXor(Key32,
                            BogusIR.CreateLShr(Key32,
                                               ConstantInt::get(I32Ty, 5)));
  }
  Value *RealSlot = BogusIR.CreateLoad(I32Ty, RealSlotVar);
  BogusIR.CreateStore(RealSlot, SlotVar);
  BogusIR.CreateBr(DispatchSel);
  IRBuilder<> DispatchSelIR(DispatchSel);
  Value *SelSlot = DispatchSelIR.CreateLoad(I32Ty, SlotVar);
  SelSlot =
      DispatchSelIR.CreateAnd(SelSlot, ConstantInt::get(I32Ty, DispatchMask));
  if (DispatchPoints <= 1 || DispatchMode != VMDispatch::Indirect) {
    DispatchSelIR.CreateBr(Dispatch0);
  } else {
    // Two-level dispatch helps avoid a single, stable indirect branch target.
    Value *Key32 =
        DispatchSelIR.CreateTrunc(DispatchSelIR.CreateLoad(I64Ty, KeyPtr),
                                  I32Ty);
    Value *Mix = DispatchSelIR.CreateXor(SelSlot, Key32);
    Value *Sel = DispatchSelIR.CreateAnd(
        Mix, ConstantInt::get(I32Ty, DispatchPoints - 1));
    Value *IsZero =
        DispatchSelIR.CreateICmpEQ(Sel, ConstantInt::get(I32Ty, 0));
    DispatchSelIR.CreateCondBr(IsZero, Dispatch0, Dispatch1);
  }

  emitDispatchBlock(Dispatch0, DispTables[0], SlotVar, Bogus, SlotTargets,
                    DispatchCount, DispatchMask, DispatchMode, Hard,
                    SlotMixConst, I32Ty, IntPtrTy, I8PtrTy);
  if (DispatchPoints > 1 && Dispatch1)
    emitDispatchBlock(Dispatch1, DispTables[1], SlotVar, Bogus, SlotTargets,
                      DispatchCount, DispatchMask, DispatchMode, Hard,
                      SlotMixConst, I32Ty, IntPtrTy, I8PtrTy);
  NextPcHelper NextPc{Hard,  PcMask, PcBits, PcMul, RotAmt, KeyPtr,
                      NextPcVar, CurPcVar, Update, I32Ty};
  /* Handler blocks */
  for (unsigned OpId = 0; OpId < OpSlots; ++OpId) {
    BasicBlock *Case = CaseBlocks[OpId];
    IRBuilder<> CaseIR(Case);
    bumpCounter(CaseIR, Ctrs.Dispatch);
    bumpCounter(CaseIR, Ctrs.Instr);
    unsigned Op = OpId;
    unsigned Var = 0;
    if (HandlerVariants > 1) {
      Op = OpId / HandlerVariants;
      Var = OpId % HandlerVariants;
    }
    // Mix op id and variant with odd multipliers to decorrelate junk seeds.
    unsigned JunkVar =
        static_cast<unsigned>(OpId * kJunkMulOp + Var * kJunkMulVar);
    emitOpaqueJunk(CaseIR, JunkCtx, JunkVar);
    if (HandlerVariants > 1 && Var != 0)
      emitOpaqueJunk(CaseIR, JunkCtx, JunkVar + 1);
    switch (static_cast<VMOpcode>(Op)) {
    case VMOpcode::Mov: {
      Value *Dst = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *Aux = CaseIR.CreateLoad(I8Ty, AuxVar);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      SwitchInst *Sw = CaseIR.CreateSwitch(Aux, Trap, 3);
      BasicBlock *BReg = BasicBlock::Create(Ctx, "mov.reg", Run);
      BasicBlock *BImm = BasicBlock::Create(Ctx, "mov.imm", Run);
      BasicBlock *BCst = BasicBlock::Create(Ctx, "mov.const", Run);
      Sw->addCase(ConstantInt::get(I8Ty, 0), BReg);
      Sw->addCase(ConstantInt::get(I8Ty, 1), BImm);
      Sw->addCase(ConstantInt::get(I8Ty, 2), BCst);
      IRBuilder<> RegIR(BReg);
      Value *SrcIdx = RegIR.CreateLoad(I32Ty, AVar);
      Value *SrcVal = loadReg(RegIR, RegsPtr, SrcIdx, Ctrs.RegLoad);
      SrcVal = RegIR.CreateAnd(SrcVal, Mask);
      storeReg(RegIR, RegsPtr, Dst, SrcVal, Ctrs.RegStore);
      NextPc.storeNextPcInc(RegIR);
      IRBuilder<> ImmIR(BImm);
      Value *Imm = ImmIR.CreateLoad(I64Ty, ImmVar);
      Imm = ImmIR.CreateAnd(Imm, Mask);
      storeReg(ImmIR, RegsPtr, Dst, Imm, Ctrs.RegStore);
      NextPc.storeNextPcInc(ImmIR);
      IRBuilder<> ConstIR(BCst);
      Value *CImm = ConstIR.CreateLoad(I64Ty, ImmVar);
      CImm = ConstIR.CreateAnd(CImm, Mask);
      storeReg(ConstIR, RegsPtr, Dst, CImm, Ctrs.RegStore);
      NextPc.storeNextPcInc(ConstIR);
      break;
    }
    case VMOpcode::BinOp: {
      Value *IsFloat = CaseIR.CreateLoad(I1Ty, IsFloatVar);
      BasicBlock *BInt = BasicBlock::Create(Ctx, "bin.int", Run);
      BasicBlock *BFloat = BasicBlock::Create(Ctx, "bin.float", Run);
      CaseIR.CreateCondBr(IsFloat, BFloat, BInt);
      IRBuilder<> BinIntIR(BInt);
      Value *Dst = BinIntIR.CreateLoad(I32Ty, DstVar);
      Value *AIdx = BinIntIR.CreateLoad(I32Ty, AVar);
      Value *BIdx = BinIntIR.CreateLoad(I32Ty, BVar);
      Value *AVal = loadReg(BinIntIR, RegsPtr, AIdx, Ctrs.RegLoad);
      Value *BVal = loadReg(BinIntIR, RegsPtr, BIdx, Ctrs.RegLoad);
      Value *Mask = BinIntIR.CreateLoad(I64Ty, MaskVar);
      Value *Sign = BinIntIR.CreateLoad(I64Ty, SignVar);
      Value *OpK = BinIntIR.CreateLoad(I8Ty, AuxVar);
      SwitchInst *Sw = BinIntIR.CreateSwitch(OpK, Trap, 12);
      auto addCase = [&](VMBinOp K, const char *Name,
                         std::function<void(IRBuilder<> &)> Emit) {
        BasicBlock *C = BasicBlock::Create(Ctx, Name, Run);
        Sw->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(K)), C);
        IRBuilder<> CaseIR(C);
        Emit(CaseIR);
      };
      addCase(VMBinOp::Add, "bin.add", [&](IRBuilder<> &IB) {
        Value *Res = emitIntAdd(IB, AVal, BVal, Handlers, AllowArithExpand);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::Sub, "bin.sub", [&](IRBuilder<> &IB) {
        Value *Res = emitIntSub(IB, AVal, BVal, Handlers, AllowArithExpand);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::Mul, "bin.mul", [&](IRBuilder<> &IB) {
        Value *Res = IB.CreateMul(AVal, BVal);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::UDiv, "bin.udiv", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Zero = ConstantInt::get(I64Ty, 0);
        Value *IsZero = IB.CreateICmpEQ(BMask, Zero);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "udiv.ok", Run);
        IB.CreateCondBr(IsZero, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *AUsed = IOk.CreateAnd(AVal, Mask);
        Value *Res = IOk.CreateUDiv(AUsed, BMask);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::SDiv, "bin.sdiv", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Zero = ConstantInt::get(I64Ty, 0);
        Value *IsZero = IB.CreateICmpEQ(BMask, Zero);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "sdiv.ok", Run);
        IB.CreateCondBr(IsZero, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *AS = signExtendMasked(IOk, AVal, Mask, Sign);
        Value *BS = signExtendMasked(IOk, BVal, Mask, Sign);
        Value *Res = IOk.CreateSDiv(AS, BS);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::URem, "bin.urem", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Zero = ConstantInt::get(I64Ty, 0);
        Value *IsZero = IB.CreateICmpEQ(BMask, Zero);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "urem.ok", Run);
        IB.CreateCondBr(IsZero, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *AUsed = IOk.CreateAnd(AVal, Mask);
        Value *Res = IOk.CreateURem(AUsed, BMask);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::SRem, "bin.srem", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Zero = ConstantInt::get(I64Ty, 0);
        Value *IsZero = IB.CreateICmpEQ(BMask, Zero);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "srem.ok", Run);
        IB.CreateCondBr(IsZero, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *AS = signExtendMasked(IOk, AVal, Mask, Sign);
        Value *BS = signExtendMasked(IOk, BVal, Mask, Sign);
        Value *Res = IOk.CreateSRem(AS, BS);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::And, "bin.and", [&](IRBuilder<> &IB) {
        Value *Res = emitIntAnd(IB, AVal, BVal, Handlers, AllowArithExpand);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::Or, "bin.or", [&](IRBuilder<> &IB) {
        Value *Res = emitIntOr(IB, AVal, BVal, Handlers, AllowArithExpand);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::Xor, "bin.xor", [&](IRBuilder<> &IB) {
        Value *Res = emitIntXor(IB, AVal, BVal, Handlers, AllowArithExpand);
        Res = IB.CreateAnd(Res, Mask);
        storeReg(IB, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCase(VMBinOp::Shl, "bin.shl", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Bits = IB.CreateLoad(I32Ty, BitsVar);
        Value *Bits64 = IB.CreateZExt(Bits, I64Ty);
        Value *TooBig = IB.CreateICmpUGE(BMask, Bits64);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "shl.ok", Run);
        IB.CreateCondBr(TooBig, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *Res = IOk.CreateShl(AVal, BMask);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::LShr, "bin.lshr", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Bits = IB.CreateLoad(I32Ty, BitsVar);
        Value *Bits64 = IB.CreateZExt(Bits, I64Ty);
        Value *TooBig = IB.CreateICmpUGE(BMask, Bits64);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "lshr.ok", Run);
        IB.CreateCondBr(TooBig, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *Res = IOk.CreateLShr(IOk.CreateAnd(AVal, Mask), BMask);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      addCase(VMBinOp::AShr, "bin.ashr", [&](IRBuilder<> &IB) {
        Value *BMask = IB.CreateAnd(BVal, Mask);
        Value *Bits = IB.CreateLoad(I32Ty, BitsVar);
        Value *Bits64 = IB.CreateZExt(Bits, I64Ty);
        Value *TooBig = IB.CreateICmpUGE(BMask, Bits64);
        BasicBlock *Ok = BasicBlock::Create(Ctx, "ashr.ok", Run);
        IB.CreateCondBr(TooBig, Trap, Ok);
        IRBuilder<> IOk(Ok);
        Value *AS = signExtendMasked(IOk, AVal, Mask, Sign);
        Value *Res = IOk.CreateAShr(AS, BMask);
        Res = IOk.CreateAnd(Res, Mask);
        storeReg(IOk, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(IOk);
      });
      IRBuilder<> FloatIR(BFloat);
      Value *DstF = FloatIR.CreateLoad(I32Ty, DstVar);
      Value *AIdxF = FloatIR.CreateLoad(I32Ty, AVar);
      Value *BIdxF = FloatIR.CreateLoad(I32Ty, BVar);
      Value *AValF = loadReg(FloatIR, RegsPtr, AIdxF, Ctrs.RegLoad);
      Value *BValF = loadReg(FloatIR, RegsPtr, BIdxF, Ctrs.RegLoad);
      Value *OpKF = FloatIR.CreateLoad(I8Ty, AuxVar);
      SwitchInst *SwF = FloatIR.CreateSwitch(OpKF, Trap, 5);
      auto addFloatCase = [&](VMBinOp K, const char *Name,
                              Instruction::BinaryOps FOp) {
        BasicBlock *C = BasicBlock::Create(Ctx, Name, Run);
        SwF->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(K)), C);
        IRBuilder<> FloatCaseIR(C);
        Value *IsD = FloatCaseIR.CreateLoad(I1Ty, IsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "f64.bin", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "f32.bin", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "fbin.merge", Run);
        FloatCaseIR.CreateCondBr(IsD, F64, F32);
        IRBuilder<> Float64IR(F64);
        Value *DA = Float64IR.CreateBitCast(AValF, Type::getDoubleTy(Ctx));
        Value *DB = Float64IR.CreateBitCast(BValF, Type::getDoubleTy(Ctx));
        Value *DR = Float64IR.CreateBinOp(FOp, DA, DB);
        Value *Packed64 = Float64IR.CreateBitCast(DR, I64Ty);
        Float64IR.CreateBr(Merge);
        IRBuilder<> Float32IR(F32);
        Value *A32 = Float32IR.CreateTrunc(AValF, Type::getInt32Ty(Ctx));
        Value *B32 = Float32IR.CreateTrunc(BValF, Type::getInt32Ty(Ctx));
        Value *FA = Float32IR.CreateBitCast(A32, Type::getFloatTy(Ctx));
        Value *FB = Float32IR.CreateBitCast(B32, Type::getFloatTy(Ctx));
        Value *FR = Float32IR.CreateBinOp(FOp, FA, FB);
        Value *Fbits = Float32IR.CreateBitCast(FR, Type::getInt32Ty(Ctx));
        Value *Packed32 = Float32IR.CreateZExt(Fbits, I64Ty);
        Float32IR.CreateBr(Merge);
        IRBuilder<> FloatMergeIR(Merge);
        PHINode *Res = FloatMergeIR.CreatePHI(I64Ty, 2);
        Res->addIncoming(Packed64, F64);
        Res->addIncoming(Packed32, F32);
        storeReg(FloatMergeIR, RegsPtr, DstF, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(FloatMergeIR);
      };
      addFloatCase(VMBinOp::Add, "fadd", Instruction::FAdd);
      addFloatCase(VMBinOp::FAdd, "fadd.alt", Instruction::FAdd);
      addFloatCase(VMBinOp::Sub, "fsub", Instruction::FSub);
      addFloatCase(VMBinOp::FSub, "fsub.alt", Instruction::FSub);
      addFloatCase(VMBinOp::Mul, "fmul", Instruction::FMul);
      addFloatCase(VMBinOp::FMul, "fmul.alt", Instruction::FMul);
      addFloatCase(VMBinOp::FDiv, "fdiv", Instruction::FDiv);
      addFloatCase(VMBinOp::FRem, "frem", Instruction::FRem);
      break;
    }
    case VMOpcode::FNeg: {
      Value *IsFloat = CaseIR.CreateLoad(I1Ty, IsFloatVar);
      BasicBlock *FOk = BasicBlock::Create(Ctx, "fneg.ok", Run);
      CaseIR.CreateCondBr(IsFloat, FOk, Trap);
      IRBuilder<> CF(FOk);
      Value *Dst = CF.CreateLoad(I32Ty, DstVar);
      Value *SrcIdx = CF.CreateLoad(I32Ty, AVar);
      Value *SrcVal = loadReg(CF, RegsPtr, SrcIdx, Ctrs.RegLoad);
      Value *IsD = CF.CreateLoad(I1Ty, IsDoubleVar);
      BasicBlock *F64 = BasicBlock::Create(Ctx, "fneg64", Run);
      BasicBlock *F32 = BasicBlock::Create(Ctx, "fneg32", Run);
      BasicBlock *Merge = BasicBlock::Create(Ctx, "fneg.merge", Run);
      CF.CreateCondBr(IsD, F64, F32);
      IRBuilder<> C64(F64);
      Value *DA = C64.CreateBitCast(SrcVal, Type::getDoubleTy(Ctx));
      Value *DR = C64.CreateFNeg(DA);
      Value *Packed64 = C64.CreateBitCast(DR, I64Ty);
      C64.CreateBr(Merge);
      IRBuilder<> C32(F32);
      Value *A32 = C32.CreateTrunc(SrcVal, Type::getInt32Ty(Ctx));
      Value *FA = C32.CreateBitCast(A32, Type::getFloatTy(Ctx));
      Value *FR = C32.CreateFNeg(FA);
      Value *Fbits = C32.CreateBitCast(FR, Type::getInt32Ty(Ctx));
      Value *Packed32 = C32.CreateZExt(Fbits, I64Ty);
      C32.CreateBr(Merge);
      IRBuilder<> CM(Merge);
      PHINode *Res = CM.CreatePHI(I64Ty, 2);
      Res->addIncoming(Packed64, F64);
      Res->addIncoming(Packed32, F32);
      storeReg(CM, RegsPtr, Dst, Res, Ctrs.RegStore);
      NextPc.storeNextPcInc(CM);
      break;
    }
    case VMOpcode::ICmp: {
      Value *Dst = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *AIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *BIdx = CaseIR.CreateLoad(I32Ty, BVar);
      Value *AVal = loadReg(CaseIR, RegsPtr, AIdx, Ctrs.RegLoad);
      Value *BVal = loadReg(CaseIR, RegsPtr, BIdx, Ctrs.RegLoad);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Value *Sign = CaseIR.CreateLoad(I64Ty, SignVar);
      Value *Au = CaseIR.CreateAnd(AVal, Mask);
      Value *Bu = CaseIR.CreateAnd(BVal, Mask);
      Value *As = signExtendMasked(CaseIR, AVal, Mask, Sign);
      Value *Bs = signExtendMasked(CaseIR, BVal, Mask, Sign);
      Value *Pred = CaseIR.CreateLoad(I8Ty, AuxVar);
      SwitchInst *Sw = CaseIR.CreateSwitch(Pred, Trap, 10);
      auto addPred = [&](VMCmpPred P, const char *Name,
                         std::function<Value *(IRBuilder<> &)> Emit) {
        BasicBlock *C = BasicBlock::Create(Ctx, Name, Run);
        Sw->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(P)), C);
        IRBuilder<> CC(C);
        Value *R = Emit(CC);
        Value *Ext = CC.CreateZExt(R, I64Ty);
        storeReg(CC, RegsPtr, Dst, Ext, Ctrs.RegStore);
        NextPc.storeNextPcInc(CC);
      };
      addPred(VMCmpPred::EQ, "icmp.eq",
              [&](IRBuilder<> &IB) { return IB.CreateICmpEQ(Au, Bu); });
      addPred(VMCmpPred::NE, "icmp.ne",
              [&](IRBuilder<> &IB) { return IB.CreateICmpNE(Au, Bu); });
      addPred(VMCmpPred::ULT, "icmp.ult",
              [&](IRBuilder<> &IB) { return IB.CreateICmpULT(Au, Bu); });
      addPred(VMCmpPred::ULE, "icmp.ule",
              [&](IRBuilder<> &IB) { return IB.CreateICmpULE(Au, Bu); });
      addPred(VMCmpPred::UGT, "icmp.ugt",
              [&](IRBuilder<> &IB) { return IB.CreateICmpUGT(Au, Bu); });
      addPred(VMCmpPred::UGE, "icmp.uge",
              [&](IRBuilder<> &IB) { return IB.CreateICmpUGE(Au, Bu); });
      addPred(VMCmpPred::SLT, "icmp.slt",
              [&](IRBuilder<> &IB) { return IB.CreateICmpSLT(As, Bs); });
      addPred(VMCmpPred::SLE, "icmp.sle",
              [&](IRBuilder<> &IB) { return IB.CreateICmpSLE(As, Bs); });
      addPred(VMCmpPred::SGT, "icmp.sgt",
              [&](IRBuilder<> &IB) { return IB.CreateICmpSGT(As, Bs); });
      addPred(VMCmpPred::SGE, "icmp.sge",
              [&](IRBuilder<> &IB) { return IB.CreateICmpSGE(As, Bs); });
      break;
    }
    case VMOpcode::FCmp: {
      Value *IsFloat = CaseIR.CreateLoad(I1Ty, IsFloatVar);
      BasicBlock *FOk = BasicBlock::Create(Ctx, "fcmp.ok", Run);
      CaseIR.CreateCondBr(IsFloat, FOk, Trap);
      IRBuilder<> CF(FOk);
      Value *Dst = CF.CreateLoad(I32Ty, DstVar);
      Value *AIdx = CF.CreateLoad(I32Ty, AVar);
      Value *BIdx = CF.CreateLoad(I32Ty, BVar);
      Value *AVal = loadReg(CF, RegsPtr, AIdx, Ctrs.RegLoad);
      Value *BVal = loadReg(CF, RegsPtr, BIdx, Ctrs.RegLoad);
      Value *Pred = CF.CreateLoad(I8Ty, AuxVar);
      SwitchInst *Sw = CF.CreateSwitch(Pred, Trap, 6);
      auto addPred = [&](VMCmpPred P, const char *Name,
                         CmpInst::Predicate PredF) {
        BasicBlock *C = BasicBlock::Create(Ctx, Name, Run);
        Sw->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(P)), C);
        IRBuilder<> CC(C);
        Value *IsD = CC.CreateLoad(I1Ty, IsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "fcmp64", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "fcmp32", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "fcmp.merge", Run);
        CC.CreateCondBr(IsD, F64, F32);
        IRBuilder<> C64(F64);
        Value *DA = C64.CreateBitCast(AVal, Type::getDoubleTy(Ctx));
        Value *DB = C64.CreateBitCast(BVal, Type::getDoubleTy(Ctx));
        Value *R64 = C64.CreateFCmp(PredF, DA, DB);
        Value *R64E = C64.CreateZExt(R64, I64Ty);
        C64.CreateBr(Merge);
        IRBuilder<> C32(F32);
        Value *A32 = C32.CreateTrunc(AVal, Type::getInt32Ty(Ctx));
        Value *B32 = C32.CreateTrunc(BVal, Type::getInt32Ty(Ctx));
        Value *FA = C32.CreateBitCast(A32, Type::getFloatTy(Ctx));
        Value *FB = C32.CreateBitCast(B32, Type::getFloatTy(Ctx));
        Value *R32 = C32.CreateFCmp(PredF, FA, FB);
        Value *R32E = C32.CreateZExt(R32, I64Ty);
        C32.CreateBr(Merge);
        IRBuilder<> CM(Merge);
        PHINode *Res = CM.CreatePHI(I64Ty, 2);
        Res->addIncoming(R64E, F64);
        Res->addIncoming(R32E, F32);
        storeReg(CM, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(CM);
      };
      addPred(VMCmpPred::FEQ, "fcmp.eq", CmpInst::FCMP_OEQ);
      addPred(VMCmpPred::FNE, "fcmp.ne", CmpInst::FCMP_ONE);
      addPred(VMCmpPred::FLT, "fcmp.lt", CmpInst::FCMP_OLT);
      addPred(VMCmpPred::FLE, "fcmp.le", CmpInst::FCMP_OLE);
      addPred(VMCmpPred::FGT, "fcmp.gt", CmpInst::FCMP_OGT);
      addPred(VMCmpPred::FGE, "fcmp.ge", CmpInst::FCMP_OGE);
      break;
    }
    case VMOpcode::Cast: {
      Value *Dst = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *SrcIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *SrcVal = loadReg(CaseIR, RegsPtr, SrcIdx, Ctrs.RegLoad);
      Value *DstMask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Value *DstIsFloat = CaseIR.CreateLoad(I1Ty, IsFloatVar);
      Value *CastK = CaseIR.CreateLoad(I8Ty, AuxVar);
      Value *SrcTyVal = CaseIR.CreateTrunc(CaseIR.CreateLoad(I64Ty, ImmVar), I8Ty);
      BasicBlock *SrcDecode = BasicBlock::Create(Ctx, "cast.src", Run);
      BasicBlock *CastBody = BasicBlock::Create(Ctx, "cast.body", Run);
      CaseIR.CreateBr(SrcDecode);
      IRBuilder<> SD(SrcDecode);
      emitTypeInfo(SD, SrcTyVal, SrcBitsVar, SrcMaskVar, SrcSignVar,
                   SrcIsFloatVar, SrcIsDoubleVar, CastBody);
      IRBuilder<> CC(CastBody);
      Value *SrcMask = CC.CreateLoad(I64Ty, SrcMaskVar);
      Value *SrcSign = CC.CreateLoad(I64Ty, SrcSignVar);
      Value *SrcIsFloat = CC.CreateLoad(I1Ty, SrcIsFloatVar);
      SwitchInst *Sw = CC.CreateSwitch(CastK, Trap, 12);
      auto addCastCase = [&](VMCastKind K, const char *Name,
                             std::function<void(IRBuilder<> &)> Emit) {
        BasicBlock *C = BasicBlock::Create(Ctx, Name, Run);
        Sw->addCase(ConstantInt::get(I8Ty, static_cast<unsigned>(K)), C);
        IRBuilder<> CI(C);
        Emit(CI);
      };
      addCastCase(VMCastKind::ZExt, "cast.zext", [&](IRBuilder<> &IB) {
        Value *V = IB.CreateAnd(SrcVal, SrcMask);
        V = IB.CreateAnd(V, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::SExt, "cast.sext", [&](IRBuilder<> &IB) {
        Value *V = signExtendMasked(IB, SrcVal, SrcMask, SrcSign);
        V = IB.CreateAnd(V, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::Trunc, "cast.trunc", [&](IRBuilder<> &IB) {
        Value *V = IB.CreateAnd(SrcVal, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::Bitcast, "cast.bitcast", [&](IRBuilder<> &IB) {
        Value *V = IB.CreateAnd(SrcVal, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::PtrToInt, "cast.ptrtoint", [&](IRBuilder<> &IB) {
        Value *V = IB.CreateAnd(SrcVal, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::IntToPtr, "cast.inttoptr", [&](IRBuilder<> &IB) {
        Value *V = IB.CreateAnd(SrcVal, DstMask);
        storeReg(IB, RegsPtr, Dst, V, Ctrs.RegStore);
        NextPc.storeNextPcInc(IB);
      });
      addCastCase(VMCastKind::FPToUI, "cast.fptoui", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "fpui.ok", Run);
        IB.CreateCondBr(SrcIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *IsD = IOk.CreateLoad(I1Ty, SrcIsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "fpui64", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "fpui32", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "fpui.merge", Run);
        IOk.CreateCondBr(IsD, F64, F32);
        IRBuilder<> C64(F64);
        Value *FD = C64.CreateBitCast(SrcVal, Type::getDoubleTy(Ctx));
        Value *I = C64.CreateFPToUI(FD, I64Ty);
        C64.CreateBr(Merge);
        IRBuilder<> C32(F32);
        Value *FV =
            C32.CreateBitCast(C32.CreateTrunc(SrcVal, Type::getInt32Ty(Ctx)),
                              Type::getFloatTy(Ctx));
        Value *I32 = C32.CreateFPToUI(FV, I64Ty);
        C32.CreateBr(Merge);
        IRBuilder<> CM(Merge);
        PHINode *Res = CM.CreatePHI(I64Ty, 2);
        Res->addIncoming(I, F64);
        Res->addIncoming(I32, F32);
        Value *Out = CM.CreateAnd(Res, DstMask);
        storeReg(CM, RegsPtr, Dst, Out, Ctrs.RegStore);
        NextPc.storeNextPcInc(CM);
      });
      addCastCase(VMCastKind::FPToSI, "cast.fptosi", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "fpsi.ok", Run);
        IB.CreateCondBr(SrcIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *IsD = IOk.CreateLoad(I1Ty, SrcIsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "fpsi64", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "fpsi32", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "fpsi.merge", Run);
        IOk.CreateCondBr(IsD, F64, F32);
        IRBuilder<> C64(F64);
        Value *FD = C64.CreateBitCast(SrcVal, Type::getDoubleTy(Ctx));
        Value *I = C64.CreateFPToSI(FD, I64Ty);
        C64.CreateBr(Merge);
        IRBuilder<> C32(F32);
        Value *FV =
            C32.CreateBitCast(C32.CreateTrunc(SrcVal, Type::getInt32Ty(Ctx)),
                              Type::getFloatTy(Ctx));
        Value *I32 = C32.CreateFPToSI(FV, I64Ty);
        C32.CreateBr(Merge);
        IRBuilder<> CM(Merge);
        PHINode *Res = CM.CreatePHI(I64Ty, 2);
        Res->addIncoming(I, F64);
        Res->addIncoming(I32, F32);
        Value *Out = CM.CreateAnd(Res, DstMask);
        storeReg(CM, RegsPtr, Dst, Out, Ctrs.RegStore);
        NextPc.storeNextPcInc(CM);
      });
      addCastCase(VMCastKind::UIToFP, "cast.uitofp", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "uitofp.ok", Run);
        IB.CreateCondBr(DstIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *V = IOk.CreateAnd(SrcVal, SrcMask);
        Value *IsD = IOk.CreateLoad(I1Ty, IsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "uitofp64", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "uitofp32", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "uitofp.merge", Run);
        IOk.CreateCondBr(IsD, F64, F32);
        IRBuilder<> C64(F64);
        Value *FD = C64.CreateUIToFP(V, Type::getDoubleTy(Ctx));
        Value *P64 = C64.CreateBitCast(FD, I64Ty);
        C64.CreateBr(Merge);
        IRBuilder<> C32(F32);
        Value *FF = C32.CreateUIToFP(V, Type::getFloatTy(Ctx));
        Value *Fbits = C32.CreateBitCast(FF, Type::getInt32Ty(Ctx));
        Value *P32 = C32.CreateZExt(Fbits, I64Ty);
        C32.CreateBr(Merge);
        IRBuilder<> CM(Merge);
        PHINode *Res = CM.CreatePHI(I64Ty, 2);
        Res->addIncoming(P64, F64);
        Res->addIncoming(P32, F32);
        storeReg(CM, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(CM);
      });
      addCastCase(VMCastKind::SIToFP, "cast.sitofp", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "sitofp.ok", Run);
        IB.CreateCondBr(DstIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *V = signExtendMasked(IOk, SrcVal, SrcMask, SrcSign);
        Value *IsD = IOk.CreateLoad(I1Ty, IsDoubleVar);
        BasicBlock *F64 = BasicBlock::Create(Ctx, "sitofp64", Run);
        BasicBlock *F32 = BasicBlock::Create(Ctx, "sitofp32", Run);
        BasicBlock *Merge = BasicBlock::Create(Ctx, "sitofp.merge", Run);
        IOk.CreateCondBr(IsD, F64, F32);
        IRBuilder<> C64(F64);
        Value *FD = C64.CreateSIToFP(V, Type::getDoubleTy(Ctx));
        Value *P64 = C64.CreateBitCast(FD, I64Ty);
        C64.CreateBr(Merge);
        IRBuilder<> C32(F32);
        Value *FF = C32.CreateSIToFP(V, Type::getFloatTy(Ctx));
        Value *Fbits = C32.CreateBitCast(FF, Type::getInt32Ty(Ctx));
        Value *P32 = C32.CreateZExt(Fbits, I64Ty);
        C32.CreateBr(Merge);
        IRBuilder<> CM(Merge);
        PHINode *Res = CM.CreatePHI(I64Ty, 2);
        Res->addIncoming(P64, F64);
        Res->addIncoming(P32, F32);
        storeReg(CM, RegsPtr, Dst, Res, Ctrs.RegStore);
        NextPc.storeNextPcInc(CM);
      });
      addCastCase(VMCastKind::FPTrunc, "cast.fptrunc", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "fptrunc.ok", Run);
        IB.CreateCondBr(SrcIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *SrcIsD = IOk.CreateLoad(I1Ty, SrcIsDoubleVar);
        BasicBlock *Do = BasicBlock::Create(Ctx, "fptrunc.do", Run);
        IOk.CreateCondBr(SrcIsD, Do, Trap);
        IRBuilder<> CDo(Do);
        Value *FD = CDo.CreateBitCast(SrcVal, Type::getDoubleTy(Ctx));
        Value *FF = CDo.CreateFPTrunc(FD, Type::getFloatTy(Ctx));
        Value *Fbits = CDo.CreateBitCast(FF, Type::getInt32Ty(Ctx));
        Value *Out = CDo.CreateZExt(Fbits, I64Ty);
        storeReg(CDo, RegsPtr, Dst, Out, Ctrs.RegStore);
        NextPc.storeNextPcInc(CDo);
      });
      addCastCase(VMCastKind::FPExt, "cast.fpext", [&](IRBuilder<> &IB) {
        BasicBlock *Ok = BasicBlock::Create(Ctx, "fpext.ok", Run);
        IB.CreateCondBr(SrcIsFloat, Ok, Trap);
        IRBuilder<> IOk(Ok);
        Value *SrcIsD = IOk.CreateLoad(I1Ty, SrcIsDoubleVar);
        BasicBlock *Do = BasicBlock::Create(Ctx, "fpext.do", Run);
        IOk.CreateCondBr(SrcIsD, Trap, Do);
        IRBuilder<> CDo(Do);
        Value *FV =
            CDo.CreateBitCast(CDo.CreateTrunc(SrcVal, Type::getInt32Ty(Ctx)),
                              Type::getFloatTy(Ctx));
        Value *FD = CDo.CreateFPExt(FV, Type::getDoubleTy(Ctx));
        Value *Out = CDo.CreateBitCast(FD, I64Ty);
        storeReg(CDo, RegsPtr, Dst, Out, Ctrs.RegStore);
        NextPc.storeNextPcInc(CDo);
      });
      break;
    }
    case VMOpcode::Load: {
      Value *Dst = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *AddrIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *AddrVal = loadReg(CaseIR, RegsPtr, AddrIdx, Ctrs.RegLoad);
      Value *AddrInt = AddrVal;
      if (PtrBits < 64)
        AddrInt = CaseIR.CreateTrunc(AddrVal, IntPtrTy);
      Value *AddrPtr = CaseIR.CreateIntToPtr(AddrInt, I8PtrTy);
      Value *Bytes = computeByteCount(CaseIR, BitsVar);
      Value *BufPtr = CaseIR.CreateBitCast(MemTmp, I8PtrTy);
      CaseIR.CreateMemSet(BufPtr, ConstantInt::get(I8Ty, 0),
                      ConstantInt::get(I64Ty, 8), Align(1));
      CaseIR.CreateMemCpy(BufPtr, Align(1), AddrPtr, Align(1), Bytes);
      Value *Val = CaseIR.CreateLoad(I64Ty, MemTmp);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Val = CaseIR.CreateAnd(Val, Mask);
      storeReg(CaseIR, RegsPtr, Dst, Val, Ctrs.RegStore);
      NextPc.storeNextPcInc(CaseIR);
      break;
    }
    case VMOpcode::Store: {
      Value *ValIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *AddrIdx = CaseIR.CreateLoad(I32Ty, BVar);
      Value *AddrVal = loadReg(CaseIR, RegsPtr, AddrIdx, Ctrs.RegLoad);
      Value *Val = loadReg(CaseIR, RegsPtr, ValIdx, Ctrs.RegLoad);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Val = CaseIR.CreateAnd(Val, Mask);
      CaseIR.CreateStore(Val, MemTmp);
      Value *AddrInt = AddrVal;
      if (PtrBits < 64)
        AddrInt = CaseIR.CreateTrunc(AddrVal, IntPtrTy);
      Value *AddrPtr = CaseIR.CreateIntToPtr(AddrInt, I8PtrTy);
      Value *BufPtr = CaseIR.CreateBitCast(MemTmp, I8PtrTy);
      Value *Bytes = computeByteCount(CaseIR, BitsVar);
      CaseIR.CreateMemCpy(AddrPtr, Align(1), BufPtr, Align(1), Bytes);
      NextPc.storeNextPcInc(CaseIR);
      break;
    }
    case VMOpcode::MemFence: {
      Value *Aux = CaseIR.CreateLoad(I8Ty, AuxVar);
      Value *Aux32 = CaseIR.CreateZExt(Aux, I32Ty);
      BasicBlock *FAcq = BasicBlock::Create(Ctx, "fence.acq", Run);
      BasicBlock *FRel = BasicBlock::Create(Ctx, "fence.rel", Run);
      BasicBlock *FAcqRel = BasicBlock::Create(Ctx, "fence.acqrel", Run);
      BasicBlock *FSeq = BasicBlock::Create(Ctx, "fence.seq", Run);
      SwitchInst *Sw = CaseIR.CreateSwitch(Aux32, FSeq, 4);
      Sw->addCase(
          ConstantInt::get(I32Ty, static_cast<unsigned>(VMFenceKind::Acquire)),
          FAcq);
      Sw->addCase(
          ConstantInt::get(I32Ty, static_cast<unsigned>(VMFenceKind::Release)),
          FRel);
      Sw->addCase(ConstantInt::get(I32Ty, static_cast<unsigned>(
                                              VMFenceKind::AcquireRelease)),
                  FAcqRel);
      Sw->addCase(
          ConstantInt::get(I32Ty, static_cast<unsigned>(VMFenceKind::SeqCst)),
          FSeq);
      IRBuilder<> AcquireIR(FAcq);
      emitFence(AcquireIR, VMFenceKind::Acquire);
      NextPc.storeNextPcInc(AcquireIR);
      IRBuilder<> ReleaseIR(FRel);
      emitFence(ReleaseIR, VMFenceKind::Release);
      NextPc.storeNextPcInc(ReleaseIR);
      IRBuilder<> AcquireReleaseIR(FAcqRel);
      emitFence(AcquireReleaseIR, VMFenceKind::AcquireRelease);
      NextPc.storeNextPcInc(AcquireReleaseIR);
      IRBuilder<> SeqCstIR(FSeq);
      emitFence(SeqCstIR, VMFenceKind::SeqCst);
      NextPc.storeNextPcInc(SeqCstIR);
      break;
    }
    case VMOpcode::Br: {
      Value *Tgt = CaseIR.CreateLoad(I32Ty, TTrueVar);
      Value *InRange =
          CaseIR.CreateICmpULT(Tgt, ConstantInt::get(I32Ty, BlockCount));
      BasicBlock *Ok = BasicBlock::Create(Ctx, "br.ok", Run);
      CaseIR.CreateCondBr(InRange, Ok, Trap);
      IRBuilder<> COk(Ok);
      Value *Ptr = COk.CreateInBoundsGEP(I32Ty, OffsetsPtr, Tgt);
      Value *Off = COk.CreateLoad(I32Ty, Ptr);
      Off = BCDecode.decodeOffset(COk, Tgt, Off);
      NextPc.storeNextPcVal(COk, Off);
      break;
    }
    case VMOpcode::CondBr: {
      Value *CondIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
      Value *CondMask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Value *CondMasked = CaseIR.CreateAnd(CondVal, CondMask);
      Value *Cond = CaseIR.CreateICmpNE(CondMasked, ConstantInt::get(I64Ty, 0));
      Value *TgtT = CaseIR.CreateLoad(I32Ty, TTrueVar);
      Value *TgtF = CaseIR.CreateLoad(I32Ty, TFalseVar);
      Value *OkT = CaseIR.CreateICmpULT(TgtT, ConstantInt::get(I32Ty, BlockCount));
      Value *OkF = CaseIR.CreateICmpULT(TgtF, ConstantInt::get(I32Ty, BlockCount));
      Value *BothOk = CaseIR.CreateAnd(OkT, OkF);
      BasicBlock *Ok = BasicBlock::Create(Ctx, "cbr.ok", Run);
      CaseIR.CreateCondBr(BothOk, Ok, Trap);
      IRBuilder<> COk(Ok);
      Value *PtrT = COk.CreateInBoundsGEP(I32Ty, OffsetsPtr, TgtT);
      Value *PtrF = COk.CreateInBoundsGEP(I32Ty, OffsetsPtr, TgtF);
      Value *OffT = COk.CreateLoad(I32Ty, PtrT);
      Value *OffF = COk.CreateLoad(I32Ty, PtrF);
      OffT = BCDecode.decodeOffset(COk, TgtT, OffT);
      OffF = BCDecode.decodeOffset(COk, TgtF, OffF);
      Value *Next = COk.CreateSelect(Cond, OffT, OffF);
      NextPc.storeNextPcVal(COk, Next);
      break;
    }
    case VMOpcode::Switch: {
      Value *CondIdx = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Value *Cond = CaseIR.CreateAnd(CondVal, Mask);
      Value *DefaultId = CaseIR.CreateLoad(I32Ty, TTrueVar);
      Value *Off = CaseIR.CreateLoad(I32Ty, AVar);
      Value *Count = CaseIR.CreateLoad(I32Ty, BVar);
      Value *OkA =
          CaseIR.CreateICmpULT(DefaultId, ConstantInt::get(I32Ty, BlockCount));
      Value *OkB = CaseIR.CreateICmpULE(CaseIR.CreateAdd(Off, Count),
                                    ConstantInt::get(I32Ty, SwitchValsCount));
      Value *OkC = CaseIR.CreateICmpULE(CaseIR.CreateAdd(Off, Count),
                                    ConstantInt::get(I32Ty, SwitchTgtsCount));
      Value *OkAll = CaseIR.CreateAnd(OkA, CaseIR.CreateAnd(OkB, OkC));
      BasicBlock *Ok = BasicBlock::Create(Ctx, "sw.ok", Run);
      CaseIR.CreateCondBr(OkAll, Ok, Trap);
      IRBuilder<> COk(Ok);
      // Use entry-block alloca to avoid stack leak in loops
      COk.CreateStore(DefaultId, SwTgtVar);
      Value *UseBin =
          COk.CreateICmpUGE(Count, ConstantInt::get(I32Ty, 32));
      BasicBlock *BinBB = BasicBlock::Create(Ctx, "sw.bin", Run);
      BasicBlock *LinBB = BasicBlock::Create(Ctx, "sw.lin", Run);
      BasicBlock *ExitBB = BasicBlock::Create(Ctx, "sw.exit", Run);
      COk.CreateCondBr(UseBin, BinBB, LinBB);

      // Linear scan for small switches.
      IRBuilder<> LinIR(LinBB);
      // Use entry-block alloca to avoid stack leak in loops
      LinIR.CreateStore(ConstantInt::get(I32Ty, 0), SwIdxVar);
      BasicBlock *LoopBB = BasicBlock::Create(Ctx, "sw.loop", Run);
      BasicBlock *BodyBB = BasicBlock::Create(Ctx, "sw.body", Run);
      LinIR.CreateBr(LoopBB);
      IRBuilder<> LinLoopIR(LoopBB);
      Value *Idx = LinLoopIR.CreateLoad(I32Ty, SwIdxVar);
      Value *Cmp = LinLoopIR.CreateICmpULT(Idx, Count);
      LinLoopIR.CreateCondBr(Cmp, BodyBB, ExitBB);
      IRBuilder<> LinBodyIR(BodyBB);
      Value *At = LinBodyIR.CreateAdd(Off, Idx);
      Value *VPtr = LinBodyIR.CreateInBoundsGEP(I64Ty, SwitchValsPtr, At);
      Value *V = LinBodyIR.CreateLoad(I64Ty, VPtr);
      V = BCDecode.decodeSwitchVal(LinBodyIR, At, V);
      Value *VMasked = LinBodyIR.CreateAnd(V, Mask);
      Value *IsEq = LinBodyIR.CreateICmpEQ(VMasked, Cond);
      BasicBlock *FoundBB = BasicBlock::Create(Ctx, "sw.found", Run);
      BasicBlock *NextBB = BasicBlock::Create(Ctx, "sw.next", Run);
      LinBodyIR.CreateCondBr(IsEq, FoundBB, NextBB);
      IRBuilder<> LinFoundIR(FoundBB);
      Value *TPtr = LinFoundIR.CreateInBoundsGEP(I32Ty, SwitchTgtsPtr, At);
      Value *T = LinFoundIR.CreateLoad(I32Ty, TPtr);
      T = BCDecode.decodeSwitchTgt(LinFoundIR, At, T);
      LinFoundIR.CreateStore(T, SwTgtVar);
      LinFoundIR.CreateBr(ExitBB);
      IRBuilder<> LinNextIR(NextBB);
      Value *IdxN = LinNextIR.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
      LinNextIR.CreateStore(IdxN, SwIdxVar);
      LinNextIR.CreateBr(LoopBB);

      // Binary search for large switches.
      IRBuilder<> BinInitIR(BinBB);
      // Use entry-block allocas to avoid stack leak in loops
      BinInitIR.CreateStore(ConstantInt::get(I32Ty, 0), SwLowVar);
      BinInitIR.CreateStore(Count, SwHighVar);
      BasicBlock *BinLoop = BasicBlock::Create(Ctx, "sw.bin.loop", Run);
      BasicBlock *BinBody = BasicBlock::Create(Ctx, "sw.bin.body", Run);
      BinInitIR.CreateBr(BinLoop);
      IRBuilder<> BinLoopIR(BinLoop);
      Value *Low = BinLoopIR.CreateLoad(I32Ty, SwLowVar);
      Value *High = BinLoopIR.CreateLoad(I32Ty, SwHighVar);
      Value *BCond = BinLoopIR.CreateICmpULT(Low, High);
      BinLoopIR.CreateCondBr(BCond, BinBody, ExitBB);
      IRBuilder<> BinBodyIR(BinBody);
      Value *Sum = BinBodyIR.CreateAdd(Low, High);
      Value *Mid = BinBodyIR.CreateLShr(Sum, ConstantInt::get(I32Ty, 1));
      Value *AtB = BinBodyIR.CreateAdd(Off, Mid);
      Value *VBPtr = BinBodyIR.CreateInBoundsGEP(I64Ty, SwitchValsPtr, AtB);
      Value *VB = BinBodyIR.CreateLoad(I64Ty, VBPtr);
      VB = BCDecode.decodeSwitchVal(BinBodyIR, AtB, VB);
      Value *VBMasked = BinBodyIR.CreateAnd(VB, Mask);
      Value *IsEqB = BinBodyIR.CreateICmpEQ(VBMasked, Cond);
      BasicBlock *BinFound = BasicBlock::Create(Ctx, "sw.bin.found", Run);
      BasicBlock *BinCmp = BasicBlock::Create(Ctx, "sw.bin.cmp", Run);
      BinBodyIR.CreateCondBr(IsEqB, BinFound, BinCmp);
      IRBuilder<> BinFoundIR(BinFound);
      Value *TBPtr = BinFoundIR.CreateInBoundsGEP(I32Ty, SwitchTgtsPtr, AtB);
      Value *TB = BinFoundIR.CreateLoad(I32Ty, TBPtr);
      TB = BCDecode.decodeSwitchTgt(BinFoundIR, AtB, TB);
      BinFoundIR.CreateStore(TB, SwTgtVar);
      BinFoundIR.CreateBr(ExitBB);
      IRBuilder<> BinCmpIR(BinCmp);
      Value *Less = BinCmpIR.CreateICmpULT(Cond, VBMasked);
      BasicBlock *BinHi = BasicBlock::Create(Ctx, "sw.bin.hi", Run);
      BasicBlock *BinLo = BasicBlock::Create(Ctx, "sw.bin.lo", Run);
      BinCmpIR.CreateCondBr(Less, BinHi, BinLo);
      IRBuilder<> BinHiIR(BinHi);
      BinHiIR.CreateStore(Mid, SwHighVar);
      BinHiIR.CreateBr(BinLoop);
      IRBuilder<> BinLoIR(BinLo);
      Value *MidPlus = BinLoIR.CreateAdd(Mid, ConstantInt::get(I32Ty, 1));
      BinLoIR.CreateStore(MidPlus, SwLowVar);
      BinLoIR.CreateBr(BinLoop);

      IRBuilder<> ExitIR(ExitBB);
      Value *FinalTgt = ExitIR.CreateLoad(I32Ty, SwTgtVar);
      Value *OkT =
          ExitIR.CreateICmpULT(FinalTgt, ConstantInt::get(I32Ty, BlockCount));
      BasicBlock *TgtOk = BasicBlock::Create(Ctx, "sw.tok", Run);
      ExitIR.CreateCondBr(OkT, TgtOk, Trap);
      IRBuilder<> TgtIR(TgtOk);
      Value *Ptr = TgtIR.CreateInBoundsGEP(I32Ty, OffsetsPtr, FinalTgt);
      Value *Offs = TgtIR.CreateLoad(I32Ty, Ptr);
      Offs = BCDecode.decodeOffset(TgtIR, FinalTgt, Offs);
      NextPc.storeNextPcVal(TgtIR, Offs);
      break;
    }
    case VMOpcode::Select: {
      Value *Dst = CaseIR.CreateLoad(I32Ty, DstVar);
      Value *CondIdx = CaseIR.CreateLoad(I32Ty, AVar);
      Value *TIdx = CaseIR.CreateLoad(I32Ty, TTrueVar);
      Value *FIdx = CaseIR.CreateLoad(I32Ty, TFalseVar);
      Value *CondVal = loadReg(CaseIR, RegsPtr, CondIdx, Ctrs.RegLoad);
      Value *CondMask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Value *CondMasked = CaseIR.CreateAnd(CondVal, CondMask);
      Value *Cond = CaseIR.CreateICmpNE(CondMasked, ConstantInt::get(I64Ty, 0));
      Value *TV = loadReg(CaseIR, RegsPtr, TIdx, Ctrs.RegLoad);
      Value *FV = loadReg(CaseIR, RegsPtr, FIdx, Ctrs.RegLoad);
      Value *Sel = CaseIR.CreateSelect(Cond, TV, FV);
      Value *Mask = CaseIR.CreateLoad(I64Ty, MaskVar);
      Sel = CaseIR.CreateAnd(Sel, Mask);
      storeReg(CaseIR, RegsPtr, Dst, Sel, Ctrs.RegStore);
      NextPc.storeNextPcInc(CaseIR);
      break;
    }
    case VMOpcode::Ret: {
      CaseIR.CreateBr(Ret);
      break;
    }
    case VMOpcode::CallHost:
    case VMOpcode::CallHostIndirect: {
      Value *Idx = CaseIR.CreateLoad(I32Ty, CallVar);
      SwitchInst *Sw = CaseIR.CreateSwitch(Idx, Trap, Helpers.size());
      for (unsigned i = 0; i < Helpers.size(); ++i) {
        BasicBlock *C =
            BasicBlock::Create(Ctx, "call." + std::to_string(i), Run);
        Sw->addCase(ConstantInt::get(I32Ty, i), C);
        IRBuilder<> CI(C);
        checkCallSignature(Helpers[i]->getFunctionType(), {State},
                           "vm:callhost:opcode");
        CI.CreateCall(Helpers[i], {State});
        NextPc.storeNextPcInc(CI);
      }
      break;
    }
    case VMOpcode::Trap:
      CaseIR.CreateBr(Trap);
      break;
    }
  }

  if (HardRt) {
    const uint64_t InstrBytes =
        static_cast<uint64_t>(BC.Instrs.size()) *
        static_cast<uint64_t>(Layout.Stride);
    const uint64_t OffBytes =
        static_cast<uint64_t>(BC.BlockOffsets.size()) * 4ULL;
    const uint64_t SwitchValBytes =
        static_cast<uint64_t>(BC.SwitchValues.size()) * 8ULL;
    const uint64_t SwitchTgtBytes =
        static_cast<uint64_t>(BC.SwitchTargets.size()) * 4ULL;
    const uint64_t OpDecodeBytes =
        Globals.OpDecode ? static_cast<uint64_t>(OpCount) : 0ULL;
    const uint64_t OpSlotBytes =
        OpSlotGV ? static_cast<uint64_t>(OpSlots) * 4ULL : 0ULL;
    const uint64_t OpSlotEncBytes =
        OpSlotEncGV ? static_cast<uint64_t>(OpSlots) * 4ULL : 0ULL;
    const uint64_t DispBytes =
        static_cast<uint64_t>(DispatchCount) *
        static_cast<uint64_t>(PtrBits / 8u);
    const uint64_t TotalHashBytes =
        InstrBytes + OffBytes + SwitchValBytes + SwitchTgtBytes +
        OpDecodeBytes + OpSlotBytes + OpSlotEncBytes +
        DispBytes * static_cast<uint64_t>(DispatchPoints);
    uint64_t HashXor = cryptoutils->get_uint64_t();
    if (HashXor == 0)
      HashXor = Globals.HashKey ^ Globals.HashMul ^ EncInfo.MixConst;
    unsigned HashStyle = static_cast<unsigned>(cryptoutils->get_range(3));
    AntiDebugConfig AD = buildAntiDebugConfig();
    uint64_t MixC1 = cryptoutils->get_uint64_t() | 1ULL;
    uint64_t MixC2 = cryptoutils->get_uint64_t() | 1ULL;
    uint64_t MixC3 = cryptoutils->get_uint64_t();
    uint32_t TripTag = cryptoutils->get_uint32_t() | 1u;

    std::string HashInitName = ("vm_hash_init_" + F.Name).str();
    GlobalVariable *HashInitGV = new GlobalVariable(
        M, I1Ty, false, GlobalValue::PrivateLinkage,
        ConstantInt::getFalse(Ctx), HashInitName);
    std::string HashInitTag = ("vm.hash.init." + F.Name).str();
    obfuscateSymbolName(*HashInitGV, M, HashInitTag, HashInitName);
    std::string HashValName = ("vm_hash_val_" + F.Name).str();
    GlobalVariable *HashValGV = new GlobalVariable(
        M, I64Ty, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I64Ty, 0), HashValName);
    std::string HashValTag = ("vm.hash.val." + F.Name).str();
    obfuscateSymbolName(*HashValGV, M, HashValTag, HashValName);
    std::string HashCtrName = ("vm_hash_ctr_" + F.Name).str();
    GlobalVariable *HashCtrGV = new GlobalVariable(
        M, I32Ty, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I32Ty, 0), HashCtrName);
    std::string HashCtrTag = ("vm.hash.ctr." + F.Name).str();
    obfuscateSymbolName(*HashCtrGV, M, HashCtrTag, HashCtrName);
    uint32_t MinBits = 4u;
    if (TotalHashBytes >= (128ull * 1024ull))
      MinBits = 7u;
    if (TotalHashBytes >= (256ull * 1024ull))
      MinBits = 9u;
    if (TotalHashBytes >= (512ull * 1024ull))
      MinBits = 11u;
    if (TotalHashBytes >= (1024ull * 1024ull))
      MinBits = 12u;
    if (TotalHashBytes >= (2ull * 1024ull * 1024ull))
      MinBits = 13u;
    if (TotalHashBytes >= (4ull * 1024ull * 1024ull))
      MinBits = 14u;
    uint32_t CheckBits =
        MinBits + static_cast<uint32_t>(cryptoutils->get_range(3));
    if (CheckBits > 16)
      CheckBits = 16;
    uint32_t CheckMask = (CheckBits >= 31) ? 0x7FFFFFFFu : ((1u << CheckBits) - 1u);
    if (CheckMask == 0)
      CheckMask = 3u;
    uint32_t CheckTarget = cryptoutils->get_uint32_t() & CheckMask;

    // Periodic integrity sampling keeps overhead bounded while making
    // tampering probabilistically detectable over time.
    BasicBlock *RtCheck = BasicBlock::Create(Ctx, "hard.rt", Run, Loop);
    BasicBlock *RtInit = BasicBlock::Create(Ctx, "hard.rt.init", Run, Loop);
    BasicBlock *RtMaybe = BasicBlock::Create(Ctx, "hard.rt.maybe", Run, Loop);
    BasicBlock *RtVerify =
        BasicBlock::Create(Ctx, "hard.rt.verify", Run, Loop);
    BasicBlock *RtOk = BasicBlock::Create(Ctx, "hard.rt.ok", Run, Loop);
    if (auto *Term = Entry->getTerminator())
      Term->eraseFromParent();
    IRBuilder<> RtEntryIR(Entry);
    RtEntryIR.CreateBr(RtCheck);

    IRBuilder<> RtCheckIR(RtCheck);

    Function *HashFn = getOrCreateVMHashFunc(M, HashStyle);
    auto nextMul = [&]() -> uint64_t {
      uint64_t V = cryptoutils->get_uint64_t();
      if (V == 0)
        V = Globals.HashMul ^ EncInfo.MixConst;
      return V | 1ULL;
    };
    struct HashSeg {
      Value *Ptr = nullptr;
      GlobalVariable *GV = nullptr;
      uint64_t Len = 0;
      uint64_t Salt = 0;
      uint64_t Mul = 0;
    };
    SmallVector<HashSeg, 12> Segs;
    if (InstrBytes > 0)
      Segs.push_back({BCPtr, nullptr, InstrBytes, EncInfo.SaltInstr, nextMul()});
    if (OffBytes > 0)
      Segs.push_back({OffsetsPtr, nullptr, OffBytes, EncInfo.SaltOff, nextMul()});
    if (SwitchValBytes > 0)
      Segs.push_back({SwitchValsPtr, nullptr, SwitchValBytes, EncInfo.SaltSwitchVal,
                      nextMul()});
    if (SwitchTgtBytes > 0)
      Segs.push_back({SwitchTgtsPtr, nullptr, SwitchTgtBytes, EncInfo.SaltSwitchTgt,
                      nextMul()});
    if (OpDecodeGV && OpDecodeBytes > 0) {
      Segs.push_back({nullptr, OpDecodeGV, OpDecodeBytes, EncInfo.PermSeedMix,
                      nextMul()});
    }
    if (OpSlotGV && OpSlotBytes > 0) {
      Segs.push_back({nullptr, OpSlotGV, OpSlotBytes, EncInfo.MulConst1,
                      nextMul()});
    }
    if (OpSlotEncGV && OpSlotEncBytes > 0) {
      Segs.push_back({nullptr, OpSlotEncGV, OpSlotEncBytes, EncInfo.MulConst2,
                      nextMul()});
    }
    if (DispatchMode == VMDispatch::Indirect && DispBytes > 0) {
      for (unsigned Tbl = 0; Tbl < DispatchPoints; ++Tbl) {
        if (!DispTables[Tbl].Table)
          continue;
        uint64_t Salt = EncInfo.MixConst ^ (static_cast<uint64_t>(Tbl) << 32);
        Segs.push_back({nullptr, DispTables[Tbl].Table, DispBytes, Salt,
                        nextMul()});
      }
    }
    if (Segs.size() > 1) {
      for (unsigned i = static_cast<unsigned>(Segs.size()); i > 1; --i) {
        unsigned J = static_cast<unsigned>(cryptoutils->get_range(i));
        std::swap(Segs[i - 1], Segs[J]);
      }
    }
    Value *Init = RtCheckIR.CreateLoad(I1Ty, HashInitGV);
    Value *IsInit = RtCheckIR.CreateICmpNE(Init, ConstantInt::getFalse(Ctx));
    RtCheckIR.CreateCondBr(IsInit, RtMaybe, RtInit);

    AntiDebugConfig ADLight = AD;
    ADLight.UseTiming = false;
    auto emitAntiDebugMix = [&](IRBuilder<> &IB,
                                const AntiDebugConfig &CfgUse)
        -> BasicBlock * {
      AntiDebugResult ADRes = emitInlineAntiDebug(IB, M, CfgUse);
      IRBuilder<> AdTailIR(ADRes.Tail);
      Value *Dbg = ADRes.Flag;
      BasicBlock *DbgTail =
          emitRuntimeDebugIf(AdTailIR, M, Dbg, AdMsg, RtDebug);
      IRBuilder<> AdMixIR(DbgTail ? DbgTail : AdTailIR.GetInsertBlock());
      if (DbgADGV) {
        Value *Dbg32 = AdMixIR.CreateZExt(Dbg, I32Ty);
        AdMixIR.CreateStore(Dbg32, DbgADGV);
      }
      if (GlobalVariable *TripGV = getOrCreateObfFailCode(M)) {
        Value *Cur = AdMixIR.CreateLoad(I32Ty, TripGV);
        Value *Tag = ConstantInt::get(I32Ty, TripTag);
        Value *Next = AdMixIR.CreateSelect(Dbg, Tag, Cur);
        AdMixIR.CreateStore(Next, TripGV);
      }
      Value *KeyVal = AdMixIR.CreateLoad(I64Ty, KeyPtr);
      Value *PcVal = AdMixIR.CreateLoad(I32Ty, PcPtr);
      Value *Mix = AdMixIR.CreateZExt(PcVal, I64Ty);
      Mix = AdMixIR.CreateXor(Mix, ConstantInt::get(I64Ty, MixC1));
      Mix = AdMixIR.CreateMul(Mix, ConstantInt::get(I64Ty, MixC2));
      Mix = AdMixIR.CreateAdd(Mix, ConstantInt::get(I64Ty, MixC3));
      Value *Dbg64 = AdMixIR.CreateZExt(Dbg, I64Ty);
      Value *Delta = AdMixIR.CreateMul(Dbg64, Mix);
      Value *NewKey = AdMixIR.CreateXor(KeyVal, Delta);
      AdMixIR.CreateStore(NewKey, KeyPtr);
      return DbgTail ? DbgTail : ADRes.Tail;
    };

    auto emitHash = [&](IRBuilder<> &IB) -> Value * {
      Value *Hash = ConstantInt::get(I64Ty, Globals.HashKey);
      auto hashBytes = [&](Value *Seed, Value *Ptr, uint64_t Len,
                           uint64_t Salt, uint64_t Mul) -> Value * {
        if (Len == 0)
          return Seed;
        Value *SeedV = Seed;
        if (Salt != 0)
          SeedV = IB.CreateXor(SeedV, ConstantInt::get(I64Ty, Salt));
        Value *LenV = ConstantInt::get(I64Ty, Len);
        Value *PtrI8 =
            Ptr->getType() == I8PtrTy ? Ptr : IB.CreateBitCast(Ptr, I8PtrTy);
        Value *MulV = ConstantInt::get(I64Ty, Mul);
        return IB.CreateCall(HashFn, {PtrI8, LenV, SeedV, MulV});
      };
      for (const auto &Seg : Segs) {
        Value *Ptr = Seg.Ptr;
        if (!Ptr && Seg.GV)
          Ptr = IB.CreateBitCast(Seg.GV, I8PtrTy);
        Hash = hashBytes(Hash, Ptr, Seg.Len, Seg.Salt, Seg.Mul);
      }
      return Hash;
    };

    IRBuilder<> RtInitIR(RtInit);
    BasicBlock *InitTail = emitAntiDebugMix(RtInitIR, ADLight);
    IRBuilder<> RtInitMixIR(InitTail);
    Value *InitHash = emitHash(RtInitMixIR);
    Value *Enc = RtInitMixIR.CreateXor(InitHash, ConstantInt::get(I64Ty, HashXor));
    RtInitMixIR.CreateStore(Enc, HashValGV);
    RtInitMixIR.CreateStore(ConstantInt::getTrue(Ctx), HashInitGV);
    RtInitMixIR.CreateStore(ConstantInt::get(I32Ty, 0), HashCtrGV);
    RtInitMixIR.CreateBr(RtOk);

    IRBuilder<> RtMaybeIR(RtMaybe);
    Value *Ctr = RtMaybeIR.CreateLoad(I32Ty, HashCtrGV);
    Value *Next = RtMaybeIR.CreateAdd(Ctr, ConstantInt::get(I32Ty, 1));
    RtMaybeIR.CreateStore(Next, HashCtrGV);
    Value *DoCheck = RtMaybeIR.CreateICmpEQ(
        RtMaybeIR.CreateAnd(Next, ConstantInt::get(I32Ty, CheckMask)),
        ConstantInt::get(I32Ty, CheckTarget));
    RtMaybeIR.CreateCondBr(DoCheck, RtVerify, RtOk);

    IRBuilder<> RtVerifyIR(RtVerify);
    BasicBlock *VerifyTail = emitAntiDebugMix(RtVerifyIR, AD);
    IRBuilder<> RtVerifyMixIR(VerifyTail);
    Value *Stored = RtVerifyMixIR.CreateLoad(I64Ty, HashValGV);
    Value *Dec = RtVerifyMixIR.CreateXor(Stored, ConstantInt::get(I64Ty, HashXor));
    Value *VerifyHash = emitHash(RtVerifyMixIR);
    Value *Match = RtVerifyMixIR.CreateICmpEQ(VerifyHash, Dec);
    Value *Bad = RtVerifyMixIR.CreateNot(Match);
    RtVerifyMixIR.CreateCondBr(Bad, Trap, RtOk);

    IRBuilder<> RtOkIR(RtOk);
    RtOkIR.CreateBr(Loop);
  }

  return Run;
}

Function *llvm::obfvm::emitVMInterpreter(Module &M, const VMFunction &F,
                                         const VMBytecode &BC,
                                         const VMBytecodeGlobals &Globals,
                                         const VMBCLayout &Layout,
                                         const VMBCEncodingInfo &EncInfo,
                                         const VMConfig &Cfg, uint64_t BCKey) {
  if (Cfg.Mode == VMMode::BB)
    return emitVMInterpreterBB(M, F, Cfg);
  if (Cfg.Mode != VMMode::Opcode)
    return nullptr;
  return emitVMInterpreterOpcodeBC(M, F, BC, Globals, Layout, EncInfo, Cfg,
                                   BCKey);
}
