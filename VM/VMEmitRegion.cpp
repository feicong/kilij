//===- VMEmitRegion.cpp - Emit region VM executors -----------------------===//
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
// Emits region executors and the region dispatcher, including register
// caching and slot permutation.
//
//===----------------------------------------------------------------------===//
#include "VMEmitRegion.h"
#include "VMEmitUtils.h"
#include "CryptoUtils.h"
#include "VMMath.h"
#include "VMRegionFormation.h"
#include "VMRuntime.h"
#include "Utils.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <functional>
#include <limits>
#include <utility>
#include <vector>

using namespace llvm;
using namespace llvm::obfvm;

// Sentinel region ID that signals the dispatcher to exit the VM loop.
static constexpr uint32_t kVmExitId = std::numeric_limits<uint32_t>::max();
static_assert(kVmExitId == 0xFFFFFFFFu, "exit id must be uint32 max");

static VMTypeKind mapTypeKind(Type *Ty) {
  if (Ty->isIntegerTy(1))
    return VMTypeKind::I1;
  if (Ty->isIntegerTy(8))
    return VMTypeKind::I8;
  if (Ty->isIntegerTy(16))
    return VMTypeKind::I16;
  if (Ty->isIntegerTy(32))
    return VMTypeKind::I32;
  if (Ty->isIntegerTy(64))
    return VMTypeKind::I64;
  if (Ty->isFloatTy())
    return VMTypeKind::F32;
  if (Ty->isDoubleTy())
    return VMTypeKind::F64;
  if (Ty->isPointerTy())
    return VMTypeKind::Ptr;
  return VMTypeKind::I64;
}

// Each region executor is a standalone function to keep dispatch indirect.
// Unlike opcode mode, regions operate on cached SSA regs instead of a flat
// register array, spilling only at region boundaries.
static Function *emitRegionExecutor(
    Module &M, const VMFunction &F, const VMFunctionLiveness &Live,
    const VMRegion &R, const DenseMap<uint32_t, uint32_t> &BlockToRegion,
    const DenseMap<uint32_t, BitVector> &RegionLiveIn,
    const DenseMap<uint32_t, SmallVector<uint32_t, 4>> &Preds,
    const SmallVectorImpl<uint32_t> &RegionSlot, VMHandlers Handlers,
    bool AllowArithExpand, const VMCounters &Ctrs, std::string &Err) {
  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  StructType *StateTy = getOrCreateVMStateType(M);
  PointerType *StatePtrTy = PointerType::getUnqual(StateTy);
  FunctionType *FT = FunctionType::get(I32Ty, {StatePtrTy}, false);
  std::string Name =
      ("vm_region_" + F.Name + "_" + std::to_string(R.Id)).str();
  Function *Exec = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  Exec->addFnAttr("vm_runtime");
  std::string Tag =
      ("vm.region." + F.Name + "." + std::to_string(R.Id)).str();
  obfuscateSymbolName(*Exec, M, Tag, Name);
  Exec->addFnAttr(Attribute::NoInline);
  // Keep region executors isolated so dispatch stays indirect and opaque.

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Exec);
  BasicBlock *Trap = BasicBlock::Create(Ctx, "trap", Exec);

  IRBuilder<> EntryIR(Entry);
  Value *State = Exec->arg_begin();
  Value *RegsPtr = EntryIR.CreateLoad(
      PointerType::getUnqual(I64Ty),
      getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Regs));

  DenseMap<uint32_t, BasicBlock *> BlockBBs;
  for (uint32_t Bid : R.Blocks) {
    BasicBlock *BB = BasicBlock::Create(Ctx, "r" + std::to_string(Bid), Exec);
    BlockBBs.insert({Bid, BB});
  }

  std::vector<DenseMap<uint32_t, PHINode *>> PhiMap;
  PhiMap.resize(F.Blocks.size());
  for (uint32_t Bid : R.Blocks) {
    auto It = Preds.find(Bid);
    unsigned PredCount = (It != Preds.end()) ? It->second.size() : 0;
    if (Bid == R.Blocks.front())
      PredCount = 0;
    if (PredCount == 0)
      continue;
    const BitVector &LiveIn = Live.Blocks[Bid].LiveIn;
    BasicBlock *BB = BlockBBs[Bid];
    // Live-ins are materialized as PHIs so regions can cache registers locally.
    for (int Rg = LiveIn.find_first(); Rg != -1; Rg = LiveIn.find_next(Rg)) {
      PHINode *Phi = PHINode::Create(I64Ty, PredCount, "r" + std::to_string(Rg),
                                     BB->begin());
      PhiMap[Bid].insert({static_cast<uint32_t>(Rg), Phi});
    }
  }

  auto RegLiveIt = RegionLiveIn.find(R.Id);
  BitVector RegionIn = (RegLiveIt != RegionLiveIn.end())
                           ? RegLiveIt->second
                           : BitVector(F.RegCount);

  // Cache live regs in SSA to avoid repeated loads/stores inside the region.
  std::vector<Value *> RegCache(F.RegCount, nullptr);
  for (int Rg = RegionIn.find_first(); Rg != -1; Rg = RegionIn.find_next(Rg)) {
    Value *Idx = ConstantInt::get(I32Ty, Rg);
    RegCache[Rg] = loadReg(EntryIR, RegsPtr, Idx, Ctrs.RegLoad);
  }

  EntryIR.CreateBr(BlockBBs[R.Blocks.front()]);

  IRBuilder<> TrapIR(Trap);
  FunctionCallee TrapFn = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  TrapIR.CreateCall(TrapFn);
  TrapIR.CreateUnreachable();

  unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();

  for (uint32_t Bid : R.Blocks) {
    BasicBlock *BB = BlockBBs[Bid];
    IRBuilder<> BlockIR(BB);

    auto getReg = [&](uint32_t Rg) -> Value * {
      if (Rg >= RegCache.size()) {
        Err = "vm: reg index out of range in region emit";
        return ConstantInt::get(I64Ty, 0);
      }
      if (!RegCache[Rg]) {
        Value *Idx = ConstantInt::get(I32Ty, Rg);
        RegCache[Rg] = loadReg(BlockIR, RegsPtr, Idx, Ctrs.RegLoad);
      }
      return RegCache[Rg];
    };

    auto setReg = [&](uint32_t Rg, Value *V) {
      if (Rg >= RegCache.size()) {
        Err = "vm: reg index out of range in region emit";
        return;
      }
      RegCache[Rg] = V;
    };

    // Slot permutation decouples region IDs from dispatch indices.
    auto slotForRegion = [&](uint32_t RegionId) -> uint32_t {
      if (RegionId >= RegionSlot.size()) {
        Err = "vm: region slot out of range";
        return 0;
      }
      return RegionSlot[RegionId];
    };

    if (Bid != R.Blocks.front()) {
      const BitVector &LiveIn = Live.Blocks[Bid].LiveIn;
      for (int Rg = LiveIn.find_first(); Rg != -1; Rg = LiveIn.find_next(Rg)) {
        auto PhiIt = PhiMap[Bid].find(static_cast<uint32_t>(Rg));
        if (PhiIt != PhiMap[Bid].end()) {
          RegCache[Rg] = PhiIt->second;
        } else {
          Value *Idx = ConstantInt::get(I32Ty, Rg);
          RegCache[Rg] = loadReg(BlockIR, RegsPtr, Idx, Ctrs.RegLoad);
        }
      }
    }

    auto addPhiIncoming = [&](uint32_t Succ) {
      auto PhiIt = PhiMap[Succ].begin();
      for (; PhiIt != PhiMap[Succ].end(); ++PhiIt) {
        uint32_t Rg = PhiIt->first;
        PHINode *Phi = PhiIt->second;
        Value *V = getReg(Rg);
        Phi->addIncoming(V, BlockIR.GetInsertBlock());
      }
    };

    // Spill only live-out regs so cross-region state stays coherent.
    auto storeLiveOut = [&](const BitVector &LiveOut, IRBuilder<> &SB) {
      for (int Rg = LiveOut.find_first(); Rg != -1;
           Rg = LiveOut.find_next(Rg)) {
        Value *Idx = ConstantInt::get(I32Ty, Rg);
        Value *Val = getReg(static_cast<uint32_t>(Rg));
        storeReg(SB, RegsPtr, Idx, Val, Ctrs.RegStore);
      }
    };

    bool Terminated = false;
    for (const VMInstr &I : F.Blocks[Bid].Instrs) {
      if (Terminated || !Err.empty())
        break;
      bumpCounter(BlockIR, Ctrs.Instr);
      switch (I.Op) {
      case VMOpcode::Mov: {
        Value *SrcVal = nullptr;
        if (!I.Ops.empty()) {
          if (I.Ops[0].K == VMValue::Kind::Reg) {
            SrcVal = getReg(I.Ops[0].Reg);
          } else if (I.Ops[0].K == VMValue::Kind::Const) {
            SrcVal = asI64(I.Ops[0].C, I64Ty);
          } else {
            SrcVal = ConstantInt::get(I64Ty, I.Ops[0].Imm);
          }
        }
        SrcVal = maskValue(BlockIR, SrcVal, I.Ty.Kind, PtrBits);
        setReg(I.Dst, SrcVal);
        break;
      }
      case VMOpcode::BinOp: {
        Value *AVal = getReg(I.Ops[0].Reg);
        Value *BVal = getReg(I.Ops[1].Reg);
        Value *Res = nullptr;
        if (I.Ty.Kind == VMTypeKind::F32 || I.Ty.Kind == VMTypeKind::F64) {
          Value *FA = unpackValue(BlockIR, AVal, I.Ty.Kind, PtrBits);
          Value *FB = unpackValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
          Value *FR = nullptr;
          switch (I.Bin) {
          case VMBinOp::Add:
          case VMBinOp::FAdd:
            FR = BlockIR.CreateFAdd(FA, FB);
            break;
          case VMBinOp::Sub:
          case VMBinOp::FSub:
            FR = BlockIR.CreateFSub(FA, FB);
            break;
          case VMBinOp::Mul:
          case VMBinOp::FMul:
            FR = BlockIR.CreateFMul(FA, FB);
            break;
          case VMBinOp::FDiv:
            FR = BlockIR.CreateFDiv(FA, FB);
            break;
          case VMBinOp::FRem:
            FR = BlockIR.CreateFRem(FA, FB);
            break;
          default:
            BlockIR.CreateBr(Trap);
            Terminated = true;
            continue;
          }
          Res = packValue(BlockIR, FR, I.Ty.Kind, PtrBits);
        } else {
          switch (I.Bin) {
          case VMBinOp::Add:
            Res = emitIntAdd(BlockIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Sub:
            Res = emitIntSub(BlockIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Mul:
            Res = BlockIR.CreateMul(AVal, BVal);
            break;
          case VMBinOp::UDiv: {
            Value *BMask = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(I64Ty, 0);
            Value *IsZero = BlockIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "udiv.ok", Exec);
            BlockIR.CreateCondBr(IsZero, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Res = BlockIR.CreateUDiv(maskValue(BlockIR, AVal, I.Ty.Kind, PtrBits), BMask);
            break;
          }
          case VMBinOp::SDiv: {
            Value *BMask = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(I64Ty, 0);
            Value *IsZero = BlockIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "sdiv.ok", Exec);
            BlockIR.CreateCondBr(IsZero, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits);
            Value *BS = signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Res = BlockIR.CreateSDiv(AS, BS);
            break;
          }
          case VMBinOp::URem: {
            Value *BMask = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(I64Ty, 0);
            Value *IsZero = BlockIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "urem.ok", Exec);
            BlockIR.CreateCondBr(IsZero, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Res = BlockIR.CreateURem(maskValue(BlockIR, AVal, I.Ty.Kind, PtrBits), BMask);
            break;
          }
          case VMBinOp::SRem: {
            Value *BMask = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *Zero = ConstantInt::get(I64Ty, 0);
            Value *IsZero = BlockIR.CreateICmpEQ(BMask, Zero);
            BasicBlock *Ok = BasicBlock::Create(Ctx, "srem.ok", Exec);
            BlockIR.CreateCondBr(IsZero, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits);
            Value *BS = signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Res = BlockIR.CreateSRem(AS, BS);
            break;
          }
          case VMBinOp::And:
            Res = emitIntAnd(BlockIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Or:
            Res = emitIntOr(BlockIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Xor:
            Res = emitIntXor(BlockIR, AVal, BVal, Handlers, AllowArithExpand);
            break;
          case VMBinOp::Shl: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                BlockIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "shl.ok", Exec);
            BlockIR.CreateCondBr(TooBig, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Value *AV = maskValue(BlockIR, AVal, I.Ty.Kind, PtrBits);
            Res = BlockIR.CreateShl(AV, Sh);
            break;
          }
          case VMBinOp::LShr: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                BlockIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "lshr.ok", Exec);
            BlockIR.CreateCondBr(TooBig, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Value *AV = maskValue(BlockIR, AVal, I.Ty.Kind, PtrBits);
            Res = BlockIR.CreateLShr(AV, Sh);
            break;
          }
          case VMBinOp::AShr: {
            unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
            Value *Sh = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
            Value *TooBig =
                BlockIR.CreateICmpUGE(Sh, ConstantInt::get(I64Ty, Bits));
            BasicBlock *Ok = BasicBlock::Create(Ctx, "ashr.ok", Exec);
            BlockIR.CreateCondBr(TooBig, Trap, Ok);
            BlockIR.SetInsertPoint(Ok);
            Value *AS = signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits);
            Res = BlockIR.CreateAShr(AS, Sh);
            break;
          }
          default:
            BlockIR.CreateBr(Trap);
            Terminated = true;
            continue;
          }
          Res = maskValue(BlockIR, Res, I.Ty.Kind, PtrBits);
        }
        setReg(I.Dst, Res);
        break;
      }
      case VMOpcode::FNeg: {
        Value *SrcVal = getReg(I.Ops[0].Reg);
        Value *Src = unpackValue(BlockIR, SrcVal, I.Ty.Kind, PtrBits);
        Value *Neg = BlockIR.CreateFNeg(Src);
        Value *Packed = packValue(BlockIR, Neg, I.Ty.Kind, PtrBits);
        setReg(I.Dst, Packed);
        break;
      }
      case VMOpcode::ICmp: {
        Value *AVal = getReg(I.Ops[0].Reg);
        Value *BVal = getReg(I.Ops[1].Reg);
        Value *AMask = maskValue(BlockIR, AVal, I.Ty.Kind, PtrBits);
        Value *BMask = maskValue(BlockIR, BVal, I.Ty.Kind, PtrBits);
        Value *Res = nullptr;
        switch (I.Pred) {
        case VMCmpPred::EQ:
          Res = BlockIR.CreateICmpEQ(AMask, BMask);
          break;
        case VMCmpPred::NE:
          Res = BlockIR.CreateICmpNE(AMask, BMask);
          break;
        case VMCmpPred::ULT:
          Res = BlockIR.CreateICmpULT(AMask, BMask);
          break;
        case VMCmpPred::ULE:
          Res = BlockIR.CreateICmpULE(AMask, BMask);
          break;
        case VMCmpPred::UGT:
          Res = BlockIR.CreateICmpUGT(AMask, BMask);
          break;
        case VMCmpPred::UGE:
          Res = BlockIR.CreateICmpUGE(AMask, BMask);
          break;
        case VMCmpPred::SLT:
          Res = BlockIR.CreateICmpSLT(signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SLE:
          Res = BlockIR.CreateICmpSLE(signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SGT:
          Res = BlockIR.CreateICmpSGT(signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits));
          break;
        case VMCmpPred::SGE:
          Res = BlockIR.CreateICmpSGE(signExtendToI64(BlockIR, AVal, I.Ty.Kind, PtrBits),
                                 signExtendToI64(BlockIR, BVal, I.Ty.Kind, PtrBits));
          break;
        default:
          BlockIR.CreateBr(Trap);
          Terminated = true;
          continue;
        }
        Value *Ext = BlockIR.CreateZExt(Res, I64Ty);
        setReg(I.Dst, Ext);
        break;
      }
      case VMOpcode::FCmp: {
        Value *AVal = unpackValue(BlockIR, getReg(I.Ops[0].Reg), I.Ty.Kind, PtrBits);
        Value *BVal = unpackValue(BlockIR, getReg(I.Ops[1].Reg), I.Ty.Kind, PtrBits);
        Value *Res = nullptr;
        switch (I.Pred) {
        case VMCmpPred::FEQ:
          Res = BlockIR.CreateFCmpOEQ(AVal, BVal);
          break;
        case VMCmpPred::FNE:
          Res = BlockIR.CreateFCmpONE(AVal, BVal);
          break;
        case VMCmpPred::FLT:
          Res = BlockIR.CreateFCmpOLT(AVal, BVal);
          break;
        case VMCmpPred::FLE:
          Res = BlockIR.CreateFCmpOLE(AVal, BVal);
          break;
        case VMCmpPred::FGT:
          Res = BlockIR.CreateFCmpOGT(AVal, BVal);
          break;
        case VMCmpPred::FGE:
          Res = BlockIR.CreateFCmpOGE(AVal, BVal);
          break;
        default:
          BlockIR.CreateBr(Trap);
          Terminated = true;
          continue;
        }
        Value *Ext = BlockIR.CreateZExt(Res, I64Ty);
        setReg(I.Dst, Ext);
        break;
      }
      case VMOpcode::Cast: {
        VMTypeKind SrcK = I.SrcTy.Kind;
        VMTypeKind DstK = I.Ty.Kind;
        Value *SrcVal = unpackValue(BlockIR, getReg(I.Ops[0].Reg), SrcK, PtrBits);
        Value *Dst = nullptr;
        Type *DstTy = getLLVMType(DstK, Ctx, PtrBits);
        switch (I.Cast) {
        case VMCastKind::ZExt:
          Dst = BlockIR.CreateZExt(SrcVal, DstTy);
          break;
        case VMCastKind::SExt:
          Dst = BlockIR.CreateSExt(SrcVal, DstTy);
          break;
        case VMCastKind::Trunc:
          Dst = BlockIR.CreateTrunc(SrcVal, DstTy);
          break;
        case VMCastKind::Bitcast:
          Dst = BlockIR.CreateBitCast(SrcVal, DstTy);
          break;
        case VMCastKind::PtrToInt:
          Dst = BlockIR.CreatePtrToInt(SrcVal, DstTy);
          break;
        case VMCastKind::IntToPtr:
          Dst = BlockIR.CreateIntToPtr(SrcVal, DstTy);
          break;
        case VMCastKind::FPToUI:
          Dst = BlockIR.CreateFPToUI(SrcVal, DstTy);
          break;
        case VMCastKind::FPToSI:
          Dst = BlockIR.CreateFPToSI(SrcVal, DstTy);
          break;
        case VMCastKind::UIToFP:
          Dst = BlockIR.CreateUIToFP(SrcVal, DstTy);
          break;
        case VMCastKind::SIToFP:
          Dst = BlockIR.CreateSIToFP(SrcVal, DstTy);
          break;
        case VMCastKind::FPTrunc:
          Dst = BlockIR.CreateFPTrunc(SrcVal, DstTy);
          break;
        case VMCastKind::FPExt:
          Dst = BlockIR.CreateFPExt(SrcVal, DstTy);
          break;
        }
        Value *Packed = packValue(BlockIR, Dst, DstK, PtrBits);
        setReg(I.Dst, Packed);
        break;
      }
      case VMOpcode::Load: {
        Value *Addr = getReg(I.Ops[0].Reg);
        if (PtrBits < 64)
          Addr = BlockIR.CreateTrunc(Addr, Type::getIntNTy(Ctx, PtrBits));
        Type *Ty = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        Value *Ptr = BlockIR.CreateIntToPtr(Addr, PointerType::getUnqual(Ty));
        LoadInst *Ld = BlockIR.CreateLoad(Ty, Ptr);
        Ld->setAlignment(Align(1));
        Value *Packed = packValue(BlockIR, Ld, I.Ty.Kind, PtrBits);
        setReg(I.Dst, Packed);
        break;
      }
      case VMOpcode::Store: {
        Value *Addr = getReg(I.Ops[1].Reg);
        if (PtrBits < 64)
          Addr = BlockIR.CreateTrunc(Addr, Type::getIntNTy(Ctx, PtrBits));
        Type *Ty = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        Value *Ptr = BlockIR.CreateIntToPtr(Addr, PointerType::getUnqual(Ty));
        Value *Val = unpackValue(BlockIR, getReg(I.Ops[0].Reg), I.Ty.Kind, PtrBits);
        StoreInst *St = BlockIR.CreateStore(Val, Ptr);
        St->setAlignment(Align(1));
        break;
      }
      case VMOpcode::MemFence: {
        emitFence(BlockIR, I.Fence);
        break;
      }
      case VMOpcode::Select: {
        Value *CondV = getReg(I.Ops[0].Reg);
        Value *Cond =
            BlockIR.CreateICmpNE(maskValue(BlockIR, CondV, VMTypeKind::I1, PtrBits),
                            ConstantInt::get(I64Ty, 0));
        Value *TV = getReg(I.Ops[1].Reg);
        Value *FV = getReg(I.Ops[2].Reg);
        Value *Sel = BlockIR.CreateSelect(Cond, TV, FV);
        Sel = maskValue(BlockIR, Sel, I.Ty.Kind, PtrBits);
        setReg(I.Dst, Sel);
        break;
      }
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect: {
        if (I.CallIndex >= F.Calls.size()) {
          BlockIR.CreateBr(Trap);
          Terminated = true;
          break;
        }
        const VMCallInfo &CI = F.Calls[I.CallIndex];
        SmallVector<Value *, 8> Args;
        Args.reserve(CI.ArgRegs.size());
        for (unsigned i = 0; i < CI.ArgRegs.size(); ++i) {
          uint32_t Rg = CI.ArgRegs[i];
          Type *CallTy = (CI.CalleeTy && i < CI.CalleeTy->getNumParams())
                             ? CI.CalleeTy->getParamType(i)
                             : nullptr;
          Type *DecodeTy = CallTy;
          if (!DecodeTy) {
            DecodeTy = (i < CI.ArgTypes.size() && CI.ArgTypes[i])
                           ? CI.ArgTypes[i]
                           : nullptr;
          }
          VMTypeKind K = DecodeTy ? mapTypeKind(DecodeTy) : VMTypeKind::I64;
          Value *ArgVal = unpackValue(BlockIR, getReg(Rg), K, PtrBits);
          if (DecodeTy && DecodeTy->isPointerTy()) {
            Value *IntPtr = ArgVal;
            if (PtrBits < 64)
              IntPtr = BlockIR.CreateTrunc(ArgVal, Type::getIntNTy(Ctx, PtrBits));
            ArgVal = BlockIR.CreateIntToPtr(IntPtr, DecodeTy);
          } else if (DecodeTy && ArgVal->getType() != DecodeTy) {
            if (DecodeTy->isIntegerTy())
              ArgVal = BlockIR.CreateZExtOrTrunc(ArgVal, DecodeTy);
            else if (DecodeTy->isFloatingPointTy())
              ArgVal = BlockIR.CreateBitCast(ArgVal, DecodeTy);
          }
          if (CallTy && ArgVal->getType() != CallTy) {
            ArgVal = castValueToParam(BlockIR, ArgVal, CallTy, PtrBits);
          }
          Args.push_back(ArgVal);
        }
        Value *HostStart = nullptr;
        if (Ctrs.HostCycles) {
          FunctionCallee Rd =
              Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
          HostStart = BlockIR.CreateCall(Rd);
        }
        bumpCounter(BlockIR, Ctrs.HostCall);
        PointerType *CalleePtrTy =
            CI.CalleeTy ? PointerType::get(CI.CalleeTy, CI.CalleeAddrSpace)
                        : nullptr;
        Value *CalleeVal = nullptr;
        if (CI.IsIndirect) {
          Value *RegVal = getReg(CI.CalleeReg);
          if (PtrBits < 64)
            RegVal = BlockIR.CreateTrunc(RegVal, Type::getIntNTy(Ctx, PtrBits));
          CalleeVal = BlockIR.CreateIntToPtr(
              RegVal,
              CalleePtrTy ? CalleePtrTy
                          : PointerType::getUnqual(CI.CalleeTy));
        } else {
          CalleeVal = CI.Callee;
          if (CalleeVal && CalleePtrTy && CalleeVal->getType() != CalleePtrTy) {
            if (auto *PT = dyn_cast<PointerType>(CalleeVal->getType())) {
              if (PT->getAddressSpace() != CI.CalleeAddrSpace) {
                CalleeVal = BlockIR.CreateAddrSpaceCast(CalleeVal, CalleePtrTy);
              } else {
                CalleeVal = BlockIR.CreateBitCast(CalleeVal, CalleePtrTy);
              }
            } else {
              CalleeVal = BlockIR.CreateBitCast(CalleeVal, CalleePtrTy);
            }
          }
        }
        CallInst *Call = BlockIR.CreateCall(CI.CalleeTy, CalleeVal, Args);
        Call->setCallingConv(static_cast<CallingConv::ID>(CI.CallConv));
        if (!CI.CallAttrs.isEmpty())
          Call->setAttributes(CI.CallAttrs);
        if (Ctrs.HostCycles && HostStart) {
          FunctionCallee Rd =
              Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
          Value *HostEnd = BlockIR.CreateCall(Rd);
          Value *Delta = BlockIR.CreateSub(HostEnd, HostStart);
          addCounter(BlockIR, Ctrs.HostCycles, Delta);
        }
        if (!CI.IsVoid) {
          Value *RetVal = Call;
          VMTypeKind RK = CI.RetTy.Kind;
          Value *Packed;
          if (CI.CalleeTy->getReturnType()->isPointerTy()) {
            Value *PtrAsInt =
                BlockIR.CreatePtrToInt(RetVal, Type::getIntNTy(Ctx, PtrBits));
            Packed = packValue(BlockIR, PtrAsInt, RK, PtrBits);
          } else {
            Packed = packValue(BlockIR, RetVal, RK, PtrBits);
          }
          setReg(CI.RetReg, Packed);
        }
        break;
      }
      case VMOpcode::Br: {
        uint32_t Tgt = I.TargetTrue;
        auto It = BlockToRegion.find(Tgt);
        if (It == BlockToRegion.end()) {
          Err = "vm: branch target region not found";
          return Exec;
        }
        if (It->second == R.Id) {
          addPhiIncoming(Tgt);
          BlockIR.CreateBr(BlockBBs[Tgt]);
        } else {
          BasicBlock *Exit = BasicBlock::Create(
              Ctx, "exit." + std::to_string(Bid) + "." + std::to_string(Tgt),
              Exec);
          IRBuilder<> EdgeIR(Exit);
          storeLiveOut(Live.Blocks[Bid].LiveOut, EdgeIR);
          uint32_t NextId = slotForRegion(It->second);
          if (!Err.empty())
            return Exec;
          EdgeIR.CreateRet(ConstantInt::get(I32Ty, NextId));
          BlockIR.CreateBr(Exit);
        }
        Terminated = true;
        break;
      }
      case VMOpcode::CondBr: {
        Value *CondV = getReg(I.Ops[0].Reg);
        Value *Cond =
            BlockIR.CreateICmpNE(maskValue(BlockIR, CondV, VMTypeKind::I1, PtrBits),
                            ConstantInt::get(I64Ty, 0));
        uint32_t TgtT = I.TargetTrue;
        uint32_t TgtF = I.TargetFalse;
        auto ItT = BlockToRegion.find(TgtT);
        auto ItF = BlockToRegion.find(TgtF);
        if (ItT == BlockToRegion.end() || ItF == BlockToRegion.end()) {
          Err = "vm: condbr target region not found";
          return Exec;
        }
        BasicBlock *TrueBB = nullptr;
        BasicBlock *FalseBB = nullptr;
        if (ItT->second == R.Id) {
          addPhiIncoming(TgtT);
          TrueBB = BlockBBs[TgtT];
        } else {
          TrueBB = BasicBlock::Create(
              Ctx, "exit." + std::to_string(Bid) + "." + std::to_string(TgtT),
              Exec);
          IRBuilder<> EdgeIR(TrueBB);
          storeLiveOut(Live.Blocks[Bid].LiveOut, EdgeIR);
          uint32_t NextId = slotForRegion(ItT->second);
          if (!Err.empty())
            return Exec;
          EdgeIR.CreateRet(ConstantInt::get(I32Ty, NextId));
        }
        if (ItF->second == R.Id) {
          addPhiIncoming(TgtF);
          FalseBB = BlockBBs[TgtF];
        } else {
          FalseBB = BasicBlock::Create(
              Ctx, "exit." + std::to_string(Bid) + "." + std::to_string(TgtF),
              Exec);
          IRBuilder<> EdgeIR(FalseBB);
          storeLiveOut(Live.Blocks[Bid].LiveOut, EdgeIR);
          uint32_t NextId = slotForRegion(ItF->second);
          if (!Err.empty())
            return Exec;
          EdgeIR.CreateRet(ConstantInt::get(I32Ty, NextId));
        }
        BlockIR.CreateCondBr(Cond, TrueBB, FalseBB);
        Terminated = true;
        break;
      }
      case VMOpcode::Switch: {
        Value *CondV = getReg(I.Ops[0].Reg);
        Type *CondTy = getLLVMType(I.Ty.Kind, Ctx, PtrBits);
        auto *CondITy = cast<IntegerType>(CondTy);
        Value *Masked = maskValue(BlockIR, CondV, I.Ty.Kind, PtrBits);
        Value *Cond = BlockIR.CreateTruncOrBitCast(Masked, CondTy);
        auto ItD = BlockToRegion.find(I.SwitchDefault);
        if (ItD == BlockToRegion.end()) {
          Err = "vm: switch default region not found";
          return Exec;
        }
        BasicBlock *DefaultBB = nullptr;
        if (ItD->second == R.Id) {
          addPhiIncoming(I.SwitchDefault);
          DefaultBB = BlockBBs[I.SwitchDefault];
        } else {
          DefaultBB = BasicBlock::Create(Ctx,
                                         "exit." + std::to_string(Bid) + "." +
                                             std::to_string(I.SwitchDefault),
                                         Exec);
          IRBuilder<> EdgeIR(DefaultBB);
          storeLiveOut(Live.Blocks[Bid].LiveOut, EdgeIR);
          uint32_t NextId = slotForRegion(ItD->second);
          if (!Err.empty())
            return Exec;
          EdgeIR.CreateRet(ConstantInt::get(I32Ty, NextId));
        }
        SwitchInst *Sw = BlockIR.CreateSwitch(
            Cond, DefaultBB, static_cast<unsigned>(I.SwitchValues.size()));
        for (size_t i = 0; i < I.SwitchValues.size(); ++i) {
          uint32_t Tgt = I.SwitchTargets[i];
          auto It = BlockToRegion.find(Tgt);
          if (It == BlockToRegion.end()) {
            Err = "vm: switch target region not found";
            return Exec;
          }
          BasicBlock *CaseBB = nullptr;
          if (It->second == R.Id) {
            addPhiIncoming(Tgt);
            CaseBB = BlockBBs[Tgt];
          } else {
            CaseBB = BasicBlock::Create(
                Ctx, "exit." + std::to_string(Bid) + "." + std::to_string(Tgt),
                Exec);
            IRBuilder<> EdgeIR(CaseBB);
            storeLiveOut(Live.Blocks[Bid].LiveOut, EdgeIR);
            uint32_t NextId = slotForRegion(It->second);
            if (!Err.empty())
              return Exec;
            EdgeIR.CreateRet(ConstantInt::get(I32Ty, NextId));
          }
          uint64_t Mask = maskForType(I.Ty.Kind, PtrBits);
          uint64_t CV = I.SwitchValues[i] & Mask;
          Sw->addCase(ConstantInt::get(CondITy, CV), CaseBB);
        }
        Terminated = true;
        break;
      }
      case VMOpcode::Ret: {
        if (!I.Ops.empty()) {
          uint32_t Rg = I.Ops[0].Reg;
          Value *Val = getReg(Rg);
          Value *Idx = ConstantInt::get(I32Ty, Rg);
          storeReg(BlockIR, RegsPtr, Idx, Val, Ctrs.RegStore);
        }
        BlockIR.CreateRet(ConstantInt::get(I32Ty, kVmExitId));
        Terminated = true;
        break;
      }
      case VMOpcode::Trap:
        BlockIR.CreateBr(Trap);
        Terminated = true;
        break;
      }
    }
    if (!Terminated && Err.empty())
      BlockIR.CreateBr(Trap);
  }
  return Exec;
}

Function *llvm::obfvm::emitVMRegions(Module &M, const VMFunction &F,
                                     const VMConfig &Cfg, std::string &Err,
                                     uint32_t &EntrySlot) {
  EntrySlot = 0;
  VMHandlers Handlers = Cfg.Handlers;
  bool AllowArithExpand =
      (Handlers == VMHandlers::Random) && (Cfg.Encode != VMEncode::MBA);
  bool Counters = Cfg.Counters;
  VMDispatch DispatchMode = Cfg.Dispatch;
  bool Hard = Cfg.Hard;
  VMFunctionLiveness Live;
  if (!computeVMLiveness(F, Live, Err))
    return nullptr;

  SmallVector<VMRegion, 8> Regions;
  DenseMap<uint32_t, uint32_t> BlockToRegion;
  if (!formEBBRegions(F, Regions, BlockToRegion, Err))
    return nullptr;
  if (Cfg.Debug)
    dumpVMRegions(Regions, errs());

  DenseMap<uint32_t, SmallVector<uint32_t, 4>> Preds;
  for (const VMBlock &Block : F.Blocks) {
    for (uint32_t Succ : Live.Blocks[Block.Id].Succs) {
      Preds[Succ].push_back(Block.Id);
    }
  }

  DenseMap<uint32_t, BitVector> RegionLiveIn;
  for (const VMRegion &R : Regions) {
    BitVector LiveIn(F.RegCount);
    for (uint32_t Bid : R.Blocks) {
      bool IsEntry = (Bid == R.Blocks.front());
      auto It = Preds.find(Bid);
      if (IsEntry || It == Preds.end()) {
        LiveIn |= Live.Blocks[Bid].LiveIn;
        continue;
      }
      bool HasOutsidePred = false;
      for (uint32_t P : It->second) {
        auto Pr = BlockToRegion.find(P);
        if (Pr == BlockToRegion.end() || Pr->second != R.Id) {
          HasOutsidePred = true;
          break;
        }
      }
      if (HasOutsidePred)
        LiveIn |= Live.Blocks[Bid].LiveIn;
    }
    RegionLiveIn[R.Id] = LiveIn;
  }

  uint32_t EntryBlockId = F.Blocks.front().Id;
  auto EntryIt = BlockToRegion.find(EntryBlockId);
  if (EntryIt == BlockToRegion.end()) {
    Err = "vm: entry region not found";
    return nullptr;
  }
  uint32_t EntryRegion = EntryIt->second;
  // Entry region must be slot 0 so the caller can start the VM deterministically;
  // remaining slots are shuffled to decouple region IDs from dispatch layout.
  SmallVector<uint32_t, 8> DispatchOrder;
  DispatchOrder.reserve(Regions.size());
  DispatchOrder.push_back(EntryRegion);
  for (uint32_t RId = 0; RId < Regions.size(); ++RId) {
    if (RId == EntryRegion)
      continue;
    DispatchOrder.push_back(RId);
  }
  shuffleDispatchOrder(DispatchOrder, 1, Handlers);

  SmallVector<uint32_t, 8> RegionDispatchId(Regions.size(), 0);
  for (size_t I = 0; I < DispatchOrder.size(); ++I)
    RegionDispatchId[DispatchOrder[I]] = static_cast<uint32_t>(I);

  unsigned BogusExtra = 0;
  if (Hard && Cfg.BogusCount > 0) {
    BogusExtra = Cfg.Debug
                     ? Cfg.BogusCount
                     : cryptoutils->get_range(Cfg.BogusCount + 1);
  }
  DispatchLayout Layout = buildDispatchLayout(
      static_cast<unsigned>(Regions.size()), BogusExtra, Handlers);
  unsigned DispatchCount = static_cast<unsigned>(Layout.SlotToId.size());
  unsigned DispatchBits = log2Exact(DispatchCount);
  uint32_t DispatchMask = DispatchCount - 1;
  // Affine slot permutation: odd multiplier mod 2^n is bijective, preventing
  // simple slot-index correlation even when the dispatch table is dumped.
  uint32_t PcMul = 1;
  uint32_t PcInvMul = 1;
  if (Hard && DispatchBits > 0) {
    uint64_t Inv = 1;
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

  SmallVector<uint32_t, 8> RegionSlot(Regions.size(), 0);
  for (uint32_t RId = 0; RId < Regions.size(); ++RId) {
    RegionSlot[RId] = Layout.IdToSlot[RegionDispatchId[RId]];
  }
  EntrySlot = RegionSlot[EntryRegion];
  if (Hard && DispatchBits > 0) {
    EntrySlot = static_cast<uint32_t>(
        (static_cast<uint64_t>(EntrySlot) * PcInvMul) & DispatchMask);
  }

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

  SmallVector<Function *, 8> Execs;
  Execs.reserve(Regions.size());
  for (const VMRegion &R : Regions) {
    Function *Exec =
        emitRegionExecutor(M, F, Live, R, BlockToRegion, RegionLiveIn, Preds,
                           RegionSlot, Handlers, AllowArithExpand, Ctrs, Err);
    if (!Err.empty() || !Exec)
      return nullptr;
    Execs.push_back(Exec);
  }

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  unsigned PtrBits = M.getDataLayout().getPointerSizeInBits();
  if (PtrBits == 0)
    vmFatal("vm: invalid pointer size");
  IntegerType *IntPtrTy = Type::getIntNTy(Ctx, PtrBits);
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

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Run);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", Run);
  BasicBlock *Update = BasicBlock::Create(Ctx, "update", Run);
  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", Run);
  BasicBlock *BogusEntry = BasicBlock::Create(Ctx, "bogus.entry", Run);
  BasicBlock *Bogus = BasicBlock::Create(Ctx, "bogus", Run);
  BasicBlock *Trap = BasicBlock::Create(Ctx, "trap", Run);
  BasicBlock *Ret = BasicBlock::Create(Ctx, "ret", Run);

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
    BogusGV =
        new GlobalVariable(M, BogusTy, true, GlobalValue::PrivateLinkage,
                           BogusInit, BogusName);
    std::string BogusTag = ("vm.bogus.slots." + F.Name).str();
    obfuscateSymbolName(*BogusGV, M, BogusTag, BogusName);
    BogusGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  }

  IRBuilder<> EntryIR(Entry);
  Value *State = Run->arg_begin();
  Value *PcPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::PC);
  Value *KeyPtr = getStateFieldPtr(EntryIR, M, StateTy, State, VMStateField::Key);
  AllocaInst *NextPcVar = EntryIR.CreateAlloca(I32Ty);
  NextPcVar->setAlignment(Align(4));
  AllocaInst *SlotVar = EntryIR.CreateAlloca(I32Ty);
  SlotVar->setAlignment(Align(4));
  AllocaInst *RealSlotVar = EntryIR.CreateAlloca(I32Ty);
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
  uint64_t DispSeed = 0;
  AllocaInst *DispKeyVar = nullptr;
  AllocaInst *DispTable = nullptr;
  if (DispatchMode == VMDispatch::Indirect) {
    if (Hard) {
      DispSeed = cryptoutils->get_uint64_t();
      Value *KeyVal = EntryIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
      Value *DispKey =
          EntryIR.CreateXor(KeyVal, ConstantInt::get(Type::getInt64Ty(Ctx), DispSeed));
      FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
      Value *Cycle = EntryIR.CreateCall(Rd);
      DispKey = EntryIR.CreateXor(DispKey, Cycle);
      Value *DispKeyTr = DispKey;
      if (PtrBits < 64)
        DispKeyTr = EntryIR.CreateTrunc(DispKey, IntPtrTy);
      DispKeyVar = EntryIR.CreateAlloca(IntPtrTy);
      DispKeyVar->setAlignment(Align(PtrBits / 8));
      EntryIR.CreateStore(DispKeyTr, DispKeyVar);
    }
    DispTable =
        EntryIR.CreateAlloca(IntPtrTy, ConstantInt::get(I32Ty, DispatchCount));
    DispTable->setAlignment(Align(PtrBits / 8));
  }
  EntryIR.CreateBr(Loop);

  IRBuilder<> TrapIR(Trap);
  FunctionCallee TrapFn = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  TrapIR.CreateCall(TrapFn);
  TrapIR.CreateUnreachable();

  IRBuilder<> RetIR(Ret);
  if (Ctrs.VmCycles && VmStartVar) {
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *End = RetIR.CreateCall(Rd);
    Value *Start = RetIR.CreateLoad(I64Ty, VmStartVar);
    Value *Delta = RetIR.CreateSub(End, Start);
    addCounter(RetIR, Ctrs.VmCycles, Delta);
  }
  RetIR.CreateRetVoid();

  BasicBlock *Decode = BasicBlock::Create(Ctx, "decode", Run);

  OpaqueJunkContext JunkCtx{M, KeyPtr, OpaqueTmp, JunkSeed, PredMul,
                            PredAdd, PredMask, PredTarget, Hard};

  EntryIR.SetInsertPoint(Loop);
  Value *PcVal = EntryIR.CreateLoad(I32Ty, PcPtr);
  Value *IsExit = EntryIR.CreateICmpEQ(PcVal, ConstantInt::get(I32Ty, kVmExitId));
  EntryIR.CreateCondBr(IsExit, Ret, Decode);

  IRBuilder<> DecodeIR(Decode);
  Value *DecPc = PcVal;
  Value *KeyValLoop = nullptr;
  Value *Key32Loop = nullptr;
  if (Hard) {
    KeyValLoop = DecodeIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Key32Loop = DecodeIR.CreateTrunc(KeyValLoop, I32Ty);
    DecPc = DecodeIR.CreateXor(PcVal, Key32Loop);
  }
  Value *SlotVal =
      slotFromPc(DecodeIR, DecPc, Hard, DispatchMask, DispatchBits, PcMul);
  DecodeIR.CreateStore(SlotVal, SlotVar);
  DecodeIR.CreateStore(SlotVal, RealSlotVar);
  if (Hard && BogusGV) {
    Value *Key32 = DecodeIR.CreateTrunc(KeyValLoop, I32Ty);
    Value *Mix = rotl32(DecodeIR, Key32, RotAmt);
    Mix = DecodeIR.CreateXor(Mix, Key32);
    Mix = DecodeIR.CreateXor(Mix, DecPc);
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = DecodeIR.CreateCall(Rd);
    Value *Cycle32 = DecodeIR.CreateTrunc(Cycle, I32Ty);
    Mix = DecodeIR.CreateXor(Mix, Cycle32);
    Value *Fold =
        DecodeIR.CreateXor(Mix, DecodeIR.CreateLShr(Mix, ConstantInt::get(I32Ty, 11)));
    Fold = DecodeIR.CreateMul(Fold, ConstantInt::get(I32Ty, PredMul));
    Fold = DecodeIR.CreateAdd(Fold, ConstantInt::get(I32Ty, PredAdd));
    Value *Masked =
        DecodeIR.CreateAnd(Fold, ConstantInt::get(I32Ty, PredMask));
    Value *Cond =
        DecodeIR.CreateICmpEQ(Masked, ConstantInt::get(I32Ty, PredTarget));
    DecodeIR.CreateCondBr(Cond, Dispatch, BogusEntry);
  } else {
    DecodeIR.CreateBr(Dispatch);
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

  SmallVector<BasicBlock *, 16> CaseBlocks;
  CaseBlocks.resize(DispatchOrder.size(), nullptr);
  for (uint32_t Disp = 0; Disp < DispatchOrder.size(); ++Disp) {
    uint32_t RId = DispatchOrder[Disp];
    BasicBlock *Case =
        BasicBlock::Create(Ctx, "region." + std::to_string(RId), Run);
    CaseBlocks[Disp] = Case;
    IRBuilder<> CaseIR(Case);
    bumpCounter(CaseIR, Ctrs.Dispatch);
    emitOpaqueJunk(CaseIR, JunkCtx);
    Value *Next = CaseIR.CreateCall(Execs[RId], {State});
    Value *IsExit = CaseIR.CreateICmpEQ(Next, ConstantInt::get(I32Ty, kVmExitId));
    Value *PcVal =
        pcFromSlot(CaseIR, Next, Hard, DispatchMask, DispatchBits, PcInvMul);
    Value *NextPc = CaseIR.CreateSelect(IsExit, Next, PcVal);
    Value *EncNext = encodeNextPc(CaseIR, NextPc, Hard, KeyPtr, RotAmt);
    CaseIR.CreateStore(EncNext, NextPcVar);
    CaseIR.CreateBr(Update);
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
      emitOpaqueJunk(TrampIR, JunkCtx);
      TrampIR.CreateBr(Dest);
      SlotTargets[Slot] = Tramp;
    }
  }

  EntryIR.SetInsertPoint(Update);
  Value *EncNext = EntryIR.CreateLoad(I32Ty, NextPcVar);
  Value *NextPcVal = EncNext;
  if (Hard) {
    Value *KeyVal = EntryIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *Key32 = EntryIR.CreateTrunc(KeyVal, I32Ty);
    Value *Rot = rotl32(EntryIR, Key32, RotAmt);
    NextPcVal = EntryIR.CreateXor(EntryIR.CreateSub(EncNext, Key32), Rot);
  }
  Value *IsExitNext =
      EntryIR.CreateICmpEQ(NextPcVal, ConstantInt::get(I32Ty, kVmExitId));
  BasicBlock *StoreExit = BasicBlock::Create(Ctx, "store.exit", Run);
  BasicBlock *StoreEnc = BasicBlock::Create(Ctx, "store.enc", Run);
  EntryIR.CreateCondBr(IsExitNext, StoreExit, StoreEnc);

  IRBuilder<> StoreExitIR(StoreExit);
  StoreExitIR.CreateStore(ConstantInt::get(I32Ty, kVmExitId), PcPtr);
  StoreExitIR.CreateBr(Loop);

  IRBuilder<> StoreEncIR(StoreEnc);
  if (Hard) {
    Value *KeyVal = StoreEncIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *KeyMulC = ConstantInt::get(Type::getInt64Ty(Ctx), KeyMul);
    Value *KeyAddC = ConstantInt::get(Type::getInt64Ty(Ctx), KeyAdd);
    Value *NextPc64 = StoreEncIR.CreateZExt(NextPcVal, Type::getInt64Ty(Ctx));
    Value *NewKey = StoreEncIR.CreateMul(KeyVal, KeyMulC);
    NewKey = StoreEncIR.CreateAdd(NewKey, KeyAddC);
    NewKey = StoreEncIR.CreateAdd(NewKey, NextPc64);
    FunctionCallee Rd = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
    Value *Cycle = StoreEncIR.CreateCall(Rd);
    NewKey = StoreEncIR.CreateXor(NewKey, Cycle);
    StoreEncIR.CreateStore(NewKey, KeyPtr);
    Value *Key32 = StoreEncIR.CreateTrunc(NewKey, I32Ty);
    Value *EncPc = StoreEncIR.CreateXor(NextPcVal, Key32);
    StoreEncIR.CreateStore(EncPc, PcPtr);
    if (DispatchMode == VMDispatch::Indirect && Hard && DispTable &&
        DispKeyVar) {
      Value *DispKey = StoreEncIR.CreateXor(NewKey, ConstantInt::get(I64Ty, DispSeed));
      FunctionCallee Rd2 =
          Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
      Value *Cycle2 = StoreEncIR.CreateCall(Rd2);
      DispKey = StoreEncIR.CreateXor(DispKey, Cycle2);
      Value *DispKeyTr = DispKey;
      if (PtrBits < 64)
        DispKeyTr = StoreEncIR.CreateTrunc(DispKey, IntPtrTy);
      StoreEncIR.CreateStore(DispKeyTr, DispKeyVar);
      for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
        BasicBlock *Dest = SlotTargets[Slot];
        Constant *Addr =
            ConstantExpr::getPtrToInt(BlockAddress::get(Run, Dest), IntPtrTy);
        Value *Enc = StoreEncIR.CreateXor(Addr, DispKeyTr);
        Value *SlotIdx = ConstantInt::get(I32Ty, Slot);
        if (DispatchMode == VMDispatch::Indirect && Hard)
          SlotIdx = permuteSlot(StoreEncIR, SlotIdx, Key32, Hard, DispatchMask,
                                SlotMixConst);
        Value *Ptr = StoreEncIR.CreateInBoundsGEP(IntPtrTy, DispTable, SlotIdx);
        StoreEncIR.CreateStore(Enc, Ptr);
      }
    }
  } else {
    StoreEncIR.CreateStore(NextPcVal, PcPtr);
  }
  StoreEncIR.CreateBr(Loop);

  IRBuilder<> BogusIR(Bogus);
  if (Hard) {
    Value *KeyVal = BogusIR.CreateLoad(Type::getInt64Ty(Ctx), KeyPtr);
    Value *Key32 = BogusIR.CreateTrunc(KeyVal, I32Ty);
    (void)BogusIR.CreateXor(Key32, BogusIR.CreateLShr(Key32, ConstantInt::get(I32Ty, 5)));
  }
  Value *RealSlot = BogusIR.CreateLoad(I32Ty, RealSlotVar);
  BogusIR.CreateStore(RealSlot, SlotVar);
  BogusIR.CreateBr(Dispatch);

  IRBuilder<> DispatchIR(Dispatch);
  Value *SlotIdx = DispatchIR.CreateLoad(I32Ty, SlotVar);
  SlotIdx = DispatchIR.CreateAnd(SlotIdx, ConstantInt::get(I32Ty, DispatchMask));
  if (DispatchMode == VMDispatch::Indirect && Hard) {
    Value *Key32 = DispatchIR.CreateTrunc(DispatchIR.CreateLoad(I64Ty, KeyPtr), I32Ty);
    SlotIdx =
        permuteSlot(DispatchIR, SlotIdx, Key32, Hard, DispatchMask,
                    SlotMixConst);
  }
  if (DispatchMode == VMDispatch::Indirect) {
    Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
    if (DispTable) {
      Value *Ptr = DispatchIR.CreateInBoundsGEP(IntPtrTy, DispTable, SlotIdx);
      Value *EncVal = DispatchIR.CreateLoad(IntPtrTy, Ptr);
      Value *DecVal = EncVal;
      if (Hard && DispKeyVar) {
        Value *KeyVal = DispatchIR.CreateLoad(IntPtrTy, DispKeyVar);
        DecVal = DispatchIR.CreateXor(EncVal, KeyVal);
      }
      Value *Target = DispatchIR.CreateIntToPtr(DecVal, I8PtrTy);
      IndirectBrInst *IB = DispatchIR.CreateIndirectBr(Target, DispatchCount);
      for (unsigned Slot = 0; Slot < DispatchCount; ++Slot)
        IB->addDestination(SlotTargets[Slot]);
    }
  } else {
    SwitchInst *Sw = DispatchIR.CreateSwitch(SlotIdx, Bogus, DispatchCount);
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      Sw->addCase(ConstantInt::get(I32Ty, Slot), SlotTargets[Slot]);
    }
  }

  if (DispatchMode == VMDispatch::Indirect && DispTable) {
    IRBuilder<> InsertIR(Entry->getTerminator());
    Value *Key32 = nullptr;
    Value *KeyVal = nullptr;
    if (Hard && DispKeyVar) {
      KeyVal = InsertIR.CreateLoad(IntPtrTy, DispKeyVar);
      Key32 = InsertIR.CreateTrunc(InsertIR.CreateLoad(I64Ty, KeyPtr), I32Ty);
    }
    for (unsigned Slot = 0; Slot < DispatchCount; ++Slot) {
      BasicBlock *Dest = SlotTargets[Slot];
      Constant *Addr =
          ConstantExpr::getPtrToInt(BlockAddress::get(Run, Dest), IntPtrTy);
      Value *Enc = Addr;
      if (Hard && KeyVal)
        Enc = InsertIR.CreateXor(Addr, KeyVal);
      Value *SlotIdx = ConstantInt::get(I32Ty, Slot);
      if (Hard && Key32)
        SlotIdx =
            permuteSlot(InsertIR, SlotIdx, Key32, Hard, DispatchMask,
                        SlotMixConst);
      Value *Ptr = InsertIR.CreateInBoundsGEP(IntPtrTy, DispTable, SlotIdx);
      InsertIR.CreateStore(Enc, Ptr);
    }
  }

  return Run;
}
