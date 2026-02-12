//===- VMInterpreter.cpp - Reference VM interpreter ----------------------===//
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
// Reference interpreter used in tests to validate VM IR and runtime
// emission.
//
//===----------------------------------------------------------------------===//
#include "VMInterpreter.h"
#include "VMMath.h"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/APSInt.h"
#include <atomic>
#include <cmath>
#include <cstring>

using namespace llvm;
using namespace llvm::obfvm;

static bool setError(std::string *Err, const char *Msg) {
  if (Err)
    *Err = Msg;
  return false;
}

static uint64_t maskToBits(uint64_t V, unsigned Bits) {
  return V & maskForBits(Bits);
}

static uint64_t signExtend(uint64_t V, unsigned FromBits, unsigned ToBits) {
  if (FromBits == 0)
    return 0;
  if (FromBits >= 64)
    return V;
  uint64_t Mask = maskForBits(FromBits);
  uint64_t X = V & Mask;
  uint64_t SignBit = 1ULL << (FromBits - 1);
  if (X & SignBit) {
    uint64_t ExtMask = ~Mask;
    X |= ExtMask;
  }
  return maskToBits(X, ToBits);
}

static uint64_t loadValue(const VMValue &V, const VMRuntimeState &State,
                          std::string *Err) {
  if (V.K == VMValue::Kind::Imm)
    return V.Imm;
  if (V.K == VMValue::Kind::Const) {
    setError(Err, "vm: const operand unsupported in interpreter");
    return 0;
  }
  if (V.Reg >= State.Regs.size()) {
    setError(Err, "vm: reg index out of range");
    return 0;
  }
  return State.Regs[V.Reg];
}

static void storeReg(uint32_t Reg, uint64_t Val, VMRuntimeState &State,
                     std::string *Err) {
  if (Reg >= State.Regs.size()) {
    setError(Err, "vm: reg index out of range");
    return;
  }
  State.Regs[Reg] = Val;
}

static uint64_t readMem(uint64_t Addr, unsigned Bits) {
  unsigned Bytes = (Bits + 7) / 8;
  if (Bytes == 0)
    return 0;
  uint64_t Out = 0;
  std::memcpy(&Out, reinterpret_cast<const void *>(
                          static_cast<uintptr_t>(Addr)),
              Bytes);
  return maskToBits(Out, Bits);
}

static void writeMem(uint64_t Addr, unsigned Bits, uint64_t Val) {
  unsigned Bytes = (Bits + 7) / 8;
  if (Bytes == 0)
    return;
  uint64_t Tmp = Val;
  std::memcpy(reinterpret_cast<void *>(static_cast<uintptr_t>(Addr)), &Tmp,
              Bytes);
}

static std::memory_order fenceOrder(VMFenceKind K) {
  switch (K) {
  case VMFenceKind::Acquire:
    return std::memory_order_acquire;
  case VMFenceKind::Release:
    return std::memory_order_release;
  case VMFenceKind::AcquireRelease:
    return std::memory_order_acq_rel;
  case VMFenceKind::SeqCst:
    return std::memory_order_seq_cst;
  }
  return std::memory_order_seq_cst;
}

static APFloat apFloatFromBits(uint64_t Bits, VMTypeKind Kind) {
  if (Kind == VMTypeKind::F32) {
    APInt AI(32, static_cast<uint32_t>(Bits));
    return APFloat(APFloat::IEEEsingle(), AI);
  }
  APInt AI(64, Bits);
  return APFloat(APFloat::IEEEdouble(), AI);
}

static uint64_t apFloatToBits(const APFloat &F) {
  APInt AI = F.bitcastToAPInt();
  return AI.getZExtValue();
}

bool VMInterpreter::run(const VMFunction &F, VMRuntimeState &State,
                        uint64_t &RetVal, std::string *Err) const {
  // Strict mode: any malformed VM IR is an error, not UB. This catches
  // lowering and encoding bugs before they surface as runtime corruption.
  if (F.Blocks.empty())
    return setError(Err, "vm: empty function");
  if (State.Regs.size() < F.RegCount)
    State.Regs.resize(F.RegCount, 0);

  unsigned PtrBits = F.PtrBits;
  if (PtrBits == 0)
    return setError(Err, "vm: invalid pointer size");

  SmallVector<const VMBlock *, 16> BlockMap;
  BlockMap.resize(F.Blocks.size(), nullptr);
  for (const VMBlock &B : F.Blocks) {
    if (B.Id >= BlockMap.size())
      return setError(Err, "vm: block id out of range");
    BlockMap[B.Id] = &B;
  }
  for (const VMBlock *B : BlockMap) {
    if (!B)
      return setError(Err, "vm: block map not contiguous");
  }

  uint32_t Cur = 0;
  for (;;) {
    if (Cur >= BlockMap.size())
      return setError(Err, "vm: pc out of range");
    const VMBlock &B = *BlockMap[Cur];
    for (const VMInstr &I : B.Instrs) {
      switch (I.Op) {
      case VMOpcode::Mov: {
        uint64_t V = loadValue(I.Ops[0], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        storeReg(I.Dst, maskToBits(V, Bits), State, Err);
        break;
      }
      case VMOpcode::BinOp: {
        uint64_t A = loadValue(I.Ops[0], State, Err);
        uint64_t Bv = loadValue(I.Ops[1], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t Res = 0;
        // APFloat preserves LLVM's rounding/NaN semantics for validation.
        if (I.Ty.Kind == VMTypeKind::F32 || I.Ty.Kind == VMTypeKind::F64) {
          APFloat FA = apFloatFromBits(A, I.Ty.Kind);
          APFloat FB = apFloatFromBits(Bv, I.Ty.Kind);
          APFloat FR = FA;
          switch (I.Bin) {
          case VMBinOp::Add:
          case VMBinOp::FAdd:
            FR.add(FB, APFloat::rmNearestTiesToEven);
            break;
          case VMBinOp::Sub:
          case VMBinOp::FSub:
            FR.subtract(FB, APFloat::rmNearestTiesToEven);
            break;
          case VMBinOp::Mul:
          case VMBinOp::FMul:
            FR.multiply(FB, APFloat::rmNearestTiesToEven);
            break;
          case VMBinOp::FDiv:
            FR.divide(FB, APFloat::rmNearestTiesToEven);
            break;
          case VMBinOp::FRem:
            FR.mod(FB);
            break;
          default:
            return setError(Err, "vm: invalid float binop");
          }
          Res = apFloatToBits(FR);
        } else {
          switch (I.Bin) {
          case VMBinOp::Add:
            Res = addMod(A, Bv, Bits);
            break;
          case VMBinOp::Sub:
            Res = subMod(A, Bv, Bits);
            break;
          case VMBinOp::Mul:
            Res = mulMod(A, Bv, Bits);
            break;
          case VMBinOp::UDiv: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask == 0)
              return setError(Err, "vm: udiv by zero");
            Res = maskToBits(A, Bits) / BMask;
            break;
          }
          case VMBinOp::SDiv: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask == 0)
              return setError(Err, "vm: sdiv by zero");
            int64_t SA = static_cast<int64_t>(signExtend(A, Bits, 64));
            int64_t SB = static_cast<int64_t>(signExtend(BMask, Bits, 64));
            if (SB == 0)
              return setError(Err, "vm: sdiv by zero");
            int64_t SR = SA / SB;
            Res = maskToBits(static_cast<uint64_t>(SR), Bits);
            break;
          }
          case VMBinOp::URem: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask == 0)
              return setError(Err, "vm: urem by zero");
            Res = maskToBits(A, Bits) % BMask;
            break;
          }
          case VMBinOp::SRem: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask == 0)
              return setError(Err, "vm: srem by zero");
            int64_t SA = static_cast<int64_t>(signExtend(A, Bits, 64));
            int64_t SB = static_cast<int64_t>(signExtend(BMask, Bits, 64));
            if (SB == 0)
              return setError(Err, "vm: srem by zero");
            int64_t SR = SA % SB;
            Res = maskToBits(static_cast<uint64_t>(SR), Bits);
            break;
          }
          case VMBinOp::And:
            Res = maskToBits(A & Bv, Bits);
            break;
          case VMBinOp::Or:
            Res = maskToBits(A | Bv, Bits);
            break;
          case VMBinOp::Xor:
            Res = maskToBits(A ^ Bv, Bits);
            break;
          case VMBinOp::Shl: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask >= Bits)
              return setError(Err, "vm: shift amount out of range");
            unsigned Sh = static_cast<unsigned>(BMask);
            Res = maskToBits(A << Sh, Bits);
            break;
          }
          case VMBinOp::LShr: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask >= Bits)
              return setError(Err, "vm: shift amount out of range");
            unsigned Sh = static_cast<unsigned>(BMask);
            Res = maskToBits(maskToBits(A, Bits) >> Sh, Bits);
            break;
          }
          case VMBinOp::AShr: {
            uint64_t BMask = maskToBits(Bv, Bits);
            if (BMask >= Bits)
              return setError(Err, "vm: shift amount out of range");
            unsigned Sh = static_cast<unsigned>(BMask);
            int64_t SA = static_cast<int64_t>(signExtend(A, Bits, 64));
            int64_t SR = SA >> Sh;
            Res = maskToBits(static_cast<uint64_t>(SR), Bits);
            break;
          }
          default:
            return setError(Err, "vm: invalid int binop");
          }
        }
        storeReg(I.Dst, Res, State, Err);
        break;
      }
      case VMOpcode::FNeg: {
        uint64_t V = loadValue(I.Ops[0], State, Err);
        if (!(I.Ty.Kind == VMTypeKind::F32 || I.Ty.Kind == VMTypeKind::F64))
          return setError(Err, "vm: fneg on non-float");
        APFloat F = apFloatFromBits(V, I.Ty.Kind);
        F.changeSign();
        uint64_t Res = apFloatToBits(F);
        storeReg(I.Dst, Res, State, Err);
        break;
      }
      case VMOpcode::ICmp: {
        uint64_t A = loadValue(I.Ops[0], State, Err);
        uint64_t Bv = loadValue(I.Ops[1], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t Au = maskToBits(A, Bits);
        uint64_t Bu = maskToBits(Bv, Bits);
        int64_t As = static_cast<int64_t>(signExtend(A, Bits, 64));
        int64_t Bs = static_cast<int64_t>(signExtend(Bv, Bits, 64));
        bool R = false;
        switch (I.Pred) {
        case VMCmpPred::EQ:
          R = (Au == Bu);
          break;
        case VMCmpPred::NE:
          R = (Au != Bu);
          break;
        case VMCmpPred::ULT:
          R = (Au < Bu);
          break;
        case VMCmpPred::ULE:
          R = (Au <= Bu);
          break;
        case VMCmpPred::UGT:
          R = (Au > Bu);
          break;
        case VMCmpPred::UGE:
          R = (Au >= Bu);
          break;
        case VMCmpPred::SLT:
          R = (As < Bs);
          break;
        case VMCmpPred::SLE:
          R = (As <= Bs);
          break;
        case VMCmpPred::SGT:
          R = (As > Bs);
          break;
        case VMCmpPred::SGE:
          R = (As >= Bs);
          break;
        default:
          return setError(Err, "vm: invalid icmp predicate");
        }
        storeReg(I.Dst, R ? 1 : 0, State, Err);
        break;
      }
      case VMOpcode::FCmp: {
        uint64_t A = loadValue(I.Ops[0], State, Err);
        uint64_t Bv = loadValue(I.Ops[1], State, Err);
        APFloat FA = apFloatFromBits(A, I.Ty.Kind);
        APFloat FB = apFloatFromBits(Bv, I.Ty.Kind);
        APFloat::cmpResult Cmp = FA.compare(FB);
        bool Unord = (Cmp == APFloat::cmpUnordered);
        bool R = false;
        switch (I.Pred) {
        case VMCmpPred::FEQ:
          R = (!Unord && Cmp == APFloat::cmpEqual);
          break;
        case VMCmpPred::FNE:
          R = (!Unord && Cmp != APFloat::cmpEqual);
          break;
        case VMCmpPred::FLT:
          R = (!Unord && Cmp == APFloat::cmpLessThan);
          break;
        case VMCmpPred::FLE:
          R = (!Unord && (Cmp == APFloat::cmpLessThan ||
                          Cmp == APFloat::cmpEqual));
          break;
        case VMCmpPred::FGT:
          R = (!Unord && Cmp == APFloat::cmpGreaterThan);
          break;
        case VMCmpPred::FGE:
          R = (!Unord && (Cmp == APFloat::cmpGreaterThan ||
                          Cmp == APFloat::cmpEqual));
          break;
        default:
          return setError(Err, "vm: invalid fcmp predicate");
        }
        storeReg(I.Dst, R ? 1 : 0, State, Err);
        break;
      }
      case VMOpcode::Cast: {
        uint64_t V = loadValue(I.Ops[0], State, Err);
        unsigned SrcBits = getTypeBitWidth(I.SrcTy.Kind, PtrBits);
        unsigned DstBits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t Out = 0;
        switch (I.Cast) {
        case VMCastKind::ZExt: {
          Out = maskToBits(V, SrcBits);
          break;
        }
        case VMCastKind::SExt: {
          Out = signExtend(V, SrcBits, DstBits);
          break;
        }
        case VMCastKind::Trunc:
        case VMCastKind::Bitcast:
        case VMCastKind::PtrToInt:
        case VMCastKind::IntToPtr:
          Out = maskToBits(V, DstBits);
          break;
        case VMCastKind::FPToUI: {
          uint64_t U = 0;
          if (I.SrcTy.Kind == VMTypeKind::F32) {
            uint32_t Bits = static_cast<uint32_t>(V);
            float F = 0.0f;
            std::memcpy(&F, &Bits, sizeof(F));
            if (F > 0.0f)
              U = static_cast<uint64_t>(F);
          } else {
            double F = 0.0;
            std::memcpy(&F, &V, sizeof(F));
            if (F > 0.0)
              U = static_cast<uint64_t>(F);
          }
          Out = maskToBits(U, DstBits);
          break;
        }
        case VMCastKind::FPToSI: {
          int64_t S = 0;
          if (I.SrcTy.Kind == VMTypeKind::F32) {
            uint32_t Bits = static_cast<uint32_t>(V);
            float F = 0.0f;
            std::memcpy(&F, &Bits, sizeof(F));
            S = static_cast<int64_t>(F);
          } else {
            double F = 0.0;
            std::memcpy(&F, &V, sizeof(F));
            S = static_cast<int64_t>(F);
          }
          Out = maskToBits(static_cast<uint64_t>(S), DstBits);
          break;
        }
        case VMCastKind::UIToFP: {
          uint64_t VMasked = maskToBits(V, SrcBits);
          if (I.Ty.Kind == VMTypeKind::F32) {
            float F = static_cast<float>(VMasked);
            uint32_t Bits = 0;
            std::memcpy(&Bits, &F, sizeof(F));
            Out = Bits;
          } else {
            double F = static_cast<double>(VMasked);
            uint64_t Bits = 0;
            std::memcpy(&Bits, &F, sizeof(F));
            Out = Bits;
          }
          break;
        }
        case VMCastKind::SIToFP: {
          int64_t S = static_cast<int64_t>(signExtend(V, SrcBits, 64));
          if (I.Ty.Kind == VMTypeKind::F32) {
            float F = static_cast<float>(S);
            uint32_t Bits = 0;
            std::memcpy(&Bits, &F, sizeof(F));
            Out = Bits;
          } else {
            double F = static_cast<double>(S);
            uint64_t Bits = 0;
            std::memcpy(&Bits, &F, sizeof(F));
            Out = Bits;
          }
          break;
        }
        case VMCastKind::FPTrunc: {
          APFloat F = apFloatFromBits(V, I.SrcTy.Kind);
          bool LosesInfo = false;
          F.convert(APFloat::IEEEsingle(), APFloat::rmNearestTiesToEven,
                    &LosesInfo);
          Out = apFloatToBits(F);
          break;
        }
        case VMCastKind::FPExt: {
          APFloat F = apFloatFromBits(V, I.SrcTy.Kind);
          bool LosesInfo = false;
          F.convert(APFloat::IEEEdouble(), APFloat::rmNearestTiesToEven,
                    &LosesInfo);
          Out = apFloatToBits(F);
          break;
        }
        }
        Out = maskToBits(Out, DstBits);
        storeReg(I.Dst, Out, State, Err);
        break;
      }
      case VMOpcode::Load: {
        uint64_t Addr = loadValue(I.Ops[0], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t V = readMem(Addr, Bits);
        storeReg(I.Dst, V, State, Err);
        break;
      }
      case VMOpcode::Store: {
        uint64_t Val = loadValue(I.Ops[0], State, Err);
        uint64_t Addr = loadValue(I.Ops[1], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        writeMem(Addr, Bits, Val);
        break;
      }
      case VMOpcode::MemFence: {
        std::atomic_thread_fence(fenceOrder(I.Fence));
        break;
      }
      case VMOpcode::Br:
        Cur = I.TargetTrue;
        goto next_block;
      case VMOpcode::CondBr: {
        uint64_t Cond = loadValue(I.Ops[0], State, Err);
        Cur = (Cond & 1ULL) ? I.TargetTrue : I.TargetFalse;
        goto next_block;
      }
      case VMOpcode::Switch: {
        if (I.Ops.empty())
          return setError(Err, "vm: switch missing cond");
        if (I.SwitchValues.size() != I.SwitchTargets.size())
          return setError(Err, "vm: switch value/target mismatch");
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t Cond = maskToBits(loadValue(I.Ops[0], State, Err), Bits);
        uint32_t Target = I.SwitchDefault;
        for (size_t i = 0; i < I.SwitchValues.size(); ++i) {
          uint64_t V = maskToBits(I.SwitchValues[i], Bits);
          if (V == Cond) {
            Target = I.SwitchTargets[i];
            break;
          }
        }
        Cur = Target;
        goto next_block;
      }
      case VMOpcode::Select: {
        uint64_t Cond = loadValue(I.Ops[0], State, Err);
        uint64_t TV = loadValue(I.Ops[1], State, Err);
        uint64_t FV = loadValue(I.Ops[2], State, Err);
        unsigned Bits = getTypeBitWidth(I.Ty.Kind, PtrBits);
        uint64_t Res = (Cond & 1ULL) ? TV : FV;
        storeReg(I.Dst, maskToBits(Res, Bits), State, Err);
        break;
      }
      case VMOpcode::Ret:
        if (!I.Ops.empty())
          RetVal = loadValue(I.Ops[0], State, Err);
        else
          RetVal = 0;
        return true;
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect:
        return setError(Err, "vm: callhost not supported in interpreter");
      case VMOpcode::Trap:
        return setError(Err, "vm: trap");
      }
    }
    return setError(Err, "vm: block without terminator");
  next_block:
    continue;
  }
}
