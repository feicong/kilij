//===- VMEncode.cpp - VM register encoding and MBA -----------------------===//
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
// Applies affine/Feistel register encoding and MBA expansion to VM IR
// while preserving semantics.
//
//===----------------------------------------------------------------------===//
#include "VMEncode.h"
#include "CryptoUtils.h"
#include "VMMath.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <map>

using namespace llvm;
using namespace llvm::obfvm;

#define DEBUG_TYPE "vmencode"

namespace {
struct ConstKey {
  VMTypeKind Kind;
  uint64_t Val;
  bool operator<(const ConstKey &O) const {
    if (Kind != O.Kind)
      return Kind < O.Kind;
    return Val < O.Val;
  }
};

static VMType encodedType(VMType Ty) {
  if (Ty.Kind == VMTypeKind::F32)
    return VMType(VMTypeKind::I32);
  if (Ty.Kind == VMTypeKind::F64)
    return VMType(VMTypeKind::I64);
  return Ty;
}

static VMAffineKey identityKey(unsigned Bits) {
  VMAffineKey K;
  K.A = 1;
  K.B = 0;
  K.InvA = 1;
  K.Bits = Bits;
  return K;
}

// Generate a random affine key E(x) = A*x + B mod 2^Bits with known inverse.
// Odd A guarantees a bijection mod 2^n; we compute A^{-1} via extended Euclid.
static VMAffineKey makeRandomKey(unsigned Bits) {
  VMAffineKey K;
  K.Bits = Bits;
  if (Bits == 0) {
    K.A = 1;
    K.B = 0;
    K.InvA = 1;
    return K;
  }
  uint64_t Mask = maskForBits(Bits);
  for (unsigned Attempt = 0; Attempt < 32; ++Attempt) {
    uint64_t A = cryptoutils->get_uint64_t();
    if (Bits < 64)
      A &= Mask;
    A |= 1ULL; // ensure odd
    if (A == 0)
      A = 1;
    uint64_t Inv = 0;
    if (!modInversePow2(A, Bits, Inv))
      continue;
    uint64_t B = cryptoutils->get_uint64_t();
    if (Bits < 64)
      B &= Mask;
    K.A = A & Mask;
    K.B = B & Mask;
    K.InvA = Inv & Mask;
    if (K.isValid())
      return K;
  }
  // Identity fallback -- shouldn't happen, but don't crash the build.
  return identityKey(Bits);
}

static constexpr unsigned kFeistelMaxRounds = 8;

// Per-register Feistel network parameters. Layered on top of affine encoding
// to break the linear structure that makes affine keys trivially recoverable.
struct VMFeistelKey {
  bool Enabled = false;
  unsigned Rounds = 0;
  unsigned Bits = 0;
  unsigned HalfBits = 0;
  uint64_t HalfMask = 0;
  uint64_t K1[kFeistelMaxRounds]{};
  uint64_t K2[kFeistelMaxRounds]{};
  uint8_t Rot[kFeistelMaxRounds]{};
};

static uint64_t rotlMasked(uint64_t V, unsigned Rot, unsigned Bits) {
  if (Bits == 0)
    return 0;
  uint64_t Mask = maskForBits(Bits);
  V &= Mask;
  Rot %= Bits;
  if (Rot == 0)
    return V;
  uint64_t L = (V << Rot) & Mask;
  uint64_t R = (V >> (Bits - Rot)) & Mask;
  return (L | R) & Mask;
}

// Round function F: multiply-add-rotate. Non-linear (mul+xor) so the
// overall cipher isn't reducible to a single affine transform.
static uint64_t feistelF(uint64_t R, const VMFeistelKey &K, unsigned Round) {
  uint64_t Mask = K.HalfMask;
  R &= Mask;
  uint64_t Mul = (R * (K.K1[Round] & Mask)) & Mask;
  uint64_t Add = (Mul + (K.K2[Round] & Mask)) & Mask;
  uint64_t Rot = rotlMasked(R, K.Rot[Round], K.HalfBits);
  return (Add ^ Rot) & Mask;
}

static uint64_t feistelEncodeScalar(uint64_t X, const VMFeistelKey &K) {
  if (!K.Enabled)
    return X;
  uint64_t Mask = maskForBits(K.Bits);
  uint64_t L = X & K.HalfMask;
  uint64_t R = (X >> K.HalfBits) & K.HalfMask;
  for (unsigned i = 0; i < K.Rounds; ++i) {
    uint64_t F = feistelF(R, K, i);
    uint64_t NewL = R;
    uint64_t NewR = (L ^ F) & K.HalfMask;
    L = NewL;
    R = NewR;
  }
  return ((R << K.HalfBits) | L) & Mask;
}

static uint64_t feistelDecodeScalar(uint64_t X, const VMFeistelKey &K) {
  if (!K.Enabled)
    return X;
  uint64_t Mask = maskForBits(K.Bits);
  uint64_t L = X & K.HalfMask;
  uint64_t R = (X >> K.HalfBits) & K.HalfMask;
  for (unsigned i = K.Rounds; i-- > 0;) {
    uint64_t F = feistelF(L, K, i);
    uint64_t NewR = L;
    uint64_t NewL = (R ^ F) & K.HalfMask;
    L = NewL;
    R = NewR;
  }
  return ((R << K.HalfBits) | L) & Mask;
}

// Encode-then-decode round-trip on a small sample to catch key schedule bugs
// early. Runs only in debug builds (guarded by NDEBUG at call sites).
static bool feistelSelfTest(const VMFeistelKey &K) {
  if (!K.Enabled)
    return true;
  uint64_t Mask = maskForBits(K.Bits);
  for (uint64_t i = 0; i < 256; ++i) {
    uint64_t V = (i * 37ULL) & Mask;
    uint64_t Enc = feistelEncodeScalar(V, K);
    uint64_t Dec = feistelDecodeScalar(Enc, K);
    if ((Dec & Mask) != (V & Mask))
      return false;
  }
  return true;
}

struct EncodeContext {
  VMFunction &F;
  VMLoweringResult &Res;
  unsigned PtrBits;
  bool EnableFeistel = false;
  bool FeistelAllRegs = false;
  unsigned FeistelRounds = 0;
  unsigned EncodePercent = 100;
  std::vector<unsigned> RegBits;
  std::vector<VMAffineKey> Keys;
  std::vector<VMFeistelKey> FeistelKeys;
  std::vector<uint8_t> EncodeEligible;
  std::vector<uint8_t> EncodeBlocked;
  std::vector<uint8_t> FeistelEligible;
  uint32_t NextReg;
  std::map<ConstKey, uint32_t> ConstRegs;
  DenseMap<const Constant *, uint32_t> ConstPtrRegs;
  SmallVector<VMInstr, 32> EntryPrefix;

  EncodeContext(VMFunction &Func, VMLoweringResult &R, bool EnableF,
                bool FeistelAll, unsigned Rounds, unsigned Pct)
      : F(Func), Res(R), PtrBits(Func.PtrBits), EnableFeistel(EnableF),
        FeistelAllRegs(FeistelAll), FeistelRounds(Rounds),
        EncodePercent(Pct) {
    RegBits.resize(Func.RegCount, 0);
    Keys.resize(Func.RegCount);
    FeistelKeys.resize(Func.RegCount);
    EncodeEligible.resize(Func.RegCount, 0);
    EncodeBlocked.resize(Func.RegCount, 0);
    FeistelEligible.resize(Func.RegCount, 0);
    NextReg = Func.RegCount;
  }

  unsigned bitsForKind(VMTypeKind K) const {
    return getTypeBitWidth(K, PtrBits);
  }

  void recordBits(uint32_t Reg, VMTypeKind K) {
    if (Reg >= RegBits.size())
      return;
    if (K == VMTypeKind::Ptr)
      blockEncodeReg(Reg);
    unsigned Bits = bitsForKind(K);
    if (RegBits[Reg] == 0)
      RegBits[Reg] = Bits;
    else if (RegBits[Reg] != Bits)
      RegBits[Reg] = 0;
  }

  void blockEncodeReg(uint32_t Reg) {
    if (Reg < EncodeBlocked.size())
      EncodeBlocked[Reg] = 1;
  }

  void analyze() {
    for (VMBlock &B : F.Blocks) {
      for (VMInstr &I : B.Instrs) {
        switch (I.Op) {
        case VMOpcode::Mov:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          if (!I.Ops.empty() && I.Ops[0].K == VMValue::Kind::Reg)
            recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::BinOp:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          recordBits(I.Ops[1].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::FNeg:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::ICmp:
        case VMOpcode::FCmp:
          recordBits(I.Dst, VMTypeKind::I1);
          recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          recordBits(I.Ops[1].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::Cast:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          recordBits(I.Ops[0].Reg, encodedType(I.SrcTy).Kind);
          if (I.Cast == VMCastKind::PtrToInt ||
              I.Cast == VMCastKind::IntToPtr) {
            blockEncodeReg(I.Dst);
            if (!I.Ops.empty() && I.Ops[0].K == VMValue::Kind::Reg)
              blockEncodeReg(I.Ops[0].Reg);
          }
          break;
        case VMOpcode::Load:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          recordBits(I.Ops[0].Reg, VMTypeKind::Ptr);
          break;
        case VMOpcode::Store:
          recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          recordBits(I.Ops[1].Reg, VMTypeKind::Ptr);
          break;
        case VMOpcode::Br:
          break;
        case VMOpcode::CondBr:
          recordBits(I.Ops[0].Reg, VMTypeKind::I1);
          break;
        case VMOpcode::Switch:
          recordBits(I.Ops[0].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::Select:
          recordBits(I.Dst, encodedType(I.Ty).Kind);
          recordBits(I.Ops[0].Reg, VMTypeKind::I1);
          recordBits(I.Ops[1].Reg, encodedType(I.Ty).Kind);
          recordBits(I.Ops[2].Reg, encodedType(I.Ty).Kind);
          break;
        case VMOpcode::Ret:
          break;
        case VMOpcode::CallHost:
        case VMOpcode::CallHostIndirect:
          if (I.CallIndex < F.Calls.size()) {
            VMCallInfo &CI = F.Calls[I.CallIndex];
            if (CI.CalleeTy && CI.CalleeTy->isVarArg()) {
              for (uint32_t R : CI.ArgRegs)
                blockEncodeReg(R);
            }
            for (unsigned i = 0; i < CI.ArgRegs.size(); ++i) {
              VMTypeKind K = VMTypeKind::I64;
              Type *ATy = nullptr;
              if (CI.CalleeTy && i < CI.CalleeTy->getNumParams()) {
                ATy = CI.CalleeTy->getParamType(i);
              } else if (i < CI.ArgTypes.size() && CI.ArgTypes[i]) {
                ATy = CI.ArgTypes[i];
              }
              if (ATy) {
                if (ATy->isIntegerTy(1))
                  K = VMTypeKind::I1;
                else if (ATy->isIntegerTy(8))
                  K = VMTypeKind::I8;
                else if (ATy->isIntegerTy(16))
                  K = VMTypeKind::I16;
                else if (ATy->isIntegerTy(32))
                  K = VMTypeKind::I32;
                else if (ATy->isIntegerTy(64))
                  K = VMTypeKind::I64;
                else if (ATy->isFloatTy())
                  K = VMTypeKind::F32;
                else if (ATy->isDoubleTy())
                  K = VMTypeKind::F64;
                else if (ATy->isPointerTy())
                  K = VMTypeKind::Ptr;
              }
              recordBits(CI.ArgRegs[i], encodedType(VMType(K)).Kind);
            }
            if (CI.IsIndirect && CI.CalleeReg != UINT32_MAX)
              recordBits(CI.CalleeReg, VMTypeKind::Ptr);
            if (!CI.IsVoid && CI.RetReg != UINT32_MAX) {
              recordBits(CI.RetReg, encodedType(CI.RetTy).Kind);
            }
          }
          break;
        case VMOpcode::MemFence:
        case VMOpcode::Trap:
          break;
        }
      }
    }

    // Stochastic selection keeps code-size growth bounded at lower encode%.
    EncodeEligible.assign(RegBits.size(), 0);
    if (EncodePercent >= 100) {
      for (uint32_t R = 0; R < RegBits.size(); ++R) {
        if (R < EncodeBlocked.size() && EncodeBlocked[R])
          continue;
        EncodeEligible[R] = (RegBits[R] > 1);
      }
    } else if (EncodePercent > 0) {
      for (uint32_t R = 0; R < RegBits.size(); ++R) {
        if (R < EncodeBlocked.size() && EncodeBlocked[R])
          continue;
        if (RegBits[R] > 1 &&
            cryptoutils->get_range(100) < EncodePercent)
          EncodeEligible[R] = 1;
      }
    }

    // Feistel is expensive; default to arg/ret/alloca regs only since those
    // are the most valuable targets for attackers recovering function ABI.
    FeistelEligible.assign(RegBits.size(), 0);
    if (EnableFeistel) {
      if (FeistelAllRegs) {
        for (uint32_t R = 0; R < RegBits.size(); ++R)
          FeistelEligible[R] =
              (EncodeEligible[R] != 0);
      } else {
        for (uint32_t R : Res.ArgRegs) {
          if (R < FeistelEligible.size() && EncodeEligible[R])
            FeistelEligible[R] = 1;
        }
        if (Res.HasRet && Res.RetReg != UINT32_MAX &&
            Res.RetReg < FeistelEligible.size() && EncodeEligible[Res.RetReg])
          FeistelEligible[Res.RetReg] = 1;
        for (const VMAllocaInfo &A : Res.Allocas) {
          if (A.Reg < FeistelEligible.size() && EncodeEligible[A.Reg])
            FeistelEligible[A.Reg] = 1;
        }
      }
    }

    for (uint32_t R = 0; R < RegBits.size(); ++R) {
      unsigned Bits = RegBits[R];
      if (!EncodeEligible[R] || Bits <= 1 || Bits == 0) {
        Keys[R] = identityKey(Bits == 0 ? 64 : Bits);
      } else {
        Keys[R] = makeRandomKey(Bits);
      }
    }

    if (EnableFeistel) {
      for (uint32_t R = 0; R < RegBits.size(); ++R) {
        VMFeistelKey FK;
        if (R >= FeistelEligible.size() || !FeistelEligible[R]) {
          FeistelKeys[R] = FK;
          continue;
        }
        unsigned Bits = RegBits[R];
        // Feistel needs even bit-width for balanced halves; skip odd widths.
        if (Bits < 16 || Bits > 64 || (Bits & 1) != 0) {
          FeistelKeys[R] = FK;
          continue;
        }
        unsigned Half = Bits / 2;
        if (Half <= 1) {
          FeistelKeys[R] = FK;
          continue;
        }
        unsigned Rounds = FeistelRounds;
        if (Rounds < 2)
          Rounds = 2;
        if (Rounds > kFeistelMaxRounds)
          Rounds = kFeistelMaxRounds;
        FK.Enabled = true;
        FK.Rounds = Rounds;
        FK.Bits = Bits;
        FK.HalfBits = Half;
        FK.HalfMask = maskForBits(Half);
        for (unsigned i = 0; i < FK.Rounds; ++i) {
          uint64_t K1 = cryptoutils->get_uint64_t() & FK.HalfMask;
          if (K1 == 0)
            K1 = 1;
          uint64_t K2 = cryptoutils->get_uint64_t() & FK.HalfMask;
          unsigned RotMax = Half - 1;
          unsigned Rot = RotMax ? (1u + cryptoutils->get_range(RotMax)) : 0u;
          if (Rot == 0)
            Rot = 1;
          FK.K1[i] = K1;
          FK.K2[i] = K2;
          FK.Rot[i] = static_cast<uint8_t>(Rot);
        }
#ifndef NDEBUG
        assert(feistelSelfTest(FK) && "feistel key self-test failed");
#endif
        FeistelKeys[R] = FK;
      }
    } else {
      for (uint32_t R = 0; R < RegBits.size(); ++R)
        FeistelKeys[R] = VMFeistelKey();
    }
  }

  uint32_t allocTemp(VMType Ty) {
    uint32_t R = NextReg++;
    unsigned Bits = bitsForKind(encodedType(Ty).Kind);
    RegBits.push_back(Bits);
    Keys.push_back(identityKey(Bits));
    FeistelKeys.push_back(VMFeistelKey());
    EncodeEligible.push_back(0);
    EncodeBlocked.push_back(0);
    FeistelEligible.push_back(0);
    return R;
  }

  bool isEncodedReg(uint32_t R) const {
    return (R < EncodeEligible.size()) && (EncodeEligible[R] != 0);
  }

  uint32_t getConstRegImm(uint64_t Val, VMType Ty) {
    VMType EncTy = encodedType(Ty);
    unsigned Bits = bitsForKind(EncTy.Kind);
    uint64_t Mask = maskForBits(Bits);
    uint64_t V = Val & Mask;
    ConstKey Key{EncTy.Kind, V};
    auto It = ConstRegs.find(Key);
    if (It != ConstRegs.end())
      return It->second;
    uint32_t R = allocTemp(EncTy);
    VMInstr Mov;
    Mov.Op = VMOpcode::Mov;
    Mov.Ty = EncTy;
    Mov.Dst = R;
    Mov.Ops = {VMValue::imm(V)};
    EntryPrefix.push_back(Mov);
    ConstRegs.emplace(Key, R);
    return R;
  }

  uint32_t getConstRegConst(Constant *C, VMType Ty) {
    VMType EncTy = encodedType(Ty);
    auto It = ConstPtrRegs.find(C);
    if (It != ConstPtrRegs.end())
      return It->second;
    uint32_t R = allocTemp(EncTy);
    VMInstr Mov;
    Mov.Op = VMOpcode::Mov;
    Mov.Ty = EncTy;
    Mov.Dst = R;
    Mov.Ops = {VMValue::constant(C)};
    EntryPrefix.push_back(Mov);
    ConstPtrRegs.insert({C, R});
    return R;
  }

  // Pre-encode immediates so they land in the destination's encoded domain
  // without an extra decode/encode pair at runtime.
  uint64_t encodeImmediate(uint64_t Val, VMType Ty, uint32_t DstReg) const {
    VMType EncTy = encodedType(Ty);
    unsigned Bits = bitsForKind(EncTy.Kind);
    uint64_t Mask = maskForBits(Bits);
    uint64_t X = Val & Mask;
    if (DstReg < Keys.size()) {
      const VMAffineKey &K = Keys[DstReg];
      if (!(K.A == 1 && K.B == 0))
        X = K.encode(X);
      if (DstReg < FeistelKeys.size()) {
        const VMFeistelKey &FK = FeistelKeys[DstReg];
        if (FK.Enabled)
          X = feistelEncodeScalar(X, FK);
      }
    }
    return X & Mask;
  }

  uint32_t emitFeistel(uint32_t SrcReg, uint32_t DstReg, VMType EncTy,
                       VMFeistelKey FK, bool Encode,
                       SmallVectorImpl<VMInstr> &Out) {
    if (!FK.Enabled)
      return SrcReg;
    unsigned Bits = bitsForKind(EncTy.Kind);
    if (Bits != FK.Bits || FK.HalfBits == 0)
      return SrcReg;

    uint32_t MaskReg = getConstRegImm(FK.HalfMask, EncTy);
    uint32_t HalfReg = getConstRegImm(FK.HalfBits, EncTy);

    auto emitBin = [&](VMBinOp Op, uint32_t Dst, uint32_t A, uint32_t B) {
      VMInstr I;
      I.Op = VMOpcode::BinOp;
      I.Ty = EncTy;
      I.Bin = Op;
      I.Dst = Dst;
      I.Ops = {VMValue::reg(A), VMValue::reg(B)};
      Out.push_back(I);
    };

    uint32_t L = allocTemp(EncTy);
    emitBin(VMBinOp::And, L, SrcReg, MaskReg);

    uint32_t RShift = allocTemp(EncTy);
    emitBin(VMBinOp::LShr, RShift, SrcReg, HalfReg);
    uint32_t R = allocTemp(EncTy);
    emitBin(VMBinOp::And, R, RShift, MaskReg);

    auto emitRotl = [&](uint32_t VReg, unsigned Rot) -> uint32_t {
      if (Rot == 0 || Rot >= FK.HalfBits)
        return VReg;
      uint32_t RotReg = getConstRegImm(Rot, EncTy);
      uint32_t InvRotReg =
          getConstRegImm(FK.HalfBits - Rot, EncTy);
      uint32_t Shl = allocTemp(EncTy);
      emitBin(VMBinOp::Shl, Shl, VReg, RotReg);
      uint32_t Shr = allocTemp(EncTy);
      emitBin(VMBinOp::LShr, Shr, VReg, InvRotReg);
      uint32_t Or = allocTemp(EncTy);
      emitBin(VMBinOp::Or, Or, Shl, Shr);
      uint32_t Masked = allocTemp(EncTy);
      emitBin(VMBinOp::And, Masked, Or, MaskReg);
      return Masked;
    };

    auto emitF = [&](uint32_t InReg, unsigned Round) -> uint32_t {
      uint32_t K1Reg = getConstRegImm(FK.K1[Round], EncTy);
      uint32_t K2Reg = getConstRegImm(FK.K2[Round], EncTy);
      uint32_t Mul = allocTemp(EncTy);
      emitBin(VMBinOp::Mul, Mul, InReg, K1Reg);
      uint32_t Add = allocTemp(EncTy);
      emitBin(VMBinOp::Add, Add, Mul, K2Reg);
      uint32_t Rot = emitRotl(InReg, FK.Rot[Round]);
      uint32_t Xor = allocTemp(EncTy);
      emitBin(VMBinOp::Xor, Xor, Add, Rot);
      uint32_t Masked = allocTemp(EncTy);
      emitBin(VMBinOp::And, Masked, Xor, MaskReg);
      return Masked;
    };

    if (Encode) {
      for (unsigned Round = 0; Round < FK.Rounds; ++Round) {
        uint32_t Fv = emitF(R, Round);
        uint32_t NewR = allocTemp(EncTy);
        emitBin(VMBinOp::Xor, NewR, L, Fv);
        emitBin(VMBinOp::And, NewR, NewR, MaskReg);
        uint32_t NewL = R;
        L = NewL;
        R = NewR;
      }
    } else {
      for (unsigned Round = FK.Rounds; Round-- > 0;) {
        uint32_t Fv = emitF(L, Round);
        uint32_t NewL = allocTemp(EncTy);
        emitBin(VMBinOp::Xor, NewL, R, Fv);
        emitBin(VMBinOp::And, NewL, NewL, MaskReg);
        uint32_t NewR = L;
        L = NewL;
        R = NewR;
      }
    }

    uint32_t RShiftOut = allocTemp(EncTy);
    emitBin(VMBinOp::Shl, RShiftOut, R, HalfReg);
    uint32_t OutReg = (DstReg != UINT32_MAX) ? DstReg : allocTemp(EncTy);
    emitBin(VMBinOp::Or, OutReg, RShiftOut, L);
    return OutReg;
  }

  uint32_t emitDecode(uint32_t SrcReg, VMType Ty,
                      SmallVectorImpl<VMInstr> &Out) {
    VMType EncTy = encodedType(Ty);
    unsigned Bits = bitsForKind(EncTy.Kind);
    if (SrcReg >= Keys.size())
      return SrcReg;
    if (!isEncodedReg(SrcReg))
      return SrcReg;
    uint32_t Cur = SrcReg;
    if (SrcReg < FeistelKeys.size()) {
      VMFeistelKey FK = FeistelKeys[SrcReg];
      if (FK.Enabled)
        Cur = emitFeistel(Cur, UINT32_MAX, EncTy, FK, false, Out);
    }
    const VMAffineKey &K = Keys[SrcReg];
    if (K.A == 1 && K.B == 0)
      return Cur;
    uint32_t RB = getConstRegImm(K.B, EncTy);
    uint32_t RInv = getConstRegImm(K.InvA, EncTy);
    uint32_t T1 = allocTemp(EncTy);
    VMInstr Sub;
    Sub.Op = VMOpcode::BinOp;
    Sub.Ty = EncTy;
    Sub.Bin = VMBinOp::Sub;
    Sub.Dst = T1;
    Sub.Ops = {VMValue::reg(Cur), VMValue::reg(RB)};
    uint32_t T2 = allocTemp(EncTy);
    VMInstr Mul;
    Mul.Op = VMOpcode::BinOp;
    Mul.Ty = EncTy;
    Mul.Bin = VMBinOp::Mul;
    Mul.Dst = T2;
    Mul.Ops = {VMValue::reg(T1), VMValue::reg(RInv)};
    Out.push_back(Sub);
    Out.push_back(Mul);
    (void)Bits;
    return T2;
  }

  void emitEncode(uint32_t SrcReg, uint32_t DstReg, VMType Ty,
                  SmallVectorImpl<VMInstr> &Out) {
    VMType EncTy = encodedType(Ty);
    if (DstReg >= Keys.size())
      return;
    if (!isEncodedReg(DstReg)) {
      if (SrcReg != DstReg) {
        VMInstr Mov;
        Mov.Op = VMOpcode::Mov;
        Mov.Ty = EncTy;
        Mov.Dst = DstReg;
        Mov.Ops = {VMValue::reg(SrcReg)};
        Out.push_back(Mov);
      }
      return;
    }
    const VMAffineKey &K = Keys[DstReg];
    uint32_t Cur = SrcReg;
    if (!(K.A == 1 && K.B == 0)) {
      uint32_t RA = getConstRegImm(K.A, EncTy);
      uint32_t RB = getConstRegImm(K.B, EncTy);
      VMInstr Mul;
      Mul.Op = VMOpcode::BinOp;
      Mul.Ty = EncTy;
      Mul.Bin = VMBinOp::Mul;
      Mul.Dst = DstReg;
      Mul.Ops = {VMValue::reg(Cur), VMValue::reg(RA)};
      VMInstr Add;
      Add.Op = VMOpcode::BinOp;
      Add.Ty = EncTy;
      Add.Bin = VMBinOp::Add;
      Add.Dst = DstReg;
      Add.Ops = {VMValue::reg(DstReg), VMValue::reg(RB)};
      Out.push_back(Mul);
      Out.push_back(Add);
      Cur = DstReg;
    }
    if (DstReg < FeistelKeys.size()) {
      VMFeistelKey FK = FeistelKeys[DstReg];
      if (FK.Enabled) {
        Cur = emitFeistel(Cur, DstReg, EncTy, FK, true, Out);
        return;
      }
    }
    if (Cur != DstReg) {
      VMInstr Mov;
      Mov.Op = VMOpcode::Mov;
      Mov.Ty = EncTy;
      Mov.Dst = DstReg;
      Mov.Ops = {VMValue::reg(Cur)};
      Out.push_back(Mov);
    }
  }

  VMType typeFromBits(unsigned Bits) const {
    switch (Bits) {
    case 1:
      return VMType(VMTypeKind::I1);
    case 8:
      return VMType(VMTypeKind::I8);
    case 16:
      return VMType(VMTypeKind::I16);
    case 32:
      return VMType(VMTypeKind::I32);
    case 64:
      return VMType(VMTypeKind::I64);
    default:
      return VMType(VMTypeKind::I64);
    }
  }
};
} // namespace

bool llvm::obfvm::applyAffineEncoding(VMLoweringResult &Res, bool EnableFeistel,
                                      bool FeistelAllRegs,
                                      unsigned FeistelRounds,
                                      unsigned EncodePercent,
                                      std::string &Err) {
  VMFunction &F = Res.VMF;
  if (EncodePercent == 0)
    return true;
  if (EncodePercent > 100)
    EncodePercent = 100;
  EncodeContext Ctx(F, Res, EnableFeistel, FeistelAllRegs, FeistelRounds,
                    EncodePercent);
  Ctx.analyze();
  uint32_t RetTmp = UINT32_MAX;
  uint64_t InstrIndex = 0;

  for (uint32_t R = 0; R < Ctx.Keys.size(); ++R) {
    if (!Ctx.Keys[R].isValid()) {
      Err = "vm: invalid affine key";
      return false;
    }
  }

  for (uint32_t R : Res.ArgRegs) {
    if (R < Ctx.Keys.size() && Ctx.isEncodedReg(R)) {
      VMType Ty = VMType(VMTypeKind::I64);
      unsigned Bits = Ctx.RegBits[R];
      if (Bits == 1)
        Ty = VMType(VMTypeKind::I1);
      else if (Bits == 8)
        Ty = VMType(VMTypeKind::I8);
      else if (Bits == 16)
        Ty = VMType(VMTypeKind::I16);
      else if (Bits == 32)
        Ty = VMType(VMTypeKind::I32);
      else if (Bits == 64)
        Ty = VMType(VMTypeKind::I64);
      uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
      VMInstr Mov;
      Mov.Op = VMOpcode::Mov;
      Mov.Ty = encodedType(Ty);
      Mov.Dst = Tmp;
      Mov.Ops = {VMValue::reg(R)};
      Ctx.EntryPrefix.push_back(Mov);
      Ctx.emitEncode(Tmp, R, Ty, Ctx.EntryPrefix);
    }
  }

  for (const VMAllocaInfo &A : Res.Allocas) {
    uint32_t R = A.Reg;
    if (R < Ctx.Keys.size() && Ctx.isEncodedReg(R)) {
      VMType Ty = VMType(VMTypeKind::Ptr);
      uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
      VMInstr Mov;
      Mov.Op = VMOpcode::Mov;
      Mov.Ty = encodedType(Ty);
      Mov.Dst = Tmp;
      Mov.Ops = {VMValue::reg(R)};
      Ctx.EntryPrefix.push_back(Mov);
      Ctx.emitEncode(Tmp, R, Ty, Ctx.EntryPrefix);
    }
  }

  for (VMBlock &B : F.Blocks) {
    SmallVector<VMInstr, 32> NewInstrs;
    for (VMInstr &I : B.Instrs) {
      LLVM_DEBUG(if ((InstrIndex & 0xFFu) == 0) {
        dbgs() << "vmencode: " << F.Name << " instr=" << InstrIndex
               << " op=" << static_cast<unsigned>(I.Op)
               << " ops=" << I.Ops.size() << "\n";
      });
      ++InstrIndex;
      switch (I.Op) {
      case VMOpcode::Mov: {
        VMType Ty = I.Ty;
        VMType EncTy = encodedType(Ty);
        bool DstEnc = Ctx.isEncodedReg(I.Dst);
        if (!DstEnc) {
          if (I.Ops[0].K == VMValue::Kind::Imm) {
            VMInstr Mov = I;
            Mov.Ty = Ty;
            Mov.Ops = {VMValue::imm(I.Ops[0].Imm)};
            NewInstrs.push_back(Mov);
          } else if (I.Ops[0].K == VMValue::Kind::Const) {
            uint32_t CReg = Ctx.getConstRegConst(I.Ops[0].C, Ty);
            VMInstr Mov = I;
            Mov.Ty = Ty;
            Mov.Ops = {VMValue::reg(CReg)};
            NewInstrs.push_back(Mov);
          } else {
            uint32_t Dec = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
            VMInstr Mov = I;
            Mov.Ty = Ty;
            Mov.Ops = {VMValue::reg(Dec)};
            NewInstrs.push_back(Mov);
          }
          break;
        }
        if (I.Ops[0].K == VMValue::Kind::Imm) {
          uint64_t Enc = Ctx.encodeImmediate(I.Ops[0].Imm, Ty, I.Dst);
          VMInstr Mov;
          Mov.Op = VMOpcode::Mov;
          Mov.Ty = EncTy;
          Mov.Dst = I.Dst;
          Mov.Ops = {VMValue::imm(Enc)};
          NewInstrs.push_back(Mov);
        } else if (I.Ops[0].K == VMValue::Kind::Const) {
          uint32_t CReg = Ctx.getConstRegConst(I.Ops[0].C, Ty);
          Ctx.emitEncode(CReg, I.Dst, Ty, NewInstrs);
        } else {
          uint32_t Dec = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
          Ctx.emitEncode(Dec, I.Dst, Ty, NewInstrs);
        }
        break;
      }
      case VMOpcode::BinOp: {
        VMType Ty = I.Ty;
        uint32_t A = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
        uint32_t Bv = Ctx.emitDecode(I.Ops[1].Reg, Ty, NewInstrs);
        VMInstr Op = I;
        Op.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
          Op.Dst = Tmp;
          NewInstrs.push_back(Op);
          Ctx.emitEncode(Tmp, I.Dst, Ty, NewInstrs);
        } else {
          Op.Dst = I.Dst;
          NewInstrs.push_back(Op);
        }
        break;
      }
      case VMOpcode::FNeg: {
        VMType Ty = I.Ty;
        uint32_t Src = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
        VMInstr Op = I;
        Op.Ops = {VMValue::reg(Src)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
          Op.Dst = Tmp;
          NewInstrs.push_back(Op);
          Ctx.emitEncode(Tmp, I.Dst, Ty, NewInstrs);
        } else {
          Op.Dst = I.Dst;
          NewInstrs.push_back(Op);
        }
        break;
      }
      case VMOpcode::ICmp:
      case VMOpcode::FCmp: {
        VMType Ty = I.Ty;
        uint32_t A = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
        uint32_t Bv = Ctx.emitDecode(I.Ops[1].Reg, Ty, NewInstrs);
        VMInstr Cmp = I;
        Cmp.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(VMType(VMTypeKind::I1));
          Cmp.Dst = Tmp;
          NewInstrs.push_back(Cmp);
          Ctx.emitEncode(Tmp, I.Dst, VMType(VMTypeKind::I1), NewInstrs);
        } else {
          Cmp.Dst = I.Dst;
          NewInstrs.push_back(Cmp);
        }
        break;
      }
      case VMOpcode::Cast: {
        VMType SrcTy = I.SrcTy;
        VMType DstTy = I.Ty;
        uint32_t Src = Ctx.emitDecode(I.Ops[0].Reg, SrcTy, NewInstrs);
        VMInstr Cast = I;
        Cast.Ops = {VMValue::reg(Src)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(encodedType(DstTy));
          Cast.Dst = Tmp;
          NewInstrs.push_back(Cast);
          Ctx.emitEncode(Tmp, I.Dst, DstTy, NewInstrs);
        } else {
          Cast.Dst = I.Dst;
          NewInstrs.push_back(Cast);
        }
        break;
      }
      case VMOpcode::Load: {
        VMType Ty = I.Ty;
        uint32_t Addr =
            Ctx.emitDecode(I.Ops[0].Reg, VMType(VMTypeKind::Ptr), NewInstrs);
        VMInstr Ld = I;
        Ld.Ops = {VMValue::reg(Addr)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
          Ld.Dst = Tmp;
          NewInstrs.push_back(Ld);
          Ctx.emitEncode(Tmp, I.Dst, Ty, NewInstrs);
        } else {
          Ld.Dst = I.Dst;
          NewInstrs.push_back(Ld);
        }
        break;
      }
      case VMOpcode::Store: {
        VMType Ty = I.Ty;
        uint32_t Val = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
        uint32_t Addr =
            Ctx.emitDecode(I.Ops[1].Reg, VMType(VMTypeKind::Ptr), NewInstrs);
        VMInstr St = I;
        St.Ops = {VMValue::reg(Val), VMValue::reg(Addr)};
        NewInstrs.push_back(St);
        break;
      }
      case VMOpcode::MemFence:
        NewInstrs.push_back(I);
        break;
      case VMOpcode::CondBr: {
        uint32_t Cond =
            Ctx.emitDecode(I.Ops[0].Reg, VMType(VMTypeKind::I1), NewInstrs);
        VMInstr Br = I;
        Br.Ops = {VMValue::reg(Cond)};
        NewInstrs.push_back(Br);
        break;
      }
      case VMOpcode::Switch: {
        VMType Ty = I.Ty;
        uint32_t Cond = Ctx.emitDecode(I.Ops[0].Reg, Ty, NewInstrs);
        VMInstr Sw = I;
        Sw.Ops = {VMValue::reg(Cond)};
        NewInstrs.push_back(Sw);
        break;
      }
      case VMOpcode::Select: {
        VMType Ty = I.Ty;
        uint32_t Cond =
            Ctx.emitDecode(I.Ops[0].Reg, VMType(VMTypeKind::I1), NewInstrs);
        uint32_t TV = Ctx.emitDecode(I.Ops[1].Reg, Ty, NewInstrs);
        uint32_t FV = Ctx.emitDecode(I.Ops[2].Reg, Ty, NewInstrs);
        VMInstr Sel = I;
        Sel.Ops = {VMValue::reg(Cond), VMValue::reg(TV), VMValue::reg(FV)};
        if (Ctx.isEncodedReg(I.Dst)) {
          uint32_t Tmp = Ctx.allocTemp(encodedType(Ty));
          Sel.Dst = Tmp;
          NewInstrs.push_back(Sel);
          Ctx.emitEncode(Tmp, I.Dst, Ty, NewInstrs);
        } else {
          Sel.Dst = I.Dst;
          NewInstrs.push_back(Sel);
        }
        break;
      }
      case VMOpcode::Ret: {
        VMInstr Ret = I;
        if (!I.Ops.empty()) {
          uint32_t R = I.Ops[0].Reg;
          VMType Ty = Ctx.typeFromBits(
              (R < Ctx.RegBits.size()) ? Ctx.RegBits[R] : 64);
          uint32_t V = Ctx.emitDecode(R, Ty, NewInstrs);
          if (RetTmp == UINT32_MAX) {
            RetTmp = V;
          } else if (RetTmp != V) {
            VMInstr Mov;
            Mov.Op = VMOpcode::Mov;
            Mov.Ty = encodedType(Ty);
            Mov.Dst = RetTmp;
            Mov.Ops = {VMValue::reg(V)};
            NewInstrs.push_back(Mov);
          }
          Ret.Ops = {VMValue::reg(RetTmp)};
        }
        NewInstrs.push_back(Ret);
        break;
      }
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect: {
        if (I.CallIndex < F.Calls.size()) {
          VMCallInfo &CI = F.Calls[I.CallIndex];
          SmallVector<uint32_t, 8> NewArgs;
          for (unsigned i = 0; i < CI.ArgRegs.size(); ++i) {
            VMTypeKind K = VMTypeKind::I64;
            if (i < CI.ArgTypes.size() && CI.ArgTypes[i]) {
              Type *ATy = CI.ArgTypes[i];
              if (ATy->isIntegerTy(1))
                K = VMTypeKind::I1;
              else if (ATy->isIntegerTy(8))
                K = VMTypeKind::I8;
              else if (ATy->isIntegerTy(16))
                K = VMTypeKind::I16;
              else if (ATy->isIntegerTy(32))
                K = VMTypeKind::I32;
              else if (ATy->isIntegerTy(64))
                K = VMTypeKind::I64;
              else if (ATy->isFloatTy())
                K = VMTypeKind::F32;
              else if (ATy->isDoubleTy())
                K = VMTypeKind::F64;
              else if (ATy->isPointerTy())
                K = VMTypeKind::Ptr;
            } else if (CI.CalleeTy && i < CI.CalleeTy->getNumParams()) {
              Type *ATy = CI.CalleeTy->getParamType(i);
              if (ATy->isIntegerTy(1))
                K = VMTypeKind::I1;
              else if (ATy->isIntegerTy(8))
                K = VMTypeKind::I8;
              else if (ATy->isIntegerTy(16))
                K = VMTypeKind::I16;
              else if (ATy->isIntegerTy(32))
                K = VMTypeKind::I32;
              else if (ATy->isIntegerTy(64))
                K = VMTypeKind::I64;
              else if (ATy->isFloatTy())
                K = VMTypeKind::F32;
              else if (ATy->isDoubleTy())
                K = VMTypeKind::F64;
              else if (ATy->isPointerTy())
                K = VMTypeKind::Ptr;
            }
            uint32_t Dec =
                Ctx.emitDecode(CI.ArgRegs[i], VMType(K), NewInstrs);
            NewArgs.push_back(Dec);
          }
          CI.ArgRegs = NewArgs;

          VMInstr CallInst = I;
          if (I.Op == VMOpcode::CallHostIndirect) {
            uint32_t CalleeSrc =
                !I.Ops.empty() ? I.Ops[0].Reg : CI.CalleeReg;
            if (CalleeSrc != UINT32_MAX) {
              VMType CalleeTy = VMType(VMTypeKind::Ptr);
              uint32_t CalleeDec =
                  Ctx.emitDecode(CalleeSrc, CalleeTy, NewInstrs);
              CallInst.Ops = {VMValue::reg(CalleeDec)};
              CI.CalleeReg = CalleeDec;
            }
          }

          uint32_t OrigRet = CI.RetReg;
          VMType RetTy = CI.RetTy;
          if (!CI.IsVoid) {
            if (OrigRet != UINT32_MAX && Ctx.isEncodedReg(OrigRet)) {
              uint32_t Tmp = Ctx.allocTemp(encodedType(RetTy));
              CI.RetReg = Tmp;
              NewInstrs.push_back(CallInst);
              Ctx.emitEncode(Tmp, OrigRet, RetTy, NewInstrs);
            } else {
              NewInstrs.push_back(CallInst);
            }
          } else {
            NewInstrs.push_back(CallInst);
          }
        } else {
          NewInstrs.push_back(I);
        }
        break;
      }
      case VMOpcode::Br:
      case VMOpcode::Trap:
        NewInstrs.push_back(I);
        break;
      }
    }
    B.Instrs.assign(NewInstrs.begin(), NewInstrs.end());
  }

  if (!Ctx.EntryPrefix.empty()) {
    VMBlock &EntryB = F.Blocks.front();
    SmallVector<VMInstr, 32> New;
    for (const VMInstr &I : Ctx.EntryPrefix)
      New.push_back(I);
    for (const VMInstr &I : EntryB.Instrs)
      New.push_back(I);
    EntryB.Instrs.assign(New.begin(), New.end());
  }

  F.RegCount = Ctx.NextReg;
  if (Res.HasRet && RetTmp != UINT32_MAX)
    Res.RetReg = RetTmp;
  return true;
}

static uint32_t allocTempReg(VMFunction &F, VMType Ty, uint32_t &NextReg) {
  uint32_t R = NextReg++;
  (void)Ty;
  return R;
}

bool llvm::obfvm::applyMBAObfuscation(VMFunction &F, std::string &Err) {
  unsigned PtrBits = F.PtrBits;
  (void)PtrBits;
  uint32_t NextReg = F.RegCount;
  SmallVector<VMInstr, 32> EntryPrefix;
  uint32_t ConstZero = UINT32_MAX;
  uint32_t ConstOne = UINT32_MAX;
  struct ConstKey {
    VMTypeKind Kind;
    uint64_t Val;
    bool operator<(const ConstKey &O) const {
      if (Kind != O.Kind)
        return Kind < O.Kind;
      return Val < O.Val;
    }
  };
  std::map<ConstKey, uint32_t> ConstCache;

  auto getConst = [&](uint64_t V, VMType Ty) -> uint32_t {
    unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
    uint64_t Mask = maskForBits(Bits);
    ConstKey Key{Ty.Kind, V & Mask};
    auto It = ConstCache.find(Key);
    if (It != ConstCache.end())
      return It->second;
    uint32_t R = allocTempReg(F, Ty, NextReg);
    VMInstr Mov;
    Mov.Op = VMOpcode::Mov;
    Mov.Ty = Ty;
    Mov.Dst = R;
    Mov.Ops = {VMValue::imm(V & Mask)};
    EntryPrefix.push_back(Mov);
    ConstCache.insert({Key, R});
    return R;
  };
  auto makeOddConst = [&](unsigned Bits, uint64_t &C, uint64_t &Inv) -> bool {
    if (Bits <= 1)
      return false;
    uint64_t Mask = maskForBits(Bits);
    for (unsigned Attempt = 0; Attempt < 8; ++Attempt) {
      uint64_t V = cryptoutils->get_uint64_t() | 1ULL;
      if (Bits < 64)
        V &= Mask;
      if (V == 0)
        V = 1;
      uint64_t InvV = 0;
      if (!modInversePow2(V, Bits, InvV))
        continue;
      uint64_t Check = mulMod(V, InvV, Bits) & Mask;
      if (Check != 1)
        continue;
      assert(Check == 1 && "invalid multiplicative inverse");
      C = V & Mask;
      Inv = InvV & Mask;
      return true;
    }
    return false;
  };

  for (VMBlock &B : F.Blocks) {
    SmallVector<VMInstr, 32> New;
    for (VMInstr &I : B.Instrs) {
      if (I.Op == VMOpcode::BinOp &&
          !(I.Ty.Kind == VMTypeKind::F32 || I.Ty.Kind == VMTypeKind::F64)) {
        VMType Ty = I.Ty;
        unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
        // Avoid MBA rewrites on 1-bit types. Several patterns introduce
        // shifts by 1 which are invalid when bit-width is 1 and will trap
        // in the interpreter.
        if (Bits < 2) {
          New.push_back(I);
          continue;
        }
        switch (I.Bin) {
        case VMBinOp::Add: {
          unsigned Choice = cryptoutils->get_range(7);
          if (Choice == 0) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Xor;
            Xor.Op = VMOpcode::BinOp;
            Xor.Ty = Ty;
            Xor.Bin = VMBinOp::Xor;
            Xor.Dst = T1;
            Xor.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = I.Ops;
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Shl;
            Shl.Op = VMOpcode::BinOp;
            Shl.Ty = Ty;
            Shl.Bin = VMBinOp::Shl;
            Shl.Dst = T3;
            if (ConstOne == UINT32_MAX)
              ConstOne = getConst(1, Ty);
            Shl.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = I.Dst;
            Add.Ops = {VMValue::reg(T1), VMValue::reg(T3)};
            New.push_back(Xor);
            New.push_back(And);
            New.push_back(Shl);
            New.push_back(Add);
            continue;
          }
          if (Choice == 1) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Or;
            Or.Op = VMOpcode::BinOp;
            Or.Ty = Ty;
            Or.Bin = VMBinOp::Or;
            Or.Dst = T1;
            Or.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = I.Ops;
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = I.Dst;
            Add.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Or);
            New.push_back(And);
            New.push_back(Add);
            continue;
          }
          if (Choice == 2) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t C = 0;
            uint64_t Inv = 0;
            if (makeOddConst(Bits, C, Inv)) {
              uint32_t CReg = getConst(C, Ty);
              uint32_t InvReg = getConst(Inv, Ty);
              uint32_t T1 = allocTempReg(F, Ty, NextReg);
              VMInstr MulA;
              MulA.Op = VMOpcode::BinOp;
              MulA.Ty = Ty;
              MulA.Bin = VMBinOp::Mul;
              MulA.Dst = T1;
              MulA.Ops = {I.Ops[0], VMValue::reg(CReg)};
              uint32_t T2 = allocTempReg(F, Ty, NextReg);
              VMInstr MulB;
              MulB.Op = VMOpcode::BinOp;
              MulB.Ty = Ty;
              MulB.Bin = VMBinOp::Mul;
              MulB.Dst = T2;
              MulB.Ops = {I.Ops[1], VMValue::reg(CReg)};
              uint32_t T3 = allocTempReg(F, Ty, NextReg);
              VMInstr Add;
              Add.Op = VMOpcode::BinOp;
              Add.Ty = Ty;
              Add.Bin = VMBinOp::Add;
              Add.Dst = T3;
              Add.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
              VMInstr MulInv;
              MulInv.Op = VMOpcode::BinOp;
              MulInv.Ty = Ty;
              MulInv.Bin = VMBinOp::Mul;
              MulInv.Dst = I.Dst;
              MulInv.Ops = {VMValue::reg(T3), VMValue::reg(InvReg)};
              New.push_back(MulA);
              New.push_back(MulB);
              New.push_back(Add);
              New.push_back(MulInv);
              continue;
            }
          }
          if (Choice == 3) {
            uint64_t K = cryptoutils->get_uint64_t();
            uint32_t KReg = getConst(K, Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T1;
            Add1.Ops = {I.Ops[0], VMValue::reg(KReg)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Sub1;
            Sub1.Op = VMOpcode::BinOp;
            Sub1.Ty = Ty;
            Sub1.Bin = VMBinOp::Sub;
            Sub1.Dst = T2;
            Sub1.Ops = {I.Ops[1], VMValue::reg(KReg)};
            VMInstr Add2;
            Add2.Op = VMOpcode::BinOp;
            Add2.Ty = Ty;
            Add2.Bin = VMBinOp::Add;
            Add2.Dst = I.Dst;
            Add2.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Add1);
            New.push_back(Sub1);
            New.push_back(Add2);
            continue;
          }
          if (Choice == 4) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t Mask = maskForBits(Bits);
            uint64_t RandMask = cryptoutils->get_uint64_t() & Mask;
            if (RandMask == 0)
              RandMask = Mask;
            uint32_t MaskReg = getConst(RandMask, Ty);
            uint32_t Tm = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = Tm;
            And.Ops = {I.Ops[0], VMValue::reg(MaskReg)};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add0;
            Add0.Op = VMOpcode::BinOp;
            Add0.Ty = Ty;
            Add0.Bin = VMBinOp::Add;
            Add0.Dst = T1;
            Add0.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T2;
            Add1.Ops = {VMValue::reg(T1), VMValue::reg(Tm)};
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T2), VMValue::reg(Tm)};
            New.push_back(And);
            New.push_back(Add0);
            New.push_back(Add1);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 5) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t Mask = maskForBits(Bits);
            uint64_t K1 = cryptoutils->get_uint64_t() & Mask;
            uint64_t K2 = cryptoutils->get_uint64_t() & Mask;
            uint64_t Ksum = (K1 + K2) & Mask;
            uint32_t K1Reg = getConst(K1, Ty);
            uint32_t K2Reg = getConst(K2, Ty);
            uint32_t KsumReg = getConst(Ksum, Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T1;
            Add1.Ops = {I.Ops[0], VMValue::reg(K1Reg)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add2;
            Add2.Op = VMOpcode::BinOp;
            Add2.Ty = Ty;
            Add2.Bin = VMBinOp::Add;
            Add2.Dst = T2;
            Add2.Ops = {I.Ops[1], VMValue::reg(K2Reg)};
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Add3;
            Add3.Op = VMOpcode::BinOp;
            Add3.Ty = Ty;
            Add3.Bin = VMBinOp::Add;
            Add3.Dst = T3;
            Add3.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T3), VMValue::reg(KsumReg)};
            New.push_back(Add1);
            New.push_back(Add2);
            New.push_back(Add3);
            New.push_back(Sub);
            continue;
          }
          uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
          uint32_t T1 = allocTempReg(F, Ty, NextReg);
          VMInstr Xor;
          Xor.Op = VMOpcode::BinOp;
          Xor.Ty = Ty;
          Xor.Bin = VMBinOp::Xor;
          Xor.Dst = T1;
          Xor.Ops = {I.Ops[1], VMValue::reg(MaskC)};
          uint32_t T2 = allocTempReg(F, Ty, NextReg);
          VMInstr Sub1;
          Sub1.Op = VMOpcode::BinOp;
          Sub1.Ty = Ty;
          Sub1.Bin = VMBinOp::Sub;
          Sub1.Dst = T2;
          Sub1.Ops = {I.Ops[0], VMValue::reg(T1)};
          if (ConstOne == UINT32_MAX)
            ConstOne = getConst(1, Ty);
          VMInstr Sub2;
          Sub2.Op = VMOpcode::BinOp;
          Sub2.Ty = Ty;
          Sub2.Bin = VMBinOp::Sub;
          Sub2.Dst = I.Dst;
          Sub2.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
          New.push_back(Xor);
          New.push_back(Sub1);
          New.push_back(Sub2);
          continue;
        }
        case VMBinOp::Sub: {
          unsigned Choice = cryptoutils->get_range(7);
          if (Choice == 0) {
            if (ConstZero == UINT32_MAX)
              ConstZero = getConst(0, Ty);
            uint32_t Neg = allocTempReg(F, Ty, NextReg);
            VMInstr Sub0;
            Sub0.Op = VMOpcode::BinOp;
            Sub0.Ty = Ty;
            Sub0.Bin = VMBinOp::Sub;
            Sub0.Dst = Neg;
            Sub0.Ops = {VMValue::reg(ConstZero), I.Ops[1]};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Xor;
            Xor.Op = VMOpcode::BinOp;
            Xor.Ty = Ty;
            Xor.Bin = VMBinOp::Xor;
            Xor.Dst = T1;
            Xor.Ops = {I.Ops[0], VMValue::reg(Neg)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = {I.Ops[0], VMValue::reg(Neg)};
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Shl;
            Shl.Op = VMOpcode::BinOp;
            Shl.Ty = Ty;
            Shl.Bin = VMBinOp::Shl;
            Shl.Dst = T3;
            if (ConstOne == UINT32_MAX)
              ConstOne = getConst(1, Ty);
            Shl.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = I.Dst;
            Add.Ops = {VMValue::reg(T1), VMValue::reg(T3)};
            New.push_back(Sub0);
            New.push_back(Xor);
            New.push_back(And);
            New.push_back(Shl);
            New.push_back(Add);
            continue;
          }
          if (Choice == 1) {
            uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Xor;
            Xor.Op = VMOpcode::BinOp;
            Xor.Ty = Ty;
            Xor.Bin = VMBinOp::Xor;
            Xor.Dst = T1;
            Xor.Ops = {I.Ops[1], VMValue::reg(MaskC)};
            if (ConstOne == UINT32_MAX)
              ConstOne = getConst(1, Ty);
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = T2;
            Add.Ops = {VMValue::reg(T1), VMValue::reg(ConstOne)};
            VMInstr Add2;
            Add2.Op = VMOpcode::BinOp;
            Add2.Ty = Ty;
            Add2.Bin = VMBinOp::Add;
            Add2.Dst = I.Dst;
            Add2.Ops = {I.Ops[0], VMValue::reg(T2)};
            New.push_back(Xor);
            New.push_back(Add);
            New.push_back(Add2);
            continue;
          }
          if (Choice == 2) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t C = 0;
            uint64_t Inv = 0;
            if (makeOddConst(Bits, C, Inv)) {
              uint32_t CReg = getConst(C, Ty);
              uint32_t InvReg = getConst(Inv, Ty);
              uint32_t T1 = allocTempReg(F, Ty, NextReg);
              VMInstr MulA;
              MulA.Op = VMOpcode::BinOp;
              MulA.Ty = Ty;
              MulA.Bin = VMBinOp::Mul;
              MulA.Dst = T1;
              MulA.Ops = {I.Ops[0], VMValue::reg(CReg)};
              uint32_t T2 = allocTempReg(F, Ty, NextReg);
              VMInstr MulB;
              MulB.Op = VMOpcode::BinOp;
              MulB.Ty = Ty;
              MulB.Bin = VMBinOp::Mul;
              MulB.Dst = T2;
              MulB.Ops = {I.Ops[1], VMValue::reg(CReg)};
              uint32_t T3 = allocTempReg(F, Ty, NextReg);
              VMInstr Sub;
              Sub.Op = VMOpcode::BinOp;
              Sub.Ty = Ty;
              Sub.Bin = VMBinOp::Sub;
              Sub.Dst = T3;
              Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
              VMInstr MulInv;
              MulInv.Op = VMOpcode::BinOp;
              MulInv.Ty = Ty;
              MulInv.Bin = VMBinOp::Mul;
              MulInv.Dst = I.Dst;
              MulInv.Ops = {VMValue::reg(T3), VMValue::reg(InvReg)};
              New.push_back(MulA);
              New.push_back(MulB);
              New.push_back(Sub);
              New.push_back(MulInv);
              continue;
            }
          }
          if (Choice == 3) {
            uint64_t K = cryptoutils->get_uint64_t();
            uint32_t KReg = getConst(K, Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T1;
            Add1.Ops = {I.Ops[0], VMValue::reg(KReg)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add2;
            Add2.Op = VMOpcode::BinOp;
            Add2.Ty = Ty;
            Add2.Bin = VMBinOp::Add;
            Add2.Dst = T2;
            Add2.Ops = {I.Ops[1], VMValue::reg(KReg)};
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Add1);
            New.push_back(Add2);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 4) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t Mask = maskForBits(Bits);
            uint64_t RandMask = cryptoutils->get_uint64_t() & Mask;
            if (RandMask == 0)
              RandMask = Mask;
            uint32_t MaskReg = getConst(RandMask, Ty);
            uint32_t Tm = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = Tm;
            And.Ops = {I.Ops[0], VMValue::reg(MaskReg)};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Sub0;
            Sub0.Op = VMOpcode::BinOp;
            Sub0.Ty = Ty;
            Sub0.Bin = VMBinOp::Sub;
            Sub0.Dst = T1;
            Sub0.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T2;
            Add1.Ops = {VMValue::reg(T1), VMValue::reg(Tm)};
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T2), VMValue::reg(Tm)};
            New.push_back(And);
            New.push_back(Sub0);
            New.push_back(Add1);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 5) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t Mask = maskForBits(Bits);
            uint64_t K1 = cryptoutils->get_uint64_t() & Mask;
            uint64_t K2 = cryptoutils->get_uint64_t() & Mask;
            uint64_t Kdiff = (K1 - K2) & Mask;
            uint32_t K1Reg = getConst(K1, Ty);
            uint32_t K2Reg = getConst(K2, Ty);
            uint32_t KdiffReg = getConst(Kdiff, Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add1;
            Add1.Op = VMOpcode::BinOp;
            Add1.Ty = Ty;
            Add1.Bin = VMBinOp::Add;
            Add1.Dst = T1;
            Add1.Ops = {I.Ops[0], VMValue::reg(K1Reg)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Add2;
            Add2.Op = VMOpcode::BinOp;
            Add2.Ty = Ty;
            Add2.Bin = VMBinOp::Add;
            Add2.Dst = T2;
            Add2.Ops = {I.Ops[1], VMValue::reg(K2Reg)};
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Sub0;
            Sub0.Op = VMOpcode::BinOp;
            Sub0.Ty = Ty;
            Sub0.Bin = VMBinOp::Sub;
            Sub0.Dst = T3;
            Sub0.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T3), VMValue::reg(KdiffReg)};
            New.push_back(Add1);
            New.push_back(Add2);
            New.push_back(Sub0);
            New.push_back(Sub);
            continue;
          }
          uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
          uint32_t T1 = allocTempReg(F, Ty, NextReg);
          VMInstr XorA;
          XorA.Op = VMOpcode::BinOp;
          XorA.Ty = Ty;
          XorA.Bin = VMBinOp::Xor;
          XorA.Dst = T1;
          XorA.Ops = {I.Ops[0], VMValue::reg(MaskC)};
          uint32_t T2 = allocTempReg(F, Ty, NextReg);
          VMInstr And;
          And.Op = VMOpcode::BinOp;
          And.Ty = Ty;
          And.Bin = VMBinOp::And;
          And.Dst = T2;
          And.Ops = {VMValue::reg(T1), I.Ops[1]};
          uint32_t T3 = allocTempReg(F, Ty, NextReg);
          VMInstr Shl;
          Shl.Op = VMOpcode::BinOp;
          Shl.Ty = Ty;
          Shl.Bin = VMBinOp::Shl;
          Shl.Dst = T3;
          if (ConstOne == UINT32_MAX)
            ConstOne = getConst(1, Ty);
          Shl.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
          uint32_t T4 = allocTempReg(F, Ty, NextReg);
          VMInstr Xor;
          Xor.Op = VMOpcode::BinOp;
          Xor.Ty = Ty;
          Xor.Bin = VMBinOp::Xor;
          Xor.Dst = T4;
          Xor.Ops = I.Ops;
          VMInstr Sub;
          Sub.Op = VMOpcode::BinOp;
          Sub.Ty = Ty;
          Sub.Bin = VMBinOp::Sub;
          Sub.Dst = I.Dst;
          Sub.Ops = {VMValue::reg(T4), VMValue::reg(T3)};
          New.push_back(XorA);
          New.push_back(And);
          New.push_back(Shl);
          New.push_back(Xor);
          New.push_back(Sub);
          continue;
        }
        case VMBinOp::Xor: {
          unsigned Choice = cryptoutils->get_range(4);
          if (Choice == 0) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Or;
            Or.Op = VMOpcode::BinOp;
            Or.Ty = Ty;
            Or.Bin = VMBinOp::Or;
            Or.Dst = T1;
            Or.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = I.Ops;
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Or);
            New.push_back(And);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 1) {
            unsigned Bits = getTypeBitWidth(Ty.Kind, PtrBits);
            uint64_t Mask = maskForBits(Bits);
            uint64_t K = cryptoutils->get_uint64_t() & Mask;
            uint32_t KReg = getConst(K, Ty);
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = T1;
            Add.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = I.Ops;
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Shl;
            Shl.Op = VMOpcode::BinOp;
            Shl.Ty = Ty;
            Shl.Bin = VMBinOp::Shl;
            Shl.Dst = T3;
            if (ConstOne == UINT32_MAX)
              ConstOne = getConst(1, Ty);
            Shl.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
            uint32_t T4 = allocTempReg(F, Ty, NextReg);
            VMInstr AddK;
            AddK.Op = VMOpcode::BinOp;
            AddK.Ty = Ty;
            AddK.Bin = VMBinOp::Add;
            AddK.Dst = T4;
            AddK.Ops = {VMValue::reg(T1), VMValue::reg(KReg)};
            uint32_t T5 = allocTempReg(F, Ty, NextReg);
            VMInstr Sub1;
            Sub1.Op = VMOpcode::BinOp;
            Sub1.Ty = Ty;
            Sub1.Bin = VMBinOp::Sub;
            Sub1.Dst = T5;
            Sub1.Ops = {VMValue::reg(T4), VMValue::reg(T3)};
            VMInstr Sub2;
            Sub2.Op = VMOpcode::BinOp;
            Sub2.Ty = Ty;
            Sub2.Bin = VMBinOp::Sub;
            Sub2.Dst = I.Dst;
            Sub2.Ops = {VMValue::reg(T5), VMValue::reg(KReg)};
            New.push_back(Add);
            New.push_back(And);
            New.push_back(Shl);
            New.push_back(AddK);
            New.push_back(Sub1);
            New.push_back(Sub2);
            continue;
          }
          if (Choice == 2) {
            uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
            uint32_t NotA = allocTempReg(F, Ty, NextReg);
            VMInstr XorA;
            XorA.Op = VMOpcode::BinOp;
            XorA.Ty = Ty;
            XorA.Bin = VMBinOp::Xor;
            XorA.Dst = NotA;
            XorA.Ops = {I.Ops[0], VMValue::reg(MaskC)};
            uint32_t NotB = allocTempReg(F, Ty, NextReg);
            VMInstr XorB;
            XorB.Op = VMOpcode::BinOp;
            XorB.Ty = Ty;
            XorB.Bin = VMBinOp::Xor;
            XorB.Dst = NotB;
            XorB.Ops = {I.Ops[1], VMValue::reg(MaskC)};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr And1;
            And1.Op = VMOpcode::BinOp;
            And1.Ty = Ty;
            And1.Bin = VMBinOp::And;
            And1.Dst = T1;
            And1.Ops = {I.Ops[0], VMValue::reg(NotB)};
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And2;
            And2.Op = VMOpcode::BinOp;
            And2.Ty = Ty;
            And2.Bin = VMBinOp::And;
            And2.Dst = T2;
            And2.Ops = {VMValue::reg(NotA), I.Ops[1]};
            VMInstr Or;
            Or.Op = VMOpcode::BinOp;
            Or.Ty = Ty;
            Or.Bin = VMBinOp::Or;
            Or.Dst = I.Dst;
            Or.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(XorA);
            New.push_back(XorB);
            New.push_back(And1);
            New.push_back(And2);
            New.push_back(Or);
            continue;
          }
          uint32_t T1 = allocTempReg(F, Ty, NextReg);
          VMInstr Add;
          Add.Op = VMOpcode::BinOp;
          Add.Ty = Ty;
          Add.Bin = VMBinOp::Add;
          Add.Dst = T1;
          Add.Ops = I.Ops;
          uint32_t T2 = allocTempReg(F, Ty, NextReg);
          VMInstr And;
          And.Op = VMOpcode::BinOp;
          And.Ty = Ty;
          And.Bin = VMBinOp::And;
          And.Dst = T2;
          And.Ops = I.Ops;
          uint32_t T3 = allocTempReg(F, Ty, NextReg);
          VMInstr Shl;
          Shl.Op = VMOpcode::BinOp;
          Shl.Ty = Ty;
          Shl.Bin = VMBinOp::Shl;
          Shl.Dst = T3;
          if (ConstOne == UINT32_MAX)
            ConstOne = getConst(1, Ty);
          Shl.Ops = {VMValue::reg(T2), VMValue::reg(ConstOne)};
          VMInstr Sub;
          Sub.Op = VMOpcode::BinOp;
          Sub.Ty = Ty;
          Sub.Bin = VMBinOp::Sub;
          Sub.Dst = I.Dst;
          Sub.Ops = {VMValue::reg(T1), VMValue::reg(T3)};
          New.push_back(Add);
          New.push_back(And);
          New.push_back(Shl);
          New.push_back(Sub);
          continue;
        }
        case VMBinOp::And: {
          unsigned Choice = cryptoutils->get_range(4);
          if (Choice == 0) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = T1;
            Add.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Or;
            Or.Op = VMOpcode::BinOp;
            Or.Ty = Ty;
            Or.Bin = VMBinOp::Or;
            Or.Dst = T2;
            Or.Ops = I.Ops;
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Add);
            New.push_back(Or);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 1) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = T1;
            Add.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr Xor;
            Xor.Op = VMOpcode::BinOp;
            Xor.Ty = Ty;
            Xor.Bin = VMBinOp::Xor;
            Xor.Dst = T2;
            Xor.Ops = I.Ops;
            uint32_t T3 = allocTempReg(F, Ty, NextReg);
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = T3;
            Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            VMInstr Shr;
            Shr.Op = VMOpcode::BinOp;
            Shr.Ty = Ty;
            Shr.Bin = VMBinOp::LShr;
            Shr.Dst = I.Dst;
            if (ConstOne == UINT32_MAX)
              ConstOne = getConst(1, Ty);
            Shr.Ops = {VMValue::reg(T3), VMValue::reg(ConstOne)};
            New.push_back(Add);
            New.push_back(Xor);
            New.push_back(Sub);
            New.push_back(Shr);
            continue;
          }
          if (Choice == 2) {
            uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
            uint32_t NotA = allocTempReg(F, Ty, NextReg);
            VMInstr XorA;
            XorA.Op = VMOpcode::BinOp;
            XorA.Ty = Ty;
            XorA.Bin = VMBinOp::Xor;
            XorA.Dst = NotA;
            XorA.Ops = {I.Ops[0], VMValue::reg(MaskC)};
            uint32_t NotB = allocTempReg(F, Ty, NextReg);
            VMInstr XorB;
            XorB.Op = VMOpcode::BinOp;
            XorB.Ty = Ty;
            XorB.Bin = VMBinOp::Xor;
            XorB.Dst = NotB;
            XorB.Ops = {I.Ops[1], VMValue::reg(MaskC)};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Or;
            Or.Op = VMOpcode::BinOp;
            Or.Ty = Ty;
            Or.Bin = VMBinOp::Or;
            Or.Dst = T1;
            Or.Ops = {VMValue::reg(NotA), VMValue::reg(NotB)};
            VMInstr XorC;
            XorC.Op = VMOpcode::BinOp;
            XorC.Ty = Ty;
            XorC.Bin = VMBinOp::Xor;
            XorC.Dst = I.Dst;
            XorC.Ops = {VMValue::reg(T1), VMValue::reg(MaskC)};
            New.push_back(XorA);
            New.push_back(XorB);
            New.push_back(Or);
            New.push_back(XorC);
            continue;
          }
          uint32_t T1 = allocTempReg(F, Ty, NextReg);
          VMInstr Or;
          Or.Op = VMOpcode::BinOp;
          Or.Ty = Ty;
          Or.Bin = VMBinOp::Or;
          Or.Dst = T1;
          Or.Ops = I.Ops;
          uint32_t T2 = allocTempReg(F, Ty, NextReg);
          VMInstr Xor;
          Xor.Op = VMOpcode::BinOp;
          Xor.Ty = Ty;
          Xor.Bin = VMBinOp::Xor;
          Xor.Dst = T2;
          Xor.Ops = I.Ops;
          VMInstr Sub;
          Sub.Op = VMOpcode::BinOp;
          Sub.Ty = Ty;
          Sub.Bin = VMBinOp::Sub;
          Sub.Dst = I.Dst;
          Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
          New.push_back(Or);
          New.push_back(Xor);
          New.push_back(Sub);
          continue;
        }
        case VMBinOp::Or: {
          unsigned Choice = cryptoutils->get_range(3);
          if (Choice == 0) {
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr Add;
            Add.Op = VMOpcode::BinOp;
            Add.Ty = Ty;
            Add.Bin = VMBinOp::Add;
            Add.Dst = T1;
            Add.Ops = I.Ops;
            uint32_t T2 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T2;
            And.Ops = I.Ops;
            VMInstr Sub;
            Sub.Op = VMOpcode::BinOp;
            Sub.Ty = Ty;
            Sub.Bin = VMBinOp::Sub;
            Sub.Dst = I.Dst;
            Sub.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
            New.push_back(Add);
            New.push_back(And);
            New.push_back(Sub);
            continue;
          }
          if (Choice == 2) {
            uint32_t MaskC = getConst(maskForBits(getTypeBitWidth(Ty.Kind, PtrBits)), Ty);
            uint32_t NotA = allocTempReg(F, Ty, NextReg);
            VMInstr XorA;
            XorA.Op = VMOpcode::BinOp;
            XorA.Ty = Ty;
            XorA.Bin = VMBinOp::Xor;
            XorA.Dst = NotA;
            XorA.Ops = {I.Ops[0], VMValue::reg(MaskC)};
            uint32_t NotB = allocTempReg(F, Ty, NextReg);
            VMInstr XorB;
            XorB.Op = VMOpcode::BinOp;
            XorB.Ty = Ty;
            XorB.Bin = VMBinOp::Xor;
            XorB.Dst = NotB;
            XorB.Ops = {I.Ops[1], VMValue::reg(MaskC)};
            uint32_t T1 = allocTempReg(F, Ty, NextReg);
            VMInstr And;
            And.Op = VMOpcode::BinOp;
            And.Ty = Ty;
            And.Bin = VMBinOp::And;
            And.Dst = T1;
            And.Ops = {VMValue::reg(NotA), VMValue::reg(NotB)};
            VMInstr XorC;
            XorC.Op = VMOpcode::BinOp;
            XorC.Ty = Ty;
            XorC.Bin = VMBinOp::Xor;
            XorC.Dst = I.Dst;
            XorC.Ops = {VMValue::reg(T1), VMValue::reg(MaskC)};
            New.push_back(XorA);
            New.push_back(XorB);
            New.push_back(And);
            New.push_back(XorC);
            continue;
          }
          uint32_t T1 = allocTempReg(F, Ty, NextReg);
          VMInstr Xor;
          Xor.Op = VMOpcode::BinOp;
          Xor.Ty = Ty;
          Xor.Bin = VMBinOp::Xor;
          Xor.Dst = T1;
          Xor.Ops = I.Ops;
          uint32_t T2 = allocTempReg(F, Ty, NextReg);
          VMInstr And;
          And.Op = VMOpcode::BinOp;
          And.Ty = Ty;
          And.Bin = VMBinOp::And;
          And.Dst = T2;
          And.Ops = I.Ops;
          VMInstr Add;
          Add.Op = VMOpcode::BinOp;
          Add.Ty = Ty;
          Add.Bin = VMBinOp::Add;
          Add.Dst = I.Dst;
          Add.Ops = {VMValue::reg(T1), VMValue::reg(T2)};
          New.push_back(Xor);
          New.push_back(And);
          New.push_back(Add);
          continue;
        }
        default:
          break;
        }
      }
      New.push_back(I);
    }
    B.Instrs.assign(New.begin(), New.end());
  }

  if (!EntryPrefix.empty()) {
    VMBlock &Entry = F.Blocks.front();
    SmallVector<VMInstr, 32> New;
    for (const VMInstr &I : EntryPrefix)
      New.push_back(I);
    for (const VMInstr &I : Entry.Instrs)
      New.push_back(I);
    Entry.Instrs.assign(New.begin(), New.end());
  }

  F.RegCount = NextReg;
  return true;
}
