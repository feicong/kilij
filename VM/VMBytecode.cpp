//===- VMBytecode.cpp - VM bytecode encoding helpers ---------------------===//
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
// Implements bytecode encoding, padding randomization, and validation
// hashes used by the VM runtime.
//
//===----------------------------------------------------------------------===//
#include "VMBytecode.h"
#include "CryptoUtils.h"
#include "VMEmitUtils.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace llvm::obfvm;

static uint64_t fnv1a64(StringRef S, uint64_t H = 1469598103934665603ULL) {
  for (unsigned char C : S) {
    H ^= C;
    H *= 1099511628211ULL;
  }
  return H;
}

// MurmurHash3-style finalizer with per-build constants for key derivation.
static uint64_t bcMix64(uint64_t X, const VMBCEncodingInfo &Enc) {
  X ^= X >> 30;
  X *= Enc.MulConst1;
  X ^= X >> 27;
  X *= Enc.MulConst2;
  X ^= X >> 31;
  return X;
}

static uint64_t bcRand(uint64_t &State, const VMBCEncodingInfo &Enc) {
  State += Enc.MixConst;
  return bcMix64(State, Enc);
}

static uint64_t deriveBCKey(uint64_t BaseKey, uint32_t Index, uint64_t Salt,
                            const VMBCEncodingInfo &Enc) {
  uint64_t X = BaseKey ^ (Salt + static_cast<uint64_t>(Index) * Enc.MixConst);
  return bcMix64(X, Enc);
}

static uint8_t rotl8(uint8_t V, uint8_t Rot) {
  Rot &= 7u;
  if (Rot == 0)
    return V;
  return static_cast<uint8_t>((V << Rot) | (V >> (8u - Rot)));
}

static void buildOpcodePermutation(uint64_t Seed, unsigned OpCount,
                                   const VMBCEncodingInfo &Enc,
                                   std::vector<uint8_t> &Perm,
                                   std::vector<uint8_t> &Inv) {
  Perm.resize(OpCount);
  Inv.resize(OpCount);
  for (unsigned i = 0; i < OpCount; ++i)
    Perm[i] = static_cast<uint8_t>(i);
  if (OpCount > 1) {
    uint64_t S = Seed ? Seed : Enc.PermSeedMix;
    // Shuffle opcode numbers per build so byte values don't map to semantics.
    for (unsigned i = OpCount; i > 1; --i) {
      uint64_t R = bcRand(S, Enc);
      unsigned J = static_cast<unsigned>(R % i);
      std::swap(Perm[i - 1], Perm[J]);
    }
  }
  for (unsigned i = 0; i < OpCount; ++i)
    Inv[Perm[i]] = static_cast<uint8_t>(i);
}

static std::array<VMBCField, VMBCFieldCount>
getFieldOrder(const VMBCLayout &Layout) {
  std::array<VMBCField, VMBCFieldCount> Order{};
  for (unsigned i = 0; i < VMBCFieldCount; ++i) {
    unsigned Idx = Layout.FieldIndex[i];
    if (Idx < Order.size())
      Order[Idx] = static_cast<VMBCField>(i);
  }
  return Order;
}

VMBCEncodingInfo llvm::obfvm::buildVMBCEncodingInfo(uint64_t Seed, bool Hard) {
  VMBCEncodingInfo Enc;
  uint64_t S = Seed ? Seed : cryptoutils->get_uint64_t();
  // SplitMix64-style generator gives stable diffusion without global state.
  auto next = [&]() -> uint64_t { return ::splitmix64(S); };
  Enc.MixConst = (next() | 1ULL);
  Enc.MulConst1 = (next() | 1ULL);
  Enc.MulConst2 = (next() | 1ULL);
  Enc.SaltInstr = next();
  Enc.SaltOff = next();
  Enc.SaltSwitchVal = next();
  Enc.SaltSwitchTgt = next();
  Enc.PermSeedMix = next();
  if (Hard) {
    uint8_t Rot = static_cast<uint8_t>(1u + (next() % 7u));
    Enc.Rot8 = Rot;
  } else {
    Enc.Rot8 = 0;
  }
  return Enc;
}

VMBCLayout llvm::obfvm::buildVMBCLayout(bool Hard, uint64_t Seed) {
  VMBCLayout L;
  uint64_t S = Seed ? Seed : cryptoutils->get_uint64_t();
  // Per-function layout randomization: field order and stride change so a
  // single struct definition can't match all bytecode arrays in a binary.
  auto next = [&]() -> uint64_t { return ::splitmix64(S); };

  uint8_t Stride = 36;
  if (Hard) {
    static constexpr uint8_t Strides[] = {36, 40, 44};
    // Vary stride/padding to defeat fixed-record scanning in memory dumps.
    Stride = Strides[next() % (sizeof(Strides) / sizeof(Strides[0]))];
  }
  L.Stride = Stride;
  L.PadBytes = (Stride > 36) ? static_cast<uint8_t>(Stride - 36) : 0;

  std::array<uint8_t, VMBCFieldCount> Fields{};
  for (unsigned i = 0; i < VMBCFieldCount; ++i)
    Fields[i] = static_cast<uint8_t>(i);

  for (unsigned i = VMBCFieldCount; i > 1; --i) {
    unsigned J = static_cast<unsigned>(next() % i);
    std::swap(Fields[i - 1], Fields[J]);
  }
  for (unsigned i = 0; i < VMBCFieldCount; ++i)
    L.FieldIndex[Fields[i]] = static_cast<uint8_t>(i);
  return L;
}

StructType *llvm::obfvm::getOrCreateBCInstrType(LLVMContext &Ctx,
                                                const VMBCLayout &Layout) {
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  std::array<Type *, VMBCFieldCount> FieldTypes = {
      I8Ty, I8Ty, I8Ty, I8Ty, I32Ty, I32Ty, I32Ty, I64Ty, I32Ty, I32Ty, I32Ty};
  auto Order = getFieldOrder(Layout);
  SmallVector<Type *, 16> Fields;
  Fields.reserve(VMBCFieldCount + (Layout.PadBytes ? 1 : 0));
  for (unsigned i = 0; i < VMBCFieldCount; ++i) {
    VMBCField F = Order[i];
    Fields.push_back(FieldTypes[static_cast<unsigned>(F)]);
  }
  if (Layout.PadBytes > 0) {
    Fields.push_back(ArrayType::get(I8Ty, Layout.PadBytes));
  }
  return StructType::get(Ctx, Fields, /*isPacked=*/true);
}

VMBytecode llvm::obfvm::buildBytecode(const VMFunction &F) {
  VMBytecode BC;
  BC.BlockOffsets.resize(F.Blocks.size(), 0);

  uint32_t Offset = 0;
  for (const VMBlock &B : F.Blocks) {
    if (B.Id >= BC.BlockOffsets.size())
      vmFatal("vm: block id out of range in buildBytecode");
    // Record per-block offsets so control-flow uses block-local indices.
    BC.BlockOffsets[B.Id] = Offset;
    for (const VMInstr &I : B.Instrs) {
      VMBCInstr BI;
      BI.Op = static_cast<uint8_t>(I.Op);
      BI.Type = static_cast<uint8_t>(I.Ty.Kind);
      {
        uint8_t Rand = static_cast<uint8_t>(cryptoutils->get_uint8_t());
        uint8_t Pad = I.Pad;
        // Mix random high bits into padding to reduce bytecode patterns.
        Pad = static_cast<uint8_t>((Pad & 0x3Fu) | (Rand & 0xC0u));
        BI.Pad = Pad;
      }
      switch (I.Op) {
      case VMOpcode::Mov:
        BI.Dst = I.Dst;
        if (!I.Ops.empty()) {
          if (I.Ops[0].K == VMValue::Kind::Reg) {
            BI.Aux = 0;
            BI.A = I.Ops[0].Reg;
          } else if (I.Ops[0].K == VMValue::Kind::Imm) {
            BI.Aux = 1;
            BI.Imm = I.Ops[0].Imm;
          } else {
            BI.Aux = 2;
            BI.ImmConst = I.Ops[0].C;
          }
        }
        break;
      case VMOpcode::BinOp:
        BI.Dst = I.Dst;
        BI.Aux = static_cast<uint8_t>(I.Bin);
        BI.A = I.Ops[0].Reg;
        BI.B = I.Ops[1].Reg;
        break;
      case VMOpcode::FNeg:
        BI.Dst = I.Dst;
        BI.A = I.Ops[0].Reg;
        break;
      case VMOpcode::ICmp:
      case VMOpcode::FCmp:
        BI.Dst = I.Dst;
        BI.Aux = static_cast<uint8_t>(I.Pred);
        BI.A = I.Ops[0].Reg;
        BI.B = I.Ops[1].Reg;
        break;
      case VMOpcode::Cast:
        BI.Dst = I.Dst;
        BI.Aux = static_cast<uint8_t>(I.Cast);
        BI.A = I.Ops[0].Reg;
        BI.Imm = static_cast<uint8_t>(I.SrcTy.Kind);
        break;
      case VMOpcode::Load:
        BI.Dst = I.Dst;
        BI.A = I.Ops[0].Reg;
        break;
      case VMOpcode::Store:
        BI.A = I.Ops[0].Reg;
        BI.B = I.Ops[1].Reg;
        break;
      case VMOpcode::MemFence:
        BI.Aux = static_cast<uint8_t>(I.Fence);
        break;
      case VMOpcode::Br:
        BI.TTrue = I.TargetTrue;
        break;
      case VMOpcode::CondBr:
        BI.A = I.Ops[0].Reg;
        BI.TTrue = I.TargetTrue;
        BI.TFalse = I.TargetFalse;
        break;
      case VMOpcode::Select:
        BI.Dst = I.Dst;
        BI.A = I.Ops[0].Reg;
        BI.TTrue = I.Ops[1].Reg;
        BI.TFalse = I.Ops[2].Reg;
        break;
      case VMOpcode::Switch: {
        BI.Dst = I.Ops[0].Reg; // condition register
        BI.TTrue = I.SwitchDefault;
        uint32_t Offset = static_cast<uint32_t>(BC.SwitchValues.size());
        BI.A = Offset;
        BI.B = static_cast<uint32_t>(I.SwitchValues.size());
        for (size_t i = 0; i < I.SwitchValues.size(); ++i) {
          BC.SwitchValues.push_back(I.SwitchValues[i]);
          BC.SwitchTargets.push_back(I.SwitchTargets[i]);
        }
        break;
      }
      case VMOpcode::Ret:
        BI.Aux = I.Ops.empty() ? 0 : 1;
        if (!I.Ops.empty())
          BI.A = I.Ops[0].Reg;
        break;
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect:
        BI.CallIndex = I.CallIndex;
        break;
      case VMOpcode::Trap:
        break;
      }
      BC.Instrs.push_back(BI);
      ++Offset;
    }
  }
  return BC;
}

void llvm::obfvm::dumpVMBytecode(const VMBytecode &BC, raw_ostream &OS) {
  OS << "vm-bytecode: instrs=" << BC.Instrs.size()
     << " blocks=" << BC.BlockOffsets.size()
     << " switch_vals=" << BC.SwitchValues.size()
     << " switch_tgts=" << BC.SwitchTargets.size() << "\n";
  for (size_t i = 0; i < BC.Instrs.size(); ++i) {
    const VMBCInstr &I = BC.Instrs[i];
    OS << "  #" << i << " op=" << static_cast<unsigned>(I.Op)
       << " ty=" << static_cast<unsigned>(I.Type)
       << " aux=" << static_cast<unsigned>(I.Aux)
       << " dst=" << I.Dst << " a=" << I.A << " b=" << I.B
       << " imm=" << I.Imm << " t=" << I.TTrue << " f=" << I.TFalse
       << " call=" << I.CallIndex << "\n";
  }
  if (!BC.BlockOffsets.empty()) {
    OS << "  block_offsets:";
    for (uint32_t O : BC.BlockOffsets)
      OS << " " << O;
    OS << "\n";
  }
}

// Relocation-bearing constants (globals, block addresses) can't be XOR-encoded
// because the linker needs to patch them; emit them unencoded and flag via Pad.
static bool immNeedsRawEncoding(const Constant *C) {
  if (!C)
    return false;
  if (isa<ConstantInt>(C) || isa<ConstantFP>(C) || isa<ConstantPointerNull>(C))
    return false;
  if (auto *CE = dyn_cast<ConstantExpr>(C)) {
    unsigned Op = CE->getOpcode();
    if (Op == Instruction::PtrToInt || Op == Instruction::IntToPtr)
      return true;
    for (const Use &U : CE->operands()) {
      if (isa<GlobalValue>(U) || isa<BlockAddress>(U))
        return true;
    }
  }
  if (isa<GlobalValue>(C) || isa<BlockAddress>(C))
    return true;
  return true;
}

// Encode each instruction with a per-index derived key so changing one byte
// doesn't reveal the key for the rest.  Opcode permutation, field shuffling,
// and rotate-XOR layering all feed from the same seed tree.
VMBytecodeGlobals llvm::obfvm::emitBytecodeGlobals(
    Module &M, const VMBytecode &BC, StringRef BaseName,
    const VMBCLayout &Layout, const VMBCEncodingInfo &EncInfo,
    uint64_t EncodeKey, bool Encode, uint64_t HashKey, uint64_t HashMul) {
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  unsigned OpCount = static_cast<unsigned>(VMOpcode::Trap) + 1;
  bool PermuteOps = Encode && OpCount > 1;
  std::vector<uint8_t> OpPerm;
  std::vector<uint8_t> OpInv;
  if (PermuteOps) {
    uint64_t Seed = EncodeKey ^ EncInfo.PermSeedMix;
    Seed ^= fnv1a64(BaseName);
    buildOpcodePermutation(Seed, OpCount, EncInfo, OpPerm, OpInv);
  }

  StructType *InstrTy = getOrCreateBCInstrType(Ctx, Layout);
  auto Order = getFieldOrder(Layout);

  auto encode8 = [&](uint8_t V, uint8_t Key) -> uint8_t {
    uint8_t X = static_cast<uint8_t>(V ^ Key);
    if (!Encode)
      return X;
    unsigned R = EncInfo.Rot8 & 7u;
    if (R == 0)
      return X;
    return static_cast<uint8_t>((X << R) | (X >> (8u - R)));
  };

  SmallVector<Constant *, 32> InstrConsts;
  InstrConsts.reserve(BC.Instrs.size());
  for (size_t Idx = 0; Idx < BC.Instrs.size(); ++Idx) {
    const VMBCInstr &I = BC.Instrs[Idx];
    uint64_t Key64 =
        Encode ? deriveBCKey(EncodeKey, static_cast<uint32_t>(Idx),
                             EncInfo.SaltInstr, EncInfo)
               : 0;
    uint8_t Key8 = static_cast<uint8_t>(Key64 & 0xFFu);
    uint32_t Key32 = static_cast<uint32_t>(Key64 & 0xFFFFFFFFu);
    uint32_t Key32B = static_cast<uint32_t>((Key64 >> 32) & 0xFFFFFFFFu);
    uint8_t Op = I.Op;
    if (PermuteOps)
      Op = OpPerm[Op];
    Op = Encode ? encode8(Op, Key8) : Op;
    uint8_t Ty = Encode ? encode8(I.Type, Key8) : I.Type;
    uint8_t Aux = Encode ? encode8(I.Aux, Key8) : I.Aux;
    bool ImmRaw = Encode && I.ImmConst && immNeedsRawEncoding(I.ImmConst);
    uint8_t PadRaw = I.Pad;
    if (ImmRaw)
      PadRaw = static_cast<uint8_t>(PadRaw | VMBCPadImmRaw);
    uint8_t Pad = Encode ? encode8(PadRaw, Key8) : PadRaw;
    uint32_t Dst = Encode ? (I.Dst ^ Key32) : I.Dst;
    uint32_t A = Encode ? (I.A ^ Key32) : I.A;
    uint32_t B = Encode ? (I.B ^ Key32) : I.B;
    Constant *ImmC =
        I.ImmConst ? asI64(I.ImmConst, I64Ty)
                   : ConstantInt::get(I64Ty, I.Imm);
    if (Encode && !ImmRaw)
      ImmC = ConstantExpr::getXor(ImmC, ConstantInt::get(I64Ty, Key64));
    uint32_t TTrue = Encode ? (I.TTrue ^ Key32B) : I.TTrue;
    uint32_t TFalse = Encode ? (I.TFalse ^ Key32B) : I.TFalse;
    uint32_t CallIndex = Encode ? (I.CallIndex ^ Key32B) : I.CallIndex;
    std::array<Constant *, VMBCFieldCount> FieldVals = {
        ConstantInt::get(I8Ty, Op),
        ConstantInt::get(I8Ty, Ty),
        ConstantInt::get(I8Ty, Aux),
        ConstantInt::get(I8Ty, Pad),
        ConstantInt::get(I32Ty, Dst),
        ConstantInt::get(I32Ty, A),
        ConstantInt::get(I32Ty, B),
        ImmC,
        ConstantInt::get(I32Ty, TTrue),
        ConstantInt::get(I32Ty, TFalse),
        ConstantInt::get(I32Ty, CallIndex)};
    SmallVector<Constant *, 16> Ordered;
    Ordered.reserve(VMBCFieldCount + (Layout.PadBytes ? 1 : 0));
    for (unsigned i = 0; i < VMBCFieldCount; ++i) {
      VMBCField F = Order[i];
      Ordered.push_back(FieldVals[static_cast<unsigned>(F)]);
    }
    if (Layout.PadBytes > 0) {
      SmallVector<uint8_t, 16> PadBytes;
      PadBytes.reserve(Layout.PadBytes);
      for (unsigned i = 0; i < Layout.PadBytes; ++i)
        PadBytes.push_back(static_cast<uint8_t>(cryptoutils->get_uint8_t()));
      Constant *PadInit = ConstantDataArray::get(Ctx, PadBytes);
      Ordered.push_back(PadInit);
    }
    InstrConsts.push_back(ConstantStruct::get(InstrTy, Ordered));
  }

  ArrayType *InstrArrTy = ArrayType::get(InstrTy, InstrConsts.size());
  Constant *InstrInit = ConstantArray::get(InstrArrTy, InstrConsts);
  std::string InstrName = ("vm_bc_" + BaseName).str();
  auto *InstrGV = new GlobalVariable(
      M, InstrArrTy, true, GlobalValue::PrivateLinkage, InstrInit, InstrName);
  std::string InstrTag = ("vm.bc." + BaseName).str();
  obfuscateSymbolName(*InstrGV, M, InstrTag, InstrName);
  InstrGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

  SmallVector<Constant *, 16> OffsetConsts;
  OffsetConsts.reserve(BC.BlockOffsets.size());
  for (size_t Idx = 0; Idx < BC.BlockOffsets.size(); ++Idx) {
    uint32_t O = BC.BlockOffsets[Idx];
    uint32_t Enc = O;
      if (Encode) {
        uint64_t Key64 = deriveBCKey(EncodeKey, static_cast<uint32_t>(Idx),
                                     EncInfo.SaltOff, EncInfo);
        uint32_t Key32B = static_cast<uint32_t>((Key64 >> 32) & 0xFFFFFFFFu);
        Enc = O ^ Key32B;
      }
    OffsetConsts.push_back(ConstantInt::get(I32Ty, Enc));
  }
  ArrayType *OffTy = ArrayType::get(I32Ty, OffsetConsts.size());
  Constant *OffInit = ConstantArray::get(OffTy, OffsetConsts);
  std::string OffName = ("vm_bc_offsets_" + BaseName).str();
  auto *OffGV = new GlobalVariable(M, OffTy, true, GlobalValue::PrivateLinkage,
                                   OffInit, OffName);
  std::string OffTag = ("vm.bc.offsets." + BaseName).str();
  obfuscateSymbolName(*OffGV, M, OffTag, OffName);
  OffGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

  Constant *SwitchValsGV = nullptr;
  Constant *SwitchTgtsGV = nullptr;
  if (!BC.SwitchValues.empty()) {
    SmallVector<Constant *, 16> SV;
    SV.reserve(BC.SwitchValues.size());
    for (size_t Idx = 0; Idx < BC.SwitchValues.size(); ++Idx) {
      uint64_t V = BC.SwitchValues[Idx];
      uint64_t Enc = V;
        if (Encode) {
          uint64_t Key64 =
              deriveBCKey(EncodeKey, static_cast<uint32_t>(Idx),
                          EncInfo.SaltSwitchVal, EncInfo);
          Enc = V ^ Key64;
        }
      SV.push_back(ConstantInt::get(I64Ty, Enc));
    }
    ArrayType *SVTy = ArrayType::get(I64Ty, SV.size());
    Constant *SVInit = ConstantArray::get(SVTy, SV);
    std::string ValsName = ("vm_bc_switch_vals_" + BaseName).str();
    SwitchValsGV = new GlobalVariable(
        M, SVTy, true, GlobalValue::PrivateLinkage, SVInit, ValsName);
    std::string ValsTag = ("vm.bc.switch.vals." + BaseName).str();
    obfuscateSymbolName(*cast<GlobalVariable>(SwitchValsGV), M, ValsTag,
                        ValsName);
    cast<GlobalVariable>(SwitchValsGV)
        ->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  }

  if (!BC.SwitchTargets.empty()) {
    SmallVector<Constant *, 16> ST;
    ST.reserve(BC.SwitchTargets.size());
    for (size_t Idx = 0; Idx < BC.SwitchTargets.size(); ++Idx) {
      uint32_t V = BC.SwitchTargets[Idx];
      uint32_t Enc = V;
        if (Encode) {
          uint64_t Key64 =
              deriveBCKey(EncodeKey, static_cast<uint32_t>(Idx),
                          EncInfo.SaltSwitchTgt, EncInfo);
          uint32_t Key32B = static_cast<uint32_t>((Key64 >> 32) & 0xFFFFFFFFu);
          Enc = V ^ Key32B;
        }
      ST.push_back(ConstantInt::get(I32Ty, Enc));
    }
    ArrayType *STTy = ArrayType::get(I32Ty, ST.size());
    Constant *STInit = ConstantArray::get(STTy, ST);
    std::string TgtsName = ("vm_bc_switch_tgts_" + BaseName).str();
    SwitchTgtsGV = new GlobalVariable(
        M, STTy, true, GlobalValue::PrivateLinkage, STInit, TgtsName);
    std::string TgtsTag = ("vm.bc.switch.tgts." + BaseName).str();
    obfuscateSymbolName(*cast<GlobalVariable>(SwitchTgtsGV), M, TgtsTag,
                        TgtsName);
    cast<GlobalVariable>(SwitchTgtsGV)
        ->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  }

  VMBytecodeGlobals G;
  G.InstrArray = InstrGV;
  G.BlockOffsets = OffGV;
  G.SwitchValues = SwitchValsGV;
  G.SwitchTargets = SwitchTgtsGV;
  G.HashKey = HashKey;
  G.HashMul = HashMul;
  if (PermuteOps) {
    SmallVector<Constant *, 16> OpDec;
    OpDec.reserve(OpInv.size());
    for (uint8_t V : OpInv)
      OpDec.push_back(ConstantInt::get(I8Ty, V));
    ArrayType *OpTy = ArrayType::get(I8Ty, OpDec.size());
    Constant *OpInit = ConstantArray::get(OpTy, OpDec);
    std::string OpName = ("vm_op_decode_" + BaseName).str();
    auto *OpGV =
        new GlobalVariable(M, OpTy, true, GlobalValue::PrivateLinkage, OpInit,
                           OpName);
    std::string OpTag = ("vm.op.decode." + BaseName).str();
    obfuscateSymbolName(*OpGV, M, OpTag, OpName);
    OpGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    G.OpDecode = OpGV;
  }
  return G;
}
