//===- ConstObfuscation.cpp - Constant obfuscation -----------------------===//
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
// Implements integer constant hiding and decode materialization.
//
//===----------------------------------------------------------------------===//
#include "ConstObfuscation.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

#define DEBUG_TYPE "obfconst"

static cl::opt<bool>
    ObfConst("obf-const", cl::init(false),
             cl::desc("Enable constant obfuscation"));
static cl::opt<int> ObfConstProb(
    "obf-const-prob", cl::init(40),
    cl::desc("Probability of constant obfuscation (0-100)"));
static cl::opt<int> ObfConstMinBits(
    "obf-const-minbits", cl::init(8),
    cl::desc("Minimum integer bit-width to obfuscate (default 8)"));

static GlobalVariable *getOrCreateConstKey(Module &M) {
  if (auto *GV = findTaggedGlobal(M, "obf.const.key")) {
    GV->setConstant(true);
    return GV;
  }
  LLVMContext &Ctx = M.getContext();
  // Per-module key keeps constants stable within a build but opaque to static analysis.
  uint64_t Key = cryptoutils->get_uint64_t();
  if (Key == 0)
    Key = 0xC0FFEE1234ULL;
  auto *KeyGV = new GlobalVariable(
      M, Type::getInt64Ty(Ctx), true, GlobalValue::PrivateLinkage,
      ConstantInt::get(Type::getInt64Ty(Ctx), Key), "obf_const_key");
  KeyGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*KeyGV, M, "obf.const.key", "obf_const_key");
  return KeyGV;
}

// Encode an integer constant as: Enc = Val ^ R ^ Key ^ rotl(Key, Rot).
// At runtime: Val = Enc ^ R ^ load(KeyGV) ^ rotl(load(KeyGV), Rot).
// R and Rot are per-site random so identical constants encode differently.
static Value *buildEncodedConst(IRBuilder<> &B, ConstantInt *CI,
                                GlobalVariable *KeyGV) {
  if (!CI || !KeyGV)
    return nullptr;
  unsigned Bits = CI->getBitWidth();
  if (Bits == 0 || Bits > 64)
    return nullptr;

  uint64_t Rand = cryptoutils->get_uint64_t();
  if (Bits < 64)
    Rand &= ((1ULL << Bits) - 1ULL);
  APInt R(Bits, Rand);
  APInt KeyVal(Bits, 0);
  if (KeyGV && KeyGV->hasInitializer()) {
    if (auto *KeyInit = dyn_cast<ConstantInt>(KeyGV->getInitializer())) {
      KeyVal = KeyInit->getValue();
      if (KeyVal.getBitWidth() != Bits)
        KeyVal = KeyVal.zextOrTrunc(Bits);
    }
  }
  unsigned Rot = (Bits > 1) ? (1u + cryptoutils->get_range(Bits - 1)) : 0u;
  APInt KeyRot = (Rot != 0) ? KeyVal.rotl(Rot) : KeyVal;
  APInt Enc = CI->getValue() ^ R ^ KeyVal ^ KeyRot;

  LoadInst *KeyL = B.CreateLoad(KeyGV->getValueType(), KeyGV);
  // Volatile keeps the key materialized and blocks constant folding.
  KeyL->setVolatile(true);
  Value *Key = B.CreateTruncOrBitCast(KeyL, CI->getType());
  Value *RotKey = Key;
  if (Rot != 0 && Bits > 1) {
    Value *RotC = ConstantInt::get(CI->getType(), Rot);
    Value *InvC = ConstantInt::get(CI->getType(), Bits - Rot);
    Value *Shl = B.CreateShl(Key, RotC);
    Value *Shr = B.CreateLShr(Key, InvC);
    RotKey = B.CreateOr(Shl, Shr);
  }

  Value *EncC = ConstantInt::get(CI->getType(), Enc);
  Value *RC = ConstantInt::get(CI->getType(), R);
  Value *Tmp = B.CreateXor(EncC, RC);
  Tmp = B.CreateXor(Tmp, Key);
  return B.CreateXor(Tmp, RotKey);
}

PreservedAnalyses ConstObfuscationPass::run(Function &F,
                                            FunctionAnalysisManager &AM) {
  (void)AM;
  bool Want = toObfuscate(ObfConst, &F, "const");
  if (!Want) {
    // Legacy alias for older builds that annotated "constobf".
    if (hasAnnotation(&F, "constobf") && !shouldSkipFunction(&F)) {
      ensureObfBaseline(F);
      Want = true;
    } else {
      return PreservedAnalyses::all();
    }
  }
  if (!Want)
    return PreservedAnalyses::all();

  Module &M = *F.getParent();
  ObfPassContext Ctx = beginFunctionObfuscation(F, "const");
  LLVM_DEBUG(dbgs() << "obfconst: run " << F.getName() << "\n");

  unsigned Prob = clampProb(ObfConstProb.getValue());
  unsigned MinBits =
      static_cast<unsigned>(clampInt(ObfConstMinBits.getValue(), 0, 64));

  GlobalVariable *KeyGV = getOrCreateConstKey(M);
  bool Changed = false;

  for (BasicBlock &BB : F) {
    if (shouldSkipBlock(&BB))
      continue;
    for (Instruction &I : BB) {
      if (shouldSkipInstruction(&I))
        continue;
      // Only encode operands of binary ops and compares; other instructions
      // (stores, calls, etc.) may need exact constants for correctness.
      if (!isa<BinaryOperator>(&I) && !isa<ICmpInst>(&I))
        continue;
      for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
        auto *CI = dyn_cast<ConstantInt>(I.getOperand(OpIdx));
        if (!CI)
          continue;
        if (CI->getBitWidth() < MinBits)
          continue;
        if (CI->getBitWidth() > 64)
          continue;
        if (cryptoutils->get_range(100) >= Prob)
          continue;
        IRBuilder<> B(&I);
        Value *NewVal = buildEncodedConst(B, CI, KeyGV);
        if (!NewVal)
          continue;
        I.setOperand(OpIdx, NewVal);
        Changed = true;
      }
    }
  }

  if (Changed) {
    LLVM_DEBUG(dbgs() << "obfconst: changed " << F.getName() << "\n");
    finishFunctionObfuscation(F, "const", Ctx, true);
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}
