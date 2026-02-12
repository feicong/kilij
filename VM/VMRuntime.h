//===- VMRuntime.h - VM runtime layout helpers ---------------------------===//
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
// Declares VM runtime layout helpers, metadata tags, and helper hooks.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMRUNTIME_H
#define LLVM_OBFUSCATION_VMRUNTIME_H

#include "CryptoUtils.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include <array>

namespace llvm {
namespace obfvm {

// Logical field names; physical struct order is randomized per module so
// attackers can't hardcode offsets into the VM state.
enum class VMStateField : unsigned {
  Regs = 0,
  PC = 1,
  Key = 2,
  Bytecode = 3,
  Offsets = 4,
  SwitchValues = 5,
  SwitchTargets = 6,
  ConstPool = 7,
  HostCtx = 8
};

static constexpr unsigned kVMStateFieldCount = 9;

struct VMStateLayout {
  std::array<unsigned, kVMStateFieldCount> FieldToIndex{};
};

inline uint64_t fnv1a64(StringRef S, uint64_t H = 1469598103934665603ULL) {
  for (unsigned char C : S) {
    H ^= C;
    H *= 1099511628211ULL;
  }
  return H;
}

inline uint64_t getVMStateSeed(Module &M) {
  // Persist a per-module seed so layout stays stable but not globally uniform.
  if (Metadata *MD = M.getModuleFlag("obf.vmstate.seed")) {
    if (auto *C = mdconst::extract_or_null<ConstantInt>(MD))
      return C->getZExtValue();
  }
  uint64_t Seed = getObfuscationSeed();
  if (Seed == 0)
    Seed = cryptoutils->get_uint64_t();
  if (Seed == 0)
    Seed = 0x9E3779B97F4A7C15ULL;
  Seed ^= fnv1a64(M.getModuleIdentifier());
  auto *SeedMD = ConstantAsMetadata::get(
      ConstantInt::get(Type::getInt64Ty(M.getContext()), Seed));
  M.addModuleFlag(Module::Override, "obf.vmstate.seed", SeedMD);
  return Seed;
}

inline uint64_t xorshift64(uint64_t &State) {
  uint64_t X = State;
  X ^= X >> 12;
  X ^= X << 25;
  X ^= X >> 27;
  State = X;
  return X * 2685821657736338717ULL;
}

inline VMStateLayout getVMStateLayout(Module &M) {
  // Shuffle fields to avoid fixed offsets while remaining deterministic.
  VMStateLayout L;
  std::array<unsigned, kVMStateFieldCount> Fields{};
  for (unsigned i = 0; i < kVMStateFieldCount; ++i)
    Fields[i] = i;

  uint64_t Seed = getVMStateSeed(M);
  for (unsigned i = kVMStateFieldCount; i > 1; --i) {
    uint64_t R = xorshift64(Seed);
    unsigned J = static_cast<unsigned>(R % i);
    std::swap(Fields[i - 1], Fields[J]);
  }
  for (unsigned i = 0; i < kVMStateFieldCount; ++i)
    L.FieldToIndex[Fields[i]] = i;
  return L;
}

inline unsigned getVMStateFieldIndex(Module &M, VMStateField Field) {
  VMStateLayout L = getVMStateLayout(M);
  return L.FieldToIndex[static_cast<unsigned>(Field)];
}

inline std::string getVMStateTypeName(Module &M) {
  // Derive a non-obvious type name from the same seed.
  uint64_t Seed = getVMStateSeed(M);
  uint64_t H = fnv1a64("vmstate", Seed);
  std::string Name = "struct.vmstate.";
  Name += utohexstr(H);
  return Name;
}

// Cached by name so all users in the module share one layout.  The hash-based
// name prevents type merging across modules.
inline StructType *getOrCreateVMStateType(Module &M) {
  LLVMContext &Ctx = M.getContext();
  std::string Name = getVMStateTypeName(M);
  if (StructType *ST = StructType::getTypeByName(Ctx, Name))
    return ST;

  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
  Type *I64PtrTy = PointerType::getUnqual(I64Ty);
  Type *I32PtrTy = PointerType::getUnqual(I32Ty);

  // Order matches VMStateField enum; layout shuffle reorders at struct creation.
  std::array<Type *, kVMStateFieldCount> FieldTypes = {
      I64PtrTy, I32Ty, I64Ty, I8PtrTy, I32PtrTy, I64PtrTy, I32PtrTy, I8PtrTy,
      I8PtrTy};
  VMStateLayout Layout = getVMStateLayout(M);
  std::array<Type *, kVMStateFieldCount> Ordered{};
  for (unsigned i = 0; i < kVMStateFieldCount; ++i) {
    unsigned Idx = Layout.FieldToIndex[i];
    Ordered[Idx] = FieldTypes[i];
  }

  StructType *ST = StructType::create(Ctx,
                                      ArrayRef<Type *>(Ordered.data(),
                                                       Ordered.size()),
                                      Name);
  return ST;
}

} // namespace obfvm
} // namespace llvm

#endif
