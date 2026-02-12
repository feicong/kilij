//===- VMMath.h - Math helpers for encoding ------------------------------===//
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
// Math helpers for affine/Feistel encoding (mod inverse, ring
// arithmetic).
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMMATH_H
#define LLVM_OBFUSCATION_VMMATH_H

#include <cstdint>

namespace llvm {
namespace obfvm {

static inline uint64_t maskForBits(unsigned Bits) {
  if (Bits >= 64)
    return ~0ULL;
  if (Bits == 0)
    return 0ULL;
  return (1ULL << Bits) - 1ULL;
}

static inline uint64_t addMod(uint64_t A, uint64_t B, unsigned Bits) {
  uint64_t M = maskForBits(Bits);
  return (A + B) & M;
}

static inline uint64_t subMod(uint64_t A, uint64_t B, unsigned Bits) {
  uint64_t M = maskForBits(Bits);
  return (A - B) & M;
}

static inline uint64_t mulMod(uint64_t A, uint64_t B, unsigned Bits) {
  uint64_t P = static_cast<uint64_t>(A * B);
  if (Bits >= 64)
    return P;
  return P & maskForBits(Bits);
}

// Modular inverse for odd A over 2^Bits via Newton's method (needed for
// affine decode).  Converges in log2(Bits) iterations.
static inline bool modInversePow2(uint64_t A, unsigned Bits, uint64_t &InvOut) {
  if (Bits == 0)
    return false;
  if ((A & 1ULL) == 0)
    return false;
  uint64_t Inv = 1;
  unsigned HaveBits = 1;
  // Each iteration doubles the number of correct low bits (Hensel lifting).
  while (HaveBits < Bits) {
    uint64_t Prod = mulMod(A, Inv, Bits);
    uint64_t TwoMinus = subMod(2, Prod, Bits);
    Inv = mulMod(Inv, TwoMinus, Bits);
    HaveBits <<= 1;
  }
  InvOut = Inv & maskForBits(Bits);
  return true;
}

// Affine encoding on a 2^Bits ring for cheap encode/decode.
struct VMAffineKey {
  uint64_t A = 1;
  uint64_t B = 0;
  uint64_t InvA = 1;
  unsigned Bits = 64;

  bool isValid() const {
    if (Bits == 0)
      return false;
    if ((A & 1ULL) == 0)
      return false;
    uint64_t M = maskForBits(Bits);
    uint64_t Check = mulMod(A, InvA, Bits) & M;
    return Check == 1;
  }

  uint64_t encode(uint64_t X) const {
    return addMod(mulMod(A, X, Bits), B, Bits);
  }

  uint64_t decode(uint64_t X) const {
    return mulMod(subMod(X, B, Bits), InvA, Bits);
  }
};

} // namespace obfvm
} // namespace llvm

#endif
