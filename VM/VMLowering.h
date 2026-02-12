//===- VMLowering.h - Lower LLVM IR to VM IR -----------------------------===//
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
// Declares the LLVM IR to VM IR lowering pipeline.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMLOWERING_H
#define LLVM_OBFUSCATION_VMLOWERING_H

#include "VMIR.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include <string>

namespace llvm {
namespace obfvm {

struct VMAllocaInfo {
  Type *AllocaTy = nullptr;
  Align Alignment;
  uint64_t ArraySize = 1;
  uint32_t Reg = 0;
};

// Captures the full lowering output so the encoding and emission passes can
// reconstruct ABI boundaries (args, ret, allocas) without re-analyzing LLVM IR.
struct VMLoweringResult {
  VMFunction VMF;
  SmallVector<uint32_t, 8> ArgRegs;
  uint32_t RetReg = UINT32_MAX;
  bool HasRet = false;
  SmallVector<VMAllocaInfo, 8> Allocas;
};

class VMLowerer {
public:
  // Lowers LLVM IR into VM IR with a stable reg/const mapping for the function.
  VMLowerer(Function &F, const DataLayout &DL);

  bool lower(VMLoweringResult &Out, std::string &Err);

private:
  Function &F;
  const DataLayout &DL;
  DenseMap<const Value *, uint32_t> RegMap;
  DenseMap<const Constant *, uint32_t> ConstRegs;
  DenseMap<const BasicBlock *, uint32_t> BlockIds;
  SmallVector<std::pair<PHINode *, uint32_t>, 16> Phis;

  uint32_t nextReg();
  uint32_t getOrCreateReg(const Value *V, VMType Kind, VMBlock &Entry,
                          std::string &Err);
  uint32_t getOrCreateConstReg(const Constant *C, VMType Kind, VMBlock &Entry,
                               std::string &Err);
  VMType mapType(Type *Ty, std::string &Err) const;
  bool lowerInstruction(Instruction &I, VMBlock &B, VMBlock &Entry,
                        VMLoweringResult &Out, std::string &Err);
  bool finalizePhis(VMFunction &VMF, std::string &Err);
};

} // namespace obfvm
} // namespace llvm

#endif
