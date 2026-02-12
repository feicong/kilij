//===- VMRegionFormation.h - VM region formation -------------------------===//
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
// Declares liveness and region-formation utilities.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMREGIONFORMATION_H
#define LLVM_OBFUSCATION_VMREGIONFORMATION_H

#include "VMIR.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include <string>

namespace llvm {
class raw_ostream;
namespace obfvm {

struct VMBlockLiveness {
  BitVector Use;
  BitVector Def;
  BitVector LiveIn;
  BitVector LiveOut;
  SmallVector<uint32_t, 4> Succs;
};

struct VMFunctionLiveness {
  SmallVector<VMBlockLiveness, 8> Blocks;
};

struct VMRegion {
  uint32_t Id = 0;
  SmallVector<uint32_t, 8> Blocks;
};

// Compute classic liveness sets for the VM IR register file.
bool computeVMLiveness(const VMFunction &F, VMFunctionLiveness &Out,
                       std::string &Err);

// Group blocks into extended basic blocks for region-based execution.
bool formEBBRegions(const VMFunction &F, SmallVectorImpl<VMRegion> &Out,
                    DenseMap<uint32_t, uint32_t> &BlockToRegion,
                    std::string &Err);

// Debug utility for dumping region membership.
void dumpVMRegions(const SmallVectorImpl<VMRegion> &Regions,
                   raw_ostream &OS);

} // namespace obfvm
} // namespace llvm

#endif
