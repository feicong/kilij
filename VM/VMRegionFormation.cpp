//===- VMRegionFormation.cpp - VM region formation -----------------------===//
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
// Computes liveness and groups VM blocks into regions for region-mode
// execution.
//
//===----------------------------------------------------------------------===//
#include "VMRegionFormation.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace llvm::obfvm;

static bool isTerminator(const VMInstr &I) {
  switch (I.Op) {
  case VMOpcode::Br:
  case VMOpcode::CondBr:
  case VMOpcode::Switch:
  case VMOpcode::Ret:
  case VMOpcode::Trap:
    return true;
  default:
    return false;
  }
}

static void collectSuccs(const VMInstr &Term,
                         SmallVectorImpl<uint32_t> &Out) {
  switch (Term.Op) {
  case VMOpcode::Br:
    Out.push_back(Term.TargetTrue);
    break;
  case VMOpcode::CondBr:
    Out.push_back(Term.TargetTrue);
    Out.push_back(Term.TargetFalse);
    break;
  case VMOpcode::Switch:
    Out.push_back(Term.SwitchDefault);
    for (uint32_t T : Term.SwitchTargets)
      Out.push_back(T);
    break;
  default:
    break;
  }
}

static void addUse(BitVector &Use, const BitVector &Def, uint32_t Reg,
                   std::string &Err) {
  if (Reg >= Use.size()) {
    Err = "vm: reg index out of range in liveness";
    return;
  }
  if (!Def.test(Reg))
    Use.set(Reg);
}

static void addDef(BitVector &Def, uint32_t Reg, std::string &Err) {
  if (Reg >= Def.size()) {
    Err = "vm: reg index out of range in liveness";
    return;
  }
  Def.set(Reg);
}

bool llvm::obfvm::computeVMLiveness(const VMFunction &F,
                                    VMFunctionLiveness &Out,
                                    std::string &Err) {
  // Precise liveness lets region executors cache only needed regs in SSA,
  // reducing register-file traffic and obscuring the live-range footprint.
  if (F.Blocks.empty()) {
    Err = "vm: empty function";
    return false;
  }
  const unsigned RegCount = F.RegCount;
  Out.Blocks.clear();
  Out.Blocks.resize(F.Blocks.size());

  DenseSet<uint32_t> SeenIds;
  for (const VMBlock &B : F.Blocks) {
    if (B.Id >= Out.Blocks.size()) {
      Err = "vm: block id out of range in liveness";
      return false;
    }
    if (!SeenIds.insert(B.Id).second) {
      Err = "vm: duplicate block id in liveness";
      return false;
    }
    if (B.Instrs.empty()) {
      Err = "vm: empty block in liveness";
      return false;
    }
    const VMInstr &Term = B.Instrs.back();
    if (!isTerminator(Term)) {
      Err = "vm: missing terminator in liveness";
      return false;
    }
    VMBlockLiveness &L = Out.Blocks[B.Id];
    L.Use = BitVector(RegCount);
    L.Def = BitVector(RegCount);
    L.LiveIn = BitVector(RegCount);
    L.LiveOut = BitVector(RegCount);
    L.Succs.clear();
    collectSuccs(Term, L.Succs);
  }

  for (const VMBlock &B : F.Blocks) {
    VMBlockLiveness &L = Out.Blocks[B.Id];
    BitVector Def(RegCount);
    BitVector Use(RegCount);
    for (const VMInstr &I : B.Instrs) {
      auto useReg = [&](uint32_t R) { addUse(Use, Def, R, Err); };
      auto defReg = [&](uint32_t R) { addDef(Def, R, Err); };
      switch (I.Op) {
      case VMOpcode::Mov:
        if (!I.Ops.empty() && I.Ops[0].K == VMValue::Kind::Reg)
          useReg(I.Ops[0].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::BinOp:
        useReg(I.Ops[0].Reg);
        useReg(I.Ops[1].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::FNeg:
        useReg(I.Ops[0].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::ICmp:
      case VMOpcode::FCmp:
        useReg(I.Ops[0].Reg);
        useReg(I.Ops[1].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::Cast:
        useReg(I.Ops[0].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::Load:
        useReg(I.Ops[0].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::Store:
        useReg(I.Ops[0].Reg);
        useReg(I.Ops[1].Reg);
        break;
      case VMOpcode::MemFence:
        break;
      case VMOpcode::CondBr:
        useReg(I.Ops[0].Reg);
        break;
      case VMOpcode::Switch:
        useReg(I.Ops[0].Reg);
        break;
      case VMOpcode::Select:
        useReg(I.Ops[0].Reg);
        useReg(I.Ops[1].Reg);
        useReg(I.Ops[2].Reg);
        defReg(I.Dst);
        break;
      case VMOpcode::Ret:
        if (!I.Ops.empty())
          useReg(I.Ops[0].Reg);
        break;
      case VMOpcode::CallHost:
      case VMOpcode::CallHostIndirect: {
        if (I.CallIndex < F.Calls.size()) {
          const VMCallInfo &CI = F.Calls[I.CallIndex];
          for (uint32_t R : CI.ArgRegs)
            useReg(R);
          if (CI.IsIndirect && CI.CalleeReg != UINT32_MAX)
            useReg(CI.CalleeReg);
          else if (!I.Ops.empty())
            useReg(I.Ops[0].Reg);
          if (!CI.IsVoid && CI.RetReg != UINT32_MAX)
            defReg(CI.RetReg);
        }
        break;
      }
      case VMOpcode::Br:
      case VMOpcode::Trap:
        break;
      }
      if (!Err.empty())
        return false;
    }
    L.Use = Use;
    L.Def = Def;
  }

  // Classic backward iterative dataflow; converges fast on structured CFGs.
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (int i = static_cast<int>(F.Blocks.size()) - 1; i >= 0; --i) {
      const VMBlock &B = F.Blocks[i];
      VMBlockLiveness &L = Out.Blocks[B.Id];
      BitVector NewOut(RegCount);
      for (uint32_t Succ : L.Succs) {
        if (Succ < Out.Blocks.size())
          NewOut |= Out.Blocks[Succ].LiveIn;
      }
      BitVector NewIn = L.Use;
      BitVector Tmp = NewOut;
      Tmp.reset(L.Def);
      NewIn |= Tmp;
      if (NewOut != L.LiveOut || NewIn != L.LiveIn) {
        L.LiveOut = NewOut;
        L.LiveIn = NewIn;
        Changed = true;
      }
    }
  }
  return true;
}

bool llvm::obfvm::formEBBRegions(const VMFunction &F,
                                 SmallVectorImpl<VMRegion> &Out,
                                 DenseMap<uint32_t, uint32_t> &BlockToRegion,
                                 std::string &Err) {
  Out.clear();
  BlockToRegion.clear();
  if (F.Blocks.empty()) {
    Err = "vm: empty function";
    return false;
  }

  const unsigned N = F.Blocks.size();
  SmallVector<unsigned, 16> PredCount(N, 0);
  SmallVector<SmallVector<uint32_t, 4>, 16> Succs(N);
  for (const VMBlock &B : F.Blocks) {
    if (B.Id >= N) {
      Err = "vm: block id out of range in region formation";
      return false;
    }
    if (B.Instrs.empty()) {
      Err = "vm: empty block in region formation";
      return false;
    }
    const VMInstr &Term = B.Instrs.back();
    if (!isTerminator(Term)) {
      Err = "vm: missing terminator in region formation";
      return false;
    }
    collectSuccs(Term, Succs[B.Id]);
    for (uint32_t S : Succs[B.Id]) {
      if (S >= N) {
        Err = "vm: successor out of range in region formation";
        return false;
      }
      PredCount[S]++;
    }
  }

  SmallVector<bool, 16> Assigned(N, false);
  // EBB heuristic: extend along single-succ/single-pred chains so straight-
  // line code stays in one executor, minimizing cross-region spills.
  for (uint32_t B = 0; B < N; ++B) {
    if (Assigned[B])
      continue;
    VMRegion R;
    R.Id = static_cast<uint32_t>(Out.size());
    uint32_t Cur = B;
    for (;;) {
      R.Blocks.push_back(Cur);
      Assigned[Cur] = true;
      BlockToRegion[Cur] = R.Id;
      if (Succs[Cur].size() != 1)
        break;
      uint32_t S = Succs[Cur][0];
      if (S >= N || Assigned[S])
        break;
      if (PredCount[S] != 1)
        break;
      if (S == Cur)
        break;
      Cur = S;
    }
    Out.push_back(R);
  }
  return true;
}

void llvm::obfvm::dumpVMRegions(const SmallVectorImpl<VMRegion> &Regions,
                                raw_ostream &OS) {
  OS << "vm-regions: count=" << Regions.size() << "\n";
  for (const VMRegion &R : Regions) {
    OS << "  region " << R.Id << " blocks:";
    for (uint32_t B : R.Blocks)
      OS << " " << B;
    OS << "\n";
  }
}
