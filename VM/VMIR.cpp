//===- VMIR.cpp - VM IR definitions --------------------------------------===//
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
// Implements VM IR containers, printing, and helpers used by the VM
// pipeline.
//
//===----------------------------------------------------------------------===//
#include "VMIR.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;
using namespace llvm::obfvm;

unsigned llvm::obfvm::getTypeBitWidth(VMTypeKind K, unsigned PtrBits) {
  switch (K) {
  case VMTypeKind::I1:
    return 1;
  case VMTypeKind::I8:
    return 8;
  case VMTypeKind::I16:
    return 16;
  case VMTypeKind::I32:
    return 32;
  case VMTypeKind::I64:
    return 64;
  case VMTypeKind::F32:
    return 32;
  case VMTypeKind::F64:
    return 64;
  case VMTypeKind::Ptr:
    return PtrBits;
  }
  return 0;
}

const char *llvm::obfvm::getTypeName(VMTypeKind K) {
  switch (K) {
  case VMTypeKind::I1:
    return "i1";
  case VMTypeKind::I8:
    return "i8";
  case VMTypeKind::I16:
    return "i16";
  case VMTypeKind::I32:
    return "i32";
  case VMTypeKind::I64:
    return "i64";
  case VMTypeKind::F32:
    return "f32";
  case VMTypeKind::F64:
    return "f64";
  case VMTypeKind::Ptr:
    return "ptr";
  }
  return "?";
}

static const char *binOpName(VMBinOp Op) {
  switch (Op) {
  case VMBinOp::Add:
    return "add";
  case VMBinOp::Sub:
    return "sub";
  case VMBinOp::Mul:
    return "mul";
  case VMBinOp::UDiv:
    return "udiv";
  case VMBinOp::SDiv:
    return "sdiv";
  case VMBinOp::URem:
    return "urem";
  case VMBinOp::SRem:
    return "srem";
  case VMBinOp::And:
    return "and";
  case VMBinOp::Or:
    return "or";
  case VMBinOp::Xor:
    return "xor";
  case VMBinOp::Shl:
    return "shl";
  case VMBinOp::LShr:
    return "lshr";
  case VMBinOp::AShr:
    return "ashr";
  case VMBinOp::FAdd:
    return "fadd";
  case VMBinOp::FSub:
    return "fsub";
  case VMBinOp::FMul:
    return "fmul";
  case VMBinOp::FDiv:
    return "fdiv";
  case VMBinOp::FRem:
    return "frem";
  }
  return "?";
}

static const char *predName(VMCmpPred Pred) {
  switch (Pred) {
  case VMCmpPred::EQ:
    return "eq";
  case VMCmpPred::NE:
    return "ne";
  case VMCmpPred::ULT:
    return "ult";
  case VMCmpPred::ULE:
    return "ule";
  case VMCmpPred::UGT:
    return "ugt";
  case VMCmpPred::UGE:
    return "uge";
  case VMCmpPred::SLT:
    return "slt";
  case VMCmpPred::SLE:
    return "sle";
  case VMCmpPred::SGT:
    return "sgt";
  case VMCmpPred::SGE:
    return "sge";
  case VMCmpPred::FEQ:
    return "feq";
  case VMCmpPred::FNE:
    return "fne";
  case VMCmpPred::FLT:
    return "flt";
  case VMCmpPred::FLE:
    return "fle";
  case VMCmpPred::FGT:
    return "fgt";
  case VMCmpPred::FGE:
    return "fge";
  }
  return "?";
}

static const char *castName(VMCastKind K) {
  switch (K) {
  case VMCastKind::ZExt:
    return "zext";
  case VMCastKind::SExt:
    return "sext";
  case VMCastKind::Trunc:
    return "trunc";
  case VMCastKind::Bitcast:
    return "bitcast";
  case VMCastKind::PtrToInt:
    return "ptrtoint";
  case VMCastKind::IntToPtr:
    return "inttoptr";
  case VMCastKind::FPToUI:
    return "fptoui";
  case VMCastKind::FPToSI:
    return "fptosi";
  case VMCastKind::UIToFP:
    return "uitofp";
  case VMCastKind::SIToFP:
    return "sitofp";
  case VMCastKind::FPTrunc:
    return "fptrunc";
  case VMCastKind::FPExt:
    return "fpext";
  }
  return "?";
}

static const char *fenceName(VMFenceKind K) {
  switch (K) {
  case VMFenceKind::Acquire:
    return "acquire";
  case VMFenceKind::Release:
    return "release";
  case VMFenceKind::AcquireRelease:
    return "acqrel";
  case VMFenceKind::SeqCst:
    return "seqcst";
  }
  return "?";
}

static void printValue(raw_ostream &OS, const VMValue &V) {
  if (V.K == VMValue::Kind::Reg) {
    OS << "%r" << V.Reg;
  } else if (V.K == VMValue::Kind::Const) {
    // Const values need LLVM context to print properly; placeholder is enough
    // for debug dumps.
    OS << "@const";
  } else {
    OS << "#" << V.Imm;
  }
}

static void printOp(raw_ostream &OS, const VMInstr &I, size_t Idx) {
  if (Idx >= I.Ops.size()) {
    OS << "<missing>";
    return;
  }
  printValue(OS, I.Ops[Idx]);
}

void llvm::obfvm::dumpVMFunction(const VMFunction &F, raw_ostream &OS) {
  OS << "vmfunc " << F.Name << " regs=" << F.RegCount << "\n";
  for (const VMBlock &B : F.Blocks) {
    OS << "  block %" << B.Id << "\n";
    for (const VMInstr &I : B.Instrs) {
      OS << "    ";
      switch (I.Op) {
      case VMOpcode::Mov:
        OS << "mov " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        break;
      case VMOpcode::BinOp:
        OS << binOpName(I.Bin) << " " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        OS << ", ";
        printOp(OS, I, 1);
        break;
      case VMOpcode::FNeg:
        OS << "fneg " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        break;
      case VMOpcode::ICmp:
      case VMOpcode::FCmp:
        OS << (I.Op == VMOpcode::ICmp ? "icmp" : "fcmp") << " "
           << predName(I.Pred) << " " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        OS << ", ";
        printOp(OS, I, 1);
        break;
      case VMOpcode::Cast:
        OS << castName(I.Cast) << " " << getTypeName(I.SrcTy.Kind) << "->"
           << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        break;
      case VMOpcode::Load:
        OS << "load " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        break;
      case VMOpcode::Store:
        OS << "store " << getTypeName(I.Ty.Kind) << " ";
        printOp(OS, I, 0);
        OS << ", ";
        printOp(OS, I, 1);
        break;
      case VMOpcode::MemFence:
        OS << "fence " << fenceName(I.Fence);
        break;
      case VMOpcode::Br:
        OS << "br %" << I.TargetTrue;
        break;
      case VMOpcode::CondBr:
        OS << "brcond ";
        printOp(OS, I, 0);
        OS << ", %" << I.TargetTrue << ", %" << I.TargetFalse;
        break;
      case VMOpcode::Switch: {
        OS << "switch " << getTypeName(I.Ty.Kind) << " ";
        printOp(OS, I, 0);
        OS << ", default %" << I.SwitchDefault << " [";
        for (size_t i = 0; i < I.SwitchValues.size(); ++i) {
          if (i)
            OS << ", ";
          OS << I.SwitchValues[i] << "->%" << I.SwitchTargets[i];
        }
        OS << "]";
        break;
      }
      case VMOpcode::Select:
        OS << "select " << getTypeName(I.Ty.Kind) << " ";
        OS << "%r" << I.Dst << ", ";
        printOp(OS, I, 0);
        OS << ", ";
        printOp(OS, I, 1);
        OS << ", ";
        printOp(OS, I, 2);
        break;
      case VMOpcode::Ret:
        OS << "ret ";
        if (!I.Ops.empty())
          printOp(OS, I, 0);
        else
          OS << "void";
        break;
      case VMOpcode::CallHost:
        OS << "callhost #" << I.CallIndex;
        break;
      case VMOpcode::CallHostIndirect:
        OS << "callhost_ind #" << I.CallIndex << " ";
        if (!I.Ops.empty())
          printOp(OS, I, 0);
        else
          OS << "%r?";
        break;
      case VMOpcode::Trap:
        OS << "trap";
        break;
      }
      OS << "\n";
    }
  }
}
