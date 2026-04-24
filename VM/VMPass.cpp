//===- VMPass.cpp - VM pass orchestration --------------------------------===//
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
// Drives VM obfuscation: selection, lowering, encoding, emission, and
// integration.
//
//===----------------------------------------------------------------------===//
#include "VMBytecode.h"
#include "CryptoUtils.h"
#include "VMConfig.h"
#include "VMEmitInterp.h"
#include "VMEmitRegion.h"
#include "VMEmitUtils.h"
#include "VMEncode.h"
#include "VMLowering.h"
#include "VMPass.h"
#include "VMRuntime.h"
#include "Utils.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;
using namespace llvm::obfvm;

#define DEBUG_TYPE "vmobf"

static cl::opt<std::string>
    VMModeOpt("vm-mode", cl::init("none"),
              cl::desc("VM obfuscation mode: none|opcode|bb|region"));
static cl::opt<std::string>
    VMEncodeOpt("vm-encode", cl::init("off"),
                cl::desc("VM encoding: off|affine|mba"));
static cl::opt<std::string>
    VMSelectOpt("vm-select", cl::init("all"),
                cl::desc("VM selection: none|all|marked|cold"));
static cl::opt<std::string> VMSelectPathOpt(
    "vm-select-path", cl::init(""),
    cl::desc("Only virtualize functions whose source path contains one of "
             "these substrings (comma/semicolon separated)"));
static cl::opt<std::string>
    VMHandlersOpt("vm-handlers", cl::init("static"),
                  cl::desc("VM handlers: static|random"));
static cl::opt<std::string>
    VMDispatchOpt("vm-dispatch", cl::init("indirect"),
                  cl::desc("VM dispatch: switch|indirect"));
static cl::opt<bool> VMHardOpt(
    "vm-hard", cl::init(true),
    cl::desc("VM hardening: encoded PC/bytecode and indirect dispatch"));
static cl::opt<bool> VMHardRtOpt(
    "vm-hard-rt", cl::init(false),
    cl::desc("VM hard runtime checks (anti-debug/integrity)"));
static cl::opt<unsigned> VMBogusOpt(
    "vm-bogus", cl::init(2),
    cl::desc("Extra bogus entries in VM dispatch tables when hardening"));
static cl::opt<unsigned> VMMaxBBsOpt(
    "vm-max-bbs", cl::init(0),
    cl::desc("Max basic blocks per function eligible for VM (0 = unlimited)"));
static cl::opt<unsigned> VMMaxIRInstsOpt(
    "vm-max-ir-insts", cl::init(0),
    cl::desc("Max original IR instruction count per function eligible for VM "
             "(0 = unlimited)"));
static cl::opt<unsigned> VMMaxBCInstrsOpt(
    "vm-max-bc-instrs", cl::init(0),
    cl::desc("Max VM bytecode instructions per function "
             "(0 = unlimited)"));
static cl::opt<unsigned> VMMaxRuntimeInstrsOpt(
    "vm-max-runtime-insts", cl::init(0),
    cl::desc("Max VM-IR instruction count allowed for BB/region emission "
             "(0 = unlimited)"));
// Windows defaults to heap allocation because its 1MB default stack is tight;
// Linux can afford 256KB of on-stack register file.
static cl::opt<unsigned> VMMaxStackRegBytesOpt(
    "vm-max-stack-reg-bytes",
#ifdef _WIN32
    cl::init(0),
#else
    cl::init(256 * 1024),
#endif
    cl::desc("Max VM reg-file bytes to keep on stack (0 = always heap)"));
static cl::opt<unsigned> VMMaxGlobalBytesOpt(
    "vm-max-global-bytes", cl::init(0),
    cl::desc("Max VM bytecode/global bytes per function (0 = unlimited)"));
static cl::opt<uint64_t> VMColdThresholdOpt(
    "vm-cold-threshold", cl::init(0),
    cl::desc("Cold select threshold (profile count)"));
static cl::opt<bool> VMValidateOpt(
    "vm-validate", cl::init(false),
    cl::desc("VM validation: compare native vs VM and trap on mismatch"));
static cl::opt<bool> VMDebugOpt(
    "vm-debug", cl::init(false),
    cl::desc("VM debug: dump VM-IR before/after encoding"));
static cl::opt<bool> VMDebugRtOpt(
    "vm-debug-rt", cl::init(false),
    cl::desc("VM runtime debug logging (OutputDebugStringA)"));
static cl::opt<unsigned> VMDebugMaxInstrsOpt(
    "vm-debug-max-instrs", cl::init(20000),
    cl::desc("Max VM-IR instructions to dump with -vm-debug (0 = unlimited)"));
static cl::opt<bool> VMCountersOpt(
    "vm-counters", cl::init(false),
    cl::desc("VM debug counters: dispatch/reg load/store counters"));
static cl::opt<bool> VMTraceOpt(
    "vm-trace", cl::init(false),
    cl::desc("VM trace: emit OutputDebugStringA for every instruction, "
             "register access, and bounds check"));
static cl::opt<unsigned> VMTraceLimitOpt(
    "vm-trace-limit", cl::init(0),
    cl::desc("VM trace limit: dump last PCs after N VM instructions (0 = off)"));
static cl::opt<bool> VMBoundsCheckOpt(
    "vm-bounds-check", cl::init(false),
    cl::desc("VM bounds check: trap on out-of-bounds register access"));
static cl::opt<bool> VMEncodeFeistelOpt(
    "vm-encode-feistel", cl::init(false),
    cl::desc("Enable Feistel-based data encoding in VM affine/mba encoding"));
static cl::opt<bool> VMEncodeFeistelAllOpt(
    "vm-encode-feistel-all", cl::init(false),
    cl::desc("Apply Feistel encoding to all VM registers (expensive)"));
static cl::opt<unsigned> VMFeistelRoundsOpt(
    "vm-feistel-rounds", cl::init(0),
    cl::desc("Feistel rounds for VM encode (0 = auto)"));
static cl::opt<unsigned> VMEncodePctOpt(
    "vm-encode-pct", cl::init(25),
    cl::desc("Percent of VM registers to encode (0-100, default 25)"));
static cl::opt<bool> VMEncodeFullMarkedOpt(
    "vm-encode-full-marked", cl::init(false),
    cl::desc("Force full encode for functions marked vm_protect"));
static cl::opt<std::string> VMEncodeFullPathOpt(
    "vm-encode-full-path", cl::init(""),
    cl::desc("Force full encode for functions whose source path contains one "
             "of these substrings (comma/semicolon separated)"));
static cl::opt<unsigned> VMEncodeFullMaxInstrsOpt(
    "vm-encode-full-max-instrs", cl::init(200000),
    cl::desc("Max VM-IR instruction count allowed for full encode before "
             "falling back to vm-encode-pct (0 = unlimited)"));
static cl::opt<unsigned> VMEncodeMaxInstrsOpt(
    "vm-encode-max-instrs", cl::init(30000),
    cl::desc("Max VM-IR instruction count allowed for affine/MBA encoding "
             "(0 = unlimited, default 30000)"));
static cl::opt<bool> VMObfRuntimeOpt(
    "vm-obf-runtime", cl::init(false),
    cl::desc("Allow other obfuscation passes to run on VM runtime"));
static cl::opt<unsigned> VMMBAMaxGrowthOpt(
    "vm-mba-max-growth", cl::init(200),
    cl::desc("Max % VM-IR instruction growth allowed by MBA encoding "
             "(0 = unlimited)"));
static cl::opt<unsigned> VMEncodeMaxGrowthOpt(
    "vm-encode-max-growth", cl::init(300),
    cl::desc("Max % VM-IR instruction growth allowed by affine/MBA encoding "
             "(0 = unlimited, default 300)"));
static cl::opt<std::string> VMReportOpt(
    "vm-report", cl::init(""),
    cl::desc("Write VM selection report to file"));
static cl::opt<bool> VMSkipOtherObfOpt(
    "vm-skip-other-obf", cl::init(false),
    cl::desc("On VM failure, mark function obf_skip to skip other passes"));

static VMMode parseMode(StringRef S) {
  if (S == "opcode")
    return VMMode::Opcode;
  if (S == "bb")
    return VMMode::BB;
  if (S == "region")
    return VMMode::Region;
  return VMMode::None;
}

static VMEncode parseEncode(StringRef S) {
  if (S == "affine")
    return VMEncode::Affine;
  if (S == "mba")
    return VMEncode::MBA;
  return VMEncode::Off;
}

static VMSelect parseSelect(StringRef S) {
  if (S == "none")
    return VMSelect::None;
  if (S == "marked")
    return VMSelect::Marked;
  if (S == "cold")
    return VMSelect::Cold;
  return VMSelect::All;
}

static VMHandlers parseHandlers(StringRef S) {
  if (S == "random")
    return VMHandlers::Random;
  return VMHandlers::Static;
}

static VMDispatch parseDispatch(StringRef S) {
  if (S == "indirect")
    return VMDispatch::Indirect;
  return VMDispatch::Switch;
}

static std::size_t estimateBytecodeGlobalBytes(const Module &M,
                                               const VMBytecode &BC,
                                               const VMBCLayout &Layout,
                                               bool Encode) {
  const DataLayout &DL = M.getDataLayout();
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  std::size_t Bytes = 0;
  Bytes += static_cast<std::size_t>(Layout.Stride) * BC.Instrs.size();
  Bytes += static_cast<std::size_t>(DL.getTypeAllocSize(I32Ty).getFixedValue()) * BC.BlockOffsets.size();
  Bytes += static_cast<std::size_t>(DL.getTypeAllocSize(I64Ty).getFixedValue()) * BC.SwitchValues.size();
  Bytes += static_cast<std::size_t>(DL.getTypeAllocSize(I32Ty).getFixedValue()) * BC.SwitchTargets.size();
  if (Encode) {
    unsigned OpCount = static_cast<unsigned>(VMOpcode::Trap) + 1;
    Bytes += static_cast<std::size_t>(DL.getTypeAllocSize(I8Ty).getFixedValue()) * OpCount;
  }
  return Bytes;
}

static bool hasVMProtectMarker(Function &F) {
  if (F.hasFnAttribute("vm_protect"))
    return true;
  return hasAnnotation(&F, "vm_protect");
}

static bool hasVMFeistelMarker(Function &F) {
  if (F.hasFnAttribute("vm_feistel"))
    return true;
  return hasAnnotation(&F, "vm_feistel");
}

static bool hasVMFeistelAllMarker(Function &F) {
  if (F.hasFnAttribute("vm_feistel_all"))
    return true;
  return hasAnnotation(&F, "vm_feistel_all");
}

static bool matchesPathFilter(const Function &F, StringRef Patterns) {
  if (Patterns.empty())
    return false;
  auto checkFile = [&](const DIFile *FInfo) -> bool {
    if (!FInfo)
      return false;
    SmallString<256> Full;
    StringRef Dir = FInfo->getDirectory();
    StringRef File = FInfo->getFilename();
    if (!Dir.empty()) {
      Full = Dir;
      sys::path::append(Full, File);
    } else {
      Full = File;
    }
    return pathMatchesPatternList(Full, Patterns);
  };

  if (const DISubprogram *SP = F.getSubprogram()) {
    if (checkFile(SP->getFile()))
      return true;
    if (const DICompileUnit *CU = SP->getUnit()) {
      if (checkFile(CU->getFile()))
        return true;
    }
  }

  if (const Module *M = F.getParent()) {
    StringRef Src = M->getSourceFileName();
    if (!Src.empty()) {
      if (pathMatchesPatternList(Src, Patterns))
        return true;
    }
    StringRef ModId = M->getModuleIdentifier();
    if (!ModId.empty()) {
      if (pathMatchesPatternList(ModId, Patterns))
        return true;
    }
  }

  // Fallback: scan debug locs for header-inlined code not covered by SP/CU.
  unsigned Seen = 0;
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      if (!I.getDebugLoc())
        continue;
      if (const DILocation *Loc = I.getDebugLoc()) {
        if (const DIFile *File = Loc->getFile()) {
          if (checkFile(File))
            return true;
        }
      }
      if (++Seen > 128)
        return false;
    }
  }
  return false;
}

static bool shouldVirtualize(Function &F, ModuleAnalysisManager &MAM,
                             const VMConfig &Cfg) {
  if (Cfg.Mode == VMMode::None)
    return false;
  if (shouldSkipFunction(&F))
    return false;

  bool Selected = false;
  switch (Cfg.Select) {
  case VMSelect::None:
    Selected = false;
    break;
  case VMSelect::All:
    Selected = true;
    break;
  case VMSelect::Marked:
    Selected = hasVMProtectMarker(F);
    break;
  case VMSelect::Cold: {
    if (F.hasFnAttribute(Attribute::Cold))
      Selected = true;
    auto &PSI = MAM.getResult<ProfileSummaryAnalysis>(*F.getParent());
    if (PSI.isFunctionEntryCold(&F))
      Selected = true;
    if (Cfg.ColdThreshold == 0)
      break;
    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(*F.getParent())
            .getManager();
    auto &BFI = FAM.getResult<BlockFrequencyAnalysis>(F);
    if (auto C = BFI.getProfileCountFromFreq(BFI.getEntryFreq()))
      Selected = *C <= Cfg.ColdThreshold;
    break;
  }
  }
  if (!Selected)
    return false;
  if (!VMSelectPathOpt.empty() && !matchesPathFilter(F, VMSelectPathOpt))
    return false;
  return true;
}

// Validation compares native vs VM results, so side-effecting functions
// (stores, calls) can't be validated without executing them twice.
static bool isValidationSafe(const VMFunction &F) {
  for (const VMBlock &B : F.Blocks) {
    for (const VMInstr &I : B.Instrs) {
      if (I.Op == VMOpcode::Store || I.Op == VMOpcode::CallHost ||
          I.Op == VMOpcode::CallHostIndirect)
        return false;
    }
  }
  return true;
}

static size_t countVMInstrs(const VMFunction &F);

static void dumpVMIfEnabled(const VMFunction &F, StringRef Tag) {
  if (!VMDebugOpt)
    return;
  size_t Instrs = countVMInstrs(F);
  if (VMDebugMaxInstrsOpt > 0 && Instrs > VMDebugMaxInstrsOpt) {
    errs() << "vm: " << Tag << " " << F.Name
           << " (dump skipped, instrs=" << Instrs << ")\n";
    return;
  }
  errs() << "vm: " << Tag << " " << F.Name << "\n";
  dumpVMFunction(F, errs());
}

static bool validateVMFunction(const VMFunction &F, std::string &Err) {
  auto bad = [&](StringRef Msg, const VMInstr &I) -> bool {
    Err = ("vm: invalid vm instr: " + Msg +
           " op=" + std::to_string(static_cast<unsigned>(I.Op)) +
           " ops=" + std::to_string(I.Ops.size()) +
           " dst=" + std::to_string(I.Dst))
              .str();
    return false;
  };
  auto checkReg = [&](uint32_t R) -> bool {
    return R < F.RegCount;
  };
  for (const VMBlock &B : F.Blocks) {
    for (const VMInstr &I : B.Instrs) {
      switch (I.Op) {
      case VMOpcode::Mov:
        if (I.Ops.size() != 1 || I.Dst == UINT32_MAX)
          return bad("mov", I);
        break;
      case VMOpcode::BinOp:
        if (I.Ops.size() != 2 || I.Dst == UINT32_MAX)
          return bad("binop", I);
        break;
      case VMOpcode::FNeg:
        if (I.Ops.size() != 1 || I.Dst == UINT32_MAX)
          return bad("fneg", I);
        break;
      case VMOpcode::ICmp:
      case VMOpcode::FCmp:
        if (I.Ops.size() != 2 || I.Dst == UINT32_MAX)
          return bad("cmp", I);
        break;
      case VMOpcode::Cast:
        if (I.Ops.size() != 1 || I.Dst == UINT32_MAX)
          return bad("cast", I);
        break;
      case VMOpcode::Load:
        if (I.Ops.size() != 1 || I.Dst == UINT32_MAX)
          return bad("load", I);
        break;
      case VMOpcode::Store:
        if (I.Ops.size() != 2)
          return bad("store", I);
        break;
      case VMOpcode::CondBr:
        if (I.Ops.size() != 1)
          return bad("condbr", I);
        break;
      case VMOpcode::Switch:
        if (I.Ops.size() != 1 ||
            I.SwitchTargets.size() != I.SwitchValues.size() ||
            I.SwitchDefault == UINT32_MAX)
          return bad("switch", I);
        break;
      case VMOpcode::Select:
        if (I.Ops.size() != 3 || I.Dst == UINT32_MAX)
          return bad("select", I);
        break;
      case VMOpcode::Ret:
        if (I.Ops.size() > 1)
          return bad("ret", I);
        break;
      case VMOpcode::CallHost:
        if (I.CallIndex == UINT32_MAX)
          return bad("callhost", I);
        break;
      case VMOpcode::CallHostIndirect:
        if (I.CallIndex == UINT32_MAX)
          return bad("callhost.ind", I);
        if (I.Ops.size() > 1)
          return bad("callhost.ind.ops", I);
        break;
      case VMOpcode::Br:
      case VMOpcode::MemFence:
      case VMOpcode::Trap:
        break;
      }

      for (const VMValue &Op : I.Ops) {
        if (Op.K == VMValue::Kind::Reg && !checkReg(Op.Reg))
          return bad("op reg out of range", I);
      }
      if (I.Dst != UINT32_MAX && I.Dst >= F.RegCount)
        return bad("dst reg out of range", I);
    }
  }
  return true;
}

static void writeVMReportLine(StringRef Line) {
  if (VMReportOpt.empty())
    return;
  std::error_code EC;
  llvm::raw_fd_ostream OS(VMReportOpt, EC, llvm::sys::fs::OF_Append);
  if (EC)
    return;
  OS << Line << "\n";
}

static void reportVMDecision(const Function &F, StringRef Status,
                             StringRef Reason) {
  if (VMReportOpt.empty())
    return;
  SmallString<256> Buf;
  raw_svector_ostream OS(Buf);
  OS << F.getName() << "\t" << Status;
  if (!Reason.empty())
    OS << "\t" << Reason;
  writeVMReportLine(OS.str());
}

static void markVMSkip(Function &F, StringRef Reason) {
  F.addFnAttr("vm_skip");
  if (!Reason.empty())
    F.addFnAttr("vm_skip_reason", Reason);
}

static void markVMFailure(Function &F, StringRef Reason, bool SkipOtherObf) {
  markVMSkip(F, Reason);
  // Only propagate to other passes when explicitly requested; over-skipping
  // creates large plaintext islands and hides real VM coverage.
  if (!SkipOtherObf)
    return;
  F.addFnAttr("obf_skip");
  if (!Reason.empty())
    F.addFnAttr("obf_skip_reason", Reason);
}

static size_t countVMInstrs(const VMFunction &F) {
  size_t Total = 0;
  for (const VMBlock &B : F.Blocks)
    Total += B.Instrs.size();
  return Total;
}

// Strip function-level attrs (noinline, etc.) but keep ABI-relevant param/ret
// attrs (sext, zext, byval) so the wrapper matches the original calling convention.
static AttributeList getABIAttributes(const Function &F) {
  AttributeList Attrs = F.getAttributes();
  LLVMContext &Ctx = F.getContext();
  unsigned ParamCount = F.getFunctionType()->getNumParams();
  SmallVector<AttributeSet, 8> Params;
  Params.reserve(ParamCount);
  for (unsigned i = 0; i < ParamCount; ++i)
    Params.push_back(Attrs.getParamAttrs(i));
  return AttributeList::get(Ctx, AttributeSet(), Attrs.getRetAttrs(), Params);
}

static void markVMRuntimeNoObf(Module &M) {
  for (Function &Fn : M) {
    if (Fn.hasFnAttribute("vm_runtime"))
      Fn.addFnAttr("no_obfuscate");
  }
}

// All VM registers are i64; pack widens narrower types and bitcasts floats
// so the register file is type-erased at the IR level.
static Value *packToReg(IRBuilder<> &B, Value *V, Type *Ty,
                        unsigned PtrBits) {
  LLVMContext &Ctx = B.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  if (Ty->isFloatTy()) {
    Value *I32 = B.CreateBitCast(V, Type::getInt32Ty(Ctx));
    return B.CreateZExt(I32, I64Ty);
  }
  if (Ty->isDoubleTy()) {
    return B.CreateBitCast(V, I64Ty);
  }
  if (Ty->isPointerTy()) {
    Value *IntPtr =
        B.CreatePtrToInt(V, Type::getIntNTy(Ctx, PtrBits));
    if (PtrBits < 64)
      return B.CreateZExt(IntPtr, I64Ty);
    return IntPtr;
  }
  if (Ty->isIntegerTy()) {
    return B.CreateZExtOrTrunc(V, I64Ty);
  }
  return ConstantInt::get(I64Ty, 0);
}

static Value *unpackFromReg(IRBuilder<> &B, Value *V, Type *Ty,
                            unsigned PtrBits) {
  LLVMContext &Ctx = B.getContext();
  if (Ty->isFloatTy()) {
    Value *I32 = B.CreateTrunc(V, Type::getInt32Ty(Ctx));
    return B.CreateBitCast(I32, Ty);
  }
  if (Ty->isDoubleTy()) {
    return B.CreateBitCast(V, Ty);
  }
  if (Ty->isPointerTy()) {
    Value *IntPtr = V;
    if (PtrBits < 64)
      IntPtr = B.CreateTrunc(V, Type::getIntNTy(Ctx, PtrBits));
    return B.CreateIntToPtr(IntPtr, Ty);
  }
  if (Ty->isIntegerTy()) {
    return B.CreateTruncOrBitCast(V, Ty);
  }
  return Constant::getNullValue(Ty);
}

static Function *createVMExec(Function &Orig, VMLoweringResult &LR,
                              Function *Run, const VMBytecodeGlobals &Globals,
                              const VMConfig &Cfg, Module &M,
                              uint32_t InitPc) {
  LLVMContext &Ctx = M.getContext();
  const DataLayout &DL = M.getDataLayout();
  unsigned PtrBits = DL.getPointerSizeInBits();

  FunctionType *FTy = Orig.getFunctionType();
  std::string Name = ("vm_exec_" + Orig.getName()).str();
  Function *Exec = Function::Create(FTy, GlobalValue::PrivateLinkage, Name, &M);
  Exec->setCallingConv(Orig.getCallingConv());
  Exec->setAttributes(getABIAttributes(Orig));
  Exec->addFnAttr(Attribute::NoInline);
  Exec->addFnAttr("vm_runtime");
  obfuscateSymbolName(*Exec, M, ("vm.exec." + Orig.getName()).str(), Name);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Exec);
  IRBuilder<> B(Entry);

  StructType *StateTy = getOrCreateVMStateType(M);
  Value *State = B.CreateAlloca(StateTy);

  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *SizeTy = DL.getIntPtrType(Ctx);
  PointerType *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));

  // Allocate reg file (stack for small, heap for large to avoid stack overflow)
  uint32_t RegCount = LR.VMF.RegCount;
  uint64_t RegBytes = static_cast<uint64_t>(RegCount) * 8ULL;
  uint64_t MaxStackRegBytes = VMMaxStackRegBytesOpt;
  Value *RegsI8 = nullptr;
  Value *Regs = nullptr;
  bool UseHeapRegs = (MaxStackRegBytes == 0) || (RegBytes > MaxStackRegBytes);
  if (UseHeapRegs) {
    FunctionCallee MallocFn = M.getOrInsertFunction(
        "malloc", FunctionType::get(I8PtrTy, {SizeTy}, false));
    Value *SizeV64 = ConstantInt::get(I64Ty, RegBytes == 0 ? 8 : RegBytes);
    Value *SizeV = B.CreateIntCast(SizeV64, SizeTy, /*isSigned=*/false);
    checkCallSignature(MallocFn.getFunctionType(), {SizeV}, "vm:malloc");
    RegsI8 = B.CreateCall(MallocFn, {SizeV});
    Regs = B.CreateBitCast(RegsI8, PointerType::getUnqual(I64Ty));
  } else {
    Value *RegCountV = ConstantInt::get(I32Ty, RegCount == 0 ? 1 : RegCount);
    AllocaInst *RegsAlloca = B.CreateAlloca(I64Ty, RegCountV);
    RegsAlloca->setAlignment(Align(8));
    RegsI8 = B.CreateBitCast(RegsAlloca, I8PtrTy);
    Regs = RegsAlloca;
  }
  B.CreateMemSet(RegsI8, ConstantInt::get(Type::getInt8Ty(Ctx), 0),
                 ConstantInt::get(I64Ty, RegBytes == 0 ? 8 : RegBytes),
                 Align(8));

  auto stateFieldPtr = [&](VMStateField F) -> Value * {
    return B.CreateStructGEP(StateTy, State, getVMStateFieldIndex(M, F));
  };

  Value *RegsField = stateFieldPtr(VMStateField::Regs);
  B.CreateStore(Regs, RegsField);

  // XOR key with state address so each invocation has a unique runtime key
  // even when the constant seed is shared across compilations.
  Value *KeyField = stateFieldPtr(VMStateField::Key);
  uint64_t KeySeed = cryptoutils->get_uint64_t();
  Value *KeyConst = ConstantInt::get(I64Ty, KeySeed);
  Value *StateInt = B.CreatePtrToInt(State, I64Ty);
  Value *Key = B.CreateXor(KeyConst, StateInt);
  B.CreateStore(Key, KeyField);

  Value *PcField = stateFieldPtr(VMStateField::PC);
  Value *PcVal = ConstantInt::get(I32Ty, InitPc);
  if (Cfg.Hard) {
    Value *Key32 = B.CreateTrunc(Key, I32Ty);
    PcVal = B.CreateXor(PcVal, Key32);
  }
  B.CreateStore(PcVal, PcField);

  Value *BCField = stateFieldPtr(VMStateField::Bytecode);
  Value *OffField = stateFieldPtr(VMStateField::Offsets);
  Value *SVField = stateFieldPtr(VMStateField::SwitchValues);
  Value *STField = stateFieldPtr(VMStateField::SwitchTargets);
  Value *BCVal =
      Globals.InstrArray ? B.CreateBitCast(Globals.InstrArray, I8PtrTy)
                         : ConstantPointerNull::get(I8PtrTy);
  Value *OffVal =
      Globals.BlockOffsets
          ? B.CreateBitCast(Globals.BlockOffsets,
                            PointerType::getUnqual(I32Ty))
          : ConstantPointerNull::get(PointerType::getUnqual(I32Ty));
  Value *SVVal =
      Globals.SwitchValues
          ? B.CreateBitCast(Globals.SwitchValues,
                            PointerType::getUnqual(I64Ty))
          : ConstantPointerNull::get(PointerType::getUnqual(I64Ty));
  Value *STVal =
      Globals.SwitchTargets
          ? B.CreateBitCast(Globals.SwitchTargets,
                            PointerType::getUnqual(I32Ty))
          : ConstantPointerNull::get(PointerType::getUnqual(I32Ty));
  B.CreateStore(BCVal, BCField);
  B.CreateStore(OffVal, OffField);
  B.CreateStore(SVVal, SVField);
  B.CreateStore(STVal, STField);
  Value *CPField = stateFieldPtr(VMStateField::ConstPool);
  Value *HCField = stateFieldPtr(VMStateField::HostCtx);
  B.CreateStore(ConstantPointerNull::get(I8PtrTy), CPField);
  B.CreateStore(ConstantPointerNull::get(I8PtrTy), HCField);

  for (const VMAllocaInfo &AI : LR.Allocas) {
    uint64_t Size = DL.getTypeAllocSize(AI.AllocaTy) * AI.ArraySize;
    Value *SizeV = ConstantInt::get(I64Ty, Size == 0 ? 1 : Size);
    AllocaInst *Mem = B.CreateAlloca(Type::getInt8Ty(Ctx), SizeV);
    if (AI.Alignment.value() != 0)
      Mem->setAlignment(AI.Alignment);
    Value *PtrAsInt = B.CreatePtrToInt(
        Mem, Type::getIntNTy(Ctx, PtrBits));
    Value *Packed = packToReg(B, PtrAsInt,
                              Type::getIntNTy(Ctx, PtrBits), PtrBits);
    storeReg(B, Regs, ConstantInt::get(I32Ty, AI.Reg), Packed);
  }

  auto ArgIt = Exec->arg_begin();
  for (unsigned i = 0; i < LR.ArgRegs.size(); ++i) {
    Value *Arg = ArgIt++;
    Value *Packed = packToReg(B, Arg, Arg->getType(), PtrBits);
    storeReg(B, Regs, ConstantInt::get(I32Ty, LR.ArgRegs[i]), Packed);
  }

  checkCallSignature(Run->getFunctionType(), {State}, "vm:run");
  B.CreateCall(Run, {State});

  Value *RetVal = nullptr;
  if (!Orig.getReturnType()->isVoidTy()) {
    Value *RetReg = loadReg(B, Regs, ConstantInt::get(I32Ty, LR.RetReg));
    RetVal = unpackFromReg(B, RetReg, Orig.getReturnType(), PtrBits);
  }

  if (UseHeapRegs) {
    FunctionCallee FreeFn = M.getOrInsertFunction(
        "free", FunctionType::get(Type::getVoidTy(Ctx), {I8PtrTy}, false));
    checkCallSignature(FreeFn.getFunctionType(), {RegsI8}, "vm:free");
    B.CreateCall(FreeFn, {RegsI8});
  }

  if (Orig.getReturnType()->isVoidTy()) {
    B.CreateRetVoid();
  } else {
    B.CreateRet(RetVal);
  }

  return Exec;
}

static Function *createWrapper(Function &Orig, Function *Exec, Function *Native,
                               bool Validate) {
  LLVMContext &Ctx = Orig.getContext();
  FunctionType *FTy = Orig.getFunctionType();
  Function *Wrapper = &Orig;
  if (Validate)
    Wrapper->addFnAttr("no_obfuscate");
  Wrapper->deleteBody();
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Wrapper);
  IRBuilder<> B(Entry);

  SmallVector<Value *, 8> Args;
  for (Argument &A : Wrapper->args())
    Args.push_back(&A);

  Value *VmRet = nullptr;
  if (!Validate) {
    checkCallSignature(Exec->getFunctionType(), Args, "vm:exec");
    CallInst *Call = B.CreateCall(Exec, Args);
    Call->setAttributes(getABIAttributes(*Exec));
    VmRet = Call;
    if (FTy->getReturnType()->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(VmRet);
    return Wrapper;
  }

  Value *NatRet = nullptr;
  if (Native) {
    checkCallSignature(Native->getFunctionType(), Args, "vm:native");
    CallInst *Call = B.CreateCall(Native, Args);
    Call->setAttributes(getABIAttributes(*Native));
    NatRet = Call;
  }
  checkCallSignature(Exec->getFunctionType(), Args, "vm:exec");
  CallInst *Call = B.CreateCall(Exec, Args);
  Call->setAttributes(getABIAttributes(*Exec));
  VmRet = Call;

  if (FTy->getReturnType()->isVoidTy()) {
    B.CreateRetVoid();
    return Wrapper;
  }

  Type *RetTy = FTy->getReturnType();
  Value *Eq = nullptr;
  if (RetTy->isFloatingPointTy()) {
    Type *IntTy = RetTy->isFloatTy() ? Type::getInt32Ty(Ctx)
                                     : Type::getInt64Ty(Ctx);
    Value *NatBits = B.CreateBitCast(NatRet, IntTy);
    Value *VmBits = B.CreateBitCast(VmRet, IntTy);
    Eq = B.CreateICmpEQ(NatBits, VmBits);
  } else if (RetTy->isPointerTy()) {
    const DataLayout &DL = Orig.getParent()->getDataLayout();
    Type *IntPtrTy = DL.getIntPtrType(Ctx);
    Value *NatBits = B.CreatePtrToInt(NatRet, IntPtrTy);
    Value *VmBits = B.CreatePtrToInt(VmRet, IntPtrTy);
    Eq = B.CreateICmpEQ(NatBits, VmBits);
  } else {
    Eq = B.CreateICmpEQ(NatRet, VmRet);
  }

  BasicBlock *Ok = BasicBlock::Create(Ctx, "vm.ok", Wrapper);
  BasicBlock *Fail = BasicBlock::Create(Ctx, "vm.fail", Wrapper);
  B.CreateCondBr(Eq, Ok, Fail);

  IRBuilder<> BF(Fail);
  if (Validate) {
    Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
    FunctionType *PutsTy =
        FunctionType::get(Type::getInt32Ty(Ctx), {I8PtrTy}, false);
    FunctionCallee Puts = Wrapper->getParent()->getOrInsertFunction("puts", PutsTy);
    std::string Msg = ("vm: validate fail: " + Orig.getName()).str();
    Value *MsgGV = BF.CreateGlobalString(Msg);
    Value *MsgPtr = BF.CreateInBoundsGEP(
        cast<GlobalVariable>(MsgGV)->getValueType(),
        cast<GlobalVariable>(MsgGV),
        {ConstantInt::get(Type::getInt32Ty(Ctx), 0),
         ConstantInt::get(Type::getInt32Ty(Ctx), 0)});
    BF.CreateCall(Puts, {MsgPtr});
  }
  FunctionCallee Trap =
      Intrinsic::getOrInsertDeclaration(Wrapper->getParent(), Intrinsic::trap);
  checkCallSignature(Trap.getFunctionType(), {}, "vm:trap");
  BF.CreateCall(Trap);
  BF.CreateUnreachable();

  IRBuilder<> BOk(Ok);
  BOk.CreateRet(VmRet);
  return Wrapper;
}

namespace llvm {
namespace obfvm {

PreservedAnalyses VMPass::run(Module &M, ModuleAnalysisManager &MAM) {
  VMConfig Cfg;
  Cfg.Mode = parseMode(VMModeOpt);
  Cfg.Encode = parseEncode(VMEncodeOpt);
  Cfg.Select = parseSelect(VMSelectOpt);
  Cfg.Handlers = parseHandlers(VMHandlersOpt);
  Cfg.Dispatch = parseDispatch(VMDispatchOpt);
  Cfg.Hard = VMHardOpt;
  Cfg.HardRuntime = VMHardRtOpt;
  Cfg.Debug = VMDebugOpt;
  Cfg.RuntimeDebug = VMDebugRtOpt;
  Cfg.Trace = VMTraceOpt;
  Cfg.TraceLimit = VMTraceLimitOpt;
  Cfg.BoundsCheck = VMBoundsCheckOpt;
  Cfg.Validate = VMValidateOpt;
  Cfg.Counters = VMCountersOpt;
  Cfg.EncodeFeistel = VMEncodeFeistelOpt;
  Cfg.EncodeFeistelAll = VMEncodeFeistelAllOpt;
  if (VMFeistelRoundsOpt != 0)
    Cfg.FeistelRounds = VMFeistelRoundsOpt;
  else
    Cfg.FeistelRounds = Cfg.Hard ? 6u : 2u;
  if (Cfg.FeistelRounds < 2)
    Cfg.FeistelRounds = 2;
  if (Cfg.FeistelRounds > 8)
    Cfg.FeistelRounds = 8;
  Cfg.ObfuscateRuntime = VMObfRuntimeOpt;
  Cfg.BogusCount = VMBogusOpt;
  Cfg.ColdThreshold = VMColdThresholdOpt;

  // Hard mode forces the strongest option for each axis so the user only
  // needs one flag for production-grade protection.
  if (Cfg.Hard) {
    Cfg.Dispatch = VMDispatch::Indirect;
    if (Cfg.Handlers == VMHandlers::Static)
      Cfg.Handlers = VMHandlers::Random;
    if (Cfg.BogusCount == 0)
      Cfg.BogusCount = 4;
    if (Cfg.Encode == VMEncode::Off)
      Cfg.Encode = VMEncode::MBA;
  }

  if (Cfg.Mode == VMMode::None)
    return PreservedAnalyses::all();

  recordObfuscationSeed(M);
  maybeDumpIR(M, "vm.before");

  bool Changed = false;
  SmallVector<Function *, 8> ToProcess;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (shouldSkipFunction(&F)) {
      reportVMDecision(F, "skip", "shouldSkipFunction");
      continue;
    }
    if (!shouldVirtualize(F, MAM, Cfg)) {
      switch (Cfg.Select) {
      case VMSelect::None:
        reportVMDecision(F, "skip", "select_none");
        break;
      case VMSelect::Marked:
        reportVMDecision(F, "skip", "not_marked");
        break;
      case VMSelect::Cold:
        reportVMDecision(F, "skip", "not_cold");
        break;
      default:
        reportVMDecision(F, "skip", "not_selected");
        break;
      }
      continue;
    }
    if (VMMaxBBsOpt > 0) {
      std::size_t BBs = countBasicBlocks(F);
      if (BBs > VMMaxBBsOpt) {
        reportVMDecision(F, "skip",
                         Twine("too_many_bbs:").concat(Twine(BBs)).str());
        markVMSkip(F, "too_many_bbs");
        continue;
      }
    }
    if (VMMaxIRInstsOpt > 0) {
      std::size_t Insts = countInstructions(F);
      if (Insts > VMMaxIRInstsOpt) {
        reportVMDecision(F, "skip",
                         Twine("too_many_insts:").concat(Twine(Insts)).str());
        markVMSkip(F, "too_many_insts");
        continue;
      }
    }
    reportVMDecision(F, "selected", "");
    ToProcess.push_back(&F);
  }

  for (Function *F : ToProcess) {
    // VM wrapping must not change the original symbol linkage/visibility.
    // If an internal (C `static`) function is accidentally made external, it
    // can collide at link time with same-named statics in other translation
    // units (e.g. common callback names like fail_cb/timer_cb in test suites).
    const auto SavedLinkage = F->getLinkage();
    const auto SavedVisibility = F->getVisibility();
    const auto SavedDLLStorage = F->getDLLStorageClass();
    const bool SavedDSOLocal = F->isDSOLocal();
    const auto SavedUnnamedAddr = F->getUnnamedAddr();
    Comdat *SavedComdat = F->getComdat();

    std::string Err;
    VMLoweringResult LR;
    if (VMDebugOpt) {
      errs() << "vm: lowering " << F->getName() << "\n";
    }
    VMLowerer L(*F, M.getDataLayout());
    if (!L.lower(LR, Err)) {
      LLVM_DEBUG(dbgs() << "vm: skip " << F->getName() << ": " << Err << "\n");
      reportVMDecision(*F, "skip", Twine("lower_fail:").concat(Err).str());
      // Lowering failed; mark VM skip and optionally skip other passes.
      markVMFailure(*F, Err, VMSkipOtherObfOpt);
      continue;
    }

    dumpVMIfEnabled(LR.VMF, "before");
    if (VMDebugOpt)
      errs() << "vm: validate " << F->getName() << "\n";
    if (!validateVMFunction(LR.VMF, Err)) {
      LLVM_DEBUG(dbgs() << "vm: invalid vmf " << F->getName() << ": " << Err
                        << "\n");
      reportVMDecision(*F, "skip", Twine("invalid_vm:").concat(Err).str());
      markVMFailure(*F, Err, VMSkipOtherObfOpt);
      continue;
    }
    if (VMDebugOpt)
      errs() << "vm: validate ok " << F->getName() << "\n";

    if (VMMaxBCInstrsOpt > 0 || VMMaxRuntimeInstrsOpt > 0) {
      size_t PreInstrs = countVMInstrs(LR.VMF);
      if (VMMaxRuntimeInstrsOpt > 0 &&
          (Cfg.Mode == VMMode::BB || Cfg.Mode == VMMode::Region)) {
        if (PreInstrs > VMMaxRuntimeInstrsOpt) {
          reportVMDecision(
              *F, "skip",
              Twine("vm_runtime_too_large:").concat(Twine(PreInstrs)).str());
          markVMSkip(*F, "vm_runtime_too_large");
          continue;
        }
      }
      if (VMMaxBCInstrsOpt > 0 && PreInstrs > VMMaxBCInstrsOpt) {
        reportVMDecision(
            *F, "skip",
            Twine("vm_ir_too_large:").concat(Twine(PreInstrs)).str());
        markVMSkip(*F, "vm_ir_too_large");
        continue;
      }
    }

    bool MBASkipped = false;
    bool FeistelThis =
        (Cfg.Encode != VMEncode::Off) &&
        (Cfg.EncodeFeistel || hasVMFeistelMarker(*F));
    bool FeistelAllThis =
        FeistelThis &&
        (Cfg.EncodeFeistelAll || hasVMFeistelAllMarker(*F));
    bool FullEncodeThis =
        (VMEncodeFullMarkedOpt && hasVMProtectMarker(*F)) ||
        matchesPathFilter(*F, VMEncodeFullPathOpt);
    bool FullEncodeFallback = false;
    if (FullEncodeThis && VMEncodeFullMaxInstrsOpt > 0) {
      size_t PreEncInstrs = countVMInstrs(LR.VMF);
      if (PreEncInstrs > VMEncodeFullMaxInstrsOpt) {
        FullEncodeThis = false;
        FullEncodeFallback = true;
      }
    }
    unsigned EncodePct = FullEncodeThis ? 100u : VMEncodePctOpt;
    if (EncodePct > 100)
      EncodePct = 100;
    size_t PreEncodeInstrs = countVMInstrs(LR.VMF);
    bool EncodeAllowed = (Cfg.Encode != VMEncode::Off);
    if (EncodeAllowed && VMEncodeMaxInstrsOpt > 0 &&
        PreEncodeInstrs > VMEncodeMaxInstrsOpt) {
      EncodePct = 0;
      EncodeAllowed = false;
      FeistelThis = false;
      FeistelAllThis = false;
      if (VMDebugOpt) {
        errs() << "vm: encode skip " << F->getName()
               << " instrs=" << PreEncodeInstrs
               << " max=" << VMEncodeMaxInstrsOpt << "\n";
      }
    }
    VMLoweringResult BeforeEncodeLR;
    size_t BeforeEncodeInstrs = 0;
    bool HaveBeforeEncode = EncodeAllowed;
    if (HaveBeforeEncode) {
      BeforeEncodeLR = LR;
      BeforeEncodeInstrs = PreEncodeInstrs;
    }
    if (EncodeAllowed &&
        (Cfg.Encode == VMEncode::Affine || Cfg.Encode == VMEncode::MBA)) {
      if (VMDebugOpt)
        errs() << "vm: encode affine begin " << F->getName() << "\n";
      if (!applyAffineEncoding(LR, FeistelThis, FeistelAllThis,
                               Cfg.FeistelRounds, EncodePct, Err)) {
        LLVM_DEBUG(dbgs() << "vm: encode failed " << F->getName() << ": " << Err
                          << "\n");
        reportVMDecision(*F, "skip",
                         Twine("encode_fail:").concat(Err).str());
        markVMFailure(*F, Err, VMSkipOtherObfOpt);
        continue;
      }
      if (VMDebugOpt)
        errs() << "vm: encode affine ok " << F->getName() << "\n";
    }

    if (EncodeAllowed && Cfg.Encode == VMEncode::MBA && EncodePct > 0) {
      VMLoweringResult BeforeMBA = LR;
      size_t BeforeInstrs = countVMInstrs(BeforeMBA.VMF);
      if (VMDebugOpt)
        errs() << "vm: encode mba begin " << F->getName() << "\n";
      if (!applyMBAObfuscation(LR.VMF, Err)) {
        LLVM_DEBUG(dbgs() << "vm: mba failed " << F->getName() << ": " << Err
                          << "\n");
        reportVMDecision(*F, "skip", Twine("mba_fail:").concat(Err).str());
        markVMFailure(*F, Err, VMSkipOtherObfOpt);
        continue;
      }
      if (VMDebugOpt)
        errs() << "vm: encode mba ok " << F->getName() << "\n";
      if (VMMBAMaxGrowthOpt > 0 && BeforeInstrs > 0) {
        size_t AfterInstrs = countVMInstrs(LR.VMF);
        size_t MaxInstrs =
            (BeforeInstrs * static_cast<size_t>(VMMBAMaxGrowthOpt)) / 100;
        if (VMDebugOpt) {
          errs() << "vm: mba growth " << F->getName() << " "
                 << BeforeInstrs << " -> " << AfterInstrs
                 << " max=" << MaxInstrs << " pct=" << VMMBAMaxGrowthOpt
                 << "\n";
        }
        if (AfterInstrs > MaxInstrs) {
          LLVM_DEBUG(dbgs() << "vm: mba growth cap hit for " << F->getName()
                            << " (" << AfterInstrs << " > " << MaxInstrs
                            << "), keeping affine only\n");
          LR = std::move(BeforeMBA);
          MBASkipped = true;
        }
      }
    }
    if (HaveBeforeEncode && VMEncodeMaxGrowthOpt > 0 && BeforeEncodeInstrs > 0) {
      size_t AfterInstrs = countVMInstrs(LR.VMF);
      size_t MaxInstrs =
          (BeforeEncodeInstrs * static_cast<size_t>(VMEncodeMaxGrowthOpt)) /
          100;
      if (VMDebugOpt) {
        errs() << "vm: encode growth " << F->getName() << " "
               << BeforeEncodeInstrs << " -> " << AfterInstrs
               << " max=" << MaxInstrs << " pct=" << VMEncodeMaxGrowthOpt
               << "\n";
      }
      if (AfterInstrs > MaxInstrs) {
        LLVM_DEBUG(dbgs() << "vm: encode growth cap hit for " << F->getName()
                          << " (" << AfterInstrs << " > " << MaxInstrs
                          << "), keeping unencoded VM\n");
        LR = std::move(BeforeEncodeLR);
      }
    }

    if (Cfg.Encode != VMEncode::Off)
      dumpVMIfEnabled(LR.VMF, "after-encode");

    if (VMMaxRuntimeInstrsOpt > 0 &&
        (Cfg.Mode == VMMode::BB || Cfg.Mode == VMMode::Region)) {
      size_t PostInstrs = countVMInstrs(LR.VMF);
      if (PostInstrs > VMMaxRuntimeInstrsOpt) {
        reportVMDecision(
            *F, "skip",
            Twine("vm_runtime_too_large_post:").concat(Twine(PostInstrs)).str());
        markVMSkip(*F, "vm_runtime_too_large_post");
        continue;
      }
    }

    if (VMDebugOpt)
      errs() << "vm: bytecode " << F->getName() << "\n";
    VMBytecode BC = buildBytecode(LR.VMF);
    if (Cfg.Debug) {
      if (VMDebugMaxInstrsOpt > 0 && BC.Instrs.size() > VMDebugMaxInstrsOpt) {
        errs() << "vm: bytecode dump skipped (instrs=" << BC.Instrs.size()
               << ")\n";
      } else {
        dumpVMBytecode(BC, errs());
      }
    }
    if (VMMaxBCInstrsOpt > 0 && BC.Instrs.size() > VMMaxBCInstrsOpt) {
      reportVMDecision(
          *F, "skip",
          Twine("bc_too_large:").concat(Twine(BC.Instrs.size())).str());
      markVMSkip(*F, "bc_too_large");
      continue;
    }
    // Bytecode encoding is only meaningful in opcode mode; bb/region emit native
    // IR so they don't benefit from encoded instruction streams.
    bool EncodeBC = (Cfg.Mode == VMMode::Opcode && Cfg.Hard);
    uint64_t LayoutSeed = cryptoutils->get_uint64_t();
    VMBCLayout Layout = buildVMBCLayout(Cfg.Hard, LayoutSeed);
    uint64_t EncSeed = cryptoutils->get_uint64_t();
    VMBCEncodingInfo EncInfo = buildVMBCEncodingInfo(EncSeed, Cfg.Hard);
    // Hash constants must be nonzero; HashMul must be odd for invertibility.
    uint64_t HashKey = cryptoutils->get_uint64_t();
    if (HashKey == 0)
      HashKey = 1;
    uint64_t HashMul = cryptoutils->get_uint64_t() | 1ULL;
    if (VMMaxGlobalBytesOpt > 0) {
      std::size_t GlobalBytes =
          estimateBytecodeGlobalBytes(M, BC, Layout, EncodeBC);
      if (GlobalBytes > VMMaxGlobalBytesOpt) {
        reportVMDecision(*F, "skip",
                         Twine("bc_globals_too_large:")
                             .concat(Twine(GlobalBytes))
                             .str());
        markVMSkip(*F, "bc_globals_too_large");
        continue;
      }
    }
    uint64_t BCKey = 0;
    if (EncodeBC) {
      BCKey = cryptoutils->get_uint64_t();
      if (BCKey == 0)
        BCKey = 1;
    }
    VMBytecodeGlobals Globals =
        emitBytecodeGlobals(M, BC, F->getName(), Layout, EncInfo, BCKey,
                            EncodeBC, HashKey, HashMul);
    (void)Globals;

    Function *Run = nullptr;
    uint32_t EntrySlot = 0;
    if (Cfg.Mode == VMMode::Region) {
      // Region mode trades obfuscation strength for speed by re-emitting IR.
      if (VMDebugOpt)
        errs() << "vm: emit regions " << F->getName() << "\n";
      Run = emitVMRegions(M, LR.VMF, Cfg, Err, EntrySlot);
    } else {
      if (VMDebugOpt)
        errs() << "vm: emit interp " << F->getName() << "\n";
      Run = emitVMInterpreter(M, LR.VMF, BC, Globals, Layout, EncInfo, Cfg,
                              BCKey);
    }
    if (!Run) {
      LLVM_DEBUG(dbgs() << "vm: emit failed " << F->getName() << ": " << Err
                        << "\n");
      reportVMDecision(*F, "skip", Twine("emit_fail:").concat(Err).str());
      markVMFailure(*F, Err, VMSkipOtherObfOpt);
      continue;
    }
    verifyFunctionOrDie(*Run, "vm.run");

    bool ValidateThis = Cfg.Validate && isValidationSafe(LR.VMF);
    Function *Native = nullptr;
    if (ValidateThis) {
      ValueToValueMapTy VMap;
      Native = CloneFunction(F, VMap);
      Native->setName(F->getName() + ".native");
      Native->setLinkage(GlobalValue::InternalLinkage);
      Native->addFnAttr("no_obfuscate");
    }

    Function *Exec = createVMExec(*F, LR, Run, Globals, Cfg, M, EntrySlot);
    Exec->addFnAttr("no_obfuscate");
    verifyFunctionOrDie(*Exec, "vm.exec");

    createWrapper(*F, Exec, Native, ValidateThis);
    if (!Cfg.ObfuscateRuntime) {
      F->addFnAttr("no_obfuscate");
      markVMRuntimeNoObf(M);
    }

    // Keep the function's original linkage/visibility. The VM transform
    // replaces the body but should not change how the symbol is exported.
    F->setLinkage(SavedLinkage);
    F->setVisibility(SavedVisibility);
    F->setDLLStorageClass(SavedDLLStorage);
    F->setDSOLocal(SavedDSOLocal);
    F->setUnnamedAddr(SavedUnnamedAddr);
    if (SavedComdat)
      F->setComdat(SavedComdat);

    Changed = true;
    SmallString<256> Info;
    raw_svector_ostream IOS(Info);
    IOS << "blocks=" << LR.VMF.Blocks.size()
        << "\tinstrs=" << BC.Instrs.size()
        << "\toffsets=" << BC.BlockOffsets.size()
        << "\tswitch_vals=" << BC.SwitchValues.size()
        << "\tswitch_tgts=" << BC.SwitchTargets.size();
    if (Cfg.Encode != VMEncode::Off)
      IOS << "\tencode_pct=" << EncodePct;
    if (FullEncodeThis)
      IOS << "\tencode_full=1";
    if (FullEncodeFallback)
      IOS << "\tencode_full_fallback=1";
    if (FeistelThis)
      IOS << "\tfeistel=1";
    if (FeistelAllThis)
      IOS << "\tfeistel_all=1";
    if (MBASkipped)
      IOS << "\tmba_skipped=1";
    std::string InfoStr = IOS.str().str();
    reportVMDecision(*F, "vm", InfoStr);
    if (!VMReportOpt.empty()) {
      SmallString<256> StatLine;
      raw_svector_ostream StatOS(StatLine);
      StatOS << F->getName() << "\tvm_stats\t" << InfoStr;
      writeVMReportLine(StatOS.str());
    }
    verifyFunctionOrDie(*F, "vm");
  }

  if (Changed) {
    verifyModuleOrDie(M, "vm");
    maybeDumpIR(M, "vm.after");
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}

} // namespace obfvm
} // namespace llvm
