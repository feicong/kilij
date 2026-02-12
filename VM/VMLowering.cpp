//===- VMLowering.cpp - Lower LLVM IR to VM IR ---------------------------===//
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
// Lowers LLVM IR to VM IR with stable register/constant mapping and
// preserved control flow.
//
//===----------------------------------------------------------------------===//
#include "VMLowering.h"
#include "VMEmitUtils.h"
#include "Utils.h"
#include "llvm/Analysis/ConstantFolding.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/raw_ostream.h"
#include <cctype>

using namespace llvm;
using namespace llvm::obfvm;

namespace {
struct VMLowererImpl {
  Function &F;
  const DataLayout &DL;
  uint32_t RegCounter = 0;

  // Deterministic maps so builds with identical input produce identical VM IR.
  DenseMap<const Value *, uint32_t> RegMap;
  DenseMap<const Constant *, uint32_t> ConstRegs;
  DenseMap<const BasicBlock *, uint32_t> BlockIds;
    DenseMap<const AtomicCmpXchgInst *, std::pair<uint32_t, uint32_t>>
        CmpXchgRegs;
  // Phis are deferred because successors may not have regs assigned yet.
  SmallVector<std::pair<PHINode *, uint32_t>, 16> Phis;
    uint32_t InlineAsmCounter = 0;

  VMLowererImpl(Function &Func, const DataLayout &Layout)
      : F(Func), DL(Layout) {}

  uint32_t nextReg() { return RegCounter++; }

  VMType mapType(Type *Ty, std::string &Err) const {
    if (!Ty) {
      Err = "vm: null type";
      return VMType(VMTypeKind::I64);
    }
    if (Ty->isIntegerTy(1))
      return VMType(VMTypeKind::I1);
    if (Ty->isIntegerTy(8))
      return VMType(VMTypeKind::I8);
    if (Ty->isIntegerTy(16))
      return VMType(VMTypeKind::I16);
    if (Ty->isIntegerTy(32))
      return VMType(VMTypeKind::I32);
    if (Ty->isIntegerTy(64))
      return VMType(VMTypeKind::I64);
    if (Ty->isFloatTy())
      return VMType(VMTypeKind::F32);
    if (Ty->isDoubleTy())
      return VMType(VMTypeKind::F64);
    if (Ty->isPointerTy())
      return VMType(VMTypeKind::Ptr);
    {
      std::string TyStr;
      raw_string_ostream OS(TyStr);
      Ty->print(OS);
      Err = ("vm: unsupported type: " + OS.str());
    }
    return VMType(VMTypeKind::I64);
  }

  unsigned getCallAddrSpace(const CallBase &CB) const {
    if (auto *PT = dyn_cast<PointerType>(CB.getCalledOperand()->getType())) {
      return PT->getAddressSpace();
    }
    return 0;
  }

  VMFenceKind mapFence(AtomicOrdering O) const {
    switch (O) {
    case AtomicOrdering::Acquire:
      return VMFenceKind::Acquire;
    case AtomicOrdering::Release:
      return VMFenceKind::Release;
    case AtomicOrdering::AcquireRelease:
      return VMFenceKind::AcquireRelease;
    case AtomicOrdering::SequentiallyConsistent:
      return VMFenceKind::SeqCst;
    default:
      return VMFenceKind::SeqCst;
    }
  }

  // Debug/lifetime intrinsics have no observable side effects in VM IR.
  bool isIgnorableIntrinsic(Intrinsic::ID ID) const {
    switch (ID) {
    case Intrinsic::dbg_declare:
    case Intrinsic::dbg_value:
    case Intrinsic::dbg_label:
    case Intrinsic::lifetime_start:
    case Intrinsic::lifetime_end:
    case Intrinsic::assume:
    case Intrinsic::expect:
    case Intrinsic::invariant_start:
    case Intrinsic::invariant_end:
    case Intrinsic::prefetch:
    case Intrinsic::annotation:
    case Intrinsic::ptr_annotation:
    case Intrinsic::var_annotation:
    case Intrinsic::donothing:
    case Intrinsic::experimental_noalias_scope_decl:
      return true;
    default:
      return false;
    }
  }

  std::string sanitizeName(StringRef Name) const {
    if (Name.empty())
      return "anon";
    std::string Out = Name.str();
    for (char &C : Out) {
      if (!isalnum(static_cast<unsigned char>(C)) && C != '_')
        C = '_';
    }
    return Out;
  }

  std::string typeSuffix(Type *Ty, unsigned PtrBits) const {
    if (Ty->isIntegerTy())
      return ("i" + std::to_string(Ty->getIntegerBitWidth()));
    if (Ty->isFloatTy())
      return "f32";
    if (Ty->isDoubleTy())
      return "f64";
    if (Ty->isPointerTy())
      return ("p" + std::to_string(PtrBits));
    return "t";
  }

  AttributeList sanitizeCallAttrs(const AttributeList &Attrs,
                                  FunctionType *FTy) const {
    if (!FTy)
      return Attrs;
    LLVMContext &Ctx = F.getContext();
    SmallVector<AttributeSet, 8> ParamAttrs;
    ParamAttrs.reserve(FTy->getNumParams());
    for (unsigned i = 0; i < FTy->getNumParams(); ++i)
      ParamAttrs.push_back(Attrs.getParamAttrs(i));
    return AttributeList::get(Ctx, Attrs.getFnAttrs(), Attrs.getRetAttrs(),
                              ParamAttrs);
  }

  Function *getOrCreateIntrinsicWrapper(Intrinsic::ID ID,
                                        FunctionType *FTy) {
    Module *M = F.getParent();
    if (!M)
      return nullptr;
    unsigned PtrBits = DL.getPointerSizeInBits();
    SmallVector<Type *, 2> OverTys;
    if (Intrinsic::isOverloaded(ID)) {
      switch (ID) {
      case Intrinsic::ctlz:
      case Intrinsic::cttz:
      case Intrinsic::umax:
      case Intrinsic::umin:
      case Intrinsic::smax:
      case Intrinsic::smin:
      case Intrinsic::fshl:
      case Intrinsic::fabs:
      case Intrinsic::ceil:
      case Intrinsic::threadlocal_address:
        OverTys.push_back(FTy->getReturnType());
        break;
      default:
        break;
      }
    }

    std::string IntrName =
        Intrinsic::isOverloaded(ID)
            ? Intrinsic::getName(ID, OverTys, M, FTy)
            : Intrinsic::getName(ID).str();
    std::string Name =
        "vm_intrin_" + sanitizeName(IntrName) + "_" +
        typeSuffix(FTy->getReturnType(), PtrBits);
    if (FTy->getNumParams() > 0) {
      Name += "_" + typeSuffix(FTy->getParamType(0), PtrBits);
    }
    Name += "_" + std::to_string(FTy->getNumParams());
    std::string Tag = "vm.intrin." + Name;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    Function *Fn = Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    FunctionCallee Intr = Intrinsic::getOrInsertDeclaration(M, ID, OverTys);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    SmallVector<Value *, 4> Args;
    auto castToParam = [&](Value *V, Type *Ty) -> Value * {
      if (!Ty || V->getType() == Ty)
        return V;
      LLVMContext &LCtx = B.getContext();
      unsigned PtrBits = DL.getPointerSizeInBits();
      auto intPtrTy = [&]() -> Type * { return Type::getIntNTy(LCtx, PtrBits); };
      if (Ty->isPointerTy()) {
        if (V->getType()->isPointerTy()) {
          unsigned SrcAS = V->getType()->getPointerAddressSpace();
          unsigned DstAS = Ty->getPointerAddressSpace();
          if (SrcAS != DstAS)
            return B.CreateAddrSpaceCast(V, Ty);
          return B.CreateBitCast(V, Ty);
        }
        if (V->getType()->isIntegerTy()) {
          Type *IntPtrTy = intPtrTy();
          Value *IntV =
              (V->getType() == IntPtrTy) ? V : B.CreateZExtOrTrunc(V, IntPtrTy);
          return B.CreateIntToPtr(IntV, Ty);
        }
        if (V->getType()->isFloatingPointTy()) {
          unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
          Type *IntSrcTy = Type::getIntNTy(LCtx, SrcBits);
          Value *IntV = B.CreateBitCast(V, IntSrcTy);
          Type *IntPtrTy = intPtrTy();
          if (IntSrcTy != IntPtrTy)
            IntV = B.CreateZExtOrTrunc(IntV, IntPtrTy);
          return B.CreateIntToPtr(IntV, Ty);
        }
      } else if (Ty->isIntegerTy()) {
        if (V->getType()->isPointerTy()) {
          Type *IntPtrTy = intPtrTy();
          Value *IntV = B.CreatePtrToInt(V, IntPtrTy);
          return B.CreateZExtOrTrunc(IntV, Ty);
        }
        if (V->getType()->isIntegerTy())
          return B.CreateZExtOrTrunc(V, Ty);
        if (V->getType()->isFloatingPointTy()) {
          unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
          if (SrcBits == Ty->getIntegerBitWidth())
            return B.CreateBitCast(V, Ty);
          return B.CreateFPToSI(V, Ty);
        }
      } else if (Ty->isFloatingPointTy()) {
        if (V->getType()->isFloatingPointTy()) {
          unsigned SrcBits = V->getType()->getPrimitiveSizeInBits();
          unsigned DstBits = Ty->getPrimitiveSizeInBits();
          if (SrcBits == DstBits)
            return B.CreateBitCast(V, Ty);
          if (SrcBits < DstBits)
            return B.CreateFPExt(V, Ty);
          return B.CreateFPTrunc(V, Ty);
        }
        if (V->getType()->isIntegerTy()) {
          if (V->getType()->getIntegerBitWidth() ==
              Ty->getPrimitiveSizeInBits())
            return B.CreateBitCast(V, Ty);
          return B.CreateSIToFP(V, Ty);
        }
        if (V->getType()->isPointerTy()) {
          Type *IntPtrTy = intPtrTy();
          Value *IntV = B.CreatePtrToInt(V, IntPtrTy);
          if (IntPtrTy->getIntegerBitWidth() ==
              Ty->getPrimitiveSizeInBits())
            return B.CreateBitCast(IntV, Ty);
          return B.CreateSIToFP(IntV, Ty);
        }
      }
      if (V->getType()->isFirstClassType() && Ty->isFirstClassType() &&
          V->getType()->getPrimitiveSizeInBits() ==
              Ty->getPrimitiveSizeInBits())
        return B.CreateBitCast(V, Ty);
      return V;
    };
    FunctionType *IntrTy = Intr.getFunctionType();
    unsigned ArgCount = Fn->arg_size();
    Args.reserve(ArgCount);
    for (unsigned i = 0; i < ArgCount; ++i) {
      Argument &A = *std::next(Fn->arg_begin(), i);
      Type *ParamTy = (i < IntrTy->getNumParams()) ? IntrTy->getParamType(i)
                                                   : A.getType();
      Args.push_back(castToParam(&A, ParamTy));
    }
    checkCallSignature(Intr.getFunctionType(), Args,
                       "__vm_intrinsic_wrapper");
    CallInst *Call = B.CreateCall(Intr, Args);
    if (FTy->getReturnType()->isVoidTy())
      B.CreateRetVoid();
    else if (FTy->getReturnType() == Call->getType())
      B.CreateRet(Call);
    else
      B.CreateRet(castToParam(Call, FTy->getReturnType()));
    return Fn;
  }

  Function *getOrCreateThreadLocalWrapper(GlobalValue *GV, Type *RetTy) {
    Module *M = F.getParent();
    if (!M || !GV)
      return nullptr;

    unsigned PtrBits = DL.getPointerSizeInBits();
    std::string GName = sanitizeName(GV->getName());
    if (GName.empty())
      GName = "tls";

    std::string Name =
        "vm_tls_" + GName + "_" + typeSuffix(RetTy, PtrBits);
    std::string Tag = "vm.tls." + GName + "." + typeSuffix(RetTy, PtrBits);
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    FunctionType *FTy = FunctionType::get(RetTy, {}, false);
    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    SmallVector<Type *, 1> OverTys;
    OverTys.push_back(RetTy);
    FunctionCallee Intr =
        Intrinsic::getOrInsertDeclaration(M, Intrinsic::threadlocal_address, OverTys);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    Value *Arg = GV;
    Type *ParamTy = Intr.getFunctionType()->getParamType(0);
    if (Arg->getType() != ParamTy)
      Arg = B.CreateBitCast(Arg, ParamTy);
    checkCallSignature(Intr.getFunctionType(), {Arg},
                       "__vm_tls_wrapper");
    CallInst *Call = B.CreateCall(Intr, {Arg});
    if (RetTy->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(Call);
    return Fn;
  }

  Function *getOrCreateCtlzCttzWrapper(Intrinsic::ID ID, Type *RetTy,
                                       Type *OpTy, uint64_t ImmVal) {
    Module *M = F.getParent();
    if (!M)
      return nullptr;

    unsigned PtrBits = DL.getPointerSizeInBits();
    SmallVector<Type *, 1> OverTys;
    OverTys.push_back(RetTy);
    std::string IntrName = Intrinsic::getName(ID, OverTys, M);
    std::string Name =
        "vm_intrin_" + sanitizeName(IntrName) + "_" +
        typeSuffix(RetTy, PtrBits) + "_" + typeSuffix(OpTy, PtrBits) + "_imm" +
        std::to_string(ImmVal & 1u);
    std::string Tag = "vm.intrin." + Name;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    FunctionType *FTy = FunctionType::get(RetTy, {OpTy}, false);
    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    FunctionCallee Intr = Intrinsic::getOrInsertDeclaration(M, ID, OverTys);
    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    Value *Arg = &*Fn->arg_begin();
    Type *ParamTy = Intr.getFunctionType()->getParamType(0);
    if (Arg->getType() != ParamTy)
      Arg = B.CreateBitCast(Arg, ParamTy);
    Value *Imm = ConstantInt::get(Type::getInt1Ty(F.getContext()),
                                  ImmVal ? 1 : 0);
    checkCallSignature(Intr.getFunctionType(), {Arg, Imm},
                       "__vm_ctlz_cttz_wrapper");
    CallInst *Call = B.CreateCall(Intr, {Arg, Imm});
    if (RetTy->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(Call);
    return Fn;
  }

  bool lowerIntrinsicToHostCall(CallBase &CB, Intrinsic::ID ID, VMBlock &B,
                                VMBlock &Entry, VMLoweringResult &Out,
                                std::string &Err) {
    FunctionType *FTy = CB.getFunctionType();
    Function *Wrapper = getOrCreateIntrinsicWrapper(ID, FTy);
    if (!Wrapper) {
      Err = "vm: intrinsic wrapper unavailable";
      return false;
    }

    VMCallInfo CI;
    CI.Name = Wrapper->getName();
    CI.Callee = Wrapper;
    CI.CalleeTy = Wrapper->getFunctionType();
    CI.CalleeAddrSpace = Wrapper->getAddressSpace();
    CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
    CI.CallAttrs = sanitizeCallAttrs(CB.getAttributes(), CI.CalleeTy);
    CI.IsVoid = CB.getType()->isVoidTy();
    if (!CI.IsVoid) {
      VMType RetTy = mapType(CB.getType(), Err);
      if (!Err.empty())
        return false;
      CI.RetTy = RetTy;
      CI.RetReg = getOrCreateReg(&CB, RetTy, Entry, Err);
      if (!Err.empty())
        return false;
    }
    for (Value *Arg : CB.args()) {
      VMType ATy = mapType(Arg->getType(), Err);
      if (!Err.empty())
        return false;
      CI.ArgRegs.push_back(getOrCreateReg(Arg, ATy, Entry, Err));
      if (!Err.empty())
        return false;
      CI.ArgTypes.push_back(Arg->getType());
    }
    uint32_t CallIndex = Out.VMF.Calls.size();
    Out.VMF.Calls.push_back(CI);

    VMInstr Inst;
    Inst.Op = VMOpcode::CallHost;
    Inst.CallIndex = CallIndex;
    B.Instrs.push_back(Inst);
    return true;
  }

  Function *getOrCreateLibcall(StringRef Name, FunctionType *FTy) {
    Module *M = F.getParent();
    if (!M)
      return nullptr;
    if (Function *Fn = M->getFunction(Name))
      return Fn;
    Function *Fn =
        Function::Create(FTy, GlobalValue::ExternalLinkage, Name, M);
    Fn->setCallingConv(CallingConv::C);
    return Fn;
  }

  Function *getOrCreateInlineAsmWrapper(InlineAsm *IA, FunctionType *FTy,
                                        CallingConv::ID CC,
                                        const AttributeList &Attrs) {
    Module *M = F.getParent();
    if (!M || !IA || !FTy)
      return nullptr;

    std::string CounterStr = std::to_string(InlineAsmCounter++);
    std::string BaseName = sanitizeName(F.getName());
    std::string Name = "vm_inlineasm_" + BaseName + "_" + CounterStr;
    std::string Tag = "vm.inlineasm." + BaseName + "." + CounterStr;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    obfuscateSymbolName(*Fn, *M, Tag, Name);
    Fn->setCallingConv(CC);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    SmallVector<Value *, 8> Args;
    for (Argument &A : Fn->args())
      Args.push_back(&A);
    checkCallSignature(IA->getFunctionType(), Args,
                       "__vm_inlineasm_wrapper");
    CallInst *Call = B.CreateCall(IA, Args);
    Call->setCallingConv(CC);
    if (!Attrs.isEmpty())
      Call->setAttributes(Attrs);
    if (FTy->getReturnType()->isVoidTy())
      B.CreateRetVoid();
    else
      B.CreateRet(Call);
    return Fn;
  }

  static StringRef atomicOrderName(AtomicOrdering O) {
    switch (O) {
    case AtomicOrdering::NotAtomic:
      return "na";
    case AtomicOrdering::Unordered:
      return "uo";
    case AtomicOrdering::Monotonic:
      return "mo";
    case AtomicOrdering::Acquire:
      return "acq";
    case AtomicOrdering::Release:
      return "rel";
    case AtomicOrdering::AcquireRelease:
      return "acqrel";
    case AtomicOrdering::SequentiallyConsistent:
      return "seq";
    }
    return "na";
  }

  Function *getOrCreateAtomicLoadWrapper(LoadInst &LI) {
    Module *M = F.getParent();
    if (!M)
      return nullptr;

    Type *ValTy = LI.getType();
    Type *PtrTy = LI.getPointerOperandType();
    unsigned PtrBits = DL.getPointerSizeInBits();
    std::string Name = "vm_atomic_load_" + typeSuffix(ValTy, PtrBits) + "_" +
                       atomicOrderName(LI.getOrdering()).str() + "_s" +
                       std::to_string(static_cast<unsigned>(LI.getSyncScopeID())) +
                       (LI.isVolatile() ? "_v" : "");
    std::string Tag = "vm.atomic.load." + Name;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    FunctionType *FTy = FunctionType::get(ValTy, {PtrTy}, false);
    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setCallingConv(CallingConv::C);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    Argument *PtrArg = Fn->getArg(0);
    LoadInst *Ld = B.CreateLoad(ValTy, PtrArg);
    if (LI.isVolatile())
      Ld->setVolatile(true);
    if (LI.getOrdering() != AtomicOrdering::NotAtomic) {
      Ld->setAtomic(LI.getOrdering());
      Ld->setSyncScopeID(LI.getSyncScopeID());
    }
    if (LI.getAlign().value() != 0)
      Ld->setAlignment(LI.getAlign());
    B.CreateRet(Ld);
    return Fn;
  }

  Function *getOrCreateAtomicStoreWrapper(StoreInst &SI) {
    Module *M = F.getParent();
    if (!M)
      return nullptr;

    Type *ValTy = SI.getValueOperand()->getType();
    Type *PtrTy = SI.getPointerOperandType();
    unsigned PtrBits = DL.getPointerSizeInBits();
    std::string Name =
        "vm_atomic_store_" + typeSuffix(ValTy, PtrBits) + "_" +
        atomicOrderName(SI.getOrdering()).str() + "_s" +
        std::to_string(static_cast<unsigned>(SI.getSyncScopeID())) +
        (SI.isVolatile() ? "_v" : "");
    std::string Tag = "vm.atomic.store." + Name;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    FunctionType *FTy =
        FunctionType::get(Type::getVoidTy(F.getContext()), {PtrTy, ValTy},
                          false);
    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setCallingConv(CallingConv::C);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    Argument *PtrArg = Fn->getArg(0);
    Argument *ValArg = Fn->getArg(1);
    StoreInst *St = B.CreateStore(ValArg, PtrArg);
    if (SI.isVolatile())
      St->setVolatile(true);
    if (SI.getOrdering() != AtomicOrdering::NotAtomic) {
      St->setAtomic(SI.getOrdering());
      St->setSyncScopeID(SI.getSyncScopeID());
    }
    if (SI.getAlign().value() != 0)
      St->setAlignment(SI.getAlign());
    B.CreateRetVoid();
    return Fn;
  }

    Function *getOrCreateAtomicRMWWrapper(AtomicRMWInst &AI) {
      Module *M = F.getParent();
      if (!M)
        return nullptr;

    Type *ValTy = AI.getValOperand()->getType();
    Type *PtrTy = AI.getPointerOperand()->getType();
    unsigned PtrBits = DL.getPointerSizeInBits();
    std::string Name = "vm_atomic_rmw_" +
                       sanitizeName(AtomicRMWInst::getOperationName(
                                        AI.getOperation())) +
                       "_" + typeSuffix(ValTy, PtrBits) + "_" +
                       atomicOrderName(AI.getOrdering()).str() + "_s" +
                       std::to_string(static_cast<unsigned>(AI.getSyncScopeID())) +
                       (AI.isVolatile() ? "_v" : "");
    std::string Tag = "vm.atomic.rmw." + Name;
    if (Function *Existing = findTaggedFunction(*M, Tag))
      return Existing;
    if (Function *Existing = M->getFunction(Name)) {
      obfuscateSymbolName(*Existing, *M, Tag, Name);
      return Existing;
    }

    FunctionType *FTy = FunctionType::get(ValTy, {PtrTy, ValTy}, false);
    Function *Fn =
        Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
    Fn->addFnAttr("vm_runtime");
    Fn->addFnAttr("no_obfuscate");
    Fn->addFnAttr(Attribute::NoInline);
    Fn->setCallingConv(CallingConv::C);
    obfuscateSymbolName(*Fn, *M, Tag, Name);

    BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
    IRBuilder<> B(EntryBB);
    Argument *PtrArg = Fn->getArg(0);
    Argument *ValArg = Fn->getArg(1);
    AtomicRMWInst *RMW = B.CreateAtomicRMW(
        AI.getOperation(), PtrArg, ValArg, AI.getAlign(), AI.getOrdering());
    RMW->setSyncScopeID(AI.getSyncScopeID());
    if (AI.isVolatile())
      RMW->setVolatile(true);
      B.CreateRet(RMW);
      return Fn;
    }

    Function *getOrCreateAtomicCmpXchgWrapper(AtomicCmpXchgInst &CX) {
      Module *M = F.getParent();
      if (!M)
        return nullptr;

      Type *ValTy = CX.getCompareOperand()->getType();
      Type *PtrTy = CX.getPointerOperand()->getType();
      unsigned PtrBits = DL.getPointerSizeInBits();
      std::string Name = "vm_atomic_cmpxchg_" + typeSuffix(ValTy, PtrBits) + "_" +
                         atomicOrderName(CX.getSuccessOrdering()).str() + "_" +
                         atomicOrderName(CX.getFailureOrdering()).str() + "_s" +
                         std::to_string(static_cast<unsigned>(CX.getSyncScopeID())) +
                         (CX.isVolatile() ? "_v" : "") +
                         (CX.isWeak() ? "_w" : "");
      std::string Tag = "vm.atomic.cmpxchg." + Name;
      if (Function *Existing = findTaggedFunction(*M, Tag))
        return Existing;
      if (Function *Existing = M->getFunction(Name)) {
        obfuscateSymbolName(*Existing, *M, Tag, Name);
        return Existing;
      }

      FunctionType *FTy = FunctionType::get(ValTy, {PtrTy, ValTy, ValTy}, false);
      Function *Fn =
          Function::Create(FTy, GlobalValue::InternalLinkage, Name, M);
      Fn->addFnAttr("vm_runtime");
      Fn->addFnAttr("no_obfuscate");
      Fn->addFnAttr(Attribute::NoInline);
      Fn->setCallingConv(CallingConv::C);
      obfuscateSymbolName(*Fn, *M, Tag, Name);

      BasicBlock *EntryBB = BasicBlock::Create(F.getContext(), "entry", Fn);
      IRBuilder<> B(EntryBB);
      Argument *PtrArg = Fn->getArg(0);
      Argument *CmpArg = Fn->getArg(1);
      Argument *NewArg = Fn->getArg(2);
      AtomicCmpXchgInst *CCX = B.CreateAtomicCmpXchg(
          PtrArg, CmpArg, NewArg, CX.getAlign(),
          CX.getSuccessOrdering(), CX.getFailureOrdering(),
          CX.getSyncScopeID());
      CCX->setWeak(CX.isWeak());
      if (CX.isVolatile())
        CCX->setVolatile(true);
      Value *Old = B.CreateExtractValue(CCX, 0);
      // Return only the old value; VM reconstructs success by comparing.
      B.CreateRet(Old);
      return Fn;
    }

  bool lowerIntrinsicCall(CallBase &CB, Intrinsic::ID ID, VMBlock &B,
                          VMBlock &Entry, VMLoweringResult &Out,
                          std::string &Err) {
    LLVMContext &Ctx = F.getContext();
    switch (ID) {
    case Intrinsic::trap: {
      VMInstr Inst;
      Inst.Op = VMOpcode::Trap;
      B.Instrs.push_back(Inst);
      return true;
    }
    case Intrinsic::memcpy:
    case Intrinsic::memmove:
    case Intrinsic::memset: {
      if (CB.arg_size() < 4) {
        Err = "vm: mem intrinsic arg mismatch";
        return false;
      }
      Value *IsVol = CB.getArgOperand(3);
      if (auto *C = dyn_cast<ConstantInt>(IsVol)) {
        if (!C->isZero()) {
          Err = "vm: volatile mem intrinsic unsupported";
          return false;
        }
      } else {
        Err = "vm: volatile mem intrinsic unsupported";
        return false;
      }

      Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(Ctx));
      Type *SizeTy = DL.getIntPtrType(Ctx);
      Function *Lib = nullptr;
      if (ID == Intrinsic::memset) {
        Type *I32Ty = Type::getInt32Ty(Ctx);
        FunctionType *FTy =
            FunctionType::get(Type::getVoidTy(Ctx), {I8PtrTy, I32Ty, SizeTy},
                              false);
        Lib = getOrCreateLibcall("memset", FTy);
      } else if (ID == Intrinsic::memcpy) {
        FunctionType *FTy =
            FunctionType::get(Type::getVoidTy(Ctx), {I8PtrTy, I8PtrTy, SizeTy},
                              false);
        Lib = getOrCreateLibcall("memcpy", FTy);
      } else {
        FunctionType *FTy =
            FunctionType::get(Type::getVoidTy(Ctx), {I8PtrTy, I8PtrTy, SizeTy},
                              false);
        Lib = getOrCreateLibcall("memmove", FTy);
      }
      if (!Lib) {
        Err = "vm: mem intrinsic helper unavailable";
        return false;
      }

      VMCallInfo CI;
      CI.Name = Lib->getName();
      CI.Callee = Lib;
      CI.CalleeTy = Lib->getFunctionType();
      CI.CalleeAddrSpace = Lib->getAddressSpace();
      CI.CallConv = static_cast<unsigned>(Lib->getCallingConv());
      CI.CallAttrs = sanitizeCallAttrs(CB.getAttributes(), CI.CalleeTy);
      CI.IsVoid = true;

      if (ID == Intrinsic::memset) {
        Value *Dst = CB.getArgOperand(0);
        Value *Val = CB.getArgOperand(1);
        Value *Len = CB.getArgOperand(2);
        VMType DstTy = mapType(Dst->getType(), Err);
        if (!Err.empty())
          return false;
        VMType ValTy = mapType(Val->getType(), Err);
        if (!Err.empty())
          return false;
        VMType LenTy = mapType(Len->getType(), Err);
        if (!Err.empty())
          return false;
        CI.ArgRegs.push_back(getOrCreateReg(Dst, DstTy, Entry, Err));
        CI.ArgRegs.push_back(getOrCreateReg(Val, ValTy, Entry, Err));
        CI.ArgRegs.push_back(getOrCreateReg(Len, LenTy, Entry, Err));
        CI.ArgTypes.push_back(Dst->getType());
        CI.ArgTypes.push_back(Val->getType());
        CI.ArgTypes.push_back(Len->getType());
      } else {
        Value *Dst = CB.getArgOperand(0);
        Value *Src = CB.getArgOperand(1);
        Value *Len = CB.getArgOperand(2);
        VMType DstTy = mapType(Dst->getType(), Err);
        if (!Err.empty())
          return false;
        VMType SrcTy = mapType(Src->getType(), Err);
        if (!Err.empty())
          return false;
        VMType LenTy = mapType(Len->getType(), Err);
        if (!Err.empty())
          return false;
        CI.ArgRegs.push_back(getOrCreateReg(Dst, DstTy, Entry, Err));
        CI.ArgRegs.push_back(getOrCreateReg(Src, SrcTy, Entry, Err));
        CI.ArgRegs.push_back(getOrCreateReg(Len, LenTy, Entry, Err));
        CI.ArgTypes.push_back(Dst->getType());
        CI.ArgTypes.push_back(Src->getType());
        CI.ArgTypes.push_back(Len->getType());
      }
      uint32_t CallIndex = Out.VMF.Calls.size();
      Out.VMF.Calls.push_back(CI);

      VMInstr Inst;
      Inst.Op = VMOpcode::CallHost;
      Inst.CallIndex = CallIndex;
      B.Instrs.push_back(Inst);
      return true;
    }
    case Intrinsic::umax:
    case Intrinsic::umin:
    case Intrinsic::smax:
    case Intrinsic::smin: {
      if (CB.arg_size() < 2) {
        Err = "vm: min/max arg mismatch";
        return false;
      }
      VMType Ty = mapType(CB.getType(), Err);
      if (!Err.empty())
        return false;
      if (Ty.Kind != VMTypeKind::I8 && Ty.Kind != VMTypeKind::I16 &&
          Ty.Kind != VMTypeKind::I32 && Ty.Kind != VMTypeKind::I64) {
        Err = "vm: min/max type unsupported";
        return false;
      }
      uint32_t A = getOrCreateReg(CB.getArgOperand(0), Ty, Entry, Err);
      uint32_t Bv = getOrCreateReg(CB.getArgOperand(1), Ty, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t CmpReg = nextReg();
      VMInstr Cmp;
      Cmp.Op = VMOpcode::ICmp;
      Cmp.Ty = Ty;
      switch (ID) {
      case Intrinsic::umax:
        Cmp.Pred = VMCmpPred::UGT;
        break;
      case Intrinsic::umin:
        Cmp.Pred = VMCmpPred::ULT;
        break;
      case Intrinsic::smax:
        Cmp.Pred = VMCmpPred::SGT;
        break;
      case Intrinsic::smin:
        Cmp.Pred = VMCmpPred::SLT;
        break;
      default:
        Cmp.Pred = VMCmpPred::UGT;
        break;
      }
      Cmp.Dst = CmpReg;
      Cmp.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
      B.Instrs.push_back(Cmp);

      uint32_t Dst = getOrCreateReg(&CB, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      VMInstr Sel;
      Sel.Op = VMOpcode::Select;
      Sel.Ty = Ty;
      Sel.Dst = Dst;
      Sel.Ops = {VMValue::reg(CmpReg), VMValue::reg(A), VMValue::reg(Bv)};
      B.Instrs.push_back(Sel);
      return true;
    }
    case Intrinsic::abs: {
      if (CB.arg_size() < 1) {
        Err = "vm: abs arg mismatch";
        return false;
      }
      VMType Ty = mapType(CB.getType(), Err);
      if (!Err.empty())
        return false;
      if (Ty.Kind != VMTypeKind::I8 && Ty.Kind != VMTypeKind::I16 &&
          Ty.Kind != VMTypeKind::I32 && Ty.Kind != VMTypeKind::I64) {
        Err = "vm: abs type unsupported";
        return false;
      }
      uint32_t Val = getOrCreateReg(CB.getArgOperand(0), Ty, Entry, Err);
      if (!Err.empty())
        return false;
      Constant *ZeroC = ConstantInt::get(CB.getType(), 0);
      uint32_t ZeroReg = getOrCreateReg(ZeroC, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t CmpReg = nextReg();
      VMInstr Cmp;
      Cmp.Op = VMOpcode::ICmp;
      Cmp.Ty = Ty;
      Cmp.Pred = VMCmpPred::SLT;
      Cmp.Dst = CmpReg;
      Cmp.Ops = {VMValue::reg(Val), VMValue::reg(ZeroReg)};
      B.Instrs.push_back(Cmp);

      uint32_t NegReg = nextReg();
      VMInstr Neg;
      Neg.Op = VMOpcode::BinOp;
      Neg.Ty = Ty;
      Neg.Bin = VMBinOp::Sub;
      Neg.Dst = NegReg;
      Neg.Ops = {VMValue::reg(ZeroReg), VMValue::reg(Val)};
      B.Instrs.push_back(Neg);

      uint32_t Dst = getOrCreateReg(&CB, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      VMInstr Sel;
      Sel.Op = VMOpcode::Select;
      Sel.Ty = Ty;
      Sel.Dst = Dst;
      Sel.Ops = {VMValue::reg(CmpReg), VMValue::reg(NegReg),
                 VMValue::reg(Val)};
      B.Instrs.push_back(Sel);
      return true;
    }
    case Intrinsic::fabs: {
      if (CB.arg_size() < 1) {
        Err = "vm: fabs arg mismatch";
        return false;
      }
      VMType Ty = mapType(CB.getType(), Err);
      if (!Err.empty())
        return false;
      VMType IntTy =
          (Ty.Kind == VMTypeKind::F32) ? VMType(VMTypeKind::I32)
                                       : VMType(VMTypeKind::I64);
      if (Ty.Kind != VMTypeKind::F32 && Ty.Kind != VMTypeKind::F64) {
        Err = "vm: fabs type unsupported";
        return false;
      }
      uint32_t Src = getOrCreateReg(CB.getArgOperand(0), Ty, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t IntReg = nextReg();
      VMInstr CastToInt;
      CastToInt.Op = VMOpcode::Cast;
      CastToInt.SrcTy = Ty;
      CastToInt.Ty = IntTy;
      CastToInt.Cast = VMCastKind::Bitcast;
      CastToInt.Dst = IntReg;
      CastToInt.Ops = {VMValue::reg(Src)};
      B.Instrs.push_back(CastToInt);

      uint64_t MaskVal = (Ty.Kind == VMTypeKind::F32)
                             ? 0x7fffffffULL
                             : 0x7fffffffffffffffULL;
      Constant *MaskC = ConstantInt::get(
          (Ty.Kind == VMTypeKind::F32) ? Type::getInt32Ty(Ctx)
                                       : Type::getInt64Ty(Ctx),
          MaskVal);
      uint32_t MaskReg = getOrCreateReg(MaskC, IntTy, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t AndReg = nextReg();
      VMInstr And;
      And.Op = VMOpcode::BinOp;
      And.Ty = IntTy;
      And.Bin = VMBinOp::And;
      And.Dst = AndReg;
      And.Ops = {VMValue::reg(IntReg), VMValue::reg(MaskReg)};
      B.Instrs.push_back(And);

      uint32_t Dst = getOrCreateReg(&CB, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      VMInstr CastBack;
      CastBack.Op = VMOpcode::Cast;
      CastBack.SrcTy = IntTy;
      CastBack.Ty = Ty;
      CastBack.Cast = VMCastKind::Bitcast;
      CastBack.Dst = Dst;
      CastBack.Ops = {VMValue::reg(AndReg)};
      B.Instrs.push_back(CastBack);
      return true;
    }
    case Intrinsic::fshl: {
      if (CB.arg_size() < 3) {
        Err = "vm: fshl arg mismatch";
        return false;
      }
      VMType Ty = mapType(CB.getType(), Err);
      if (!Err.empty())
        return false;
      if (Ty.Kind != VMTypeKind::I8 && Ty.Kind != VMTypeKind::I16 &&
          Ty.Kind != VMTypeKind::I32 && Ty.Kind != VMTypeKind::I64) {
        Err = "vm: fshl type unsupported";
        return false;
      }
      unsigned Bits = getTypeBitWidth(Ty.Kind, DL.getPointerSizeInBits());
      if (Bits == 0 || Bits > 64) {
        Err = "vm: fshl width unsupported";
        return false;
      }
      uint32_t A = getOrCreateReg(CB.getArgOperand(0), Ty, Entry, Err);
      uint32_t Bv = getOrCreateReg(CB.getArgOperand(1), Ty, Entry, Err);
      uint32_t Sh = getOrCreateReg(CB.getArgOperand(2), Ty, Entry, Err);
      if (!Err.empty())
        return false;
      Constant *MaskC = ConstantInt::get(CB.getType(), Bits - 1);
      Constant *WidthC = ConstantInt::get(CB.getType(), Bits);
      uint32_t MaskReg = getOrCreateReg(MaskC, Ty, Entry, Err);
      uint32_t WidthReg = getOrCreateReg(WidthC, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t ShMasked = nextReg();
      VMInstr And1;
      And1.Op = VMOpcode::BinOp;
      And1.Ty = Ty;
      And1.Bin = VMBinOp::And;
      And1.Dst = ShMasked;
      And1.Ops = {VMValue::reg(Sh), VMValue::reg(MaskReg)};
      B.Instrs.push_back(And1);

      uint32_t SubReg = nextReg();
      VMInstr Sub;
      Sub.Op = VMOpcode::BinOp;
      Sub.Ty = Ty;
      Sub.Bin = VMBinOp::Sub;
      Sub.Dst = SubReg;
      Sub.Ops = {VMValue::reg(WidthReg), VMValue::reg(ShMasked)};
      B.Instrs.push_back(Sub);

      uint32_t RSh = nextReg();
      VMInstr And2;
      And2.Op = VMOpcode::BinOp;
      And2.Ty = Ty;
      And2.Bin = VMBinOp::And;
      And2.Dst = RSh;
      And2.Ops = {VMValue::reg(SubReg), VMValue::reg(MaskReg)};
      B.Instrs.push_back(And2);

      uint32_t ShlReg = nextReg();
      VMInstr Shl;
      Shl.Op = VMOpcode::BinOp;
      Shl.Ty = Ty;
      Shl.Bin = VMBinOp::Shl;
      Shl.Dst = ShlReg;
      Shl.Ops = {VMValue::reg(A), VMValue::reg(ShMasked)};
      B.Instrs.push_back(Shl);

      uint32_t ShrReg = nextReg();
      VMInstr Shr;
      Shr.Op = VMOpcode::BinOp;
      Shr.Ty = Ty;
      Shr.Bin = VMBinOp::LShr;
      Shr.Dst = ShrReg;
      Shr.Ops = {VMValue::reg(Bv), VMValue::reg(RSh)};
      B.Instrs.push_back(Shr);

      uint32_t Dst = getOrCreateReg(&CB, Ty, Entry, Err);
      if (!Err.empty())
        return false;
      VMInstr Or;
      Or.Op = VMOpcode::BinOp;
      Or.Ty = Ty;
      Or.Bin = VMBinOp::Or;
      Or.Dst = Dst;
      Or.Ops = {VMValue::reg(ShlReg), VMValue::reg(ShrReg)};
      B.Instrs.push_back(Or);
      return true;
    }
    case Intrinsic::ceil:
      return lowerIntrinsicToHostCall(CB, ID, B, Entry, Out, Err);
    case Intrinsic::ctlz:
    case Intrinsic::cttz: {
      if (CB.arg_size() != 2) {
        Err = "vm: ctlz/cttz arg mismatch";
        return false;
      }
      auto *Imm = dyn_cast<ConstantInt>(CB.getArgOperand(1));
      if (!Imm) {
        Err = "vm: ctlz/cttz immarg not constant";
        return false;
      }
      Value *Val = CB.getArgOperand(0);
      Function *Wrapper =
          getOrCreateCtlzCttzWrapper(ID, CB.getType(), Val->getType(),
                                     Imm->getZExtValue());
      if (!Wrapper) {
        Err = "vm: ctlz/cttz wrapper unavailable";
        return false;
      }

      VMCallInfo CI;
      CI.Name = Wrapper->getName();
      CI.Callee = Wrapper;
      CI.CalleeTy = Wrapper->getFunctionType();
      CI.CalleeAddrSpace = Wrapper->getAddressSpace();
      CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
      CI.CallAttrs = sanitizeCallAttrs(CB.getAttributes(), CI.CalleeTy);
      CI.IsVoid = CB.getType()->isVoidTy();
      if (!CI.IsVoid) {
        VMType RetTy = mapType(CB.getType(), Err);
        if (!Err.empty())
          return false;
        CI.RetTy = RetTy;
        CI.RetReg = getOrCreateReg(&CB, RetTy, Entry, Err);
        if (!Err.empty())
          return false;
      }
      VMType ValTy = mapType(Val->getType(), Err);
      if (!Err.empty())
        return false;
      CI.ArgRegs.push_back(getOrCreateReg(Val, ValTy, Entry, Err));
      if (!Err.empty())
        return false;
      CI.ArgTypes.push_back(Val->getType());

      uint32_t CallIndex = Out.VMF.Calls.size();
      Out.VMF.Calls.push_back(CI);

      VMInstr Inst;
      Inst.Op = VMOpcode::CallHost;
      Inst.CallIndex = CallIndex;
      B.Instrs.push_back(Inst);
      return true;
    }
    case Intrinsic::threadlocal_address: {
      if (CB.arg_size() != 1) {
        Err = "vm: threadlocal.address arg mismatch";
        return false;
      }
      Value *Op0 = CB.getArgOperand(0);
      GlobalValue *GV =
          dyn_cast<GlobalValue>(Op0->stripPointerCasts());
      if (!GV) {
        Err = "vm: threadlocal.address expects global";
        return false;
      }
      Function *Wrapper = getOrCreateThreadLocalWrapper(GV, CB.getType());
      if (!Wrapper) {
        Err = "vm: threadlocal.address wrapper unavailable";
        return false;
      }

      VMCallInfo CI;
      CI.Name = Wrapper->getName();
      CI.Callee = Wrapper;
      CI.CalleeTy = Wrapper->getFunctionType();
      CI.CalleeAddrSpace = Wrapper->getAddressSpace();
      CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
      CI.CallAttrs = sanitizeCallAttrs(CB.getAttributes(), CI.CalleeTy);
      CI.IsVoid = CB.getType()->isVoidTy();
      if (!CI.IsVoid) {
        VMType RetTy = mapType(CB.getType(), Err);
        if (!Err.empty())
          return false;
        CI.RetTy = RetTy;
        CI.RetReg = getOrCreateReg(&CB, RetTy, Entry, Err);
        if (!Err.empty())
          return false;
      }

      uint32_t CallIndex = Out.VMF.Calls.size();
      Out.VMF.Calls.push_back(CI);

      VMInstr Inst;
      Inst.Op = VMOpcode::CallHost;
      Inst.CallIndex = CallIndex;
      B.Instrs.push_back(Inst);
      return true;
    }
    default:
      break;
    }
    return false;
  }

  uint32_t getOrCreateConstReg(const Constant *C, VMType Kind, VMBlock &Entry,
                               std::string &Err) {
    auto It = ConstRegs.find(C);
    if (It != ConstRegs.end())
      return It->second;

    uint32_t R = nextReg();
    ConstRegs[C] = R;

    VMInstr Mov;
    Mov.Op = VMOpcode::Mov;
    Mov.Ty = Kind;
    Mov.Dst = R;

    if (auto *CI = dyn_cast<ConstantInt>(C)) {
      if (CI->getBitWidth() > 64) {
        Err = "vm: constant int too wide";
        return R;
      }
      Mov.Ops = {VMValue::imm(CI->getZExtValue())};
    } else if (auto *CF = dyn_cast<ConstantFP>(C)) {
      APInt Bits = CF->getValueAPF().bitcastToAPInt();
      Mov.Ops = {VMValue::imm(Bits.getZExtValue())};
    } else if (isa<ConstantPointerNull>(C)) {
      Mov.Ops = {VMValue::imm(0)};
    } else if (C->getType()->isPointerTy()) {
      Type *IntPtrTy = DL.getIntPtrType(F.getContext());
      // COFF dllimport data symbols are referenced via __imp_ slots (the import
      // address table). If we materialize the dllimport symbol itself as an
      // absolute pointer constant, lld-link can't resolve it (e.g. std::cerr).
      // Instead, load the pointer from the IAT slot in the VM prolog.
      if (Module *M = F.getParent()) {
        if (auto *GV = dyn_cast<GlobalVariable>(C->stripPointerCasts())) {
          if (GV->hasDLLImportStorageClass()) {
            std::string ImpName = ("__imp_" + GV->getName()).str();
            GlobalVariable *ImpGV = M->getGlobalVariable(ImpName);
            if (!ImpGV) {
              Type *SlotTy =
                  PointerType::get(GV->getValueType(), GV->getAddressSpace());
              ImpGV =
                  new GlobalVariable(*M, SlotTy, false,
                                     GlobalValue::ExternalLinkage, nullptr,
                                     ImpName);
            }

            uint32_t AddrReg = nextReg();
            VMInstr MovAddr = Mov;
            MovAddr.Dst = AddrReg;
            Constant *SlotPtrInt = ConstantExpr::getPtrToInt(ImpGV, IntPtrTy);
            MovAddr.Ops = {VMValue::constant(SlotPtrInt)};

            VMInstr Ld;
            Ld.Op = VMOpcode::Load;
            Ld.Ty = Kind;
            Ld.Dst = R;
            Ld.Ops = {VMValue::reg(AddrReg)};

            // Ensure prolog order: address materialization before load.
            Entry.Instrs.insert(Entry.Instrs.begin(), Ld);
            Entry.Instrs.insert(Entry.Instrs.begin(), MovAddr);
            return R;
          }
        }
      }

      Constant *PtrInt =
          ConstantExpr::getPtrToInt(const_cast<Constant *>(C), IntPtrTy);
      Mov.Ops = {VMValue::constant(PtrInt)};
    } else if (auto *CE = dyn_cast<ConstantExpr>(C)) {
      if (CE->getType()->isPointerTy()) {
        Type *IntPtrTy = DL.getIntPtrType(F.getContext());
        Constant *PtrInt =
            ConstantExpr::getPtrToInt(const_cast<Constant *>(C), IntPtrTy);
        Mov.Ops = {VMValue::constant(PtrInt)};
      } else if (CE->getType()->isIntegerTy() &&
                 CE->getType()->getIntegerBitWidth() <= 64) {
        if (auto *Folded = dyn_cast<ConstantInt>(
                ConstantFoldConstant(CE, DL, nullptr))) {
          Mov.Ops = {VMValue::imm(Folded->getZExtValue())};
        } else {
          Err = "vm: constant expr not foldable";
        }
      } else {
        Err = "vm: constant expr unsupported";
      }
    } else if (isa<UndefValue>(C)) {
      Mov.Ops = {VMValue::imm(0)};
    } else {
      Err = "vm: unsupported constant";
    }

    Entry.Instrs.insert(Entry.Instrs.begin(), Mov);
    return R;
  }

  uint32_t getOrCreateReg(const Value *V, VMType Kind, VMBlock &Entry,
                          std::string &Err) {
    auto It = RegMap.find(V);
    if (It != RegMap.end())
      return It->second;

    if (auto *C = dyn_cast<Constant>(V)) {
      uint32_t R = getOrCreateConstReg(C, Kind, Entry, Err);
      RegMap[V] = R;
      return R;
    }

    uint32_t R = nextReg();
    RegMap[V] = R;
    return R;
  }

  void emitHostCall(VMCallInfo &CI, VMBlock &B, VMLoweringResult &Out) {
    uint32_t CallIndex = Out.VMF.Calls.size();
    Out.VMF.Calls.push_back(CI);
    VMInstr Inst;
    if (CI.IsIndirect) {
      Inst.Op = VMOpcode::CallHostIndirect;
      Inst.Ops = {VMValue::reg(CI.CalleeReg)};
    } else {
      Inst.Op = VMOpcode::CallHost;
    }
    Inst.CallIndex = CallIndex;
    B.Instrs.push_back(Inst);
  }

  bool lowerInstruction(Instruction &I, VMBlock &B, VMBlock &Entry,
                        VMLoweringResult &Out, std::string &Err) {
      if (auto *AI = dyn_cast<AllocaInst>(&I)) {
        if (!AI->isStaticAlloca()) {
          Err = "vm: dynamic alloca unsupported";
          return false;
        }
      VMType Ty = mapType(AI->getType(), Err);
      if (!Err.empty())
        return false;
      uint32_t R = getOrCreateReg(AI, Ty, Entry, Err);
      VMAllocaInfo Info;
      Info.AllocaTy = AI->getAllocatedType();
      Info.Alignment = AI->getAlign();
      if (auto *CI = dyn_cast<ConstantInt>(AI->getArraySize()))
        Info.ArraySize = CI->getZExtValue();
      else
        Info.ArraySize = 1;
      Info.Reg = R;
        Out.Allocas.push_back(Info);
        return true;
      }

      if (auto *EV = dyn_cast<ExtractValueInst>(&I)) {
        if (EV->getNumIndices() == 1) {
          unsigned Idx = *EV->idx_begin();
          if (auto *CX =
                  dyn_cast<AtomicCmpXchgInst>(EV->getAggregateOperand())) {
            auto It = CmpXchgRegs.find(CX);
            if (It == CmpXchgRegs.end()) {
              Err = "vm: cmpxchg extract before lowering";
              return false;
            }
            if (Idx > 1) {
              Err = "vm: cmpxchg extract index unsupported";
              return false;
            }
            // cmpxchg returns {old, success}; map each field to a VM reg.
            uint32_t R = (Idx == 0) ? It->second.first : It->second.second;
            RegMap[EV] = R;
            return true;
          }
        }
        Err = "vm: extractvalue unsupported";
        return false;
      }

      if (auto *PN = dyn_cast<PHINode>(&I)) {
        VMType Ty = mapType(PN->getType(), Err);
        if (!Err.empty())
        return false;
      uint32_t R = getOrCreateReg(PN, Ty, Entry, Err);
      Phis.push_back({PN, R});
      return true;
    }

    if (auto *FI = dyn_cast<FenceInst>(&I)) {
      VMInstr Inst;
      Inst.Op = VMOpcode::MemFence;
      Inst.Fence = mapFence(FI->getOrdering());
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *AI = dyn_cast<AtomicRMWInst>(&I)) {
      Function *Wrapper = getOrCreateAtomicRMWWrapper(*AI);
      if (!Wrapper) {
        Err = "vm: atomicrmw helper unavailable";
        return false;
      }
      VMType RetTy = mapType(AI->getType(), Err);
      if (!Err.empty())
        return false;
      VMType PtrTy = mapType(AI->getPointerOperand()->getType(), Err);
      if (!Err.empty())
        return false;
      VMType ValTy = mapType(AI->getValOperand()->getType(), Err);
      if (!Err.empty())
        return false;
      VMCallInfo CI;
      CI.Name = Wrapper->getName();
      CI.Callee = Wrapper;
      CI.CalleeTy = Wrapper->getFunctionType();
      CI.CalleeAddrSpace = Wrapper->getAddressSpace();
      CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
      CI.IsVoid = false;
      CI.RetTy = RetTy;
      CI.RetReg = getOrCreateReg(AI, RetTy, Entry, Err);
      CI.ArgRegs.push_back(
          getOrCreateReg(AI->getPointerOperand(), PtrTy, Entry, Err));
      CI.ArgTypes.push_back(AI->getPointerOperand()->getType());
      CI.ArgRegs.push_back(
          getOrCreateReg(AI->getValOperand(), ValTy, Entry, Err));
      CI.ArgTypes.push_back(AI->getValOperand()->getType());
      emitHostCall(CI, B, Out);
      return true;
    }

      if (auto *CX = dyn_cast<AtomicCmpXchgInst>(&I)) {
        Function *Wrapper = getOrCreateAtomicCmpXchgWrapper(*CX);
        if (!Wrapper) {
          Err = "vm: cmpxchg helper unavailable";
          return false;
        }
        VMType ValTy = mapType(CX->getCompareOperand()->getType(), Err);
        if (!Err.empty())
          return false;
        VMType PtrTy = mapType(CX->getPointerOperand()->getType(), Err);
        if (!Err.empty())
          return false;

        uint32_t OldReg = getOrCreateReg(CX, ValTy, Entry, Err);
        if (!Err.empty())
          return false;
        uint32_t ExpReg =
            getOrCreateReg(CX->getCompareOperand(), ValTy, Entry, Err);
        if (!Err.empty())
          return false;

        VMCallInfo CI;
        CI.Name = Wrapper->getName();
        CI.Callee = Wrapper;
        CI.CalleeTy = Wrapper->getFunctionType();
        CI.CalleeAddrSpace = Wrapper->getAddressSpace();
        CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
        CI.IsVoid = false;
        CI.RetTy = ValTy;
        CI.RetReg = OldReg;
        CI.ArgRegs.push_back(
            getOrCreateReg(CX->getPointerOperand(), PtrTy, Entry, Err));
        if (!Err.empty())
          return false;
        CI.ArgTypes.push_back(CX->getPointerOperand()->getType());
        CI.ArgRegs.push_back(ExpReg);
        CI.ArgTypes.push_back(CX->getCompareOperand()->getType());
        CI.ArgRegs.push_back(
            getOrCreateReg(CX->getNewValOperand(), ValTy, Entry, Err));
        if (!Err.empty())
          return false;
        CI.ArgTypes.push_back(CX->getNewValOperand()->getType());

        emitHostCall(CI, B, Out);

        uint32_t SuccessReg = nextReg();
        VMInstr Cmp;
        Cmp.Op = VMOpcode::ICmp;
        Cmp.Ty = ValTy;
        Cmp.Pred = VMCmpPred::EQ;
        Cmp.Dst = SuccessReg;
        Cmp.Ops = {VMValue::reg(OldReg), VMValue::reg(ExpReg)};
        B.Instrs.push_back(Cmp);
        // Keep both pieces so ExtractValue can materialize {old, success}.
        CmpXchgRegs[CX] = {OldReg, SuccessReg};
        return true;
      }

    if (auto *BO = dyn_cast<BinaryOperator>(&I)) {
      VMType Ty = mapType(BO->getType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::BinOp;
      Inst.Ty = Ty;
      Inst.Dst = getOrCreateReg(BO, Ty, Entry, Err);
      unsigned Op = BO->getOpcode();
      switch (Op) {
      case Instruction::Add:
        Inst.Bin = VMBinOp::Add;
        break;
      case Instruction::Sub:
        Inst.Bin = VMBinOp::Sub;
        break;
      case Instruction::Mul:
        Inst.Bin = VMBinOp::Mul;
        break;
      case Instruction::UDiv:
        Inst.Bin = VMBinOp::UDiv;
        break;
      case Instruction::SDiv:
        Inst.Bin = VMBinOp::SDiv;
        break;
      case Instruction::URem:
        Inst.Bin = VMBinOp::URem;
        break;
      case Instruction::SRem:
        Inst.Bin = VMBinOp::SRem;
        break;
      case Instruction::FAdd:
        Inst.Bin = VMBinOp::FAdd;
        break;
      case Instruction::FSub:
        Inst.Bin = VMBinOp::FSub;
        break;
      case Instruction::FMul:
        Inst.Bin = VMBinOp::FMul;
        break;
      case Instruction::FDiv:
        Inst.Bin = VMBinOp::FDiv;
        break;
      case Instruction::FRem:
        Inst.Bin = VMBinOp::FRem;
        break;
      case Instruction::And:
        Inst.Bin = VMBinOp::And;
        break;
      case Instruction::Or:
        Inst.Bin = VMBinOp::Or;
        break;
      case Instruction::Xor:
        Inst.Bin = VMBinOp::Xor;
        break;
      case Instruction::Shl:
        Inst.Bin = VMBinOp::Shl;
        break;
      case Instruction::LShr:
        Inst.Bin = VMBinOp::LShr;
        break;
      case Instruction::AShr:
        Inst.Bin = VMBinOp::AShr;
        break;
      default:
        Err = "vm: unsupported binop";
        return false;
      }

      VMType OpTy = mapType(BO->getOperand(0)->getType(), Err);
      if (!Err.empty())
        return false;
      uint32_t A = getOrCreateReg(BO->getOperand(0), OpTy, Entry, Err);
      uint32_t Bv = getOrCreateReg(BO->getOperand(1), OpTy, Entry, Err);
      Inst.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *UO = dyn_cast<UnaryOperator>(&I)) {
      if (UO->getOpcode() == Instruction::FNeg) {
        VMType Ty = mapType(UO->getType(), Err);
        if (!Err.empty())
          return false;
        VMInstr Inst;
        Inst.Op = VMOpcode::FNeg;
        Inst.Ty = Ty;
        Inst.Dst = getOrCreateReg(UO, Ty, Entry, Err);
        uint32_t Src = getOrCreateReg(UO->getOperand(0), Ty, Entry, Err);
        Inst.Ops = {VMValue::reg(Src)};
        B.Instrs.push_back(Inst);
        return true;
      }
    }

    if (auto *IC = dyn_cast<ICmpInst>(&I)) {
      VMType Ty = mapType(IC->getOperand(0)->getType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::ICmp;
      Inst.Ty = Ty;
      Inst.Dst = getOrCreateReg(IC, VMType(VMTypeKind::I1), Entry, Err);
      switch (IC->getPredicate()) {
      case CmpInst::ICMP_EQ:
        Inst.Pred = VMCmpPred::EQ;
        break;
      case CmpInst::ICMP_NE:
        Inst.Pred = VMCmpPred::NE;
        break;
      case CmpInst::ICMP_ULT:
        Inst.Pred = VMCmpPred::ULT;
        break;
      case CmpInst::ICMP_ULE:
        Inst.Pred = VMCmpPred::ULE;
        break;
      case CmpInst::ICMP_UGT:
        Inst.Pred = VMCmpPred::UGT;
        break;
      case CmpInst::ICMP_UGE:
        Inst.Pred = VMCmpPred::UGE;
        break;
      case CmpInst::ICMP_SLT:
        Inst.Pred = VMCmpPred::SLT;
        break;
      case CmpInst::ICMP_SLE:
        Inst.Pred = VMCmpPred::SLE;
        break;
      case CmpInst::ICMP_SGT:
        Inst.Pred = VMCmpPred::SGT;
        break;
      case CmpInst::ICMP_SGE:
        Inst.Pred = VMCmpPred::SGE;
        break;
      default:
        Err = "vm: unsupported icmp pred";
        return false;
      }
      uint32_t A = getOrCreateReg(IC->getOperand(0), Ty, Entry, Err);
      uint32_t Bv = getOrCreateReg(IC->getOperand(1), Ty, Entry, Err);
      Inst.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *FC = dyn_cast<FCmpInst>(&I)) {
      VMType Ty = mapType(FC->getOperand(0)->getType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::FCmp;
      Inst.Ty = Ty;
      Inst.Dst = getOrCreateReg(FC, VMType(VMTypeKind::I1), Entry, Err);
      switch (FC->getPredicate()) {
      case CmpInst::FCMP_OEQ:
        Inst.Pred = VMCmpPred::FEQ;
        break;
      case CmpInst::FCMP_ONE:
        Inst.Pred = VMCmpPred::FNE;
        break;
      case CmpInst::FCMP_OLT:
        Inst.Pred = VMCmpPred::FLT;
        break;
      case CmpInst::FCMP_OLE:
        Inst.Pred = VMCmpPred::FLE;
        break;
      case CmpInst::FCMP_OGT:
        Inst.Pred = VMCmpPred::FGT;
        break;
      case CmpInst::FCMP_OGE:
        Inst.Pred = VMCmpPred::FGE;
        break;
      default:
        Err = "vm: unsupported fcmp pred";
        return false;
      }
      uint32_t A = getOrCreateReg(FC->getOperand(0), Ty, Entry, Err);
      uint32_t Bv = getOrCreateReg(FC->getOperand(1), Ty, Entry, Err);
      Inst.Ops = {VMValue::reg(A), VMValue::reg(Bv)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *CI = dyn_cast<CastInst>(&I)) {
      VMType SrcTy = mapType(CI->getSrcTy(), Err);
      if (!Err.empty())
        return false;
      VMType DstTy = mapType(CI->getDestTy(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::Cast;
      Inst.Ty = DstTy;
      Inst.SrcTy = SrcTy;
      Inst.Dst = getOrCreateReg(CI, DstTy, Entry, Err);
      switch (CI->getOpcode()) {
      case Instruction::ZExt:
        Inst.Cast = VMCastKind::ZExt;
        break;
      case Instruction::SExt:
        Inst.Cast = VMCastKind::SExt;
        break;
      case Instruction::Trunc:
        Inst.Cast = VMCastKind::Trunc;
        break;
      case Instruction::BitCast:
        Inst.Cast = VMCastKind::Bitcast;
        break;
      case Instruction::PtrToInt:
        Inst.Cast = VMCastKind::PtrToInt;
        break;
      case Instruction::IntToPtr:
        Inst.Cast = VMCastKind::IntToPtr;
        break;
      case Instruction::FPToUI:
        Inst.Cast = VMCastKind::FPToUI;
        break;
      case Instruction::FPToSI:
        Inst.Cast = VMCastKind::FPToSI;
        break;
      case Instruction::UIToFP:
        Inst.Cast = VMCastKind::UIToFP;
        break;
      case Instruction::SIToFP:
        Inst.Cast = VMCastKind::SIToFP;
        break;
      case Instruction::FPTrunc:
        Inst.Cast = VMCastKind::FPTrunc;
        break;
      case Instruction::FPExt:
        Inst.Cast = VMCastKind::FPExt;
        break;
      default:
        Err = "vm: unsupported cast";
        return false;
      }
      uint32_t Src = getOrCreateReg(CI->getOperand(0), SrcTy, Entry, Err);
      Inst.Ops = {VMValue::reg(Src)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *LI = dyn_cast<LoadInst>(&I)) {
      if (LI->isAtomic() || LI->isVolatile()) {
        Function *Wrapper = getOrCreateAtomicLoadWrapper(*LI);
        if (!Wrapper) {
          Err = "vm: atomic load helper unavailable";
          return false;
        }
        VMType RetTy = mapType(LI->getType(), Err);
        if (!Err.empty())
          return false;
        VMType PtrTy = mapType(LI->getPointerOperandType(), Err);
        if (!Err.empty())
          return false;
      VMCallInfo CI;
      CI.Name = Wrapper->getName();
      CI.Callee = Wrapper;
      CI.CalleeTy = Wrapper->getFunctionType();
      CI.CalleeAddrSpace = Wrapper->getAddressSpace();
      CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
        CI.IsVoid = false;
        CI.RetTy = RetTy;
        CI.RetReg = getOrCreateReg(LI, RetTy, Entry, Err);
        CI.ArgRegs.push_back(
            getOrCreateReg(LI->getPointerOperand(), PtrTy, Entry, Err));
        CI.ArgTypes.push_back(LI->getPointerOperandType());
        emitHostCall(CI, B, Out);
        return true;
      }
      VMType Ty = mapType(LI->getType(), Err);
      if (!Err.empty())
        return false;
      VMType PtrTy = mapType(LI->getPointerOperandType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::Load;
      Inst.Ty = Ty;
      Inst.Dst = getOrCreateReg(LI, Ty, Entry, Err);
      uint32_t Addr =
          getOrCreateReg(LI->getPointerOperand(), PtrTy, Entry, Err);
      Inst.Ops = {VMValue::reg(Addr)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *SI = dyn_cast<StoreInst>(&I)) {
      if (SI->isAtomic() || SI->isVolatile()) {
        Function *Wrapper = getOrCreateAtomicStoreWrapper(*SI);
        if (!Wrapper) {
          Err = "vm: atomic store helper unavailable";
          return false;
        }
        VMType ValTy = mapType(SI->getValueOperand()->getType(), Err);
        if (!Err.empty())
          return false;
        VMType PtrTy = mapType(SI->getPointerOperandType(), Err);
        if (!Err.empty())
          return false;
        VMCallInfo CI;
        CI.Name = Wrapper->getName();
        CI.Callee = Wrapper;
        CI.CalleeTy = Wrapper->getFunctionType();
        CI.CalleeAddrSpace = Wrapper->getAddressSpace();
        CI.CallConv = static_cast<unsigned>(Wrapper->getCallingConv());
        CI.IsVoid = true;
        CI.ArgRegs.push_back(
            getOrCreateReg(SI->getPointerOperand(), PtrTy, Entry, Err));
        CI.ArgTypes.push_back(SI->getPointerOperandType());
        CI.ArgRegs.push_back(
            getOrCreateReg(SI->getValueOperand(), ValTy, Entry, Err));
        CI.ArgTypes.push_back(SI->getValueOperand()->getType());
        emitHostCall(CI, B, Out);
        return true;
      }
      VMType Ty = mapType(SI->getValueOperand()->getType(), Err);
      if (!Err.empty())
        return false;
      VMType PtrTy = mapType(SI->getPointerOperandType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::Store;
      Inst.Ty = Ty;
      uint32_t Val =
          getOrCreateReg(SI->getValueOperand(), Ty, Entry, Err);
      uint32_t Addr =
          getOrCreateReg(SI->getPointerOperand(), PtrTy, Entry, Err);
      Inst.Ops = {VMValue::reg(Val), VMValue::reg(Addr)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
      VMType PtrTy = mapType(GEP->getType(), Err);
      if (!Err.empty())
        return false;
      uint32_t Dst = getOrCreateReg(GEP, PtrTy, Entry, Err);
      if (!Err.empty())
        return false;
      uint32_t Base =
          getOrCreateReg(GEP->getPointerOperand(), PtrTy, Entry, Err);
      if (!Err.empty())
        return false;

      if (Dst != Base) {
        VMInstr Mov;
        Mov.Op = VMOpcode::Mov;
        Mov.Ty = PtrTy;
        Mov.Dst = Dst;
        Mov.Ops = {VMValue::reg(Base)};
        B.Instrs.push_back(Mov);
      }

      unsigned PtrBits = DL.getPointerSizeInBits();
      Type *IntPtrTy = DL.getIntPtrType(F.getContext());
      APInt ConstOff(PtrBits, 0, true);

      auto emitConstAdd = [&](const APInt &Off) {
        if (Off.isZero())
          return;
        Constant *C = ConstantInt::get(IntPtrTy, Off);
        uint32_t CReg = getOrCreateReg(C, PtrTy, Entry, Err);
        if (!Err.empty())
          return;
        VMInstr Add;
        Add.Op = VMOpcode::BinOp;
        Add.Ty = PtrTy;
        Add.Bin = VMBinOp::Add;
        Add.Dst = Dst;
        Add.Ops = {VMValue::reg(Dst), VMValue::reg(CReg)};
        B.Instrs.push_back(Add);
      };

      auto GTI = gep_type_begin(GEP);
      auto GTE = gep_type_end(GEP);
      for (auto IdxIt = GEP->idx_begin(); IdxIt != GEP->idx_end();
           ++IdxIt, ++GTI) {
        Value *IdxV = *IdxIt;
        if (GTI == GTE) {
          Err = "vm: gep type iterator mismatch";
          return false;
        }
        if (GTI.isStruct()) {
          StructType *ST = GTI.getStructType();
          auto *CI = dyn_cast<ConstantInt>(IdxV);
          if (!CI) {
            Err = "vm: gep struct index must be constant";
            return false;
          }
          unsigned Field = static_cast<unsigned>(CI->getZExtValue());
          if (Field >= ST->getNumElements()) {
            Err = "vm: gep struct index out of range";
            return false;
          }
          const StructLayout *SL = DL.getStructLayout(ST);
          APInt FieldOff(PtrBits, SL->getElementOffset(Field));
          ConstOff = ConstOff + FieldOff;
          continue;
        }

        TypeSize ElemSizeTS = GTI.getSequentialElementStride(DL);
        if (ElemSizeTS.isScalable()) {
          Err = "vm: gep scalable vector unsupported";
          return false;
        }
        uint64_t ElemSize = ElemSizeTS.getFixedValue();
        if (auto *CI = dyn_cast<ConstantInt>(IdxV)) {
          APInt Idx = CI->getValue().sextOrTrunc(PtrBits);
          APInt ElemSz(PtrBits, ElemSize);
          APInt Scaled = Idx * ElemSz;
          ConstOff = ConstOff + Scaled;
        } else {
          if (!ConstOff.isZero()) {
            emitConstAdd(ConstOff);
            if (!Err.empty())
              return false;
            ConstOff = APInt(PtrBits, 0, true);
          }

          VMType IdxTy = mapType(IdxV->getType(), Err);
          if (!Err.empty())
            return false;
          uint32_t IdxReg = getOrCreateReg(IdxV, IdxTy, Entry, Err);
          if (!Err.empty())
            return false;

          uint32_t IdxExt = IdxReg;
          unsigned IdxBits = getTypeBitWidth(IdxTy.Kind, PtrBits);
          if (IdxBits != PtrBits) {
            uint32_t CastReg = nextReg();
            VMInstr Cast;
            Cast.Op = VMOpcode::Cast;
            Cast.SrcTy = IdxTy;
            Cast.Ty = PtrTy;
            Cast.Dst = CastReg;
            Cast.Cast = (IdxBits < PtrBits) ? VMCastKind::SExt
                                            : VMCastKind::Trunc;
            Cast.Ops = {VMValue::reg(IdxReg)};
            B.Instrs.push_back(Cast);
            IdxExt = CastReg;
          }

          uint32_t ScaledReg = IdxExt;
          if (ElemSize != 1) {
            Constant *SizeC = ConstantInt::get(IntPtrTy, ElemSize);
            uint32_t SizeReg = getOrCreateReg(SizeC, PtrTy, Entry, Err);
            if (!Err.empty())
              return false;
            uint32_t MulReg = nextReg();
            VMInstr Mul;
            Mul.Op = VMOpcode::BinOp;
            Mul.Ty = PtrTy;
            Mul.Bin = VMBinOp::Mul;
            Mul.Dst = MulReg;
            Mul.Ops = {VMValue::reg(IdxExt), VMValue::reg(SizeReg)};
            B.Instrs.push_back(Mul);
            ScaledReg = MulReg;
          }

          VMInstr Add;
          Add.Op = VMOpcode::BinOp;
          Add.Ty = PtrTy;
          Add.Bin = VMBinOp::Add;
          Add.Dst = Dst;
          Add.Ops = {VMValue::reg(Dst), VMValue::reg(ScaledReg)};
          B.Instrs.push_back(Add);
        }
      }

      if (!ConstOff.isZero()) {
        emitConstAdd(ConstOff);
        if (!Err.empty())
          return false;
      }

      return true;
    }

    if (auto *Sel = dyn_cast<SelectInst>(&I)) {
      VMType Ty = mapType(Sel->getType(), Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::Select;
      Inst.Ty = Ty;
      Inst.Dst = getOrCreateReg(Sel, Ty, Entry, Err);
      VMType CondTy = mapType(Sel->getCondition()->getType(), Err);
      if (!Err.empty())
        return false;
      uint32_t Cond =
          getOrCreateReg(Sel->getCondition(), CondTy, Entry, Err);
      uint32_t TVal = getOrCreateReg(Sel->getTrueValue(), Ty, Entry, Err);
      uint32_t FVal = getOrCreateReg(Sel->getFalseValue(), Ty, Entry, Err);
      Inst.Ops = {VMValue::reg(Cond), VMValue::reg(TVal), VMValue::reg(FVal)};
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *CB = dyn_cast<CallBase>(&I)) {
      if (isa<InvokeInst>(CB) || isa<CallBrInst>(CB)) {
        Err = "vm: invoke/callbr unsupported";
        return false;
      }
      // VM host-call wrappers are not unwind-aware. A plain `call` that may
      // unwind can throw across VM runtime frames and corrupt EH behavior.
      // Treat it as unsupported until VM call lowering supports unwinding.
      if (!CB->doesNotThrow()) {
        Err = "vm: may-unwind call unsupported";
        return false;
      }
      if (CB->isMustTailCall()) {
        Err = "vm: musttail call unsupported";
        return false;
      }
      if (CB->hasOperandBundles()) {
        Err = "vm: operand bundles unsupported";
        return false;
      }

      Function *Callee = CB->getCalledFunction();
      if (CB->isInlineAsm()) {
        InlineAsm *IA = dyn_cast<InlineAsm>(CB->getCalledOperand());
        FunctionType *FTy = CB->getFunctionType();
        if (!IA || !FTy) {
          Err = "vm: inline asm unsupported";
          return false;
        }
        Function *Wrapper = getOrCreateInlineAsmWrapper(
            IA, FTy, CB->getCallingConv(), CB->getAttributes());
        if (!Wrapper) {
          Err = "vm: inline asm helper unavailable";
          return false;
        }
        Callee = Wrapper;
      }

      if (Callee && Callee->isIntrinsic()) {
        Intrinsic::ID ID = Callee->getIntrinsicID();
        if (isIgnorableIntrinsic(ID))
          return true;
        if (lowerIntrinsicCall(*CB, ID, B, Entry, Out, Err))
          return true;
        if (Err.empty())
          Err = (Twine("vm: intrinsic unsupported: ") + Callee->getName()).str();
        return false;
      }

      VMCallInfo CI;
      CI.CallConv = static_cast<unsigned>(CB->getCallingConv());
      CI.CalleeTy = CB->getFunctionType();
      CI.CalleeAddrSpace = getCallAddrSpace(*CB);
      CI.CallAttrs = sanitizeCallAttrs(CB->getAttributes(), CI.CalleeTy);
      if (Callee) {
        CI.Name = Callee->getName();
        CI.Callee = Callee;
      } else {
        CI.Name = "indirect";
        CI.Callee = nullptr;
        CI.IsIndirect = true;
      }
      CI.IsVoid = CB->getType()->isVoidTy();
      if (!CI.IsVoid) {
        VMType RetTy = mapType(CB->getType(), Err);
        if (!Err.empty())
          return false;
        CI.RetTy = RetTy;
        CI.RetReg = getOrCreateReg(CB, RetTy, Entry, Err);
      }
      for (Value *Arg : CB->args()) {
        VMType ATy = mapType(Arg->getType(), Err);
        if (!Err.empty())
          return false;
        CI.ArgRegs.push_back(getOrCreateReg(Arg, ATy, Entry, Err));
        CI.ArgTypes.push_back(Arg->getType());
      }

      if (CI.IsIndirect) {
        VMType CalleeTy = mapType(CB->getCalledOperand()->getType(), Err);
        if (!Err.empty())
          return false;
        CI.CalleeReg =
            getOrCreateReg(CB->getCalledOperand(), CalleeTy, Entry, Err);
        if (!Err.empty())
          return false;
      }

      emitHostCall(CI, B, Out);
      return true;
    }

    if (auto *RI = dyn_cast<ReturnInst>(&I)) {
      VMInstr Inst;
      Inst.Op = VMOpcode::Ret;
      if (Value *RV = RI->getReturnValue()) {
        VMType Ty = mapType(RV->getType(), Err);
        if (!Err.empty())
          return false;
        uint32_t R = getOrCreateReg(RV, Ty, Entry, Err);
        if (Out.HasRet && Out.RetReg != UINT32_MAX && Out.RetReg != R) {
          VMInstr Mov;
          Mov.Op = VMOpcode::Mov;
          Mov.Ty = Ty;
          Mov.Dst = Out.RetReg;
          Mov.Ops = {VMValue::reg(R)};
          B.Instrs.push_back(Mov);
          R = Out.RetReg;
        }
        Inst.Ops = {VMValue::reg(R)};
      }
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *Br = dyn_cast<BranchInst>(&I)) {
      VMInstr Inst;
      if (Br->isUnconditional()) {
        Inst.Op = VMOpcode::Br;
        Inst.TargetTrue = BlockIds[Br->getSuccessor(0)];
      } else {
        Inst.Op = VMOpcode::CondBr;
        VMType Ty = mapType(Br->getCondition()->getType(), Err);
        if (!Err.empty())
          return false;
        uint32_t Cond = getOrCreateReg(Br->getCondition(), Ty, Entry, Err);
        Inst.Ops = {VMValue::reg(Cond)};
        Inst.TargetTrue = BlockIds[Br->getSuccessor(0)];
        Inst.TargetFalse = BlockIds[Br->getSuccessor(1)];
      }
      B.Instrs.push_back(Inst);
      return true;
    }

    if (auto *Sw = dyn_cast<SwitchInst>(&I)) {
      Type *CondTy = Sw->getCondition()->getType();
      if (!CondTy->isIntegerTy()) {
        Err = "vm: switch condition must be integer";
        return false;
      }
      VMType Ty = mapType(CondTy, Err);
      if (!Err.empty())
        return false;
      VMInstr Inst;
      Inst.Op = VMOpcode::Switch;
      Inst.Ty = Ty;
      uint32_t Cond = getOrCreateReg(Sw->getCondition(), Ty, Entry, Err);
      Inst.Ops = {VMValue::reg(Cond)};
      Inst.SwitchDefault = BlockIds[Sw->getDefaultDest()];
      // Collect and sort cases by value for correct binary search in opcode mode
      SmallVector<std::pair<uint64_t, uint32_t>, 32> SortedCases;
      for (auto &Case : Sw->cases()) {
        ConstantInt *CV = Case.getCaseValue();
        if (!CV || CV->getBitWidth() > 64) {
          Err = "vm: switch case value too wide";
          return false;
        }
        SortedCases.push_back({CV->getZExtValue(), BlockIds[Case.getCaseSuccessor()]});
      }
      llvm::sort(SortedCases, [](const auto &A, const auto &B) {
        return A.first < B.first;
      });
      for (const auto &P : SortedCases) {
        Inst.SwitchValues.push_back(P.first);
        Inst.SwitchTargets.push_back(P.second);
      }
      B.Instrs.push_back(Inst);
      return true;
    }

    if (isa<UnreachableInst>(&I)) {
      VMInstr Inst;
      Inst.Op = VMOpcode::Trap;
      B.Instrs.push_back(Inst);
      return true;
    }

    Err = (Twine("vm: unsupported instruction: ") + I.getOpcodeName()).str();
    return false;
  }

  bool finalizePhis(VMFunction &VMF, std::string &Err) {
    struct PhiMove {
      uint32_t Dst = 0;
      uint32_t Src = 0;
      VMType Ty;
    };

    auto edgeKey = [](uint32_t Pred, uint32_t Succ) -> uint64_t {
      return (static_cast<uint64_t>(Pred) << 32) |
             static_cast<uint64_t>(Succ);
    };
    auto keyPred = [](uint64_t Key) -> uint32_t {
      return static_cast<uint32_t>(Key >> 32);
    };
    auto keySucc = [](uint64_t Key) -> uint32_t {
      return static_cast<uint32_t>(Key & 0xFFFFFFFFu);
    };

    DenseMap<uint64_t, SmallVector<PhiMove, 8>> MovesByEdge;
    DenseMap<uint64_t, bool> NeedsEdgeBlock;
    for (auto &Pair : Phis) {
      PHINode *PN = Pair.first;
      uint32_t DstReg = Pair.second;
      VMType Ty = mapType(PN->getType(), Err);
      if (!Err.empty())
        return false;
      uint32_t SuccId = BlockIds[PN->getParent()];
      for (unsigned i = 0; i < PN->getNumIncomingValues(); ++i) {
        BasicBlock *Pred = PN->getIncomingBlock(i);
        Value *InVal = PN->getIncomingValue(i);
        uint32_t PredId = BlockIds[Pred];
        uint32_t SrcReg = getOrCreateReg(InVal, Ty, VMF.Blocks[0], Err);
        if (!Err.empty())
          return false;
        if (SrcReg == DstReg)
          continue;
        uint64_t Key = edgeKey(PredId, SuccId);
        MovesByEdge[Key].push_back({DstReg, SrcReg, Ty});
        if (auto *Term = Pred->getTerminator()) {
          if (Term->getNumSuccessors() > 1)
            NeedsEdgeBlock[Key] = true;
        }
      }
    }

    DenseMap<uint64_t, uint32_t> EdgeBlocks;
    for (auto &KV : MovesByEdge) {
      uint64_t Key = KV.first;
      if (!NeedsEdgeBlock.lookup(Key))
        continue;
      if (EdgeBlocks.count(Key))
        continue;
      uint32_t NewId = static_cast<uint32_t>(VMF.Blocks.size());
      VMF.Blocks.push_back(VMBlock{NewId, {}});
      EdgeBlocks[Key] = NewId;
    }

    auto patchPredTerminator = [&](uint32_t PredId, uint32_t SuccId,
                                   uint32_t EdgeId) -> bool {
      if (PredId >= VMF.Blocks.size())
        return false;
      VMBlock &PredBlock = VMF.Blocks[PredId];
      if (PredBlock.Instrs.empty())
        return false;
      VMInstr &Term = PredBlock.Instrs.back();
      switch (Term.Op) {
      case VMOpcode::Br:
        if (Term.TargetTrue == SuccId)
          Term.TargetTrue = EdgeId;
        else
          return false;
        return true;
      case VMOpcode::CondBr:
        if (Term.TargetTrue == SuccId)
          Term.TargetTrue = EdgeId;
        if (Term.TargetFalse == SuccId)
          Term.TargetFalse = EdgeId;
        return true;
      case VMOpcode::Switch:
        for (uint32_t &Tgt : Term.SwitchTargets) {
          if (Tgt == SuccId)
            Tgt = EdgeId;
        }
        if (Term.SwitchDefault == SuccId)
          Term.SwitchDefault = EdgeId;
        return true;
      default:
        return false;
      }
    };

    auto scheduleMoves = [&](SmallVector<PhiMove, 8> Work,
                             SmallVector<VMInstr, 16> &Emitted) {
      // Parallel-copy scheduling for phi moves on an edge.
      //
      // Each move is conceptually `Dst <- Src` that must observe the original
      // values of all sources.  We emit a safe sequential schedule using a
      // temporary register to break cycles (e.g. swaps / cyclic phis).
      for (size_t i = 0; i < Work.size();) {
        if (Work[i].Src == Work[i].Dst) {
          Work[i] = Work.back();
          Work.pop_back();
          continue;
        }
        ++i;
      }

      DenseMap<uint32_t, unsigned> SrcUseCount;
      DenseSet<uint32_t> Srcs;
      auto addSrc = [&](uint32_t R) {
        unsigned &Count = SrcUseCount[R];
        ++Count;
        if (Count == 1)
          Srcs.insert(R);
      };
      auto dropSrc = [&](uint32_t R) {
        auto It = SrcUseCount.find(R);
        if (It == SrcUseCount.end())
          return;
        if (It->second <= 1) {
          SrcUseCount.erase(It);
          Srcs.erase(R);
          return;
        }
        --It->second;
      };

      for (const PhiMove &M : Work)
        addSrc(M.Src);

      auto eraseMove = [&](size_t Idx) {
        dropSrc(Work[Idx].Src);
        Work[Idx] = Work.back();
        Work.pop_back();
      };

      while (!Work.empty()) {
        bool Progress = false;
        for (size_t i = 0; i < Work.size();) {
          if (!Srcs.count(Work[i].Dst)) {
            VMInstr Mov;
            Mov.Op = VMOpcode::Mov;
            Mov.Ty = Work[i].Ty;
            Mov.Dst = Work[i].Dst;
            Mov.Ops = {VMValue::reg(Work[i].Src)};
            Emitted.push_back(Mov);
            eraseMove(i);
            Progress = true;
            continue;
          }
          ++i;
        }
        if (Progress)
          continue;

        // Cycle: save one destination and redirect any uses of it as a source
        // to use the temporary. This removes the destination from Srcs and
        // guarantees progress next iteration.
        PhiMove M = Work.back();
        uint32_t SavedDst = M.Dst;
        uint32_t Tmp = nextReg();

        VMInstr Save;
        Save.Op = VMOpcode::Mov;
        // Use i64 to preserve full register contents when breaking cycles.
        Save.Ty = VMType(VMTypeKind::I64);
        Save.Dst = Tmp;
        Save.Ops = {VMValue::reg(SavedDst)};
        Emitted.push_back(Save);

        for (PhiMove &X : Work) {
          if (X.Src != SavedDst)
            continue;
          dropSrc(X.Src);
          X.Src = Tmp;
          addSrc(X.Src);
        }
      }
    };

    for (auto &KV : MovesByEdge) {
      uint64_t Key = KV.first;
      uint32_t PredId = keyPred(Key);
      uint32_t SuccId = keySucc(Key);
      if (NeedsEdgeBlock.lookup(Key)) {
        auto It = EdgeBlocks.find(Key);
        if (It == EdgeBlocks.end()) {
          Err = "vm: edge block missing";
          return false;
        }
        uint32_t EdgeId = It->second;
        if (!patchPredTerminator(PredId, SuccId, EdgeId)) {
          Err = "vm: failed to patch pred terminator";
          return false;
        }
        VMBlock &EdgeBlock = VMF.Blocks[EdgeId];
        SmallVector<VMInstr, 16> Emitted;
        scheduleMoves(KV.second, Emitted);
        EdgeBlock.Instrs.insert(EdgeBlock.Instrs.end(), Emitted.begin(),
                                Emitted.end());
        VMInstr Br;
        Br.Op = VMOpcode::Br;
        Br.TargetTrue = SuccId;
        EdgeBlock.Instrs.push_back(Br);
      } else {
        if (PredId >= VMF.Blocks.size()) {
          Err = "vm: phi pred block not found";
          return false;
        }
        VMBlock &PredBlock = VMF.Blocks[PredId];
        if (PredBlock.Instrs.empty()) {
          Err = "vm: pred block empty";
          return false;
        }
        SmallVector<VMInstr, 16> Emitted;
        scheduleMoves(KV.second, Emitted);
        auto InsertPos = PredBlock.Instrs.end();
        --InsertPos;
        PredBlock.Instrs.insert(InsertPos, Emitted.begin(), Emitted.end());
      }
    }
    return true;
  }
};
} // namespace

VMLowerer::VMLowerer(Function &F, const DataLayout &DL) : F(F), DL(DL) {}

bool VMLowerer::lower(VMLoweringResult &Out, std::string &Err) {
  VMLowererImpl L(F, DL);
  Out.VMF.Name = F.getName();
  Out.VMF.PtrBits = DL.getPointerSizeInBits();
  if (Out.VMF.PtrBits == 0) {
    Err = "vm: invalid pointer size";
    return false;
  }

  // Assign block IDs.
  uint32_t BlockIdx = 0;
  for (BasicBlock &BB : F) {
    L.BlockIds[&BB] = BlockIdx++;
  }

  Out.VMF.Blocks.resize(BlockIdx);
  for (auto &KV : L.BlockIds) {
    Out.VMF.Blocks[KV.second].Id = KV.second;
  }

  VMBlock &Entry = Out.VMF.Blocks[0];

  // Map arguments to initial regs.
  for (Argument &Arg : F.args()) {
    VMType Ty = L.mapType(Arg.getType(), Err);
    if (!Err.empty())
      return false;
    uint32_t R = L.getOrCreateReg(&Arg, Ty, Entry, Err);
    if (!Err.empty())
      return false;
    Out.ArgRegs.push_back(R);
  }

  if (!F.getReturnType()->isVoidTy()) {
    Out.HasRet = true;
    VMType RetTy = L.mapType(F.getReturnType(), Err);
    if (!Err.empty())
      return false;
    (void)RetTy;
    Out.RetReg = L.nextReg();
  }

  // Lower each block.
  for (BasicBlock &BB : F) {
    VMBlock &VB = Out.VMF.Blocks[L.BlockIds[&BB]];
    for (Instruction &I : BB) {
      if (!L.lowerInstruction(I, VB, Entry, Out, Err))
        return false;
    }
  }

  if (!L.finalizePhis(Out.VMF, Err))
    return false;

  Out.VMF.RegCount = L.RegCounter;
  return true;
}
