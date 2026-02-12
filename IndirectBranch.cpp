//===- IndirectBranch.cpp - Indirect branch obfuscation ------------------===//
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
// Implements indirect-branch obfuscation via encoded jump tables.
//
//===----------------------------------------------------------------------===//
#include "IndirectBranch.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <cctype>
#include <limits>

using namespace llvm;

#define DEBUG_TYPE "indbr"

static cl::opt<bool> IndirectBranch(
    "indbr", cl::init(false),
    cl::desc("Enable indirect branch obfuscation"));
static cl::opt<bool>
    IndirectCall("indcall", cl::init(false),
                 cl::desc("Enable indirect call obfuscation"));

static cl::opt<bool> IndBrLazyInit(
    "indbr-lazy-init", cl::init(true),
    cl::desc("Ensure indirect branch tables are initialized before first use"));

static cl::opt<bool> IndCallShuffleTable(
    "indcall-shuffle", cl::init(true),
    cl::desc("Shuffle indirect call function table entry order"));
static cl::opt<unsigned> IndCallDecoyEntries(
    "indcall-decoys", cl::init(0),
    cl::desc("Pad indirect call function table with N decoy entries"));
static cl::opt<bool> IndCallSplitKey(
    "indcall-split-key", cl::init(true),
    cl::desc("Split indirect call key into two globals (key_a ^ key_b)"));
static cl::opt<bool> IndCallVaryDecode(
    "indcall-vary-decode", cl::init(true),
    cl::desc("Vary indirect call decode pattern per call site"));
static cl::opt<bool> IndCallIntegrityCheck(
    "indcall-check", cl::init(true),
    cl::desc("Insert a decoded pointer integrity check before indirect calls"));
static cl::opt<bool> IndCallLazyInit(
    "indcall-lazy-init", cl::init(true),
    cl::desc("Ensure indirect call table is initialized before use"));
static cl::opt<bool> IndCallPreEncode(
    "indcall-preencode", cl::init(true),
    cl::desc("Pre-encode indirect call table entries at compile time"));
static cl::opt<std::string> IndCallReport(
    "indcall-report", cl::init(""),
    cl::desc("Write indirect call report to file"));
static cl::opt<bool> IndCallReportPerModule(
    "indcall-report-per-module", cl::init(true),
    cl::desc("Write indirect call report to per-module files"));

static std::string sanitizeName(StringRef name) {
  if (name.empty())
    return "anon";
  std::string out = name.str();
  for (char &c : out) {
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.') {
      c = '_';
    }
  }
  return out;
}

static bool functionHasEH(const Function &F) {
  if (F.hasPersonalityFn())
    return true;
  for (const BasicBlock &BB : F) {
    if (BB.isEHPad())
      return true;
  }
  return false;
}

static std::string buildIndCallReportPath(const Module &M) {
  if (IndCallReport.empty())
    return std::string();
  if (!IndCallReportPerModule)
    return IndCallReport;

  std::string Mod = sanitizeName(M.getModuleIdentifier());
  if (Mod.empty())
    Mod = "module";

  if (IndCallReport.find("%m") != StringRef::npos) {
    std::string Out = IndCallReport;
    std::string Key = "%m";
    size_t Pos = 0;
    while ((Pos = Out.find(Key, Pos)) != std::string::npos) {
      Out.replace(Pos, Key.size(), Mod);
      Pos += Mod.size();
    }
    return Out;
  }

  SmallString<256> Path(IndCallReport);
  StringRef Ext = sys::path::extension(Path);
  if (!Ext.empty()) {
    Path.resize(Path.size() - Ext.size());
    Path += ".";
    Path += Mod;
    Path += Ext;
  } else {
    Path += ".";
    Path += Mod;
  }
  return std::string(Path.str());
}

static void writeIndCallReportLine(StringRef Path, StringRef Line) {
  if (Path.empty())
    return;
  std::error_code EC;
  llvm::raw_fd_ostream OS(Path, EC, llvm::sys::fs::OF_Append);
  if (EC)
    return;
  OS << Line << "\n";
}

static uint64_t deriveKeyForFunction(StringRef FuncName, StringRef Purpose) {
  std::string seedHex = getObfuscationSeedHex();
  if (seedHex.empty()) {
    return cryptoutils->get_uint64_t();
  }
  // Derive per-function keys from the global seed so builds are reproducible
  // without reusing the same key across functions.
  std::string input =
      seedHex + "|" + Purpose.str() + "|" + FuncName.str();
  unsigned char hash[32];
  cryptoutils->sha256(input.c_str(), hash);
  uint64_t key = 0;
  for (int i = 0; i < 8; ++i) {
    key = (key << 8) | hash[i];
  }
  return key;
}

static Function *getDirectCallee(CallBase *CB) {
  if (!CB)
    return nullptr;
  Value *Op = CB->getCalledOperand();
  Op = Op->stripPointerCasts();
  if (auto *GA = dyn_cast<GlobalAlias>(Op)) {
    if (auto *Aliasee = GA->getAliaseeObject())
      Op = Aliasee;
  }
  return dyn_cast<Function>(Op);
}

template <typename T>
static void cryptoShuffle(SmallVectorImpl<T> &V) {
  if (V.size() < 2)
    return;
  for (size_t i = V.size(); i > 1; --i) {
    size_t j = static_cast<size_t>(
        cryptoutils->get_range(static_cast<uint32_t>(i)));
    std::swap(V[i - 1], V[j]);
  }
}

struct FuncKeyTables {
  GlobalVariable *A = nullptr;
  GlobalVariable *B = nullptr;
};

static GlobalVariable *buildFuncTableRuntime(Module &M, size_t Count,
                                             Type *IntPtrTy) {
  ArrayType *ArrTy = ArrayType::get(IntPtrTy, Count);
  Constant *Init = ConstantAggregateZero::get(ArrTy);
  auto *GV = new GlobalVariable(M, ArrTy, false, GlobalValue::PrivateLinkage,
                                Init, "obf_func_table");
  obfuscateSymbolName(*GV, M, "ind.func_table", "obf_func_table");
  return GV;
}

static GlobalVariable *buildFuncTableEncoded(Module &M,
                                             ArrayRef<Function *> Funcs,
                                             ArrayRef<uint64_t> Keys,
                                             Type *IntPtrTy) {
  SmallVector<Constant *, 16> Elems;
  Elems.reserve(Funcs.size());
  for (size_t i = 0; i < Funcs.size(); ++i) {
    Constant *Ptr = ConstantExpr::getPtrToInt(Funcs[i], IntPtrTy);
    Constant *KeyC = ConstantInt::get(IntPtrTy, Keys[i]);
    // Additive masking keeps table immutable while hiding raw addresses.
    Constant *Enc = ConstantExpr::getAdd(Ptr, KeyC);
    Elems.push_back(Enc);
  }

  ArrayType *ArrTy = ArrayType::get(IntPtrTy, Elems.size());
  Constant *Init = ConstantArray::get(ArrTy, Elems);
  auto *GV = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                Init, "obf_func_table");
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*GV, M, "ind.func_table", "obf_func_table");
  return GV;
}

static GlobalVariable *getOrCreateFuncTableState(Module &M) {
  if (GlobalVariable *GV = findTaggedGlobal(M, "ind.func.table.state"))
    return GV;
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  auto *GV = new GlobalVariable(M, I8Ty, false, GlobalValue::PrivateLinkage,
                                ConstantInt::get(I8Ty, 0),
                                "obf_func_table_state");
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*GV, M, "ind.func.table.state", "obf_func_table_state");
  return GV;
}

static FuncKeyTables buildFuncKeyTables(Module &M, ArrayRef<uint64_t> Keys,
                                        Type *IntPtrTy, bool Split) {
  SmallVector<Constant *, 16> ElemsA;
  SmallVector<Constant *, 16> ElemsB;
  ElemsA.reserve(Keys.size());
  ElemsB.reserve(Keys.size());
  for (uint64_t K : Keys) {
    uint64_t KA = Split ? cryptoutils->get_uint64_t() : K;
    uint64_t KB = Split ? (K ^ KA) : 0;
    // Split keys so no single memory range contains the full decode material.
    ElemsA.push_back(ConstantInt::get(IntPtrTy, KA));
    ElemsB.push_back(ConstantInt::get(IntPtrTy, KB));
  }

  ArrayType *ArrTy = ArrayType::get(IntPtrTy, ElemsA.size());
  Constant *InitA = ConstantArray::get(ArrTy, ElemsA);
  Constant *InitB = ConstantArray::get(ArrTy, ElemsB);

  auto *GVA = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                 InitA, "obf_func_keys_a");
  auto *GVB = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                 InitB, "obf_func_keys_b");
  obfuscateSymbolName(*GVA, M, "ind.func.keys.a", "obf_func_keys_a");
  obfuscateSymbolName(*GVB, M, "ind.func.keys.b", "obf_func_keys_b");
  return {GVA, GVB};
}

// Insert into llvm.global_ctors at the correct priority-sorted position.
// LLVM's appendToGlobalCtors always appends; we need priority ordering so
// table init runs before user constructors that might issue indirect calls.
static void prependToGlobalCtors(Module &M, Function *F, int Priority) {
  IRBuilder<> IRB(M.getContext());
  SmallVector<Constant *, 16> CurrentCtors;
  StructType *EltTy = nullptr;
  StringRef Section;
  MaybeAlign Align;
  GlobalValue::UnnamedAddr UA = GlobalValue::UnnamedAddr::None;
  GlobalValue::VisibilityTypes Vis = GlobalValue::DefaultVisibility;
  GlobalValue::DLLStorageClassTypes DLL = GlobalValue::DefaultStorageClass;
  Comdat *C = nullptr;
  unsigned AddrSpace = 0;
  if (GlobalVariable *GVCtor = M.getNamedGlobal("llvm.global_ctors")) {
    Section = GVCtor->getSection();
    Align = GVCtor->getAlign();
    UA = GVCtor->getUnnamedAddr();
    Vis = GVCtor->getVisibility();
    DLL = GVCtor->getDLLStorageClass();
    C = GVCtor->getComdat();
    AddrSpace = GVCtor->getAddressSpace();
    EltTy = cast<StructType>(GVCtor->getValueType()->getArrayElementType());
    if (Constant *Init = GVCtor->getInitializer()) {
      unsigned N = Init->getNumOperands();
      CurrentCtors.reserve(N + 1);
      for (unsigned i = 0; i != N; ++i)
        CurrentCtors.push_back(cast<Constant>(Init->getOperand(i)));
    }
    GVCtor->eraseFromParent();
  } else {
    EltTy = StructType::get(
        IRB.getInt32Ty(),
        PointerType::get(M.getContext(), F->getAddressSpace()), IRB.getPtrTy());
  }

  Constant *CSVals[3];
  CSVals[0] = IRB.getInt32(Priority);
  CSVals[1] = F;
  CSVals[2] = Constant::getNullValue(IRB.getPtrTy());
  Constant *CtorInit =
      ConstantStruct::get(EltTy, ArrayRef(CSVals, EltTy->getNumElements()));

  auto getPriority = [](Constant *C) -> int {
    if (auto *CS = dyn_cast<ConstantStruct>(C)) {
      if (CS->getNumOperands() > 0) {
        if (auto *CI = dyn_cast<ConstantInt>(CS->getOperand(0)))
          return static_cast<int>(CI->getSExtValue());
      }
    }
    return std::numeric_limits<int>::max();
  };

  auto It = std::find_if(CurrentCtors.begin(), CurrentCtors.end(),
                         [&](Constant *C) { return getPriority(C) > Priority; });
  CurrentCtors.insert(It, CtorInit);

  ArrayType *AT = ArrayType::get(EltTy, CurrentCtors.size());
  Constant *NewInit = ConstantArray::get(AT, CurrentCtors);
  auto *NewGV = new GlobalVariable(M, NewInit->getType(), false,
                                   GlobalValue::AppendingLinkage, NewInit,
                                   "llvm.global_ctors", nullptr,
                                   GlobalVariable::NotThreadLocal, AddrSpace);
  if (!Section.empty())
    NewGV->setSection(Section);
  if (Align)
    NewGV->setAlignment(*Align);
  NewGV->setUnnamedAddr(UA);
  NewGV->setVisibility(Vis);
  NewGV->setDLLStorageClass(DLL);
  if (C)
    NewGV->setComdat(C);
}

static Function *getOrCreateTrapFn(Module &M) {
  if (Function *F = findTaggedFunction(M, "ind.trap"))
    return F;

  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *TrapFn =
      Function::Create(FT, GlobalValue::InternalLinkage, "obf_trap", &M);
  obfuscateSymbolName(*TrapFn, M, "ind.trap", "obf_trap");

  TrapFn->addFnAttr("no_obfuscate");
  TrapFn->addFnAttr(Attribute::NoInline);
  TrapFn->addFnAttr(Attribute::OptimizeNone);
  TrapFn->addFnAttr(Attribute::Cold);
  TrapFn->addFnAttr(Attribute::NoUnwind);
  TrapFn->addFnAttr(Attribute::NoReturn);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", TrapFn);
  IRBuilder<> B(Entry);
  FunctionCallee TrapIntrinsic =
      Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  B.CreateCall(TrapIntrinsic);
  B.CreateUnreachable();

  return TrapFn;
}

// Emit semantically equivalent XOR using different instruction sequences so
// pattern matchers can't normalize all decode sites to the same form.
static Value *createXorVariant(IRBuilder<> &B, Value *A, Value *Bv,
                               unsigned Variant) {
  switch (Variant) {
  case 0: {
    return B.CreateXor(A, Bv);
  }
  case 1: {
    Value *NotA = B.CreateNot(A);
    Value *NotB = B.CreateNot(Bv);
    Value *T1 = B.CreateAnd(NotA, Bv);
    Value *T2 = B.CreateAnd(A, NotB);
    return B.CreateOr(T1, T2);
  }
  case 2: {
    Value *Or = B.CreateOr(A, Bv);
    Value *And = B.CreateAnd(A, Bv);
    Value *NotAnd = B.CreateNot(And);
    return B.CreateAnd(Or, NotAnd);
  }
  case 3: {
    Constant *Mask = ConstantInt::get(A->getType(), cryptoutils->get_uint64_t());
    Value *A1 = B.CreateXor(A, Mask);
    Value *B1 = B.CreateXor(Bv, Mask);
    return B.CreateXor(A1, B1);
  }
  default:
    return B.CreateXor(A, Bv);
  }
}

static Value *createSubVariant(IRBuilder<> &B, Value *A, Value *Bv,
                               unsigned Variant) {
  switch (Variant) {
  case 0: {
    return B.CreateSub(A, Bv);
  }
  case 1: {
    // A + (~B + 1)  (two's complement)
    Value *NotB = B.CreateNot(Bv);
    Value *NegB = B.CreateAdd(NotB, ConstantInt::get(Bv->getType(), 1));
    return B.CreateAdd(A, NegB);
  }
  default:
    return B.CreateSub(A, Bv);
  }
}

static Function *addFuncTableInit(Module &M, GlobalVariable *FuncTable,
                                  ArrayRef<Function *> Entries,
                                  GlobalVariable *KeyA, GlobalVariable *KeyB,
                                  GlobalVariable *StateGV, Type *IntPtrTy) {
  if (Function *Existing = findTaggedFunction(M, "ind.func_table.init"))
    return Existing;

  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *InitFn = Function::Create(FT, GlobalValue::InternalLinkage,
                                      "obf_init_func_table", &M);
  obfuscateSymbolName(*InitFn, M, "ind.func_table.init", "obf_init_func_table");
  InitFn->addFnAttr(Attribute::NoInline);
  InitFn->addFnAttr(Attribute::OptimizeNone);
  InitFn->addFnAttr("no_obfuscate");
  InitFn->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", InitFn);
  BasicBlock *DoInit = BasicBlock::Create(Ctx, "do_init", InitFn);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", InitFn);
  IRBuilder<> B(Entry);

  Value *Zero8 = ConstantInt::get(I8Ty, 0);
  Value *One8 = ConstantInt::get(I8Ty, 1);
  Value *Two8 = ConstantInt::get(I8Ty, 2);
  // CAS acts as a once-gate so concurrent threads don't race on table init.
  AtomicCmpXchgInst *CX = B.CreateAtomicCmpXchg(
      StateGV, Zero8, One8, MaybeAlign(1), AtomicOrdering::AcquireRelease,
      AtomicOrdering::Acquire);
  CX->setWeak(false);
  Value *CanInit = B.CreateExtractValue(CX, 1);
  B.CreateCondBr(CanInit, DoInit, Done);

  B.SetInsertPoint(DoInit);
  ArrayType *ArrTy = cast<ArrayType>(FuncTable->getValueType());
  uint64_t N = ArrTy->getNumElements();
  if (Entries.size() != N) {
    report_fatal_error("indcall: func table size mismatch");
  }
  Value *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);

  for (uint64_t i = 0; i < N; ++i) {
    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), i);
    Value *ElemPtr =
        B.CreateInBoundsGEP(FuncTable->getValueType(), FuncTable, {Zero, Idx});
    Value *KeyPtrA =
        B.CreateInBoundsGEP(KeyA->getValueType(), KeyA, {Zero, Idx});
    Value *KeyPtrB =
        B.CreateInBoundsGEP(KeyB->getValueType(), KeyB, {Zero, Idx});
    Value *KA = B.CreateLoad(IntPtrTy, KeyPtrA);
    Value *KB = B.CreateLoad(IntPtrTy, KeyPtrB);
    Value *Key = B.CreateXor(KA, KB);
    Value *FuncPtr =
        B.CreatePtrToInt(Entries[static_cast<size_t>(i)], IntPtrTy);
    Value *Enc = B.CreateXor(FuncPtr, Key);
    B.CreateStore(Enc, ElemPtr);
  }

  StoreInst *StoreDone = B.CreateStore(Two8, StateGV);
  StoreDone->setAtomic(AtomicOrdering::Release);
  B.CreateRetVoid();

  B.SetInsertPoint(Done);
  B.CreateRetVoid();

  prependToGlobalCtors(M, InitFn, 0);
  return InitFn;
}

static Function *getOrCreateFuncTableEnsure(Module &M, GlobalVariable *StateGV,
                                            Function *InitFn) {
  if (Function *F = findTaggedFunction(M, "ind.func_table.ensure"))
    return F;
  if (!StateGV || !InitFn)
    return nullptr;

  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *Ensure =
      Function::Create(FT, GlobalValue::InternalLinkage,
                       "obf_ensure_func_table", &M);
  obfuscateSymbolName(*Ensure, M, "ind.func_table.ensure",
                      "obf_ensure_func_table");
  Ensure->addFnAttr(Attribute::NoInline);
  Ensure->addFnAttr(Attribute::OptimizeNone);
  Ensure->addFnAttr("no_obfuscate");
  Ensure->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Ensure);
  BasicBlock *Wait = BasicBlock::Create(Ctx, "wait", Ensure);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", Ensure);

  Value *Two8 = ConstantInt::get(I8Ty, 2);

  IRBuilder<> B(Entry);
  LoadInst *StateVal = B.CreateLoad(I8Ty, StateGV);
  StateVal->setAtomic(AtomicOrdering::Acquire);
  Value *Ready = B.CreateICmpEQ(StateVal, Two8);
  B.CreateCondBr(Ready, Done, Wait);

  IRBuilder<> BW(Wait);
  BW.CreateCall(InitFn);
  LoadInst *StateVal2 = BW.CreateLoad(I8Ty, StateGV);
  StateVal2->setAtomic(AtomicOrdering::Acquire);
  Value *Ready2 = BW.CreateICmpEQ(StateVal2, Two8);
  BW.CreateCondBr(Ready2, Done, Wait);

  IRBuilder<> BD(Done);
  BD.CreateRetVoid();

  return Ensure;
}

static Function *getOrCreateBlockTableEnsure(Module &M, Function &F,
                                             GlobalVariable *StateGV,
                                             Function *InitFn) {
  std::string Tag = "ind.br.table.ensure." + sanitizeName(F.getName());
  if (Function *Existing = findTaggedFunction(M, Tag))
    return Existing;
  if (!StateGV || !InitFn)
    return nullptr;

  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  std::string Name = "obf_ensure_br_table." + sanitizeName(F.getName());
  Function *Ensure =
      Function::Create(FT, GlobalValue::InternalLinkage, Name, &M);
  obfuscateSymbolName(*Ensure, M, Tag, Name);
  Ensure->addFnAttr(Attribute::NoInline);
  Ensure->addFnAttr(Attribute::OptimizeNone);
  Ensure->addFnAttr("no_obfuscate");
  Ensure->addFnAttr(Attribute::Cold);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Ensure);
  BasicBlock *Wait = BasicBlock::Create(Ctx, "wait", Ensure);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", Ensure);

  Value *Two8 = ConstantInt::get(I8Ty, 2);

  IRBuilder<> B(Entry);
  LoadInst *StateVal = B.CreateLoad(I8Ty, StateGV);
  StateVal->setAtomic(AtomicOrdering::Acquire);
  Value *Ready = B.CreateICmpEQ(StateVal, Two8);
  B.CreateCondBr(Ready, Done, Wait);

  IRBuilder<> BW(Wait);
  BW.CreateCall(InitFn);
  LoadInst *StateVal2 = BW.CreateLoad(I8Ty, StateGV);
  StateVal2->setAtomic(AtomicOrdering::Acquire);
  Value *Ready2 = BW.CreateICmpEQ(StateVal2, Two8);
  BW.CreateCondBr(Ready2, Done, Wait);

  IRBuilder<> BD(Done);
  BD.CreateRetVoid();

  return Ensure;
}

static GlobalVariable *buildBlockTable(Module &M, Function &F,
                                       ArrayRef<BasicBlock *> Blocks,
                                       Type *IntPtrTy, Constant *KeyConst) {
  SmallVector<Constant *, 16> Elems;
  Elems.reserve(Blocks.size());
  for (BasicBlock *BB : Blocks) {
    Constant *Addr = BlockAddress::get(&F, BB);
    Constant *Ptr = ConstantExpr::getPtrToInt(Addr, IntPtrTy);
    Elems.push_back(Ptr);
  }

  ArrayType *ArrTy = ArrayType::get(IntPtrTy, Elems.size());
  Constant *Init = ConstantArray::get(ArrTy, Elems);
  std::string name = "obf_br_table." + sanitizeName(F.getName());
  auto *GV = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                Init, name);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  std::string Tag = "ind.br.table." + sanitizeName(F.getName());
  obfuscateSymbolName(*GV, M, Tag, name);
  return GV;
}

static GlobalVariable *buildBlockTableForComdat(Module &M, Function &F,
                                                ArrayRef<BasicBlock *> Blocks,
                                                Type *IntPtrTy,
                                                Constant *KeyConst) {
  SmallVector<Constant *, 16> Elems;
  Elems.reserve(Blocks.size());
  for (BasicBlock *BB : Blocks) {
    Constant *Addr = BlockAddress::get(&F, BB);
    Constant *Ptr = ConstantExpr::getPtrToInt(Addr, IntPtrTy);
    Elems.push_back(Ptr);
  }

  ArrayType *ArrTy = ArrayType::get(IntPtrTy, Elems.size());
  Constant *Init = ConstantArray::get(ArrTy, Elems);

  std::string tableName = "obf_br_table." + sanitizeName(F.getName());
  auto *TableGV =
      new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage, Init,
                         tableName);
  TableGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  std::string Tag = "ind.br.table." + sanitizeName(F.getName());
  obfuscateSymbolName(*TableGV, M, Tag, tableName);

  return TableGV;
}

static GlobalVariable *buildBlockTableRuntime(Module &M, Function &F,
                                              size_t Count, Type *IntPtrTy) {
  ArrayType *ArrTy = ArrayType::get(IntPtrTy, Count);
  Constant *Init = ConstantAggregateZero::get(ArrTy);
  std::string name = "obf_br_table_enc." + sanitizeName(F.getName());
  auto *GV = new GlobalVariable(M, ArrTy, false,
                                GlobalValue::PrivateLinkage, Init, name);
  std::string Tag = "ind.br.table.enc." + sanitizeName(F.getName());
  obfuscateSymbolName(*GV, M, Tag, name);
  return GV;
}

static GlobalVariable *getOrCreateBlockTableState(Module &M, Function &F) {
  std::string Tag = "ind.br.table.state." + sanitizeName(F.getName());
  if (GlobalVariable *GV = findTaggedGlobal(M, Tag))
    return GV;
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  std::string name = "obf_br_table_state." + sanitizeName(F.getName());
  auto *GV = new GlobalVariable(M, I8Ty, false,
                                GlobalValue::PrivateLinkage,
                                ConstantInt::get(I8Ty, 0), name);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*GV, M, Tag, name);
  return GV;
}

static Function *addBlockTableInit(Module &M, Function &F,
                                   GlobalVariable *RawTable,
                                   GlobalVariable *EncTable,
                                   GlobalVariable *KeyGV,
                                   GlobalVariable *StateGV, Type *IntPtrTy) {
  std::string Tag = "ind.br.table.init." + sanitizeName(F.getName());
  if (Function *Existing = findTaggedFunction(M, Tag))
    return Existing;

  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  std::string Name = "obf_init_br_table." + sanitizeName(F.getName());
  Function *InitFn =
      Function::Create(FT, GlobalValue::InternalLinkage, Name, &M);
  obfuscateSymbolName(*InitFn, M, Tag, Name);
  InitFn->addFnAttr(Attribute::NoInline);
  InitFn->addFnAttr(Attribute::OptimizeNone);
  InitFn->addFnAttr("no_obfuscate");
  InitFn->addFnAttr(Attribute::Cold);
  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", InitFn);
  BasicBlock *DoInit = BasicBlock::Create(Ctx, "do_init", InitFn);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", InitFn);
  IRBuilder<> B(Entry);

  Value *Zero8 = ConstantInt::get(I8Ty, 0);
  Value *One8 = ConstantInt::get(I8Ty, 1);
  Value *Two8 = ConstantInt::get(I8Ty, 2);
  AtomicCmpXchgInst *CX = B.CreateAtomicCmpXchg(
      StateGV, Zero8, One8, MaybeAlign(1), AtomicOrdering::AcquireRelease,
      AtomicOrdering::Acquire);
  CX->setWeak(false);
  Value *CanInit = B.CreateExtractValue(CX, 1);
  B.CreateCondBr(CanInit, DoInit, Done);

  B.SetInsertPoint(DoInit);
  ArrayType *ArrTy = cast<ArrayType>(RawTable->getValueType());
  uint64_t N = ArrTy->getNumElements();
  Value *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);

  for (uint64_t i = 0; i < N; ++i) {
    Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), i);
    Value *RawPtr =
        B.CreateInBoundsGEP(RawTable->getValueType(), RawTable, {Zero, Idx});
    Value *EncPtr =
        B.CreateInBoundsGEP(EncTable->getValueType(), EncTable, {Zero, Idx});
    Value *Raw = B.CreateLoad(IntPtrTy, RawPtr);
    Value *Key = B.CreateLoad(IntPtrTy, KeyGV);
    Value *Enc = B.CreateXor(Raw, Key);
    B.CreateStore(Enc, EncPtr);
  }

  StoreInst *StoreDone = B.CreateStore(Two8, StateGV);
  StoreDone->setAtomic(AtomicOrdering::Release);
  B.CreateRetVoid();

  B.SetInsertPoint(Done);
  B.CreateRetVoid();

  return InitFn;
}

static GlobalVariable *getOrCreatePerFunctionKey(Module &M, Function &F,
                                                 Type *IntPtrTy,
                                                 StringRef Purpose) {
  std::string Tag =
      "ind.key." + Purpose.str() + "." + sanitizeName(F.getName());
  if (GlobalVariable *GV = findTaggedGlobal(M, Tag)) {
    return GV;
  }

  if (F.hasComdat() && getObfuscationSeed() == 0)
    return nullptr;

  uint64_t Key =
      (getObfuscationSeed() != 0)
          ? deriveKeyForFunction(F.getName(), Purpose)
          : cryptoutils->get_uint64_t();

  Constant *Init = ConstantInt::get(IntPtrTy, Key);
  GlobalValue::LinkageTypes Link =
      F.hasComdat() ? GlobalValue::LinkOnceODRLinkage
                    : GlobalValue::PrivateLinkage;
  std::string Name =
      "obf_key." + Purpose.str() + "." + sanitizeName(F.getName());
  auto *GV = new GlobalVariable(M, IntPtrTy, true, Link, Init, Name);
  obfuscateSymbolName(*GV, M, Tag, Name);
  if (Comdat *C = F.getComdat()) {
    GV->setComdat(C);
  }
  return GV;
}

static bool transformCalls(Module &M, Type *IntPtrTy,
                           SmallPtrSetImpl<Function *> &Changed,
                           SmallPtrSetImpl<Function *> &DumpedBefore) {
  SmallVector<CallBase *, 32> Calls;
  struct Entry {
    Function *Callee;
    uint64_t Key;
  };
  SmallVector<Entry, 32> Entries;
  DenseMap<Function *, unsigned> Index;
  unsigned TotalCalls = 0;
  unsigned EligibleCalls = 0;
  unsigned SkipCallBr = 0;
  unsigned SkipInlineAsm = 0;
  unsigned SkipMustTail = 0;
  unsigned SkipInvoke = 0;
  unsigned SkipBundles = 0;
  unsigned SkipEHFunc = 0;
  unsigned SkipShouldSkipInst = 0;
  unsigned SkipNoDirect = 0;
  unsigned SkipIntrinsic = 0;
  unsigned SkipAvailExtern = 0;
  unsigned SkipNoObfCallee = 0;
  // Pre-encoding folds keys into the table at compile time (additive mask),
  // avoiding a runtime init function that an attacker could breakpoint.
  bool UsePreEncode = IndCallPreEncode;
  if (!IndCallPreEncode)
    LLVM_DEBUG(dbgs() << "indcall: pre-encode disabled\n");

  // --- Discover call sites + unique callees ---
  for (Function &F : M) {
    if (shouldSkipFunction(&F))
      continue;
    bool FuncHasEH = functionHasEH(F);
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;
        ++TotalCalls;
        if (FuncHasEH) {
          ++SkipEHFunc;
          continue;
        }
        if (isa<CallBrInst>(CB)) {
          ++SkipCallBr;
          continue;
        }
        if (isa<InvokeInst>(CB)) {
          ++SkipInvoke;
          continue;
        }
        if (CB->hasOperandBundles()) {
          ++SkipBundles;
          continue;
        }
        if (auto *CI = dyn_cast<CallInst>(CB)) {
          if (CI->isInlineAsm()) {
            ++SkipInlineAsm;
            continue;
          }
          if (CI->isMustTailCall()) {
            ++SkipMustTail;
            continue;
          }
        }
        if (shouldSkipInstruction(CB)) {
          ++SkipShouldSkipInst;
          continue;
        }

        Function *Callee = getDirectCallee(CB);
        if (!Callee) {
          ++SkipNoDirect;
          continue;
        }
        if (Callee->isIntrinsic()) {
          ++SkipIntrinsic;
          continue;
        }
        if (Callee->hasFnAttribute("no_obfuscate") ||
            Callee->hasFnAttribute("obf_skip")) {
          ++SkipNoObfCallee;
          continue;
        }
        if (Callee->hasAvailableExternallyLinkage())
        {
          ++SkipAvailExtern;
          continue;
        }
        ++EligibleCalls;
        auto It = Index.find(Callee);
        if (It == Index.end()) {
          unsigned Idx = static_cast<unsigned>(Entries.size());
          Index[Callee] = Idx;
          uint64_t Key =
              (getObfuscationSeed() != 0)
                  ? deriveKeyForFunction(Callee->getName(), "call")
                  : cryptoutils->get_uint64_t();
          Entries.push_back({Callee, Key});
        }
        Calls.push_back(CB);
      }
    }
  }

  bool changed = false;
  if (!Calls.empty()) {
    if (IndCallShuffleTable)
      cryptoShuffle(Entries);

    // Rebuild Index based on shuffled order.
    Index.clear();
    for (unsigned i = 0; i < Entries.size(); ++i) {
      Index[Entries[i].Callee] = i;
    }

    Function *TrapFn = nullptr;
    if (IndCallDecoyEntries > 0 || IndCallIntegrityCheck) {
      TrapFn = getOrCreateTrapFn(M);
    }
    Function *FailFn = nullptr;
    if (IndCallIntegrityCheck) {
      FailFn = getOrCreateObfFail(M);
    }

    SmallVector<Function *, 32> TableEntries;
    SmallVector<uint64_t, 32> TableKeys;
    TableEntries.reserve(Entries.size() + IndCallDecoyEntries);
    TableKeys.reserve(Entries.size() + IndCallDecoyEntries);
    for (const Entry &E : Entries) {
      TableEntries.push_back(E.Callee);
      TableKeys.push_back(E.Key);
    }
    for (unsigned i = 0; i < IndCallDecoyEntries; ++i) {
      TableEntries.push_back(TrapFn);
      TableKeys.push_back(cryptoutils->get_uint64_t());
    }

    GlobalVariable *FuncTable =
        UsePreEncode
            ? buildFuncTableEncoded(M, TableEntries, TableKeys, IntPtrTy)
            : buildFuncTableRuntime(M, TableEntries.size(), IntPtrTy);
    FuncKeyTables KeyTables =
        buildFuncKeyTables(M, TableKeys, IntPtrTy, IndCallSplitKey);
    GlobalVariable *StateGV = nullptr;
    if (!UsePreEncode) {
      StateGV = getOrCreateFuncTableState(M);
    }
    if (!Entries.empty()) {
      SmallVector<GlobalValue *, 32> Used;
      Used.reserve(Entries.size() + (TrapFn ? 1 : 0));
      for (const Entry &E : Entries)
        Used.push_back(E.Callee);
      if (TrapFn)
        Used.push_back(TrapFn);
      appendToUsed(M, Used);
    }
    Function *InitFn = nullptr;
    if (!UsePreEncode && StateGV) {
      InitFn = addFuncTableInit(M, FuncTable, TableEntries, KeyTables.A,
                                KeyTables.B, StateGV, IntPtrTy);
    }

    Function *EnsureFn = nullptr;
    if (IndCallLazyInit && InitFn && StateGV) {
      EnsureFn = getOrCreateFuncTableEnsure(M, StateGV, InitFn);
    }
    if (EnsureFn) {
      SmallPtrSet<Function *, 32> Guarded;
      for (CallBase *CB : Calls) {
        Function *Parent = CB->getFunction();
        if (Parent == EnsureFn)
          continue;
        if (Guarded.insert(Parent).second) {
          Instruction *IP = &*Parent->getEntryBlock().getFirstInsertionPt();
          IRBuilder<> BE(IP);
          BE.CreateCall(EnsureFn);
        }
      }
    }

    for (CallBase *CB : Calls) {
      Function *Parent = CB->getFunction();
      if (!DumpedBefore.contains(Parent)) {
        maybeDumpIR(*Parent, "indirect.before");
        DumpedBefore.insert(Parent);
      }
      Function *Callee = getDirectCallee(CB);
      unsigned Idx = Index[Callee];

      BasicBlock *OrigBB = CB->getParent();


      IRBuilder<> B(CB);
      B.SetCurrentDebugLocation(CB->getDebugLoc());
      if (EnsureFn) {
        CallInst *EnsureCall = B.CreateCall(EnsureFn);
        EnsureCall->setDebugLoc(CB->getDebugLoc());
      }

      Value *Zero = ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);
      Value *IdxVal = ConstantInt::get(Type::getInt32Ty(M.getContext()), Idx);
      Value *ElemPtr =
          B.CreateInBoundsGEP(FuncTable->getValueType(), FuncTable,
                              {Zero, IdxVal});
      Value *KeyPtrA =
          B.CreateInBoundsGEP(KeyTables.A->getValueType(), KeyTables.A,
                              {Zero, IdxVal});
      Value *KeyPtrB =
          B.CreateInBoundsGEP(KeyTables.B->getValueType(), KeyTables.B,
                              {Zero, IdxVal});
      LoadInst *EncPtr = B.CreateLoad(IntPtrTy, ElemPtr);
      LoadInst *KeyA = B.CreateLoad(IntPtrTy, KeyPtrA);
      LoadInst *KeyB = B.CreateLoad(IntPtrTy, KeyPtrB);
      KeyA->setVolatile(true);
      KeyB->setVolatile(true);
      unsigned KeyVariant =
          IndCallVaryDecode ? cryptoutils->get_range(4) : 0;
      Value *EffKey = createXorVariant(B, KeyA, KeyB, KeyVariant);

      unsigned Variant =
          IndCallVaryDecode ? cryptoutils->get_range(2) : 0;
      Value *DecPtrInt = nullptr;
      if (UsePreEncode) {
        DecPtrInt = createSubVariant(B, EncPtr, EffKey, Variant);
      } else {
        DecPtrInt = createXorVariant(B, EncPtr, EffKey, Variant);
      }

      BasicBlock *ContBB = nullptr;
      OrigBB = CB->getParent();
      if (IndCallIntegrityCheck) {
        Value *IsNull =
            B.CreateICmpEQ(DecPtrInt, ConstantInt::get(IntPtrTy, 0));

        ContBB = OrigBB->splitBasicBlock(CB, "obf.indcall.cont");

        BasicBlock *TrapBB =
            BasicBlock::Create(M.getContext(), "obf.indcall.trap", Parent,
                               ContBB);
        IRBuilder<> BT(TrapBB);
        BT.SetCurrentDebugLocation(CB->getDebugLoc());
        if (FailFn) {
          Value *Code =
              ConstantInt::get(Type::getInt32Ty(M.getContext()), 0x2001);
          BT.CreateCall(FailFn, {Code});
        } else {
          BT.CreateCall(TrapFn);
        }
        BT.CreateUnreachable();

        OrigBB->getTerminator()->eraseFromParent();
        B.SetInsertPoint(OrigBB);
        B.CreateCondBr(IsNull, TrapBB, ContBB);
      }

      IRBuilder<> BC(CB);
      BC.SetCurrentDebugLocation(CB->getDebugLoc());

      Type *CalledPtrTy = CB->getCalledOperand()->getType();
      FunctionType *FTy = CB->getFunctionType();
      Value *FuncPtr = BC.CreateIntToPtr(DecPtrInt, CalledPtrTy);

      SmallVector<Value *, 8> Args;
      for (auto &Arg : CB->args()) {
        Args.push_back(Arg.get());
      }

      SmallVector<OperandBundleDef, 2> Bundles;
      CB->getOperandBundlesAsDefs(Bundles);

      CallBase *NewCB = nullptr;
      if (auto *II = dyn_cast<InvokeInst>(CB)) {
        NewCB = BC.CreateInvoke(FTy, FuncPtr, II->getNormalDest(),
                                II->getUnwindDest(), Args, Bundles);
      } else {
        auto *OldCI = cast<CallInst>(CB);
        auto *NewCI = BC.CreateCall(FTy, FuncPtr, Args, Bundles);
        NewCI->setTailCallKind(OldCI->getTailCallKind());
        NewCB = NewCI;
      }

      NewCB->setCallingConv(CB->getCallingConv());
      NewCB->setAttributes(CB->getAttributes());
      NewCB->setDebugLoc(CB->getDebugLoc());

      CB->replaceAllUsesWith(NewCB);
      CB->eraseFromParent();
      Changed.insert(Parent);
    }

    changed = true;
  }

  if (!IndCallReport.empty()) {
    SmallString<256> Buf;
    raw_svector_ostream OS(Buf);
    OS << "module=" << sanitizeName(M.getModuleIdentifier())
       << "\ttotal_calls=" << TotalCalls
       << "\teligible_calls=" << EligibleCalls
       << "\ttransformed_calls=" << Calls.size()
       << "\tunique_callees=" << Entries.size()
       << "\tskip_callbr=" << SkipCallBr
       << "\tskip_inline_asm=" << SkipInlineAsm
       << "\tskip_musttail=" << SkipMustTail
       << "\tskip_invoke=" << SkipInvoke
       << "\tskip_bundles=" << SkipBundles
       << "\tskip_ehfunc=" << SkipEHFunc
       << "\tskip_shouldskip=" << SkipShouldSkipInst
       << "\tskip_no_direct=" << SkipNoDirect
       << "\tskip_intrinsic=" << SkipIntrinsic
       << "\tskip_avail_extern=" << SkipAvailExtern
       << "\tskip_no_obf_callee=" << SkipNoObfCallee;
    writeIndCallReportLine(buildIndCallReportPath(M), OS.str());
  }

  return changed;
}

static bool transformBranches(Module &M, Function &F, Type *IntPtrTy,
                              SmallPtrSetImpl<Function *> &Changed,
                              SmallPtrSetImpl<Function *> &DumpedBefore,
                              SmallPtrSetImpl<Function *> &InitFns) {
  // EH funclets and unwind edges are fragile under blockaddress/indirectbr
  // rewriting on Windows. Keep indbr out of EH-bearing functions.
  if (functionHasEH(F))
    return false;
  if (F.hasAvailableExternallyLinkage())
    return false;
  if (F.hasComdat())
    return false;
  // Discardable (COMDAT/linkonce) functions can be dropped independently by
  // the linker, which breaks BlockAddress-based branch tables.
  if (F.isDiscardableIfUnused())
    return false;
  bool IsComdat = F.hasComdat();
  SmallVector<BasicBlock *, 16> Targets;
  DenseMap<BasicBlock *, unsigned> Index;

  for (BasicBlock &BB : F) {
    if (shouldSkipBlock(&BB))
      continue;
    if (&BB == &F.getEntryBlock())
      continue;
    unsigned Idx = static_cast<unsigned>(Targets.size());
    Targets.push_back(&BB);
    Index[&BB] = Idx;
  }

  if (Targets.size() < 2)
    return false;

  SmallVector<BranchInst *, 16> Branches;

  for (BasicBlock &BB : F) {
    if (shouldSkipBlock(&BB))
      continue;
    auto *Br = dyn_cast<BranchInst>(BB.getTerminator());
    if (!Br)
      continue;
    if (Br->isUnconditional()) {
      if (!Index.count(Br->getSuccessor(0)))
        continue;
    } else {
      if (!Index.count(Br->getSuccessor(0)) ||
          !Index.count(Br->getSuccessor(1)))
        continue;
    }
    Branches.push_back(Br);
  }

  if (Branches.empty())
    return false;

  GlobalVariable *Table = nullptr;
  GlobalVariable *KeyGVToUse =
      getOrCreatePerFunctionKey(M, F, IntPtrTy, "br");
  if (!KeyGVToUse)
    return false;
  Constant *KeyConst = nullptr;
  if (KeyGVToUse->hasInitializer()) {
    KeyConst = KeyGVToUse->getInitializer();
    if (KeyConst->getType() != IntPtrTy) {
      if (KeyConst->getType()->isIntegerTy() && IntPtrTy->isIntegerTy()) {
        unsigned SrcBits = KeyConst->getType()->getIntegerBitWidth();
        unsigned DstBits = IntPtrTy->getIntegerBitWidth();
        if (SrcBits < DstBits)
          KeyConst = ConstantExpr::getCast(Instruction::ZExt, KeyConst,
                                           IntPtrTy);
        else if (SrcBits > DstBits)
          KeyConst = ConstantExpr::getTrunc(KeyConst, IntPtrTy);
        else
          KeyConst = ConstantExpr::getBitCast(KeyConst, IntPtrTy);
      } else {
        KeyConst = ConstantExpr::getBitCast(KeyConst, IntPtrTy);
      }
    }
  }
  if (IsComdat) {
    Table = buildBlockTableForComdat(M, F, Targets, IntPtrTy, KeyConst);
  } else {
    Table = buildBlockTable(M, F, Targets, IntPtrTy, KeyConst);
  }
  GlobalVariable *EncTable =
      buildBlockTableRuntime(M, F, Targets.size(), IntPtrTy);
  GlobalVariable *StateGV = getOrCreateBlockTableState(M, F);
  Function *InitFn =
      addBlockTableInit(M, F, Table, EncTable, KeyGVToUse, StateGV, IntPtrTy);
  if (InitFn) {
    InitFns.insert(InitFn);
  }

  // COMDAT (linkonce_odr) functions can be discarded by the linker when another
  // TU provides an equivalent definition. Any helpers/state associated with
  // that COMDAT must therefore also be discardable, and initialization must not
  // be driven by a module-level global ctor (which would outlive discarded
  // COMDAT members). For COMDAT functions we always inject an ensure call.
  Function *EnsureFn = nullptr;
  bool NeedEnsure = IndBrLazyInit || F.hasComdat();
  if (NeedEnsure && StateGV && InitFn) {
    EnsureFn = getOrCreateBlockTableEnsure(M, F, StateGV, InitFn);
    if (EnsureFn) {
      Instruction *IP = &*F.getEntryBlock().getFirstInsertionPt();
      IRBuilder<> BE(IP);
      BE.CreateCall(EnsureFn);
    }
  }

  for (BranchInst *Br : Branches) {
    if (!DumpedBefore.contains(&F)) {
      maybeDumpIR(F, "indirect.before");
      DumpedBefore.insert(&F);
    }

    IRBuilder<> B(Br);
    B.SetCurrentDebugLocation(Br->getDebugLoc());
    if (EnsureFn && !F.hasComdat()) {
      CallInst *EnsureCall = B.CreateCall(EnsureFn);
      EnsureCall->setDebugLoc(Br->getDebugLoc());
    }

    Value *IdxVal = nullptr;
    if (Br->isUnconditional()) {
      unsigned idx = Index[Br->getSuccessor(0)];
      IdxVal = ConstantInt::get(Type::getInt32Ty(M.getContext()), idx);
    } else {
      unsigned idxT = Index[Br->getSuccessor(0)];
      unsigned idxF = Index[Br->getSuccessor(1)];
      Value *idxTrue =
          ConstantInt::get(Type::getInt32Ty(M.getContext()), idxT);
      Value *idxFalse =
          ConstantInt::get(Type::getInt32Ty(M.getContext()), idxF);
      IdxVal = B.CreateSelect(Br->getCondition(), idxTrue, idxFalse);
    }

    Value *Zero = ConstantInt::get(Type::getInt32Ty(M.getContext()), 0);
    Value *ElemPtr = B.CreateInBoundsGEP(EncTable->getValueType(), EncTable,
                                         {Zero, IdxVal});
    LoadInst *EncPtr = B.CreateLoad(IntPtrTy, ElemPtr);
    LoadInst *Key = B.CreateLoad(IntPtrTy, KeyGVToUse);
    Key->setVolatile(true);
    Value *DecPtr = B.CreateXor(EncPtr, Key);
    Type *I8PtrTy = PointerType::getUnqual(Type::getInt8Ty(M.getContext()));
    Value *Dest = B.CreateIntToPtr(DecPtr, I8PtrTy);

    SmallVector<BasicBlock *, 2> DestBlocks;
    DestBlocks.push_back(Br->getSuccessor(0));
    if (Br->isConditional() && Br->getSuccessor(1) != Br->getSuccessor(0)) {
      DestBlocks.push_back(Br->getSuccessor(1));
    }
    auto *IB =
        IndirectBrInst::Create(Dest, DestBlocks.size(), Br->getIterator());
    for (BasicBlock *BB : DestBlocks) {
      IB->addDestination(BB);
    }
    Br->eraseFromParent();
    Changed.insert(&F);
  }

  return true;
}

static Function *getOrCreateBlockTableInitAll(Module &M,
                                              ArrayRef<Function *> Inits) {
  if (Inits.empty())
    return nullptr;
  if (Function *Existing = findTaggedFunction(M, "ind.br.table.init.all"))
    return Existing;

  LLVMContext &Ctx = M.getContext();
  FunctionType *FT = FunctionType::get(Type::getVoidTy(Ctx), false);
  Function *InitAll =
      Function::Create(FT, GlobalValue::InternalLinkage, "obf_init_br_tables",
                       &M);
  obfuscateSymbolName(*InitAll, M, "ind.br.table.init.all",
                      "obf_init_br_tables");
  InitAll->addFnAttr(Attribute::NoInline);
  InitAll->addFnAttr(Attribute::OptimizeNone);
  InitAll->addFnAttr("no_obfuscate");
  InitAll->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", InitAll);
  IRBuilder<> B(Entry);
  for (Function *Fn : Inits) {
    if (!Fn)
      continue;
    B.CreateCall(Fn);
  }
  B.CreateRetVoid();
  return InitAll;
}

PreservedAnalyses IndirectBranchPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  bool DoIndirectBranch =
      IndirectBranch || isForcedObfuscationPass("indbr");
  bool DoIndirectCall =
      IndirectCall || isForcedObfuscationPass("indcall");
  if (!DoIndirectBranch && !DoIndirectCall) {
    return PreservedAnalyses::all();
  }

  recordObfuscationSeed(M);

  const DataLayout &DL = M.getDataLayout();
  unsigned PtrBits = DL.getPointerSizeInBits();
  if (PtrBits == 0) {
    return PreservedAnalyses::all();
  }
  Type *IntPtrTy = Type::getIntNTy(M.getContext(), PtrBits);
  bool changed = false;
  SmallPtrSet<Function *, 16> ChangedFuncs;
  SmallPtrSet<Function *, 16> DumpedBefore;
  SmallPtrSet<Function *, 16> BranchInitFns;

  if (DoIndirectBranch) {
    for (Function &F : M) {
      if (shouldSkipFunction(&F))
        continue;
      if (transformBranches(M, F, IntPtrTy, ChangedFuncs, DumpedBefore,
                            BranchInitFns)) {
        changed = true;
      }
    }
  }

  if (DoIndirectCall) {
    if (transformCalls(M, IntPtrTy, ChangedFuncs, DumpedBefore)) {
      changed = true;
    }
  }

  // Eager init via a module-level ctor is only safe for non-COMDAT init
  // functions. COMDAT init functions may be discarded by the linker, but the
  // ctor itself is not discardable and would retain invalid relocations.
  //
  // When indbr-lazy-init is enabled (default), we rely on per-function ensure
  // injection instead of a global ctor.
  if (!IndBrLazyInit && !BranchInitFns.empty()) {
    SmallVector<Function *, 16> Inits;
    Inits.reserve(BranchInitFns.size());
    for (Function *Fn : BranchInitFns) {
      if (!Fn || Fn->hasComdat())
        continue;
      Inits.push_back(Fn);
    }
    if (Function *InitAll = getOrCreateBlockTableInitAll(M, Inits)) {
      prependToGlobalCtors(M, InitAll, 0);
      changed = true;
    }
  }

  for (Function *F : ChangedFuncs) {
    verifyFunctionOrDie(*F, "indirect");
    maybeDumpIR(*F, "indirect.after");
  }

  if (changed) {
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}
