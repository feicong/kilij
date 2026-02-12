//===- IATObfuscation.cpp - IAT obfuscation and resolver -----------------===//
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
// Implements import obfuscation, resolver emission, and import name
// hiding.
//
//===----------------------------------------------------------------------===//
#include "IATObfuscation.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <vector>

using namespace llvm;

#define DEBUG_TYPE "iatobf"

static cl::opt<bool>
    IATObf("obf-iat", cl::init(false),
           cl::desc("Enable IAT/API call obfuscation (Windows-only)"));
static cl::opt<bool>
    IATCache("obf-iat-cache", cl::init(true),
             cl::desc("Cache resolved API pointers in globals"));
static cl::opt<bool>
    IATHideOnly("obf-iat-hide-only", cl::init(false),
                cl::desc("Only obfuscate/hide imports that match hide rules"));
static cl::opt<bool>
    IATLoadMissing("obf-iat-load-missing", cl::init(false),
                   cl::desc("Allow IAT resolver to load missing modules "
                            "via LdrLoadDll (runtime, unsafe under loader lock)"));
static cl::opt<bool>
    IATHideAll("obf-iat-hide-all", cl::init(false),
               cl::desc("Hide all DLL imports (no IAT retention). "
                        "Use with care for stability."));
static cl::opt<bool>
    IATHideExterns("obf-hide-externs", cl::init(false),
                   cl::desc("Obfuscate all external calls (not just dllimport). "
                            "Non-dllimport externs use encoded direct pointers."));
static cl::list<std::string>
    IATHideFn("obf-iat-hide-fn", cl::CommaSeparated,
              cl::desc("Hide specific imported functions (comma-separated)"));
static cl::list<std::string>
    IATHidePfx("obf-iat-hide-pfx", cl::CommaSeparated,
               cl::desc("Hide imported functions by prefix (comma-separated, "
                        "supports '*' suffix for prefix)"));
static cl::list<std::string>
    IATHideMap("obf-iat-hide-map", cl::CommaSeparated,
               cl::desc("Hide imports by module mapping: "
                        "\"dll:Pattern1|Pattern2\" entries"));
enum class IATFailMode { Trap, Null, Fallback };
static cl::opt<IATFailMode> IATFail(
    "obf-iat-fail", cl::init(IATFailMode::Trap),
    cl::desc("IAT resolver failure behavior"),
    cl::values(
        clEnumValN(IATFailMode::Trap, "trap", "Trap on resolver failure"),
        clEnumValN(IATFailMode::Null, "null", "Return null on resolver failure"),
        clEnumValN(IATFailMode::Fallback, "fallback",
                   "Skip obfuscation for non-hidden imports")));
enum class IATBackendMode { Thunk, Resolver };
static cl::opt<IATBackendMode> IATBackend(
    "obf-iat-backend", cl::init(IATBackendMode::Thunk),
    cl::desc("IAT obfuscation backend"),
    cl::values(
        clEnumValN(IATBackendMode::Thunk, "thunk",
                   "Encode import thunk pointer (loader-safe)"),
        clEnumValN(IATBackendMode::Resolver, "resolver",
                   "Runtime export resolver (drops IAT entries)")));
// Inlining eliminates a shared wrapper that would be a single-patch target.
static cl::opt<bool>
    IATInline("obf-iat-inline", cl::init(true),
              cl::desc("Inline per-callsite resolvers to avoid wrapper symbols"));

// FNV-1a with a caller-chosen seed so hash values are build-specific
// and can't be precomputed by static analysis tools.
static uint32_t fnv1aHash(StringRef S, uint32_t Seed) {
  uint32_t H = Seed;
  for (unsigned char C : S) {
    H ^= C;
    H *= 16777619u;
  }
  return H;
}

static uint32_t deriveHashSeed() {
  uint64_t Seed = getObfuscationSeed();
  if (Seed == 0)
    Seed = cryptoutils->get_uint64_t();
  uint32_t S =
      static_cast<uint32_t>(Seed ^ (Seed >> 32) ^ (Seed >> 11));
  if (S == 0)
    S = 0xA5A5A5A5u;
  return S;
}

struct NamePattern {
  std::string Prefix;
  bool PrefixMatch = false;
};

struct EncodedWideString {
  GlobalVariable *GV = nullptr;
  uint32_t Key = 0;
  uint32_t Len = 0;
};

struct HideRule {
  std::string Module;
  uint32_t ModuleHash = 0;
  std::vector<NamePattern> Patterns;
  EncodedWideString EncName;
};

static uint32_t fnv1aHashLower(StringRef S, uint32_t Seed) {
  uint32_t H = Seed;
  for (unsigned char C : S) {
    if (C >= 'A' && C <= 'Z')
      C = static_cast<unsigned char>(C + 32);
    H ^= C;
    H *= 16777619u;
  }
  return H;
}

static NamePattern parsePattern(StringRef S) {
  NamePattern P;
  std::string T = S.trim().str();
  if (T.empty())
    return P;
  if (T.back() == '*') {
    T.pop_back();
    P.PrefixMatch = true;
  }
  P.Prefix = std::move(T);
  return P;
}

static bool matchPattern(StringRef Name, const NamePattern &P) {
  if (P.Prefix.empty())
    return false;
  if (P.PrefixMatch)
    return Name.starts_with(P.Prefix);
  return Name == P.Prefix;
}

static bool matchAny(StringRef Name, const std::vector<NamePattern> &Patterns) {
  for (const auto &P : Patterns) {
    if (matchPattern(Name, P))
      return true;
  }
  return false;
}

static std::string normalizeModuleName(StringRef Mod) {
  std::string S = Mod.trim().lower();
  if (S.empty())
    return S;
  if (!StringRef(S).ends_with(".dll"))
    S += ".dll";
  return S;
}

static uint32_t xorshift32(uint32_t S) {
  S ^= (S << 13);
  S ^= (S >> 17);
  S ^= (S << 5);
  return S;
}

static EncodedWideString buildEncodedWideString(Module &M, StringRef S,
                                                 uint32_t Seed) {
  EncodedWideString Out;
  std::string Str = S.trim().str();
  if (Str.empty())
    return Out;
  uint32_t Key = Seed ^ fnv1aHashLower(Str, Seed);
  if (Key == 0)
    Key = 0x6C8E9CF3u;
  uint32_t State = Key;
  SmallVector<uint16_t, 32> Enc;
  Enc.reserve(Str.size());
  for (unsigned char C : Str) {
    State = xorshift32(State);
    uint16_t W = static_cast<uint16_t>(C);
    uint16_t E = static_cast<uint16_t>(W ^ (State & 0xFFFFu));
    Enc.push_back(E);
  }
  LLVMContext &Ctx = M.getContext();
  ArrayType *ArrTy = ArrayType::get(Type::getInt16Ty(Ctx), Enc.size());
  SmallVector<Constant *, 32> Elems;
  Elems.reserve(Enc.size());
  for (uint16_t V : Enc)
    Elems.push_back(ConstantInt::get(Type::getInt16Ty(Ctx), V));
  Constant *Init = ConstantArray::get(ArrTy, Elems);
  uint32_t ModHash = fnv1aHashLower(Str, Seed);
  std::string GVName = "iat_mod_" + utohexstr(ModHash);
  auto *GV = new GlobalVariable(M, ArrTy, true, GlobalValue::PrivateLinkage,
                                Init, GVName);
  GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  std::string Tag = "iat.mod." + utohexstr(ModHash);
  obfuscateSymbolName(*GV, M, Tag, GVName);
  Out.GV = GV;
  Out.Key = Key;
  Out.Len = static_cast<uint32_t>(Enc.size());
  return Out;
}

// All PEB/PE struct accesses use integer arithmetic + inttoptr loads so
// LLVM's alias analysis can't prove anything about these accesses and
// won't reorder or eliminate them.
static Value *loadPtr(IRBuilder<> &B, Value *BaseInt, uint64_t Off,
                      IntegerType *IntPtrTy) {
  Value *Addr = B.CreateAdd(BaseInt, ConstantInt::get(IntPtrTy, Off));
  Value *Ptr =
      B.CreateIntToPtr(Addr, PointerType::getUnqual(IntPtrTy));
  return B.CreateLoad(IntPtrTy, Ptr);
}

static Value *loadI32(IRBuilder<> &B, Value *BaseInt, uint64_t Off) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *IntPtrTy = Type::getIntNTy(Ctx, B.GetInsertBlock()
                                                   ->getModule()
                                                   ->getDataLayout()
                                                   .getPointerSizeInBits());
  Value *Addr = B.CreateAdd(BaseInt, ConstantInt::get(IntPtrTy, Off));
  Value *Ptr = B.CreateIntToPtr(Addr, PointerType::getUnqual(I32Ty));
  return B.CreateLoad(I32Ty, Ptr);
}

static Value *loadI16(IRBuilder<> &B, Value *BaseInt, uint64_t Off) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I16Ty = Type::getInt16Ty(Ctx);
  IntegerType *IntPtrTy = Type::getIntNTy(Ctx, B.GetInsertBlock()
                                                   ->getModule()
                                                   ->getDataLayout()
                                                   .getPointerSizeInBits());
  Value *Addr = B.CreateAdd(BaseInt, ConstantInt::get(IntPtrTy, Off));
  Value *Ptr = B.CreateIntToPtr(Addr, PointerType::getUnqual(I16Ty));
  return B.CreateLoad(I16Ty, Ptr);
}

static Value *loadI32At(IRBuilder<> &B, Value *AddrInt) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Value *Ptr = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(I32Ty));
  return B.CreateLoad(I32Ty, Ptr);
}

static Value *loadI16At(IRBuilder<> &B, Value *AddrInt) {
  LLVMContext &Ctx = B.getContext();
  IntegerType *I16Ty = Type::getInt16Ty(Ctx);
  Value *Ptr = B.CreateIntToPtr(AddrInt, PointerType::getUnqual(I16Ty));
  return B.CreateLoad(I16Ty, Ptr);
}

static Function *getOrCreateHashFunc(Module &M, uint32_t Seed) {
  if (Function *F = findTaggedFunction(M, "iat.hash"))
    return F;

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);
  FunctionType *FT = FunctionType::get(I32Ty, {I8PtrTy}, false);
  Function *F =
      Function::Create(FT, GlobalValue::PrivateLinkage, "iat_hash_cstr", &M);
  obfuscateSymbolName(*F, M, "iat.hash", "iat_hash_cstr");
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);

  IRBuilder<> B(Entry);
  Value *Ptr = F->getArg(0);
  Value *H = ConstantInt::get(I32Ty, Seed);
  B.CreateBr(Loop);

  IRBuilder<> BL(Loop);
  PHINode *PH = BL.CreatePHI(I32Ty, 2);
  PHINode *PP = BL.CreatePHI(I8PtrTy, 2);
  PH->addIncoming(H, Entry);
  PP->addIncoming(Ptr, Entry);
  Value *Ch = BL.CreateLoad(I8Ty, PP);
  Value *IsZero =
      BL.CreateICmpEQ(Ch, ConstantInt::get(I8Ty, 0));
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BL.CreateCondBr(IsZero, Done, Body);

  IRBuilder<> BB(Body);
  Value *Ch32 = BB.CreateZExt(Ch, I32Ty);
  Value *H1 = BB.CreateXor(PH, Ch32);
  Value *H2 = BB.CreateMul(H1, ConstantInt::get(I32Ty, 16777619u));
  Value *NextPtr =
      BB.CreateInBoundsGEP(I8Ty, PP, ConstantInt::get(I32Ty, 1));
  PH->addIncoming(H2, Body);
  PP->addIncoming(NextPtr, Body);
  BB.CreateBr(Loop);

  IRBuilder<> BD(Done);
  BD.CreateRet(PH);
  return F;
}

// Case-insensitive variant for DLL module name matching -- Windows module
// names are case-insensitive but PE export names are not.
static Function *getOrCreateHashFuncLower(Module &M, uint32_t Seed) {
  if (Function *F = findTaggedFunction(M, "iat.hash.lower"))
    return F;

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);
  FunctionType *FT = FunctionType::get(I32Ty, {I8PtrTy}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage,
                                 "iat_hash_cstr_lower", &M);
  obfuscateSymbolName(*F, M, "iat.hash.lower", "iat_hash_cstr_lower");
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);

  IRBuilder<> B(Entry);
  Value *Ptr = F->getArg(0);
  Value *H = ConstantInt::get(I32Ty, Seed);
  B.CreateBr(Loop);

  IRBuilder<> BL(Loop);
  PHINode *PH = BL.CreatePHI(I32Ty, 2);
  PHINode *PP = BL.CreatePHI(I8PtrTy, 2);
  PH->addIncoming(H, Entry);
  PP->addIncoming(Ptr, Entry);
  Value *Ch = BL.CreateLoad(I8Ty, PP);
  Value *IsZero = BL.CreateICmpEQ(Ch, ConstantInt::get(I8Ty, 0));
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BL.CreateCondBr(IsZero, Done, Body);

  IRBuilder<> BB(Body);
  Value *IsUpperA = BB.CreateICmpUGE(Ch, ConstantInt::get(I8Ty, 'A'));
  Value *IsUpperZ = BB.CreateICmpULE(Ch, ConstantInt::get(I8Ty, 'Z'));
  Value *IsUpper = BB.CreateAnd(IsUpperA, IsUpperZ);
  Value *Lower = BB.CreateOr(Ch, ConstantInt::get(I8Ty, 0x20));
  Value *ChLower = BB.CreateSelect(IsUpper, Lower, Ch);
  Value *Ch32 = BB.CreateZExt(ChLower, I32Ty);
  Value *H1 = BB.CreateXor(PH, Ch32);
  Value *H2 = BB.CreateMul(H1, ConstantInt::get(I32Ty, 16777619u));
  Value *NextPtr =
      BB.CreateInBoundsGEP(I8Ty, PP, ConstantInt::get(I32Ty, 1));
  PH->addIncoming(H2, Body);
  PP->addIncoming(NextPtr, Body);
  BB.CreateBr(Loop);

  IRBuilder<> BD(Done);
  BD.CreateRet(PH);
  return F;
}

// Parse a forwarder string "module.dll.FuncName" into (moduleHash, funcHash)
// packed in a single i64 so the resolver can restart its PEB walk.
// Ordinal forwarders like "module.dll.#42" set bit 31 in the func half.
static Function *getOrCreateForwarderHashFunc(Module &M, uint32_t Seed) {
  if (Function *F = findTaggedFunction(M, "iat.hash.fwd"))
    return F;

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I64Ty = Type::getInt64Ty(Ctx);
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);
  FunctionType *FT = FunctionType::get(I64Ty, {I8PtrTy}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage,
                                 "iat_hash_forwarder", &M);
  obfuscateSymbolName(*F, M, "iat.hash.fwd", "iat_hash_forwarder");
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *ModLoop = BasicBlock::Create(Ctx, "mod.loop", F);
  BasicBlock *ModBody = BasicBlock::Create(Ctx, "mod.body", F);
  BasicBlock *ModDone = BasicBlock::Create(Ctx, "mod.done", F);
  BasicBlock *FnLoop = BasicBlock::Create(Ctx, "fn.loop", F);
  BasicBlock *FnBody = BasicBlock::Create(Ctx, "fn.body", F);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);

  IRBuilder<> B(Entry);
  Value *Ptr = F->getArg(0);
  Value *ModH = ConstantInt::get(I32Ty, Seed);
  Value *FnH = ConstantInt::get(I32Ty, Seed);
  Value *Tail = ConstantInt::get(I32Ty, 0);
  B.CreateBr(ModLoop);

  IRBuilder<> BML(ModLoop);
  PHINode *PHPtr = BML.CreatePHI(I8PtrTy, 2);
  PHINode *PHMod = BML.CreatePHI(I32Ty, 2);
  PHINode *PHTail = BML.CreatePHI(I32Ty, 2);
  PHPtr->addIncoming(Ptr, Entry);
  PHMod->addIncoming(ModH, Entry);
  PHTail->addIncoming(Tail, Entry);
  Value *Ch = BML.CreateLoad(I8Ty, PHPtr);
  Value *IsZero = BML.CreateICmpEQ(Ch, ConstantInt::get(I8Ty, 0));
  Value *IsDotCh = BML.CreateICmpEQ(Ch, ConstantInt::get(I8Ty, '.'));
  Value *Stop = BML.CreateOr(IsZero, IsDotCh);
  BML.CreateCondBr(Stop, ModDone, ModBody);

  IRBuilder<> BMB(ModBody);
  Value *IsUpperA = BMB.CreateICmpUGE(Ch, ConstantInt::get(I8Ty, 'A'));
  Value *IsUpperZ = BMB.CreateICmpULE(Ch, ConstantInt::get(I8Ty, 'Z'));
  Value *IsUpper = BMB.CreateAnd(IsUpperA, IsUpperZ);
  Value *Lower = BMB.CreateOr(Ch, ConstantInt::get(I8Ty, 0x20));
  Value *ChLower = BMB.CreateSelect(IsUpper, Lower, Ch);
  Value *Ch32 = BMB.CreateZExt(ChLower, I32Ty);
  Value *H1 = BMB.CreateXor(PHMod, Ch32);
  Value *H2 = BMB.CreateMul(H1, ConstantInt::get(I32Ty, 16777619u));
  Value *NextPtr =
      BMB.CreateInBoundsGEP(I8Ty, PHPtr, ConstantInt::get(I32Ty, 1));
  Value *TailShl = BMB.CreateShl(PHTail, ConstantInt::get(I32Ty, 8));
  Value *TailNext = BMB.CreateOr(TailShl, Ch32);
  PHPtr->addIncoming(NextPtr, ModBody);
  PHMod->addIncoming(H2, ModBody);
  PHTail->addIncoming(TailNext, ModBody);
  BMB.CreateBr(ModLoop);

  IRBuilder<> BMD(ModDone);
  PHINode *PHModDone = BMD.CreatePHI(I32Ty, 2);
  PHINode *PHTailDone = BMD.CreatePHI(I32Ty, 2);
  PHINode *PHPtrDone = BMD.CreatePHI(I8PtrTy, 2);
  PHModDone->addIncoming(PHMod, ModLoop);
  PHTailDone->addIncoming(PHTail, ModLoop);
  PHPtrDone->addIncoming(PHPtr, ModLoop);
  Value *DotCh = BMD.CreateLoad(I8Ty, PHPtrDone);
  Value *IsDot =
      BMD.CreateICmpEQ(DotCh, ConstantInt::get(I8Ty, '.'));
  BasicBlock *HasDot = BasicBlock::Create(Ctx, "mod.hasdot", F);
  BasicBlock *NoDot = BasicBlock::Create(Ctx, "mod.nodot", F);
  BMD.CreateCondBr(IsDot, HasDot, NoDot);

  IRBuilder<> BN(NoDot);
  BN.CreateRet(ConstantInt::get(I64Ty, 0));

  IRBuilder<> BHD(HasDot);
  Value *TailCmp =
      BHD.CreateICmpEQ(PHTailDone,
                       ConstantInt::get(I32Ty, 0x2E646C6C)); // ".dll"
  Value *ModHFinal = PHModDone;
  {
    // Forwarder module names sometimes omit ".dll"; append it when missing
    // so the hash matches our normalized module hashes.
    BasicBlock *Append = BasicBlock::Create(Ctx, "mod.append", F);
    BasicBlock *Skip = BasicBlock::Create(Ctx, "mod.skip", F);
    BHD.CreateCondBr(TailCmp, Skip, Append);

    IRBuilder<> BA(Append);
    auto appendChar = [&](char C, Value *Cur) {
      Value *C32 = ConstantInt::get(I32Ty, static_cast<uint8_t>(C));
      Value *H1 = BA.CreateXor(Cur, C32);
      return BA.CreateMul(H1, ConstantInt::get(I32Ty, 16777619u));
    };
    Value *HApp = PHModDone;
    HApp = appendChar('.', HApp);
    HApp = appendChar('d', HApp);
    HApp = appendChar('l', HApp);
    HApp = appendChar('l', HApp);
    BA.CreateBr(Skip);

    IRBuilder<> BS(Skip);
    PHINode *PHApp = BS.CreatePHI(I32Ty, 2);
    PHApp->addIncoming(PHModDone, HasDot);
    PHApp->addIncoming(HApp, Append);
    ModHFinal = PHApp;
    Value *PtrPlus =
        BS.CreateInBoundsGEP(I8Ty, PHPtrDone, ConstantInt::get(I32Ty, 1));
    Value *FnPtr = PtrPlus;
    Value *FirstCh = BS.CreateLoad(I8Ty, FnPtr);
    Value *IsOrd = BS.CreateICmpEQ(FirstCh, ConstantInt::get(I8Ty, '#'));
    BasicBlock *OrdParse = BasicBlock::Create(Ctx, "fn.ord", F);
    BasicBlock *OrdLoop = BasicBlock::Create(Ctx, "fn.ord.loop", F);
    BasicBlock *OrdBody = BasicBlock::Create(Ctx, "fn.ord.body", F);
    BasicBlock *OrdDone = BasicBlock::Create(Ctx, "fn.ord.done", F);
    BasicBlock *OrdOk = BasicBlock::Create(Ctx, "fn.ord.ok", F);
    BasicBlock *OrdBad = BasicBlock::Create(Ctx, "fn.ord.bad", F);
    BS.CreateCondBr(IsOrd, OrdParse, FnLoop);

    IRBuilder<> BOP(OrdParse);
    Value *OrdPtr =
        BOP.CreateInBoundsGEP(I8Ty, FnPtr, ConstantInt::get(I32Ty, 1));
    BOP.CreateBr(OrdLoop);

    IRBuilder<> BOL(OrdLoop);
    PHINode *PHOPtr = BOL.CreatePHI(I8PtrTy, 2);
    PHINode *PHOrd = BOL.CreatePHI(I32Ty, 2);
    PHINode *PHSeen = BOL.CreatePHI(Type::getInt1Ty(Ctx), 2);
    PHOPtr->addIncoming(OrdPtr, OrdParse);
    PHOrd->addIncoming(ConstantInt::get(I32Ty, 0), OrdParse);
    PHSeen->addIncoming(ConstantInt::getFalse(Ctx), OrdParse);
    Value *OCh = BOL.CreateLoad(I8Ty, PHOPtr);
    Value *IsDigitLo = BOL.CreateICmpUGE(OCh, ConstantInt::get(I8Ty, '0'));
    Value *IsDigitHi = BOL.CreateICmpULE(OCh, ConstantInt::get(I8Ty, '9'));
    Value *IsDigit = BOL.CreateAnd(IsDigitLo, IsDigitHi);
    BOL.CreateCondBr(IsDigit, OrdBody, OrdDone);

    IRBuilder<> BOB(OrdBody);
    Value *Digit =
        BOB.CreateSub(BOB.CreateZExt(OCh, I32Ty),
                      ConstantInt::get(I32Ty, '0'));
    Value *OrdMul = BOB.CreateMul(PHOrd, ConstantInt::get(I32Ty, 10));
    Value *OrdNext = BOB.CreateAdd(OrdMul, Digit);
    Value *NextPtr =
        BOB.CreateInBoundsGEP(I8Ty, PHOPtr, ConstantInt::get(I32Ty, 1));
    PHOPtr->addIncoming(NextPtr, OrdBody);
    PHOrd->addIncoming(OrdNext, OrdBody);
    PHSeen->addIncoming(ConstantInt::getTrue(Ctx), OrdBody);
    BOB.CreateBr(OrdLoop);

    IRBuilder<> BOD(OrdDone);
    Value *Seen = PHSeen;
    Value *HasDigits =
        BOD.CreateAnd(Seen,
                      BOD.CreateICmpNE(PHOrd, ConstantInt::get(I32Ty, 0)));
    BOD.CreateCondBr(HasDigits, OrdOk, OrdBad);

    IRBuilder<> BOk(OrdOk);
    Value *OrdMasked =
        BOk.CreateAnd(PHOrd, ConstantInt::get(I32Ty, 0x7FFFFFFFu));
    Value *FnTag =
        BOk.CreateOr(OrdMasked, ConstantInt::get(I32Ty, 0x80000000u));
    Value *Mod64Ord = BOk.CreateZExt(ModHFinal, I64Ty);
    Value *Fn64Ord = BOk.CreateZExt(FnTag, I64Ty);
    Value *OutOrd = BOk.CreateOr(BOk.CreateShl(Mod64Ord, 32), Fn64Ord);
    BOk.CreateRet(OutOrd);

    IRBuilder<> BBad(OrdBad);
    BBad.CreateRet(ConstantInt::get(I64Ty, 0));

    IRBuilder<> BFL(FnLoop);
    PHINode *PHFPtr = BFL.CreatePHI(I8PtrTy, 2);
    PHINode *PHFn = BFL.CreatePHI(I32Ty, 2);
    PHFPtr->addIncoming(FnPtr, Skip);
    PHFn->addIncoming(FnH, Skip);
    Value *FCh = BFL.CreateLoad(I8Ty, PHFPtr);
    Value *FIsZero = BFL.CreateICmpEQ(FCh, ConstantInt::get(I8Ty, 0));
    BFL.CreateCondBr(FIsZero, Done, FnBody);

    IRBuilder<> BFB(FnBody);
    Value *FCh32 = BFB.CreateZExt(FCh, I32Ty);
    Value *FH1 = BFB.CreateXor(PHFn, FCh32);
    Value *FH2 = BFB.CreateMul(FH1, ConstantInt::get(I32Ty, 16777619u));
    Value *FNextPtr =
        BFB.CreateInBoundsGEP(I8Ty, PHFPtr, ConstantInt::get(I32Ty, 1));
    PHFPtr->addIncoming(FNextPtr, FnBody);
    PHFn->addIncoming(FH2, FnBody);
    BFB.CreateBr(FnLoop);

    IRBuilder<> BD(Done);
    Value *Mod64Name = BD.CreateZExt(ModHFinal, I64Ty);
    Value *Fn64Name = BD.CreateZExt(PHFn, I64Ty);
    Value *OutName = BD.CreateOr(BD.CreateShl(Mod64Name, 32), Fn64Name);
    BD.CreateRet(OutName);
    return F;
  }

  IRBuilder<> BD(Done);
  BD.CreateRet(ConstantInt::get(I64Ty, 0));
  return F;
}

static Value *emitXorShift32(IRBuilder<> &B, Value *S) {
  Value *X = B.CreateXor(S, B.CreateShl(S, 13));
  X = B.CreateXor(X, B.CreateLShr(X, 17));
  X = B.CreateXor(X, B.CreateShl(X, 5));
  return X;
}

static Value *emitDecodeWideString(IRBuilder<> &B,
                                   const EncodedWideString &Enc,
                                   IntegerType *I16Ty,
                                   IntegerType *I32Ty) {
  ArrayType *BufTy = ArrayType::get(I16Ty, Enc.Len + 1);
  AllocaInst *Buf = B.CreateAlloca(BufTy);
  Value *Zero = ConstantInt::get(I32Ty, 0);
  Value *BufPtr = B.CreateInBoundsGEP(BufTy, Buf, {Zero, Zero});

  Value *State = ConstantInt::get(I32Ty, Enc.Key);
  for (uint32_t i = 0; i < Enc.Len; ++i) {
    State = emitXorShift32(B, State);
    Value *Idx = ConstantInt::get(I32Ty, i);
    Value *EncPtr =
        B.CreateInBoundsGEP(Enc.GV->getValueType(), Enc.GV, {Zero, Idx});
    Value *EncVal = B.CreateLoad(I16Ty, EncPtr);
    Value *Key16 = B.CreateTrunc(State, I16Ty);
    Value *Dec = B.CreateXor(EncVal, Key16);
    Value *DstPtr = B.CreateInBoundsGEP(BufTy, Buf, {Zero, Idx});
    B.CreateStore(Dec, DstPtr);
  }
  Value *NullPtr =
      B.CreateInBoundsGEP(BufTy, Buf,
                          {Zero, ConstantInt::get(I32Ty, Enc.Len)});
  B.CreateStore(ConstantInt::get(I16Ty, 0), NullPtr);
  return BufPtr;
}

// Emit a PEB-walking runtime resolver for a single (module, function) pair.
// Walks InMemoryOrderModuleList, checks export directories by hash, and
// follows PE export forwarder chains up to depth 4.  Optionally loads
// missing modules via LdrLoadDll when the caller opts in.
static Function *getOrCreateResolver(Module &M, uint32_t TargetHash,
                                     uint32_t ModuleHash,
                                     const EncodedWideString *EncMod,
                                     bool CanLoadMissing,
                                     IATFailMode FailMode, Function *HashFn,
                                     Function *HashFnLower, Function *FwdHashFn,
                                     Function *LdrResolver) {
  bool EnableLoad = CanLoadMissing && EncMod && EncMod->GV;
  std::string Tag = "iat.resolve." + utohexstr(TargetHash);
  if (ModuleHash != 0)
    Tag += "." + utohexstr(ModuleHash);
  if (EnableLoad)
    Tag += ".ld";
  if (FailMode == IATFailMode::Null)
    Tag += ".null";
  if (Function *F = findTaggedFunction(M, Tag))
    return F;

  LLVMContext &Ctx = M.getContext();
  const DataLayout &DL = M.getDataLayout();
  unsigned PtrBits = DL.getPointerSizeInBits();
  if (PtrBits != 64) {
    return nullptr;
  }
  IntegerType *IntPtrTy = Type::getInt64Ty(Ctx);
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  IntegerType *I16Ty = Type::getInt16Ty(Ctx);
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);

  FunctionType *FT = FunctionType::get(I8PtrTy, {}, false);
  Function *F =
      Function::Create(FT, GlobalValue::PrivateLinkage, "iat_resolve", &M);
  obfuscateSymbolName(*F, M, Tag, "iat_resolve");
  if (IATInline)
    F->addFnAttr(Attribute::AlwaysInline);
  else
    F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr(Attribute::NoUnwind);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);

  GlobalVariable *CacheGV = nullptr;
  if (IATCache) {
    std::string CacheTag = "iat.cache." + utohexstr(TargetHash);
    if (ModuleHash != 0)
      CacheTag += "." + utohexstr(ModuleHash);
    if (EnableLoad)
      CacheTag += ".ld";
    CacheGV = findTaggedGlobal(M, CacheTag);
    if (!CacheGV) {
      CacheGV = new GlobalVariable(
          M, I8PtrTy, false, GlobalValue::PrivateLinkage,
          ConstantPointerNull::get(cast<PointerType>(I8PtrTy)), "iat_cache");
      CacheGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      obfuscateSymbolName(*CacheGV, M, CacheTag, "iat_cache");
    }
  }

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *ResolveEntry = Entry;
  BasicBlock *RetCache = nullptr;
  if (CacheGV) {
    ResolveEntry = BasicBlock::Create(Ctx, "resolve", F);
    RetCache = BasicBlock::Create(Ctx, "retcache", F);
    IRBuilder<> BCache(Entry);
    Value *Cached = BCache.CreateLoad(I8PtrTy, CacheGV);
    Value *IsNull = BCache.CreateICmpEQ(
        Cached, ConstantPointerNull::get(cast<PointerType>(I8PtrTy)));
    BCache.CreateCondBr(IsNull, ResolveEntry, RetCache);
    IRBuilder<> BR(RetCache);
    BR.CreateRet(Cached);
  }
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *ModBody = BasicBlock::Create(Ctx, "mod", F);
  BasicBlock *ModCheck = BasicBlock::Create(Ctx, "modchk", F);
  BasicBlock *Dispatch = BasicBlock::Create(Ctx, "dispatch", F);
  BasicBlock *OrdLookup = BasicBlock::Create(Ctx, "ord", F);
  BasicBlock *NameLoop = BasicBlock::Create(Ctx, "nloop", F);
  BasicBlock *NameBody = BasicBlock::Create(Ctx, "nbody", F);
  BasicBlock *NextMod = BasicBlock::Create(Ctx, "next", F);
  BasicBlock *Found = BasicBlock::Create(Ctx, "found", F);
  BasicBlock *OrdFound = BasicBlock::Create(Ctx, "ord.found", F);
  BasicBlock *CheckFwd = BasicBlock::Create(Ctx, "check", F);
  BasicBlock *Ret = BasicBlock::Create(Ctx, "ret", F);
  BasicBlock *Forwarded = BasicBlock::Create(Ctx, "fwd", F);
  BasicBlock *Fail = BasicBlock::Create(Ctx, "fail", F);
  BasicBlock *RetFail = BasicBlock::Create(Ctx, "retfail", F);
  BasicBlock *LoadBB = EnableLoad ? BasicBlock::Create(Ctx, "load", F) : nullptr;

  IRBuilder<> B(ResolveEntry);
  AllocaInst *Tried = nullptr;
  if (EnableLoad) {
    Tried = B.CreateAlloca(Type::getInt1Ty(Ctx));
    B.CreateStore(ConstantInt::getFalse(Ctx), Tried);
  }
  // Walk the PEB directly instead of calling GetModuleHandle/GetProcAddress
  // so the resolver has no IAT dependency of its own to break the cycle.
  // GS:0x60 is the PEB pointer on x64 Windows.
  InlineAsm *Asm =
      InlineAsm::get(FunctionType::get(IntPtrTy, {}, false),
                     "mov %gs:0x60, $0", "=r", true);
  Value *Peb = B.CreateCall(Asm);
  Value *Ldr = loadPtr(B, Peb, 0x18, IntPtrTy);
  Value *List = B.CreateAdd(Ldr, ConstantInt::get(IntPtrTy, 0x20));
  Value *Head = List;
  Value *Cur = loadPtr(B, Head, 0x0, IntPtrTy);
  // Track current target/module hashes in allocas so forwarder chains
  // can update them in-place without recursion (bounded by FwdDepth).
  AllocaInst *CurTarget = B.CreateAlloca(I32Ty);
  B.CreateStore(ConstantInt::get(I32Ty, TargetHash), CurTarget);
  AllocaInst *CurModule = B.CreateAlloca(I32Ty);
  B.CreateStore(ConstantInt::get(I32Ty, ModuleHash), CurModule);
  AllocaInst *CurIsOrdinal = B.CreateAlloca(Type::getInt1Ty(Ctx));
  B.CreateStore(ConstantInt::getFalse(Ctx), CurIsOrdinal);
  AllocaInst *FwdDepth = B.CreateAlloca(I32Ty);
  B.CreateStore(ConstantInt::get(I32Ty, 0), FwdDepth);
  B.CreateBr(Loop);

  IRBuilder<> BL(Loop);
  PHINode *CurPH = BL.CreatePHI(IntPtrTy, 2);
  CurPH->addIncoming(Cur, ResolveEntry);
  Value *IsEnd = BL.CreateICmpEQ(CurPH, Head);
  BL.CreateCondBr(IsEnd, Fail, ModBody);

  // Walk x64 PE structures: InMemoryOrderLinks sits at +0x10 inside
  // LDR_DATA_TABLE_ENTRY, so subtract to get the entry base.
  IRBuilder<> BM(ModBody);
  Value *EntryPtr = BM.CreateSub(CurPH, ConstantInt::get(IntPtrTy, 0x10));
  // DllBase at +0x30; DOS.e_lfanew at +0x3c gives NT header offset.
  Value *Base = loadPtr(BM, EntryPtr, 0x30, IntPtrTy);
  Value *ELfanew = loadI32(BM, Base, 0x3c);
  Value *ELfanew64 = BM.CreateZExt(ELfanew, IntPtrTy);
  Value *Nt = BM.CreateAdd(Base, ELfanew64);
  // NT OptionalHeader DataDirectory[0] (exports) at +0x88/+0x8c.
  Value *ExpRva = loadI32(BM, Nt, 0x88);
  Value *ExpSize = loadI32(BM, Nt, 0x8c);
  Value *HasExp =
      BM.CreateICmpNE(ExpRva, ConstantInt::get(I32Ty, 0));
  BM.CreateCondBr(HasExp, ModCheck, NextMod);

  IRBuilder<> BMC(ModCheck);
  Value *CurModVal = BMC.CreateLoad(I32Ty, CurModule);
  Value *NeedCheck =
      BMC.CreateICmpNE(CurModVal, ConstantInt::get(I32Ty, 0));
  BasicBlock *DoCheck = BasicBlock::Create(Ctx, "mod.check", F);
  BasicBlock *SkipCheck = BasicBlock::Create(Ctx, "mod.skip", F);
  BMC.CreateCondBr(NeedCheck, DoCheck, SkipCheck);

  IRBuilder<> BSkip(SkipCheck);
  BSkip.CreateBr(Dispatch);

  IRBuilder<> BDo(DoCheck);
  Value *ExpRvaZMod = BDo.CreateZExt(ExpRva, IntPtrTy);
  Value *ExpMod = BDo.CreateAdd(Base, ExpRvaZMod);
  Value *ModNameRva = loadI32(BDo, ExpMod, 0x0c);
  Value *ModNamePtr =
      BDo.CreateAdd(Base, BDo.CreateZExt(ModNameRva, IntPtrTy));
  Value *ModNameStr = BDo.CreateIntToPtr(ModNamePtr, I8PtrTy);
  Value *ModHash = BDo.CreateCall(HashFnLower, {ModNameStr});
  Value *IsMod = BDo.CreateICmpEQ(ModHash, CurModVal);
  BDo.CreateCondBr(IsMod, Dispatch, NextMod);

  IRBuilder<> BDsp(Dispatch);
  Value *IsOrd = BDsp.CreateLoad(Type::getInt1Ty(Ctx), CurIsOrdinal);
  BDsp.CreateCondBr(IsOrd, OrdLookup, NameLoop);

  IRBuilder<> BN(NameLoop);
  PHINode *Idx = BN.CreatePHI(I32Ty, 2);
  Idx->addIncoming(ConstantInt::get(I32Ty, 0), Dispatch);

  Value *ExpRvaZName = BN.CreateZExt(ExpRva, IntPtrTy);
  Value *ExpName = BN.CreateAdd(Base, ExpRvaZName);
  Value *NameCount = loadI32(BN, ExpName, 0x18);
  Value *NamesRva = loadI32(BN, ExpName, 0x20);
  Value *OrdsRva = loadI32(BN, ExpName, 0x24);
  Value *FuncsRva = loadI32(BN, ExpName, 0x1c);
  Value *Cond =
      BN.CreateICmpULT(Idx, NameCount);
  BN.CreateCondBr(Cond, NameBody, NextMod);

  Value *ExpOrd = nullptr;
  Value *OrdAdj = nullptr;
  Value *FuncPtrOrd = nullptr;
  IRBuilder<> BO(OrdLookup);
  Value *OrdVal = BO.CreateLoad(I32Ty, CurTarget);
  Value *ExpRvaZOrd = BO.CreateZExt(ExpRva, IntPtrTy);
  ExpOrd = BO.CreateAdd(Base, ExpRvaZOrd);
  Value *BaseOrd = loadI32(BO, ExpOrd, 0x10);
  Value *NumFuncs = loadI32(BO, ExpOrd, 0x14);
  OrdAdj = BO.CreateSub(OrdVal, BaseOrd);
  Value *OrdGe = BO.CreateICmpUGE(OrdVal, BaseOrd);
  Value *OrdLt = BO.CreateICmpULT(OrdAdj, NumFuncs);
  Value *OrdInRange = BO.CreateAnd(OrdGe, OrdLt);
  BO.CreateCondBr(OrdInRange, OrdFound, NextMod);

  IRBuilder<> BOF(OrdFound);
  Value *FuncsRvaOrd = loadI32(BOF, ExpOrd, 0x1c);
  Value *FuncsBaseOrd =
      BOF.CreateAdd(Base, BOF.CreateZExt(FuncsRvaOrd, IntPtrTy));
  Value *OrdAdjZ = BOF.CreateZExt(OrdAdj, IntPtrTy);
  Value *FuncAddrOrd =
      BOF.CreateAdd(FuncsBaseOrd,
                    BOF.CreateMul(OrdAdjZ, ConstantInt::get(IntPtrTy, 4)));
  Value *FuncRvaOrd = loadI32At(BOF, FuncAddrOrd);
  FuncPtrOrd = BOF.CreateAdd(Base, BOF.CreateZExt(FuncRvaOrd, IntPtrTy));
  BOF.CreateBr(CheckFwd);

  IRBuilder<> NB(NameBody);
  Value *Idx64 = NB.CreateZExt(Idx, IntPtrTy);
  Value *NamesBase = NB.CreateAdd(Base, NB.CreateZExt(NamesRva, IntPtrTy));
  Value *NamePtrRvaAddr =
      NB.CreateAdd(NamesBase, NB.CreateMul(Idx64, ConstantInt::get(IntPtrTy, 4)));
  Value *NameRva = loadI32At(NB, NamePtrRvaAddr);
  Value *NamePtr =
      NB.CreateAdd(Base, NB.CreateZExt(NameRva, IntPtrTy));
  Value *NameStr = NB.CreateIntToPtr(NamePtr, I8PtrTy);
  Value *NameHash = NB.CreateCall(HashFn, {NameStr});
  Value *CurTargetVal = NB.CreateLoad(I32Ty, CurTarget);
  Value *Match =
      NB.CreateICmpEQ(NameHash, CurTargetVal);
  Value *NextIdx = NB.CreateAdd(Idx, ConstantInt::get(I32Ty, 1));
  Idx->addIncoming(NextIdx, NameBody);
  NB.CreateCondBr(Match, Found, NameLoop);

  Value *FuncPtrName = nullptr;
  PHINode *FuncPtrPhi = nullptr;
  IRBuilder<> BF(Found);
  Value *OrdsBase = BF.CreateAdd(Base, BF.CreateZExt(OrdsRva, IntPtrTy));
  Value *OrdAddr =
      BF.CreateAdd(OrdsBase, BF.CreateMul(Idx64, ConstantInt::get(IntPtrTy, 2)));
  Value *Ord16 = loadI16At(BF, OrdAddr);
  Value *Ord32 = BF.CreateZExt(Ord16, I32Ty);
  Value *FuncsBase = BF.CreateAdd(Base, BF.CreateZExt(FuncsRva, IntPtrTy));
  Value *FuncAddr =
      BF.CreateAdd(FuncsBase,
                   BF.CreateMul(BF.CreateZExt(Ord32, IntPtrTy),
                                ConstantInt::get(IntPtrTy, 4)));
  Value *FuncRva = loadI32At(BF, FuncAddr);
  FuncPtrName = BF.CreateAdd(Base, BF.CreateZExt(FuncRva, IntPtrTy));
  BF.CreateBr(CheckFwd);

  IRBuilder<> BCheck(CheckFwd);
  FuncPtrPhi = BCheck.CreatePHI(IntPtrTy, 2);
  FuncPtrPhi->addIncoming(FuncPtrName, Found);
  FuncPtrPhi->addIncoming(FuncPtrOrd, OrdFound);
  Value *ExpRvaZChk = BCheck.CreateZExt(ExpRva, IntPtrTy);
  Value *ExpChk = BCheck.CreateAdd(Base, ExpRvaZChk);
  Value *ExpSizeZ = BCheck.CreateZExt(ExpSize, IntPtrTy);
  Value *ExpEnd = BCheck.CreateAdd(ExpChk, ExpSizeZ);
  Value *IsFwdLow = BCheck.CreateICmpUGE(FuncPtrPhi, ExpChk);
  Value *IsFwdHigh = BCheck.CreateICmpULT(FuncPtrPhi, ExpEnd);
  Value *IsForwarded = BCheck.CreateAnd(IsFwdLow, IsFwdHigh);
  BCheck.CreateCondBr(IsForwarded, Forwarded, Ret);

  IRBuilder<> BR(Ret);
  Value *OutPtr = BR.CreateIntToPtr(FuncPtrPhi, I8PtrTy);
  if (CacheGV)
    BR.CreateStore(OutPtr, CacheGV);
  BR.CreateRet(OutPtr);

  IRBuilder<> BNM(NextMod);
  Value *Next = loadPtr(BNM, CurPH, 0x0, IntPtrTy);
  CurPH->addIncoming(Next, NextMod);
  BNM.CreateBr(Loop);

  // PE export forwarding: if the resolved RVA falls inside the export
  // directory, it's a forwarder string ("other.dll.Func").  Re-hash and
  // restart the PEB walk.  Depth cap avoids infinite forwarder loops.
  IRBuilder<> BFwd(Forwarded);
  Value *Depth = BFwd.CreateLoad(I32Ty, FwdDepth);
  Value *TooDeep =
      BFwd.CreateICmpUGE(Depth, ConstantInt::get(I32Ty, 4));
  BasicBlock *FwdDo = BasicBlock::Create(Ctx, "fwd.do", F);
  BFwd.CreateCondBr(TooDeep, RetFail, FwdDo);

  IRBuilder<> BFwdDo(FwdDo);
  Value *DepthNext =
      BFwdDo.CreateAdd(Depth, ConstantInt::get(I32Ty, 1));
  BFwdDo.CreateStore(DepthNext, FwdDepth);
  Value *FwdStr = BFwdDo.CreateIntToPtr(FuncPtrPhi, I8PtrTy);
  Value *FwdHashes = BFwdDo.CreateCall(FwdHashFn, {FwdStr});
  Value *NewMod =
      BFwdDo.CreateTrunc(BFwdDo.CreateLShr(FwdHashes, 32), I32Ty);
  Value *NewFn = BFwdDo.CreateTrunc(FwdHashes, I32Ty);
  Value *IsFwdOrd =
      BFwdDo.CreateICmpNE(
          BFwdDo.CreateAnd(NewFn, ConstantInt::get(I32Ty, 0x80000000u)),
          ConstantInt::get(I32Ty, 0));
  Value *OrdValFwd =
      BFwdDo.CreateAnd(NewFn, ConstantInt::get(I32Ty, 0x7FFFFFFFu));
  Value *NextTarget = BFwdDo.CreateSelect(IsFwdOrd, OrdValFwd, NewFn);
  BFwdDo.CreateStore(NextTarget, CurTarget);
  BFwdDo.CreateStore(NewMod, CurModule);
  BFwdDo.CreateStore(IsFwdOrd, CurIsOrdinal);
  Value *NewFnNz =
      BFwdDo.CreateICmpNE(NextTarget, ConstantInt::get(I32Ty, 0));
  Value *NewModNz =
      BFwdDo.CreateICmpNE(NewMod, ConstantInt::get(I32Ty, 0));
  Value *Ok = BFwdDo.CreateAnd(NewFnNz, NewModNz);
  BasicBlock *FwdLoop = BasicBlock::Create(Ctx, "fwd.loop", F);
  BFwdDo.CreateCondBr(Ok, FwdLoop, RetFail);

  IRBuilder<> BFwdLoop(FwdLoop);
  Value *Fresh = loadPtr(BFwdLoop, Head, 0x0, IntPtrTy);
  CurPH->addIncoming(Fresh, FwdLoop);
  BFwdLoop.CreateBr(Loop);

  IRBuilder<> BFail(Fail);
  if (EnableLoad) {
    Value *WasTried = BFail.CreateLoad(Type::getInt1Ty(Ctx), Tried);
    BFail.CreateCondBr(WasTried, RetFail, LoadBB);
  } else {
    BFail.CreateBr(RetFail);
  }

  if (EnableLoad) {
    IRBuilder<> BLoad(LoadBB);
    BLoad.CreateStore(ConstantInt::getTrue(Ctx), Tried);
    Value *LdrPtr = BLoad.CreateCall(LdrResolver);
    Value *IsNull =
        BLoad.CreateICmpEQ(LdrPtr,
                           ConstantPointerNull::get(cast<PointerType>(I8PtrTy)));
    BasicBlock *DoLoad = BasicBlock::Create(Ctx, "doload", F);
    BLoad.CreateCondBr(IsNull, RetFail, DoLoad);

    IRBuilder<> BD(DoLoad);
    Value *ModBuf = emitDecodeWideString(BD, *EncMod, I16Ty, I32Ty);
    StructType *USTy =
        StructType::get(I16Ty, I16Ty, PointerType::getUnqual(I16Ty));
    AllocaInst *US = BD.CreateAlloca(USTy);
    Value *LenBytes = ConstantInt::get(I16Ty, EncMod->Len * 2);
    Value *MaxBytes = ConstantInt::get(I16Ty, (EncMod->Len + 1) * 2);
    Value *LenPtr = BD.CreateStructGEP(USTy, US, 0);
    Value *MaxPtr = BD.CreateStructGEP(USTy, US, 1);
    Value *BufPtr = BD.CreateStructGEP(USTy, US, 2);
    BD.CreateStore(LenBytes, LenPtr);
    BD.CreateStore(MaxBytes, MaxPtr);
    BD.CreateStore(ModBuf, BufPtr);

    AllocaInst *Handle = BD.CreateAlloca(IntPtrTy);
    BD.CreateStore(ConstantInt::get(IntPtrTy, 0), Handle);
    FunctionType *LdrTy =
        FunctionType::get(I32Ty,
                          {PointerType::getUnqual(I16Ty), I32Ty,
                           PointerType::getUnqual(USTy),
                           PointerType::getUnqual(IntPtrTy)},
                          false);
    Value *LdrFn = BD.CreateBitCast(
        LdrPtr, PointerType::getUnqual(LdrTy));
    Value *Status = BD.CreateCall(
        LdrTy, LdrFn,
        {ConstantPointerNull::get(PointerType::getUnqual(I16Ty)),
         ConstantInt::get(I32Ty, 0), US, Handle});
    Value *Ok = BD.CreateICmpEQ(Status, ConstantInt::get(I32Ty, 0));
    Value *Fresh = loadPtr(BD, Head, 0x0, IntPtrTy);
    BD.CreateCondBr(Ok, Loop, RetFail);
    CurPH->addIncoming(Fresh, DoLoad);
  }

  IRBuilder<> BRet(RetFail);
  if (FailMode == IATFailMode::Null) {
    BRet.CreateRet(
        ConstantPointerNull::get(cast<PointerType>(I8PtrTy)));
  } else {
    if (Function *FailFn = getOrCreateObfFail(M)) {
      Value *Code =
          ConstantInt::get(Type::getInt32Ty(Ctx), 0x1001);
      BRet.CreateCall(FailFn, {Code});
    } else {
      FunctionCallee TrapFn =
          Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
      BRet.CreateCall(TrapFn);
    }
    BRet.CreateUnreachable();
  }
  return F;
}

PreservedAnalyses IATObfuscationPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  (void)AM;
  bool DoIAT = IATObf || isForcedObfuscationPass("obf-iat") ||
               isForcedObfuscationPass("iat");
  bool DoHideExterns =
      IATHideExterns || isForcedObfuscationPass("obf-hide-externs") ||
      isForcedObfuscationPass("hide-externs");
  if (!DoIAT && !DoHideExterns)
    return PreservedAnalyses::all();

  Triple TT(M.getTargetTriple());
  if (!TT.isOSWindows() || !TT.isOSBinFormatCOFF())
    return PreservedAnalyses::all();

  const DataLayout &DL = M.getDataLayout();
  if (DL.getPointerSizeInBits() != 64)
    return PreservedAnalyses::all();
  if (!TT.isX86())
    return PreservedAnalyses::all();

  recordObfuscationSeed(M);
  maybeDumpIR(M, "iat.before");

  uint32_t Seed = deriveHashSeed();
  Function *HashFn = getOrCreateHashFunc(M, Seed);
  if (!HashFn)
    return PreservedAnalyses::all();
  Function *HashFnLower = getOrCreateHashFuncLower(M, Seed);
  if (!HashFnLower)
    return PreservedAnalyses::all();
  Function *FwdHashFn = getOrCreateForwarderHashFunc(M, Seed);
  if (!FwdHashFn)
    return PreservedAnalyses::all();

  std::vector<NamePattern> HidePatterns;
  HidePatterns.reserve(IATHideFn.size() + IATHidePfx.size());
  for (const std::string &S : IATHideFn) {
    NamePattern P = parsePattern(S);
    if (!P.Prefix.empty())
      HidePatterns.push_back(std::move(P));
  }
  for (const std::string &S : IATHidePfx) {
    std::string T = S;
    if (!T.empty() && T.back() != '*')
      T.push_back('*');
    NamePattern P = parsePattern(T);
    if (!P.Prefix.empty())
      HidePatterns.push_back(std::move(P));
  }

  std::vector<HideRule> Rules;
  Rules.reserve(IATHideMap.size());
  for (const std::string &Entry : IATHideMap) {
    StringRef R = Entry;
    size_t Pos = R.find(':');
    if (Pos == StringRef::npos)
      continue;
    StringRef Mod = R.substr(0, Pos).trim();
    StringRef Pats = R.substr(Pos + 1).trim();
    if (Mod.empty() || Pats.empty())
      continue;
    HideRule Rule;
    std::string NormMod = normalizeModuleName(Mod);
    Rule.Module = NormMod;
    Rule.ModuleHash = fnv1aHashLower(NormMod, Seed);
    Rule.EncName = buildEncodedWideString(M, NormMod, Seed);

    std::string PatWork = Pats.str();
    for (char &C : PatWork) {
      if (C == ';')
        C = '|';
    }
    SmallVector<StringRef, 8> Parts;
    StringRef(PatWork).split(Parts, '|', -1, false);
    for (StringRef PStr : Parts) {
      NamePattern P = parsePattern(PStr);
      if (!P.Prefix.empty())
        Rule.Patterns.push_back(std::move(P));
    }
    if (!Rule.Patterns.empty())
      Rules.push_back(std::move(Rule));
  }

  IntegerType *IntPtrTy = Type::getInt64Ty(M.getContext());
  SmallVector<CallBase *, 32> Work;

  for (Function &F : M) {
    if (shouldSkipFunction(&F))
      continue;
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;
        if (isa<CallBrInst>(CB))
          continue;
        if (CB->isInlineAsm())
          continue;
        if (CB->isMustTailCall())
          continue;
        Function *Callee = CB->getCalledFunction();
        if (!Callee || Callee->isIntrinsic())
          continue;
        if (!Callee->isDeclaration())
          continue;
        if (!Callee->hasDLLImportStorageClass() && !DoHideExterns)
          continue;
        Work.push_back(CB);
      }
    }
  }

  bool Changed = false;
  DenseMap<uint64_t, Function *> ResolverCache;
  SmallPtrSet<Function *, 16> ResolverFns;
  struct DirectEnc {
    GlobalVariable *GV = nullptr;
    uint64_t Key = 0;
  };
  DenseMap<Function *, DirectEnc> DirectCache;
  SmallPtrSet<Function *, 32> KeepImports;
  Function *LdrResolver = nullptr;
  IATFailMode ResolverFail =
      (IATFail == IATFailMode::Null) ? IATFailMode::Null
                                     : IATFailMode::Trap;

  for (CallBase *CB : Work) {
    Function *Parent = CB->getFunction();
    if (!Parent)
      continue;
    if (CB->isInlineAsm() || CB->isMustTailCall() || CB->isConvergent())
      continue;
    if (Parent->hasFnAttribute("obf_skip"))
      continue;
    if (Parent->hasFnAttribute("no_obfuscate") &&
        !Parent->hasFnAttribute("vm_runtime"))
      continue;

    Function *Callee = CB->getCalledFunction();
    if (!Callee)
      continue;
    if (!Callee->isDeclaration())
      continue;
    if (Callee->isIntrinsic())
      continue;
    bool IsImport = Callee->hasDLLImportStorageClass();
    StringRef CalleeName = Callee->getName();
    uint32_t H = fnv1aHash(CalleeName, Seed);
    HideRule *Rule = nullptr;
    for (HideRule &R : Rules) {
      if (matchAny(CalleeName, R.Patterns)) {
        Rule = &R;
        break;
      }
    }
    bool HideImport = IATHideAll || Rule != nullptr ||
                      matchAny(CalleeName, HidePatterns);
    bool ShouldObfuscate = DoHideExterns || HideImport || !IATHideOnly;
    if (!ShouldObfuscate)
      continue;
    bool UseResolver = IsImport && (IATBackend == IATBackendMode::Resolver);
    if (HideImport && IsImport && !UseResolver) {
      LLVM_DEBUG(dbgs() << "iat: hide requested for " << CalleeName
                        << " but backend=thunk; keeping import\n");
    }
    if (IsImport && UseResolver && !HideImport &&
        IATFail == IATFailMode::Fallback)
      continue;
    uint32_t ModHash = Rule ? Rule->ModuleHash : 0;
    const EncodedWideString *Enc = Rule ? &Rule->EncName : nullptr;
    // Hidden imports without an IAT entry need a way to load the module
    // before resolving the proc address. Only enable LdrLoadDll when the
    // caller explicitly opts in to loading missing modules.
    bool EnableLoad =
        UseResolver && HideImport && Enc && Enc->GV && IATLoadMissing;
    if (EnableLoad && !LdrResolver) {
      uint32_t LdrHash = fnv1aHash("LdrLoadDll", Seed);
      uint32_t NtdllHash = fnv1aHashLower("ntdll.dll", Seed);
      LdrResolver =
          getOrCreateResolver(M, LdrHash, NtdllHash, nullptr, false,
                              ResolverFail, HashFn, HashFnLower, FwdHashFn,
                              nullptr);
      if (LdrResolver)
        ResolverFns.insert(LdrResolver);
    }
    if (EnableLoad && !LdrResolver)
      EnableLoad = false;
    Value *FuncPtr = nullptr;
    CallBase *ResCall = nullptr;
    Type *CalledPtrTy = CB->getCalledOperand()->getType();
    FunctionType *FTy = CB->getFunctionType();

    IRBuilder<> BC(CB);
    BC.SetCurrentDebugLocation(CB->getDebugLoc());
    SmallVector<OperandBundleDef, 2> Bundles;
    CB->getOperandBundlesAsDefs(Bundles);
    SmallVector<OperandBundleDef, 1> FuncletBundles;
    if (auto OBU = CB->getOperandBundle(LLVMContext::OB_funclet))
      FuncletBundles.emplace_back(*OBU);

    auto buildDirectPtr = [&](Function *Target, Type *TargetPtrTy) -> Value * {
      auto It = DirectCache.find(Target);
      GlobalVariable *EncGV = nullptr;
      uint64_t PtrKey = 0;
      if (It != DirectCache.end()) {
        EncGV = It->second.GV;
        PtrKey = It->second.Key;
      } else {
        PtrKey = cryptoutils->get_uint64_t();
        if (PtrKey == 0)
          PtrKey = static_cast<uint64_t>(Seed) | 1ULL;
        Constant *PtrC = ConstantExpr::getPtrToInt(Target, IntPtrTy);
        Constant *Enc =
            ConstantExpr::getAdd(PtrC, ConstantInt::get(IntPtrTy, PtrKey));
        std::string GVName = "iat_ptr_" + utohexstr(H);
        EncGV = new GlobalVariable(M, IntPtrTy, true,
                                   GlobalValue::PrivateLinkage, Enc, GVName);
        EncGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        std::string Tag = "iat.ptr." + utohexstr(H);
        obfuscateSymbolName(*EncGV, M, Tag, GVName);
        DirectCache[Target] = {EncGV, PtrKey};
      }
      LoadInst *EncVal = BC.CreateLoad(IntPtrTy, EncGV);
      // Volatile prevents constant folding of the encoded pointer.
      EncVal->setVolatile(true);
      Value *Dec = BC.CreateSub(EncVal, ConstantInt::get(IntPtrTy, PtrKey));
      return BC.CreateIntToPtr(Dec, TargetPtrTy);
    };

    if (IsImport && UseResolver) {
      uint64_t Key =
          (static_cast<uint64_t>(ModHash) << 32) | static_cast<uint64_t>(H);
      if (EnableLoad)
        Key ^= (1ull << 63);
      if (ResolverFail == IATFailMode::Null)
        Key ^= (1ull << 62);
      Function *Resolver = nullptr;
      auto It = ResolverCache.find(Key);
      if (It != ResolverCache.end()) {
        Resolver = It->second;
      } else {
        Resolver = getOrCreateResolver(M, H, ModHash, Enc, EnableLoad,
                                       ResolverFail, HashFn, HashFnLower,
                                       FwdHashFn, LdrResolver);
        ResolverCache[Key] = Resolver;
      }
      if (!Resolver)
        continue;
      ResolverFns.insert(Resolver);

      if (!HideImport) {
        // Non-hidden imports must stay in the IAT so the PE loader maps
        // the DLL before user code runs (resolver alone isn't enough).
        KeepImports.insert(Callee);
      }

      ResCall = BC.CreateCall(Resolver, {}, FuncletBundles);
      Value *TargetPtr = ResCall;
      FuncPtr = BC.CreateBitCast(TargetPtr, CalledPtrTy);
    } else {
      if (IsImport || DoHideExterns)
        FuncPtr = buildDirectPtr(Callee, CalledPtrTy);
      if (IsImport)
        KeepImports.insert(Callee);
    }

    SmallVector<Value *, 8> Args;
    for (auto &Arg : CB->args())
      Args.push_back(Arg.get());

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

    if (IATInline && ResCall) {
      InlineFunctionInfo IFI;
      InlineFunction(*ResCall, IFI);
    }

    CB->replaceAllUsesWith(NewCB);
    CB->eraseFromParent();
    Changed = true;
  }

  if (IATInline) {
    for (Function *Res : ResolverFns) {
      if (Res && Res->use_empty())
        Res->eraseFromParent();
    }
  }

  if (Changed) {
    if (!KeepImports.empty()) {
      SmallVector<GlobalValue *, 32> Used;
      Used.reserve(KeepImports.size());
      for (Function *F : KeepImports)
        Used.push_back(F);
      appendToUsed(M, Used);
    }
    verifyModuleOrDie(M, "iat");
    maybeDumpIR(M, "iat.after");
    return PreservedAnalyses::none();
  }

  return PreservedAnalyses::all();
}
