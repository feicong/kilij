//===- StringObfuscation.cpp - String obfuscation ------------------------===//
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
// Implements string obfuscation and the runtime decode path.
//
//===----------------------------------------------------------------------===//
#include "StringObfuscation.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <limits>

using namespace llvm;

#define DEBUG_TYPE "obfstr"

static cl::opt<bool>
    ObfStr("obf-str", cl::init(false),
           cl::desc("Enable string obfuscation"));
static cl::opt<int> ObfStrProb(
    "obf-str-prob", cl::init(100),
    cl::desc("Probability of string obfuscation (0-100)"));
static cl::opt<int> ObfStrMinLen(
    "obf-str-min", cl::init(4),
    cl::desc("Minimum string length to obfuscate (default 4)"));
static cl::opt<unsigned> ObfStrMaxBytes(
    "obf-str-max-bytes", cl::init(0),
    cl::desc("Maximum total bytes of strings to obfuscate (0 = unlimited)"));
static cl::opt<unsigned> ObfStrMaxCount(
    "obf-str-max-count", cl::init(0),
    cl::desc("Maximum number of strings to obfuscate (0 = unlimited)"));
static cl::opt<bool> ObfStrVerifyHash(
    "obf-str-verify", cl::init(true),
    cl::desc("Verify decoded strings on access and re-decode on mismatch"));
static cl::list<std::string> ObfStrInclude(
    "obf-str-include", cl::CommaSeparated,
    cl::desc("Only obfuscate string literals referenced from source paths "
             "containing any of these substrings"));
static cl::list<std::string> ObfStrExclude(
    "obf-str-exclude", cl::CommaSeparated,
    cl::desc("Skip obfuscating string literals referenced from source paths "
             "containing any of these substrings"));

// Only match null-terminated i8 arrays with no interior NULs; these are
// the C-string globals LLVM lowers from string literals.
static bool isI8StringGlobal(GlobalVariable &GV, Constant *&Init,
                             uint64_t &Len) {
  // Compiler-internal sections (e.g. llvm.metadata) are not user strings.
  if (GV.hasSection()) {
    StringRef Sec = GV.getSection();
    if (Sec.starts_with("llvm."))
      return false;
  }
  if (!GV.hasInitializer() || !GV.isConstant())
    return false;
  Init = GV.getInitializer();

  if (auto *CDA = dyn_cast<ConstantDataArray>(Init)) {
    if (!CDA->isString())
      return false;
    if (!CDA->getElementType()->isIntegerTy(8))
      return false;
    Len = CDA->getNumElements();
    if (Len == 0)
      return false;
    if (CDA->getElementAsInteger(Len - 1) != 0)
      return false;
    for (unsigned i = 0; i + 1 < Len; ++i) {
      if (CDA->getElementAsInteger(i) == 0)
        return false;
    }
    return true;
  }

  if (auto *CA = dyn_cast<ConstantArray>(Init)) {
    if (!CA->getType()->getElementType()->isIntegerTy(8))
      return false;
    Len = CA->getNumOperands();
    if (Len == 0)
      return false;
    auto *LastCI = dyn_cast<ConstantInt>(CA->getOperand(Len - 1));
    if (!LastCI || LastCI->getZExtValue() != 0)
      return false;
    for (unsigned i = 0; i < Len; ++i) {
      auto *CI = dyn_cast<ConstantInt>(CA->getOperand(i));
      if (!CI)
        return false;
      if (i + 1 < Len && CI->getZExtValue() == 0)
        return false;
    }
    return true;
  }
  return false;
}

// Walk the use chain of a global to find all instruction-level users.
// PHI nodes are rejected because inserting a decode call before a PHI
// would violate SSA dominance requirements.
static bool collectUserInstructions(GlobalVariable &GV,
                                    SmallVectorImpl<Instruction *> &OutInsts) {
  SmallVector<User *, 32> Work;
  SmallPtrSet<User *, 32> Seen;
  SmallPtrSet<Instruction *, 32> Insts;
  Work.push_back(&GV);

  while (!Work.empty()) {
    User *U = Work.pop_back_val();
    if (!Seen.insert(U).second)
      continue;
    for (User *UU : U->users()) {
      if (auto *I = dyn_cast<Instruction>(UU)) {
        if (isa<PHINode>(I))
          return false;
        Insts.insert(I);
      } else if (auto *CE = dyn_cast<ConstantExpr>(UU)) {
        Work.push_back(CE);
      } else {
        return false;
      }
    }
  }

  OutInsts.assign(Insts.begin(), Insts.end());
  return true;
}

static bool shouldObfuscateForUsers(ArrayRef<Instruction *> Users) {
  const bool HasInclude = !ObfStrInclude.empty();
  const bool HasExclude = !ObfStrExclude.empty();
  if (!HasInclude && !HasExclude)
    return true;

  for (Instruction *I : Users) {
    if (!I)
      continue;
    DebugLoc DL = I->getDebugLoc();
    if (!DL)
      continue;
    const DILocation *Loc = DL.get();
    if (!Loc)
      continue;
    const DIFile *File = Loc->getFile();
    if (!File)
      continue;
    std::string Path =
        (File->getDirectory() + "/" + File->getFilename()).str();
    if (HasExclude && pathMatchesAny(Path, ObfStrExclude))
      return false;
    if (HasInclude && pathMatchesAny(Path, ObfStrInclude))
      return true;
  }

  // If include filters are set and no user location matched, skip.
  return !HasInclude;
}


static bool constantUsesGlobal(Constant *C, GlobalVariable *GV) {
  if (!C)
    return false;
  if (C == GV)
    return true;
  for (unsigned i = 0, e = C->getNumOperands(); i < e; ++i) {
    if (auto *OpC = dyn_cast<Constant>(C->getOperand(i))) {
      if (constantUsesGlobal(OpC, GV))
        return true;
    }
  }
  return false;
}

// Build the single shared decode function for the module. Uses CAS on a
// per-string flag byte for thread-safe one-shot decode, with an optional
// FNV-1a integrity check so clobbered buffers self-heal on next access.
static Function *getOrCreateDecodeFunc(Module &M, TaggedFunctionCache &TagCache) {
  if (Function *F = TagCache.lookup("obf.str.decode"))
    return F;
  if (Function *F = findTaggedFunction(M, "obf.str.decode")) {
    TagCache.insert(*F);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I8PtrTy = PointerType::getUnqual(I8Ty);
  FunctionType *FT =
      FunctionType::get(I8PtrTy,
                        {I8PtrTy, I64Ty, I64Ty, I8PtrTy, I8PtrTy, I64Ty},
                        false);
  Function *F =
      Function::Create(FT, GlobalValue::PrivateLinkage, "obf_get_str", &M);
  obfuscateSymbolName(*F, M, "obf.str.decode", "obf_get_str");
  TagCache.insert(*F);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *CheckHash = BasicBlock::Create(Ctx, "check", F);
  BasicBlock *TryDecode = BasicBlock::Create(Ctx, "try.decode", F);
  BasicBlock *TryReDecode = BasicBlock::Create(Ctx, "try.redecode", F);
  BasicBlock *Decode = BasicBlock::Create(Ctx, "decode", F);
  BasicBlock *Wait = BasicBlock::Create(Ctx, "wait", F);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BasicBlock *HashLoop = BasicBlock::Create(Ctx, "hash.loop", F);
  BasicBlock *HashBody = BasicBlock::Create(Ctx, "hash.body", F);
  BasicBlock *HashDone = BasicBlock::Create(Ctx, "hash.done", F);
  BasicBlock *Done = BasicBlock::Create(Ctx, "done", F);
  BasicBlock *Trap = BasicBlock::Create(Ctx, "trap", F);

  IRBuilder<> B(Entry);
  auto *ArgIt = F->arg_begin();
  Value *Data = ArgIt++;
  Data->setName("data");
  Value *Len = ArgIt++;
  Len->setName("len");
  Value *Key = ArgIt++;
  Key->setName("key");
  Value *Flag = ArgIt++;
  Flag->setName("flag");
  Value *Dec = ArgIt++;
  Dec->setName("dec");
  Value *ExpectedHash = ArgIt++;
  ExpectedHash->setName("hash");

  Value *Zero = ConstantInt::get(I8Ty, 0);
  Value *One = ConstantInt::get(I8Ty, 1);
  Value *Two = ConstantInt::get(I8Ty, 2);
  // Flag states: 0 = not decoded, 1 = decoding in progress, 2 = decoded.
  // FNV-1a 64-bit constants for the integrity hash.
  Value *FnvOffset =
      ConstantInt::get(I64Ty, 14695981039346656037ULL);
  Value *FnvPrime = ConstantInt::get(I64Ty, 1099511628211ULL);
  AllocaInst *SpinVar = B.CreateAlloca(I64Ty);
  SpinVar->setAlignment(Align(8));
  B.CreateStore(ConstantInt::get(I64Ty, 0), SpinVar);
  AllocaInst *StateVar = B.CreateAlloca(I64Ty);
  StateVar->setAlignment(Align(8));
  B.CreateStore(Key, StateVar);
  // SpinMax = (len + 1) * 1024 to cap the wait loop without an arbitrary magic.
  Value *LenPlus = B.CreateAdd(Len, ConstantInt::get(I64Ty, 1));
  Value *SpinMax = B.CreateShl(LenPlus, ConstantInt::get(I64Ty, 10));
  LoadInst *FlagNow = B.CreateLoad(I8Ty, Flag);
  FlagNow->setAtomic(AtomicOrdering::Acquire);
  Value *IsDone = B.CreateICmpEQ(FlagNow, Two);
  // If already decoded, optionally verify integrity so clobbered buffers heal.
  BasicBlock *ReadyBlock = ObfStrVerifyHash ? CheckHash : Done;
  B.CreateCondBr(IsDone, ReadyBlock, TryDecode);

  B.SetInsertPoint(CheckHash);
  B.CreateBr(HashLoop);

  B.SetInsertPoint(HashLoop);
  PHINode *HIdx = B.CreatePHI(I64Ty, 2, "h.i");
  PHINode *HVal = B.CreatePHI(I64Ty, 2, "h");
  HIdx->addIncoming(ConstantInt::get(I64Ty, 0), CheckHash);
  HVal->addIncoming(FnvOffset, CheckHash);
  Value *HCond = B.CreateICmpULT(HIdx, Len);
  B.CreateCondBr(HCond, HashBody, HashDone);

  B.SetInsertPoint(HashBody);
  Value *HPtr = B.CreateInBoundsGEP(I8Ty, Dec, HIdx);
  Value *HByte = B.CreateLoad(I8Ty, HPtr);
  Value *HByte64 = B.CreateZExt(HByte, I64Ty);
  Value *HXor = B.CreateXor(HVal, HByte64);
  Value *HMul = B.CreateMul(HXor, FnvPrime);
  Value *HNext = B.CreateAdd(HIdx, ConstantInt::get(I64Ty, 1));
  B.CreateBr(HashLoop);
  HIdx->addIncoming(HNext, HashBody);
  HVal->addIncoming(HMul, HashBody);

  B.SetInsertPoint(HashDone);
  Value *HashOk = B.CreateICmpEQ(HVal, ExpectedHash);
  BasicBlock *ReturnOk = BasicBlock::Create(Ctx, "hash.ok", F);
  // Mismatch means buffer was clobbered; re-decode from ciphertext.
  B.CreateCondBr(HashOk, ReturnOk, TryReDecode);

  B.SetInsertPoint(ReturnOk);
  B.CreateRet(Dec);

  // CAS 0->1 to claim decode ownership; losers spin in Wait.
  B.SetInsertPoint(TryDecode);
  AtomicCmpXchgInst *CX = B.CreateAtomicCmpXchg(
      Flag, Zero, One, MaybeAlign(1), AtomicOrdering::AcquireRelease,
      AtomicOrdering::Acquire);
  CX->setWeak(false);
  Value *CanDecode = B.CreateExtractValue(CX, 1);
  B.CreateCondBr(CanDecode, Decode, Wait);

  // CAS 2->1 to re-acquire for re-decode after integrity failure.
  B.SetInsertPoint(TryReDecode);
  AtomicCmpXchgInst *CXRedo = B.CreateAtomicCmpXchg(
      Flag, Two, One, MaybeAlign(1), AtomicOrdering::AcquireRelease,
      AtomicOrdering::Acquire);
  CXRedo->setWeak(false);
  Value *CanReDecode = B.CreateExtractValue(CXRedo, 1);
  B.CreateCondBr(CanReDecode, Decode, Wait);

  B.SetInsertPoint(Wait);
  LoadInst *FlagVal = B.CreateLoad(I8Ty, Flag);
  FlagVal->setAtomic(AtomicOrdering::Acquire);
  Value *DoneDec = B.CreateICmpEQ(FlagVal, Two);
  BasicBlock *WaitCont = BasicBlock::Create(Ctx, "wait.cont", F);
  B.CreateCondBr(DoneDec, ReadyBlock, WaitCont);

  B.SetInsertPoint(WaitCont);
  Value *Spin = B.CreateLoad(I64Ty, SpinVar);
  Value *SpinNext = B.CreateAdd(Spin, ConstantInt::get(I64Ty, 1));
  B.CreateStore(SpinNext, SpinVar);
  Value *TooLong = B.CreateICmpUGE(SpinNext, SpinMax);
  B.CreateCondBr(TooLong, Trap, Wait);

  B.SetInsertPoint(Decode);
  B.CreateBr(Loop);

  B.SetInsertPoint(Loop);
  PHINode *Idx = B.CreatePHI(I64Ty, 2, "i");
  Idx->addIncoming(ConstantInt::get(I64Ty, 0), Decode);
  Value *Cond = B.CreateICmpULT(Idx, Len);
  B.CreateCondBr(Cond, Body, Done);

  // Decode loop: XOR each ciphertext byte with a keystream byte derived
  // from xorshift64 (12,25,27 triplet from Marsaglia). Per-index XOR into
  // the state prevents identical plaintext bytes from producing patterns.
  B.SetInsertPoint(Body);
  Value *EncPtr = B.CreateInBoundsGEP(I8Ty, Data, Idx);
  Value *Byte = B.CreateLoad(I8Ty, EncPtr);
  Value *State = B.CreateLoad(I64Ty, StateVar);
  Value *S1 = B.CreateXor(State, B.CreateLShr(State, ConstantInt::get(I64Ty, 12)));
  Value *S2 = B.CreateXor(S1, B.CreateShl(S1, ConstantInt::get(I64Ty, 25)));
  Value *S3 = B.CreateXor(S2, B.CreateLShr(S2, ConstantInt::get(I64Ty, 27)));
  B.CreateStore(S3, StateVar);
  Value *KeyByte =
      B.CreateTrunc(B.CreateXor(S3, Idx), I8Ty);
  Value *Xor = B.CreateXor(Byte, KeyByte);
  Value *DecPtr = B.CreateInBoundsGEP(I8Ty, Dec, Idx);
  B.CreateStore(Xor, DecPtr);
  Value *Next = B.CreateAdd(Idx, ConstantInt::get(I64Ty, 1));
  B.CreateBr(Loop);
  Idx->addIncoming(Next, Body);

  B.SetInsertPoint(Done);
  StoreInst *StoreDone = B.CreateStore(Two, Flag);
  StoreDone->setAtomic(AtomicOrdering::Release);
  B.CreateRet(Dec);

  B.SetInsertPoint(Trap);
  Function *FailFn = getOrCreateObfFail(M, &TagCache);
  if (FailFn) {
    Value *Code = ConstantInt::get(Type::getInt32Ty(Ctx), 0x3001);
    B.CreateCall(FailFn, {Code});
  } else {
    FunctionCallee TrapFn =
        Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
    B.CreateCall(TrapFn);
  }
  B.CreateUnreachable();

  return F;
}

// Emit a global ctor that eagerly decodes a string at startup. Used when
// we can't rewrite all use sites (e.g. PHI users or non-materializable
// ConstantExprs), so the GV itself becomes the decoded buffer.
static void createDecodeCtor(Module &M, Function *DecodeFn,
                             GlobalVariable *EncGV, GlobalVariable *DecGV,
                             GlobalVariable *FlagGV, uint64_t Len,
                             uint64_t Key, uint64_t Hash,
                             StringRef BaseName) {
  if (!DecodeFn || !EncGV || !DecGV || !FlagGV)
    return;

  LLVMContext &Ctx = M.getContext();
  Type *VoidTy = Type::getVoidTy(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FT = FunctionType::get(VoidTy, false);
  std::string InitName = ("obf_str_init." + BaseName).str();
  std::string InitTag = ("obf.str.init." + BaseName).str();
  Function *InitFn =
      Function::Create(FT, GlobalValue::PrivateLinkage, InitName, &M);
  obfuscateSymbolName(*InitFn, M, InitTag, InitName);
  InitFn->addFnAttr("no_obfuscate");
  InitFn->addFnAttr(Attribute::NoInline);
  InitFn->addFnAttr(Attribute::OptimizeNone);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", InitFn);
  IRBuilder<> B(Entry);
  auto *EncArrTy = cast<ArrayType>(EncGV->getValueType());
  auto *DecArrTy = cast<ArrayType>(DecGV->getValueType());
  Value *EncPtr = B.CreateInBoundsGEP(
      EncArrTy, EncGV, {ConstantInt::get(I64Ty, 0),
                        ConstantInt::get(I64Ty, 0)});
  Value *DecPtr = B.CreateInBoundsGEP(
      DecArrTy, DecGV, {ConstantInt::get(I64Ty, 0),
                        ConstantInt::get(I64Ty, 0)});
  B.CreateCall(DecodeFn,
               {EncPtr, ConstantInt::get(I64Ty, Len),
                ConstantInt::get(I64Ty, Key), FlagGV, DecPtr,
                ConstantInt::get(I64Ty, Hash)});
  B.CreateRetVoid();

  appendToGlobalCtors(M, InitFn, 0);
}

// Rebuild a ConstantExpr tree as IR instructions, substituting OrigGV with
// DecodedPtr. Needed because ConstantExprs can't reference SSA values.
static Value *materializeConst(IRBuilder<> &B, Constant *C,
                               GlobalVariable *OrigGV, Value *DecodedPtr) {
  if (C == OrigGV) {
    return B.CreateBitCast(DecodedPtr, OrigGV->getType());
  }
  auto *CE = dyn_cast<ConstantExpr>(C);
  if (!CE)
    return nullptr;

  if (CE->getOpcode() == Instruction::BitCast) {
    Value *Op =
        materializeConst(B, cast<Constant>(CE->getOperand(0)), OrigGV,
                         DecodedPtr);
    if (!Op)
      return nullptr;
    return B.CreateBitCast(Op, CE->getType());
  }
  if (CE->getOpcode() == Instruction::AddrSpaceCast) {
    Value *Op =
        materializeConst(B, cast<Constant>(CE->getOperand(0)), OrigGV,
                         DecodedPtr);
    if (!Op)
      return nullptr;
    return B.CreateAddrSpaceCast(Op, CE->getType());
  }

  if (CE->getOpcode() == Instruction::GetElementPtr) {
    Value *Base =
        materializeConst(B, cast<Constant>(CE->getOperand(0)), OrigGV,
                         DecodedPtr);
    if (!Base)
      return nullptr;
    SmallVector<Value *, 4> Idxs;
    for (unsigned i = 1; i < CE->getNumOperands(); ++i)
      Idxs.push_back(CE->getOperand(i));
    auto *GEP = cast<GEPOperator>(CE);
    if (GEP->isInBounds())
      return B.CreateInBoundsGEP(GEP->getSourceElementType(), Base, Idxs);
    return B.CreateGEP(GEP->getSourceElementType(), Base, Idxs);
  }

  if (CE->getOpcode() == Instruction::PtrToInt) {
    Value *Op =
        materializeConst(B, cast<Constant>(CE->getOperand(0)), OrigGV,
                         DecodedPtr);
    if (!Op)
      return nullptr;
    return B.CreatePtrToInt(Op, CE->getType());
  }

  return nullptr;
}

static bool canMaterializeConst(Constant *C, GlobalVariable *OrigGV) {
  if (!C)
    return false;
  if (C == OrigGV)
    return true;
  auto *CE = dyn_cast<ConstantExpr>(C);
  if (!CE)
    return false;

  unsigned Op = CE->getOpcode();
  if (Op == Instruction::BitCast || Op == Instruction::AddrSpaceCast ||
      Op == Instruction::PtrToInt) {
    if (CE->getNumOperands() != 1)
      return false;
    return canMaterializeConst(cast<Constant>(CE->getOperand(0)), OrigGV);
  }
  if (Op == Instruction::GetElementPtr) {
    if (CE->getNumOperands() < 1)
      return false;
    if (!canMaterializeConst(cast<Constant>(CE->getOperand(0)), OrigGV))
      return false;
    for (unsigned i = 1; i < CE->getNumOperands(); ++i) {
      if (!isa<Constant>(CE->getOperand(i)))
        return false;
    }
    return true;
  }
  return false;
}

PreservedAnalyses StringObfuscationPass::run(Module &M,
                                             ModuleAnalysisManager &AM) {
  (void)AM;
  if (!ObfStr && !isForcedObfuscationPass("obf-str") &&
      !isForcedObfuscationPass("str"))
    return PreservedAnalyses::all();

  recordObfuscationSeed(M);
  maybeDumpIR(M, "str.before");
  LLVMContext &Ctx = M.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  constexpr uint64_t FnvOffset = 14695981039346656037ULL;
  constexpr uint64_t FnvPrime = 1099511628211ULL;
  unsigned Prob = clampProb(ObfStrProb.getValue());
  uint64_t MinLen = static_cast<uint64_t>(
      clampInt(ObfStrMinLen.getValue(), 0, std::numeric_limits<int>::max()));

  bool Changed = false;
  SmallVector<GlobalVariable *, 32> Globals;
  for (GlobalVariable &GV : M.globals()) {
    Constant *Init = nullptr;
    uint64_t Len = 0;
    if (!isI8StringGlobal(GV, Init, Len))
      continue;
    if (Len < MinLen)
      continue;
    if (cryptoutils->get_range(100) >= Prob)
      continue;
    Globals.push_back(&GV);
  }

  Function *DecodeFn = nullptr;
  FuncletBundleContext FuncletCtx;

  TaggedFunctionCache TagCache(M);
  uint64_t TotalBytes = 0;
  uint64_t TotalCount = 0;
  for (GlobalVariable *GV : Globals) {
    Constant *Init = GV->getInitializer();
    uint64_t Len = 0;
    if (!isI8StringGlobal(*GV, Init, Len))
      continue;

    SmallVector<Instruction *, 32> UserInsts;
    bool UseInPlaceDecode = false;
    if (!collectUserInstructions(*GV, UserInsts))
      UseInPlaceDecode = true;
    SmallVector<Instruction *, 32> EligibleInsts;
    EligibleInsts.reserve(UserInsts.size());
    bool HasSkippedUser = false;
    for (Instruction *I : UserInsts) {
      if (!I) {
        HasSkippedUser = true;
        continue;
      }
      if (shouldSkipInstruction(I)) {
        HasSkippedUser = true;
        continue;
      }
      if (hasAmbiguousFunclet(I, FuncletCtx)) {
        HasSkippedUser = true;
        continue;
      }
      if (Function *F = I->getFunction()) {
        if (shouldSkipFunction(F)) {
          HasSkippedUser = true;
          continue;
        }
      }
      EligibleInsts.push_back(I);
    }
    if (EligibleInsts.empty())
      UseInPlaceDecode = true;
    if (HasSkippedUser)
      UseInPlaceDecode = true;
    bool AllMaterializable = true;
    for (Instruction *I : EligibleInsts) {
      for (unsigned OpIdx = 0; OpIdx < I->getNumOperands(); ++OpIdx) {
        auto *OpC = dyn_cast<Constant>(I->getOperand(OpIdx));
        if (!OpC)
          continue;
        if (!constantUsesGlobal(OpC, GV))
          continue;
        if (!canMaterializeConst(OpC, GV)) {
          AllMaterializable = false;
          break;
        }
      }
      if (!AllMaterializable)
        break;
    }
    if (!AllMaterializable)
      UseInPlaceDecode = true;
    if (!shouldObfuscateForUsers(EligibleInsts))
      continue;
    if (ObfStrMaxCount && TotalCount >= ObfStrMaxCount)
      continue;
    if (ObfStrMaxBytes && (TotalBytes + Len) > ObfStrMaxBytes)
      continue;

    // Zero key makes xorshift degenerate (all-zeros state), so avoid it.
    uint64_t Key = cryptoutils->get_uint64_t();
    if (Key == 0)
      Key = 0xA5A5A5A5A5A5A5A5ULL;

    SmallVector<Constant *, 64> EncBytes;
    EncBytes.reserve(Len);
    uint64_t Hash = FnvOffset;
    if (auto *CDA = dyn_cast<ConstantDataArray>(Init)) {
      uint64_t State = Key;
      for (unsigned i = 0; i < Len; ++i) {
        uint8_t B = static_cast<uint8_t>(CDA->getElementAsInteger(i));
        Hash ^= B;
        Hash *= FnvPrime;
        State ^= (State >> 12);
        State ^= (State << 25);
        State ^= (State >> 27);
        uint8_t K =
            static_cast<uint8_t>(State ^ static_cast<uint64_t>(i));
        EncBytes.push_back(ConstantInt::get(I8Ty, B ^ K));
      }
    } else if (auto *CA = dyn_cast<ConstantArray>(Init)) {
      auto *LastCI = dyn_cast<ConstantInt>(CA->getOperand(Len - 1));
      if (!LastCI || LastCI->getZExtValue() != 0)
        continue;
      uint64_t State = Key;
      for (unsigned i = 0; i < Len; ++i) {
        auto *CI = dyn_cast<ConstantInt>(CA->getOperand(i));
        if (!CI) {
          EncBytes.clear();
          break;
        }
        uint8_t B = static_cast<uint8_t>(CI->getZExtValue());
        Hash ^= B;
        Hash *= FnvPrime;
        State ^= (State >> 12);
        State ^= (State << 25);
        State ^= (State >> 27);
        uint8_t K =
            static_cast<uint8_t>(State ^ static_cast<uint64_t>(i));
        EncBytes.push_back(ConstantInt::get(
            I8Ty, static_cast<uint8_t>(CI->getZExtValue()) ^ K));
      }
      if (EncBytes.empty())
        continue;
    } else {
      continue;
    }

    ArrayType *ArrTy = ArrayType::get(I8Ty, Len);
    Constant *EncInit = ConstantArray::get(ArrTy, EncBytes);
    std::string BaseName = GV->getName().str();
    if (BaseName.empty())
      BaseName = "str";
    std::string EncName = "obf_str." + BaseName;
    std::string EncTag = "obf.str.data." + BaseName;
    auto *EncGV = new GlobalVariable(M, ArrTy, true,
                                     GlobalValue::PrivateLinkage, EncInit,
                                     EncName);
    EncGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    EncGV->setAlignment(GV->getAlign());
    obfuscateSymbolName(*EncGV, M, EncTag, EncName);

    std::string DecName = "obf_str_dec." + BaseName;
    std::string DecTag = "obf.str.dec." + BaseName;
    Constant *DecInit = ConstantAggregateZero::get(ArrTy);
    GlobalVariable *DecGV = nullptr;
    if (!UseInPlaceDecode) {
      DecGV = new GlobalVariable(M, ArrTy, false,
                                 GlobalValue::PrivateLinkage, DecInit,
                                 DecName);
      DecGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      DecGV->setAlignment(GV->getAlign());
      obfuscateSymbolName(*DecGV, M, DecTag, DecName);
    }

    std::string FlagName = "obf_str_decoded." + BaseName;
    std::string FlagTag = "obf.str.flag." + BaseName;
    auto *FlagGV = new GlobalVariable(
        M, I8Ty, false, GlobalValue::PrivateLinkage,
        ConstantInt::get(I8Ty, 0), FlagName);
    obfuscateSymbolName(*FlagGV, M, FlagTag, FlagName);

    if (!DecodeFn)
      DecodeFn = getOrCreateDecodeFunc(M, TagCache);

    // In-place mode: repurpose the original GV as the decode target and
    // eagerly decode via a ctor. Preferred when per-use rewriting fails.
    if (UseInPlaceDecode) {
      GV->setConstant(false);
      GV->setInitializer(DecInit);
      GV->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
      GV->setAlignment(GV->getAlign());
      DecGV = GV;
      createDecodeCtor(M, DecodeFn, EncGV, DecGV, FlagGV, Len, Key, Hash,
                       BaseName);
      Changed = true;
    } else {
      for (Instruction *I : EligibleInsts) {
        if (!I)
          continue;
        IRBuilder<> B(I);
        Value *EncPtr =
            B.CreateInBoundsGEP(ArrTy, EncGV,
                                {ConstantInt::get(I64Ty, 0),
                                 ConstantInt::get(I64Ty, 0)});
        Value *DecPtr =
            B.CreateInBoundsGEP(ArrTy, DecGV,
                                {ConstantInt::get(I64Ty, 0),
                                 ConstantInt::get(I64Ty, 0)});
        SmallVector<OperandBundleDef, 1> Bundles =
            getFuncletBundleFor(I, FuncletCtx);
        Value *Decoded =
            B.CreateCall(DecodeFn,
                         {EncPtr, ConstantInt::get(I64Ty, Len),
                          ConstantInt::get(I64Ty, Key), FlagGV, DecPtr,
                          ConstantInt::get(I64Ty, Hash)},
                         Bundles);

        for (unsigned OpIdx = 0; OpIdx < I->getNumOperands(); ++OpIdx) {
          auto *OpC = dyn_cast<Constant>(I->getOperand(OpIdx));
          if (!OpC)
            continue;
          if (!constantUsesGlobal(OpC, GV))
            continue;
          Value *NewVal = materializeConst(B, OpC, GV, Decoded);
          if (!NewVal)
            continue;
          I->setOperand(OpIdx, NewVal);
          Changed = true;
        }
      }

      if (GV->use_empty()) {
        GV->eraseFromParent();
        Changed = true;
      }
    }
    TotalBytes += Len;
    TotalCount += 1;
  }

  if (Changed) {
    verifyModuleOrDie(M, "str");
    maybeDumpIR(M, "str.after");
    return PreservedAnalyses::none();
  }
  return PreservedAnalyses::all();
}
