//===- OpaquePredicates.cpp - Opaque predicate helpers -------------------===//
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
// Implements opaque predicate construction and per-function seeding.
//
//===----------------------------------------------------------------------===//
#include "OpaquePredicates.h"
#include "CryptoUtils.h"
#include "Utils.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CommandLine.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>

using namespace llvm;

namespace {
static cl::opt<int> OpaquePredRate(
    "opaque-pred-rate", cl::init(100),
    cl::desc("Rate [%] for heavy opaque predicates (default 100)"));
static cl::opt<int> OpaquePredMaxSteps(
    "opaque-pred-max-steps", cl::init(64),
    cl::desc("Max steps for loop-based opaque predicates (default 64)"));
static cl::opt<int> OpaquePredCollatzMaskBits(
    "opaque-pred-collatz-mask-bits", cl::init(16),
    cl::desc("Mask bits for Collatz input (default 16)"));
static cl::opt<int> OpaquePredCollatzVariants(
    "opaque-pred-collatz-variants", cl::init(8),
    cl::desc("Number of Collatz helper variants per module (default 8)"));
static cl::opt<int> OpaquePredWCollatz(
    "opaque-pred-w-collatz", cl::init(10),
    cl::desc("Weight for Collatz opaque predicate (default 10)"));
static cl::opt<int> OpaquePredPowmodVariants(
    "opaque-pred-powmod-variants", cl::init(4),
    cl::desc("Number of powmod helper variants per module (default 4)"));
static cl::opt<int> OpaquePredWPowmod(
    "opaque-pred-w-powmod", cl::init(20),
    cl::desc("Weight for powmod opaque predicate (default 20)"));
static cl::opt<int> OpaquePredWDiffSq(
    "opaque-pred-w-diffsq", cl::init(35),
    cl::desc("Weight for diff-of-squares predicate (default 35)"));
static cl::opt<int> OpaquePredWXorEq(
    "opaque-pred-w-xoreq", cl::init(35),
    cl::desc("Weight for xor-equivalence predicate (default 35)"));

// Always-true algebraic identities that are cheap at runtime but hostile to
// symbolic simplification. These are implemented as per-module helper
// functions to avoid per-site IR bloat.
static cl::opt<int> OpaquePredMinorVariants(
    "opaque-pred-minor-variants", cl::init(2),
    cl::desc("Number of minor-quadric helper variants per module (default 2)"));
static cl::opt<int> OpaquePredWMinorQuadric(
    "opaque-pred-w-minorquad", cl::init(8),
    cl::desc("Weight for minor-quadric predicate (default 8)"));
static cl::opt<int> OpaquePredQSeriesVariants(
    "opaque-pred-qseries-variants", cl::init(1),
    cl::desc("Number of q-series helper variants per module (default 1)"));
static cl::opt<int> OpaquePredWQSeries(
    "opaque-pred-w-qseries", cl::init(6),
    cl::desc("Weight for q-series predicate (default 6)"));
static cl::opt<int> OpaquePredCompositeVariants(
    "opaque-pred-composite-variants", cl::init(1),
    cl::desc("Number of composite helper variants per module (default 1)"));
static cl::opt<int> OpaquePredWComposite(
    "opaque-pred-w-composite", cl::init(4),
    cl::desc("Weight for composite predicate (default 4)"));
static cl::opt<bool> OpaquePredUseCycleCounter(
    "opaque-pred-use-rc", cl::init(true),
    cl::desc("Use readcyclecounter when supported (default true)"));
} // namespace

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

// splitmix64 is provided via Utils.h.

static void store64be(uint64_t v, unsigned char *out) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<unsigned char>((v >> (56 - (i * 8))) & 0xFF);
  }
}

static std::string seedToHex(uint64_t seed) {
  unsigned char bytes[16];
  uint64_t x = seed;
  uint64_t a = ::splitmix64(x);
  uint64_t b = ::splitmix64(x);
  store64be(a, bytes);
  store64be(b, bytes + 8);

  static const char *hex = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (int i = 0; i < 16; ++i) {
    out.push_back(hex[(bytes[i] >> 4) & 0xF]);
    out.push_back(hex[bytes[i] & 0xF]);
  }
  return out;
}

static std::string getOrCreateModuleSeedHex(Module &M) {
  // Persist a per-module seed so predicate structure stays stable per build.
  if (NamedMDNode *MD = M.getNamedMetadata("obf.seed")) {
    if (MD->getNumOperands() > 0) {
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0)->getOperand(0))) {
        return S->getString().str();
      }
    }
  }

  std::string seedHex = getObfuscationSeedHex();
  if (!seedHex.empty())
    return seedHex;

  uint64_t seed = llvm::cryptoutils->get_uint64_t();
  seedHex = seedToHex(seed);

  LLVMContext &Ctx = M.getContext();
  NamedMDNode *MD = M.getOrInsertNamedMetadata("obf.seed");
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx, seedHex));
  MD->addOperand(Node);
  return seedHex;
}

// readcyclecounter gives high-entropy runtime seeds cheaply, but not all
// targets support it (e.g. WASM, MIPS). Fall back to stack-address ASLR.
static bool shouldUseCycleCounter(const Module &M) {
  if (!OpaquePredUseCycleCounter)
    return false;
  if (M.getTargetTriple().empty())
    return false;
  Triple T(M.getTargetTriple());
  switch (T.getArch()) {
  case Triple::x86:
  case Triple::x86_64:
  case Triple::arm:
  case Triple::aarch64:
  case Triple::riscv32:
  case Triple::riscv64:
  case Triple::ppc64:
  case Triple::ppc64le:
    return true;
  default:
    return false;
  }
}

static void buildInstIndex(Function &F, OpaquePredContext &Ctx) {
  Ctx.InstIndex.clear();
  Ctx.Owner = &F;
  Ctx.Funclets.FuncletPads.clear();
  Ctx.Funclets.Owner = nullptr;
  Ctx.Funclets.Built = false;
  Ctx.SeedSlot = nullptr;
  Ctx.FuncSeed = nullptr;
  uint64_t idx = 0;
  for (auto &BB : F) {
    for (auto &I : BB) {
      // Stable per-function indexing keeps predicate variation deterministic.
      Ctx.InstIndex[&I] = idx++;
    }
  }
}

static uint64_t fnvMixByte(uint64_t h, uint8_t b) {
  h ^= b;
  h *= 1099511628211ULL;
  return h;
}

static uint64_t fnvMixStr(uint64_t h, StringRef s) {
  for (unsigned char c : s) {
    h = fnvMixByte(h, c);
  }
  return h;
}

static uint64_t fnvMixU64(uint64_t h, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    h = fnvMixByte(h, static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
  }
  return h;
}

static uint64_t computeSiteSalt(Function &F, Instruction *I,
                                OpaquePredContext &Ctx) {
  if (Ctx.ModuleSeedHex.empty()) {
    Ctx.ModuleSeedHex = getOrCreateModuleSeedHex(*F.getParent());
  }
  if (Ctx.Owner != &F || Ctx.InstIndex.empty()) {
    buildInstIndex(F, Ctx);
  }

  uint64_t instIndex = 0;
  if (I) {
    auto It = Ctx.InstIndex.find(I);
    if (It != Ctx.InstIndex.end())
      instIndex = It->second;
  }

  // Mix module seed + function name + instruction index for per-site entropy.
  uint64_t h = 1469598103934665603ULL;
  h = fnvMixStr(h, Ctx.ModuleSeedHex);
  h = fnvMixStr(h, F.getName());
  h = fnvMixU64(h, instIndex);
  if (I) {
    if (const DebugLoc &DL = I->getDebugLoc()) {
      uint64_t linecol = (static_cast<uint64_t>(DL.getLine()) << 32) |
                         static_cast<uint64_t>(DL.getCol());
      h = fnvMixU64(h, linecol);
    }
  }
  h = fnvMixStr(h, "opaque_pred_v2");
  return h;
}

static Function *lookupTaggedFunction(Module &M, StringRef Tag,
                                      TaggedFunctionCache *TagCache) {
  if (TagCache) {
    if (Function *F = TagCache->lookup(Tag))
      return F;
    if (Function *F = findTaggedFunction(M, Tag)) {
      TagCache->insert(*F);
      return F;
    }
  } else {
    if (Function *F = findTaggedFunction(M, Tag))
      return F;
  }
  return nullptr;
}

static void cacheTaggedFunction(Function &F, TaggedFunctionCache *TagCache) {
  if (TagCache)
    TagCache->insert(F);
}

// Use a stack alloca address as a poor-man's entropy source when no
// cycle counter is available. ASLR makes this non-constant across runs.
static Value *createFallbackSeed(IRBuilder<> &B, Function &F,
                                 OpaquePredContext &PredCtx,
                                 Instruction *Site) {
  (void)Site;
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  if (!PredCtx.SeedSlot) {
    IRBuilder<> EntryB(&*F.getEntryBlock().getFirstInsertionPt());
    PredCtx.SeedSlot =
        EntryB.CreateAlloca(Type::getInt8Ty(Ctx), nullptr, "opaque.seed");
  }
  Value *seed = B.CreatePtrToInt(PredCtx.SeedSlot, I64Ty);

  return seed;
}

static Value *getOrCreateFuncSeed(Function &F, OpaquePredContext &PredCtx) {
  if (PredCtx.FuncSeed)
    return PredCtx.FuncSeed;

  Module &M = *F.getParent();

  IRBuilder<> EntryB(&*F.getEntryBlock().getFirstInsertionPt());
  Value *base = nullptr;

  if (shouldUseCycleCounter(M)) {
    bool canCall = true;
    SmallVector<OperandBundleDef, 1> Bundles;
    ensureFuncletMap(F, PredCtx.Funclets);
    auto It = PredCtx.Funclets.FuncletPads.find(&F.getEntryBlock());
    if (It != PredCtx.Funclets.FuncletPads.end()) {
      if (It->second.size() == 1) {
        auto PadIt = It->second.front()->getFirstNonPHIIt();
        Instruction *PadInst =
            (PadIt == It->second.front()->end()) ? nullptr : &*PadIt;
        if (PadInst && PadInst->isEHPad()) {
          Bundles.emplace_back("funclet", PadInst);
        } else {
          canCall = false;
        }
      } else {
        canCall = false;
      }
    }

    if (canCall) {
      FunctionCallee rc =
          Intrinsic::getOrInsertDeclaration(&M, Intrinsic::readcyclecounter);
      base = EntryB.CreateCall(rc, {}, Bundles);
    }
  }

  if (!base) {
    base = createFallbackSeed(EntryB, F, PredCtx, nullptr);
  }

  base = EntryB.CreateFreeze(base);
  PredCtx.FuncSeed = base;
  return base;
}

static Value *createRuntimeSeed(IRBuilder<> &B, Function &F, uint64_t siteSalt,
                                OpaquePredContext &PredCtx,
                                Instruction *Site, bool allowCalls) {
  (void)Site;
  (void)allowCalls;
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *seed = getOrCreateFuncSeed(F, PredCtx);

  seed = B.CreateFreeze(seed);
  Value *salt = ConstantInt::get(I64Ty, siteSalt);
  seed = B.CreateXor(seed, salt);
  Value *mix = B.CreateXor(seed, B.CreateLShr(seed, ConstantInt::get(I64Ty, 13)));
  mix = B.CreateAdd(mix, salt);
  return mix;
}

static Value *createCollatzInput(IRBuilder<> &B, Function &F, uint64_t siteSalt,
                                 OpaquePredContext &PredCtx,
                                 Instruction *Site, bool allowCalls) {
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *n = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);

  int maskBits = clampInt(OpaquePredCollatzMaskBits.getValue(), 1, 63);
  if (OpaquePredCollatzMaskBits.getValue() > 0) {
    // Mask input to keep the Collatz loop bounded and cheap.
    uint64_t mask = (1ULL << maskBits) - 1ULL;
    n = B.CreateAnd(n, ConstantInt::get(I64Ty, mask));
  }
  n = B.CreateOr(n, ConstantInt::get(I64Ty, 1));
  return n;
}

// Collatz conjecture: every positive integer eventually reaches 1. The
// predicate always returns true but an analyzer must prove termination
// to eliminate it, which is undecidable in the general case.
static Function *getOrCreateCollatzPredicate(Module &M, unsigned variant,
                                             TaggedFunctionCache *TagCache) {
  std::string Name =
      "opaque_collatz.v" + std::to_string(variant);
  std::string Tag = "obf.opaque.collatz.v" + std::to_string(variant);
  if (Function *F = lookupTaggedFunction(M, Tag, TagCache))
    return F;
  if (Function *F = M.getFunction(Name)) {
    obfuscateSymbolName(*F, M, Tag, Name);
    cacheTaggedFunction(*F, TagCache);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  FunctionType *FT = FunctionType::get(Type::getInt1Ty(Ctx), {I64Ty}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  obfuscateSymbolName(*F, M, Tag, Name);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *Check = BasicBlock::Create(Ctx, "check", F);
  BasicBlock *Even = BasicBlock::Create(Ctx, "even", F);
  BasicBlock *Odd = BasicBlock::Create(Ctx, "odd", F);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", F);

  Argument *ArgN = F->getArg(0);
  ArgN->setName("n");

  IRBuilder<> B(Entry);
  B.CreateBr(Loop);

  B.SetInsertPoint(Loop);
  PHINode *N = B.CreatePHI(I64Ty, 3, "n.phi");
  PHINode *Steps = B.CreatePHI(I32Ty, 3, "steps.phi");
  N->addIncoming(ArgN, Entry);
  Steps->addIncoming(ConstantInt::get(I32Ty, 0), Entry);

  Value *isZero = B.CreateICmpEQ(N, ConstantInt::get(I64Ty, 0));
  Value *isOne = B.CreateICmpEQ(N, ConstantInt::get(I64Ty, 1));
  int maxSteps = std::max(1, OpaquePredMaxSteps.getValue());
  Value *limit =
      B.CreateICmpUGE(Steps, ConstantInt::get(I32Ty, maxSteps));
  Value *done = B.CreateOr(B.CreateOr(isZero, isOne), limit);
  B.CreateCondBr(done, Exit, Check);

  B.SetInsertPoint(Check);
  Value *isEven = B.CreateICmpEQ(B.CreateAnd(N, ConstantInt::get(I64Ty, 1)),
                                 ConstantInt::get(I64Ty, 0));
  B.CreateCondBr(isEven, Even, Odd);

  B.SetInsertPoint(Even);
  Value *nextEven = B.CreateLShr(N, ConstantInt::get(I64Ty, 1));
  Value *nextStepsEven =
      B.CreateAdd(Steps, ConstantInt::get(I32Ty, 1));
  B.CreateBr(Loop);

  B.SetInsertPoint(Odd);
  Value *mul = B.CreateMul(N, ConstantInt::get(I64Ty, 3));
  Value *nextOdd = B.CreateAdd(mul, ConstantInt::get(I64Ty, 1));
  Value *nextStepsOdd = B.CreateAdd(Steps, ConstantInt::get(I32Ty, 1));
  B.CreateBr(Loop);

  N->addIncoming(nextEven, Even);
  N->addIncoming(nextOdd, Odd);
  Steps->addIncoming(nextStepsEven, Even);
  Steps->addIncoming(nextStepsOdd, Odd);

  B.SetInsertPoint(Exit);
  PHINode *NExit = B.CreatePHI(I64Ty, 1, "n.exit");
  PHINode *StepsExit = B.CreatePHI(I32Ty, 1, "steps.exit");
  NExit->addIncoming(N, Loop);
  StepsExit->addIncoming(Steps, Loop);
  Value *isOneExit = B.CreateICmpEQ(NExit, ConstantInt::get(I64Ty, 1));
  Value *isZeroExit = B.CreateICmpEQ(NExit, ConstantInt::get(I64Ty, 0));
  Value *limitExit =
      B.CreateICmpUGE(StepsExit, ConstantInt::get(I32Ty, maxSteps));
  Value *ret = B.CreateOr(B.CreateOr(isOneExit, isZeroExit), limitExit);
  B.CreateRet(ret);

  return F;
}

Function *getOrCreateCollatzPredicate(Module &M, unsigned variant) {
  return getOrCreateCollatzPredicate(M, variant, nullptr);
}

// A quadratic relation between the 2x2 minors of a 2x4 matrix.
// Written as arithmetic soup so the structure doesn't look like a
// standard compiler identity, but it is a universal polynomial identity over
// any commutative ring (including i64 wraparound).
//
// We return the raw residual (0 when the identity holds). The caller turns it
// into either an always-true or always-false condition based on wantTrue.
static Function *getOrCreateMinorQuadricPredicate(Module &M, unsigned variant,
                                                  TaggedFunctionCache *TagCache) {
  std::string Name = "opaque_minorquad.v" + std::to_string(variant);
  std::string Tag = "obf.opaque.minorquad.v" + std::to_string(variant);
  if (Function *F = lookupTaggedFunction(M, Tag, TagCache))
    return F;
  if (Function *F = M.getFunction(Name)) {
    obfuscateSymbolName(*F, M, Tag, Name);
    cacheTaggedFunction(*F, TagCache);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FT = FunctionType::get(I64Ty, {I64Ty}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  obfuscateSymbolName(*F, M, Tag, Name);
  cacheTaggedFunction(*F, TagCache);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  Argument *Arg = F->getArg(0);
  Arg->setName("n");

  // Derive per-module, per-variant constants so different builds don't share
  // identical arithmetic soup.
  uint64_t sm = 1469598103934665603ULL;
  sm = fnvMixStr(sm, getOrCreateModuleSeedHex(M));
  sm = fnvMixStr(sm, Tag);
  sm = fnvMixU64(sm, static_cast<uint64_t>(variant));
  uint64_t c1 = ::splitmix64(sm);
  uint64_t c2 = ::splitmix64(sm) | 1ULL;
  uint64_t c3 = ::splitmix64(sm);
  uint64_t c4 = ::splitmix64(sm) | 1ULL;
  uint64_t c5 = ::splitmix64(sm) | 1ULL;
  uint64_t c6 = ::splitmix64(sm);
  uint64_t c7 = ::splitmix64(sm) | 1ULL;
  uint64_t c8 = ::splitmix64(sm) | 1ULL;
  uint64_t c9 = ::splitmix64(sm) | 1ULL;

  IRBuilder<> B(Entry);
  Value *x = B.CreateFreeze(Arg);

  // Mix the seed into eight i64 values (a..h). The identity below holds for
  // all a..h, so this is purely for obfuscation, not correctness.
  Value *a = B.CreateAdd(x, ConstantInt::get(I64Ty, c1));
  Value *b = B.CreateMul(
      B.CreateXor(x, B.CreateLShr(x, ConstantInt::get(I64Ty, 17))),
      ConstantInt::get(I64Ty, c2));
  Value *c = B.CreateXor(
      B.CreateAdd(x, B.CreateShl(x, ConstantInt::get(I64Ty, 7))),
      ConstantInt::get(I64Ty, c3));
  Value *d = B.CreateAdd(B.CreateMul(x, ConstantInt::get(I64Ty, c4)),
                         B.CreateLShr(x, ConstantInt::get(I64Ty, 3)));
  Value *e = B.CreateMul(
      B.CreateXor(x, B.CreateLShr(x, ConstantInt::get(I64Ty, 31))),
      ConstantInt::get(I64Ty, c5));
  Value *f = B.CreateXor(B.CreateAdd(x, ConstantInt::get(I64Ty, c6)),
                         B.CreateShl(x, ConstantInt::get(I64Ty, 11)));
  Value *g = B.CreateAdd(B.CreateMul(x, ConstantInt::get(I64Ty, c7)),
                         B.CreateLShr(x, ConstantInt::get(I64Ty, 29)));
  Value *h = B.CreateMul(B.CreateXor(x, ConstantInt::get(I64Ty, c8)),
                         ConstantInt::get(I64Ty, c9));

  auto det2 = [&](Value *x1, Value *y1, Value *x2, Value *y2) -> Value * {
    return B.CreateSub(B.CreateMul(x1, y2), B.CreateMul(x2, y1));
  };

  // Columns: (a,e),(b,f),(c,g),(d,h). Compute all 2x2 minors.
  Value *d12 = det2(a, e, b, f);
  Value *d13 = det2(a, e, c, g);
  Value *d14 = det2(a, e, d, h);
  Value *d23 = det2(b, f, c, g);
  Value *d24 = det2(b, f, d, h);
  Value *d34 = det2(c, g, d, h);

  // Universal quadric: d12*d34 - d13*d24 + d14*d23 == 0.
  Value *res = B.CreateAdd(
      B.CreateSub(B.CreateMul(d12, d34), B.CreateMul(d13, d24)),
      B.CreateMul(d14, d23));
  B.CreateRet(res);
  return F;
}

// Finite q-series identity (q-binomial theorem in disguise).
//
// For a small fixed n, we compute:
//   Π_{r=0..n-1} (1 + t*q^r)
// and compare it to a separately computed sum with a weighted Pascal-style
// recurrence for coefficients. This is a universal polynomial identity, so the
// returned delta is always 0 for all q,t.
static Function *getOrCreateQSeriesPredicate(Module &M, unsigned variant,
                                             TaggedFunctionCache *TagCache) {
  std::string Name = "opaque_qseries.v" + std::to_string(variant);
  std::string Tag = "obf.opaque.qseries.v" + std::to_string(variant);
  if (Function *F = lookupTaggedFunction(M, Tag, TagCache))
    return F;
  if (Function *F = M.getFunction(Name)) {
    obfuscateSymbolName(*F, M, Tag, Name);
    cacheTaggedFunction(*F, TagCache);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FT = FunctionType::get(I64Ty, {I64Ty}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  obfuscateSymbolName(*F, M, Tag, Name);
  cacheTaggedFunction(*F, TagCache);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  Argument *Arg = F->getArg(0);
  Arg->setName("n");

  // Per-module constants for varying q/t derivation.
  uint64_t sm = 1469598103934665603ULL;
  sm = fnvMixStr(sm, getOrCreateModuleSeedHex(M));
  sm = fnvMixStr(sm, Tag);
  sm = fnvMixU64(sm, static_cast<uint64_t>(variant));
  uint64_t k1 = ::splitmix64(sm);
  uint64_t k2 = ::splitmix64(sm);
  uint64_t k3 = ::splitmix64(sm) | 1ULL;
  uint64_t k4 = ::splitmix64(sm);

  IRBuilder<> B(Entry);
  Value *x = B.CreateFreeze(Arg);

  // Derive q and t from x. The identity holds for all q,t.
  Value *q = B.CreateMul(B.CreateXor(x, ConstantInt::get(I64Ty, k1)),
                         ConstantInt::get(I64Ty, k3));
  Value *t = B.CreateAdd(B.CreateXor(B.CreateLShr(x, ConstantInt::get(I64Ty, 7)),
                                     ConstantInt::get(I64Ty, k2)),
                         ConstantInt::get(I64Ty, k4));

  // Fixed small n keeps runtime cost low while still producing enough
  // arithmetic to resist pattern matching.
  const int N = 6;
  const int QMAX = (N * (N - 1)) / 2; // max k(k-1)/2

  // Precompute q^i for i=0..QMAX.
  SmallVector<Value *, 16> qPow;
  qPow.reserve(QMAX + 1);
  qPow.push_back(ConstantInt::get(I64Ty, 1));
  for (int i = 1; i <= QMAX; ++i) {
    qPow.push_back(B.CreateMul(qPow.back(), q));
  }

  // Precompute t^k for k=0..N.
  SmallVector<Value *, 8> tPow;
  tPow.reserve(N + 1);
  tPow.push_back(ConstantInt::get(I64Ty, 1));
  for (int i = 1; i <= N; ++i) {
    tPow.push_back(B.CreateMul(tPow.back(), t));
  }

  // LHS = Π (1 + t*q^r)
  Value *lhs = ConstantInt::get(I64Ty, 1);
  for (int r = 0; r < N; ++r) {
    Value *term = B.CreateAdd(ConstantInt::get(I64Ty, 1),
                              B.CreateMul(t, qPow[r]));
    lhs = B.CreateMul(lhs, term);
  }

  // Coefficients C[k] via weighted Pascal recurrence.
  SmallVector<Value *, 8> C;
  C.assign(N + 1, ConstantInt::get(I64Ty, 0));
  C[0] = ConstantInt::get(I64Ty, 1);
  for (int nn = 1; nn <= N; ++nn) {
    SmallVector<Value *, 8> nxt;
    nxt.assign(N + 1, ConstantInt::get(I64Ty, 0));
    for (int k = 0; k <= nn; ++k) {
      Value *term1 = C[k];
      Value *term2 = ConstantInt::get(I64Ty, 0);
      if (k > 0) {
        term2 = B.CreateMul(qPow[nn - k], C[k - 1]);
      }
      nxt[k] = B.CreateAdd(term1, term2);
    }
    C.swap(nxt);
  }

  // RHS = Σ t^k q^{k(k-1)/2} C[k]
  Value *rhs = ConstantInt::get(I64Ty, 0);
  for (int k = 0; k <= N; ++k) {
    int tri = (k * (k - 1)) / 2;
    Value *term = B.CreateMul(B.CreateMul(tPow[k], qPow[tri]), C[k]);
    rhs = B.CreateAdd(rhs, term);
  }

  // Return delta; caller compares against 0/1.
  B.CreateRet(B.CreateSub(lhs, rhs));
  return F;
}

// Mix two independent always-zero residuals (minor
// quadric + q-series delta) into a single i64 result.
static Function *getOrCreateCompositePredicate(Module &M, unsigned variant,
                                               TaggedFunctionCache *TagCache) {
  std::string Name = "opaque_composite.v" + std::to_string(variant);
  std::string Tag = "obf.opaque.composite.v" + std::to_string(variant);
  if (Function *F = lookupTaggedFunction(M, Tag, TagCache))
    return F;
  if (Function *F = M.getFunction(Name)) {
    obfuscateSymbolName(*F, M, Tag, Name);
    cacheTaggedFunction(*F, TagCache);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *FT = FunctionType::get(I64Ty, {I64Ty}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  obfuscateSymbolName(*F, M, Tag, Name);
  cacheTaggedFunction(*F, TagCache);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  Argument *Arg = F->getArg(0);
  Arg->setName("n");

  unsigned minorV = variant % std::max(1, OpaquePredMinorVariants.getValue());
  unsigned qV = variant % std::max(1, OpaquePredQSeriesVariants.getValue());
  Function *Minor = getOrCreateMinorQuadricPredicate(M, minorV, TagCache);
  Function *QSeries = getOrCreateQSeriesPredicate(M, qV, TagCache);

  // Per-module mixing constants.
  uint64_t sm = 1469598103934665603ULL;
  sm = fnvMixStr(sm, getOrCreateModuleSeedHex(M));
  sm = fnvMixStr(sm, Tag);
  sm = fnvMixU64(sm, static_cast<uint64_t>(variant));
  uint64_t a = ::splitmix64(sm) | 1ULL;
  uint64_t b = ::splitmix64(sm) | 1ULL;
  uint64_t c = ::splitmix64(sm) | 1ULL;

  IRBuilder<> B(Entry);
  Value *x = B.CreateFreeze(Arg);
  Value *r1 = B.CreateCall(Minor, {x});
  Value *r2 = B.CreateCall(QSeries, {x});

  // Combine residuals: a*r1 + b*r2 + c*(r1 ^ r2).
  Value *mix = B.CreateXor(r1, r2);
  Value *out = B.CreateAdd(B.CreateMul(r1, ConstantInt::get(I64Ty, a)),
                           B.CreateMul(r2, ConstantInt::get(I64Ty, b)));
  out = B.CreateAdd(out, B.CreateMul(mix, ConstantInt::get(I64Ty, c)));
  B.CreateRet(out);
  return F;
}

static Value *mulMod(IRBuilder<> &B, Value *A, Value *Bv, uint32_t Prime) {
  LLVMContext &Ctx = B.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *A64 = B.CreateZExt(A, I64Ty);
  Value *B64 = B.CreateZExt(Bv, I64Ty);
  Value *Mul = B.CreateMul(A64, B64);
  Value *Mod = B.CreateURem(Mul, ConstantInt::get(I64Ty, Prime));
  return B.CreateTrunc(Mod, I32Ty);
}

// Fermat's little theorem: a^(p-1) = 1 (mod p) for prime p and 0 < a < p.
// The predicate computes this via binary exponentiation and checks == 1.
// 16-bit primes keep the loop short while still being hard to pattern-match.
static Function *getOrCreatePowmod(Module &M, uint32_t Prime, unsigned variant,
                                   TaggedFunctionCache *TagCache) {
  std::string Name = "opaque_powmod." + std::to_string(Prime) + ".v" +
                     std::to_string(variant);
  std::string Tag = "obf.opaque.powmod." + std::to_string(Prime) + ".v" +
                    std::to_string(variant);
  if (Function *F = lookupTaggedFunction(M, Tag, TagCache))
    return F;
  if (Function *F = M.getFunction(Name)) {
    obfuscateSymbolName(*F, M, Tag, Name);
    cacheTaggedFunction(*F, TagCache);
    return F;
  }

  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  FunctionType *FT = FunctionType::get(I32Ty, {I64Ty}, false);
  Function *F = Function::Create(FT, GlobalValue::PrivateLinkage, Name, &M);
  obfuscateSymbolName(*F, M, Tag, Name);
  cacheTaggedFunction(*F, TagCache);
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::OptimizeNone);
  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoUnwind);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  BasicBlock *Loop = BasicBlock::Create(Ctx, "loop", F);
  BasicBlock *Body = BasicBlock::Create(Ctx, "body", F);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "exit", F);

  Argument *ArgN = F->getArg(0);
  ArgN->setName("n");

  IRBuilder<> B(Entry);
  Value *A = B.CreateTrunc(ArgN, I32Ty);
  Value *ModMinus1 = ConstantInt::get(I32Ty, Prime - 1);
  A = B.CreateURem(A, ModMinus1);
  A = B.CreateAdd(A, ConstantInt::get(I32Ty, 1));
  Value *ExpInit = ConstantInt::get(I32Ty, Prime - 1);
  Value *ResInit = ConstantInt::get(I32Ty, 1);
  B.CreateBr(Loop);

  B.SetInsertPoint(Loop);
  PHINode *Base = B.CreatePHI(I32Ty, 2, "base");
  PHINode *Exp = B.CreatePHI(I32Ty, 2, "exp");
  PHINode *Res = B.CreatePHI(I32Ty, 2, "res");
  Base->addIncoming(A, Entry);
  Exp->addIncoming(ExpInit, Entry);
  Res->addIncoming(ResInit, Entry);

  Value *isZero = B.CreateICmpEQ(Exp, ConstantInt::get(I32Ty, 0));
  B.CreateCondBr(isZero, Exit, Body);

  B.SetInsertPoint(Body);
  Value *isOdd = B.CreateICmpEQ(B.CreateAnd(Exp, ConstantInt::get(I32Ty, 1)),
                                ConstantInt::get(I32Ty, 1));
  Value *mulRes = mulMod(B, Res, Base, Prime);
  Value *ResNext = B.CreateSelect(isOdd, mulRes, Res);
  Value *BaseNext = mulMod(B, Base, Base, Prime);
  Value *ExpNext = B.CreateLShr(Exp, ConstantInt::get(I32Ty, 1));
  B.CreateBr(Loop);

  Base->addIncoming(BaseNext, Body);
  Exp->addIncoming(ExpNext, Body);
  Res->addIncoming(ResNext, Body);

  B.SetInsertPoint(Exit);
  B.CreateRet(Res);

  return F;
}

// Algebraic identity: (a+b)(a-b) == a^2 - b^2 for all integers.
// Cheap (no calls) and always-true, but purely arithmetic so a sufficiently
// strong solver can simplify it. Paired with heavier predicates for depth.
static OpaquePredResult buildDiffSquares(IRBuilder<> &B, Function &F,
                                         uint64_t siteSalt, bool wantTrue,
                                         uint64_t &smState,
                                         OpaquePredContext &PredCtx,
                                         Instruction *Site,
                                         bool allowCalls) {
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  uint64_t c1 = ::splitmix64(smState);
  uint64_t c2 = ::splitmix64(smState);

  Value *x = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *a = B.CreateAdd(x, ConstantInt::get(I64Ty, c1));
  Value *b = B.CreateAdd(x, ConstantInt::get(I64Ty, c2));
  Value *lhs = B.CreateSub(B.CreateMul(a, a), B.CreateMul(b, b));
  Value *rhs = B.CreateMul(B.CreateAdd(a, b), B.CreateSub(a, b));
  Value *delta = B.CreateSub(lhs, rhs);
  Value *cmp = B.CreateICmpEQ(
      delta, ConstantInt::get(I64Ty, wantTrue ? 0 : 1));
  return {cmp, wantTrue, 2};
}

// Boolean identity: x^y == (~x&y)|(x&~y). Call-free, no side effects.
static OpaquePredResult buildXorEq(IRBuilder<> &B, Function &F,
                                   uint64_t siteSalt, bool wantTrue,
                                   uint64_t &smState,
                                   OpaquePredContext &PredCtx,
                                   Instruction *Site,
                                   bool allowCalls) {
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  uint64_t c1 = ::splitmix64(smState);
  uint64_t c2 = ::splitmix64(smState);

  Value *x = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *y = B.CreateAdd(B.CreateXor(x, ConstantInt::get(I64Ty, c1)),
                         ConstantInt::get(I64Ty, c2));
  Value *t1 = B.CreateXor(x, y);
  Value *t2 = B.CreateOr(B.CreateAnd(B.CreateNot(x), y),
                         B.CreateAnd(x, B.CreateNot(y)));
  Value *delta = B.CreateXor(t1, t2);
  Value *cmp = B.CreateICmpEQ(
      delta, ConstantInt::get(I64Ty, wantTrue ? 0 : 1));
  return {cmp, wantTrue, 3};
}

// Trivial identity: (x ^ c) ^ c == x. Used as the fast path when the
// heavy predicate rate is throttled, to avoid excessive compile time.
static OpaquePredResult buildCheapIdentity(IRBuilder<> &B, Function &F,
                                           uint64_t siteSalt, bool wantTrue,
                                           uint64_t &smState,
                                           OpaquePredContext &PredCtx,
                                           Instruction *Site,
                                           bool allowCalls) {
  (void)allowCalls;
  LLVMContext &Ctx = F.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  uint64_t c = ::splitmix64(smState);

  Value *seed = getOrCreateFuncSeed(F, PredCtx);
  seed = B.CreateFreeze(seed);
  Value *x = B.CreateXor(seed, ConstantInt::get(I64Ty, siteSalt));
  Value *t = B.CreateXor(B.CreateXor(x, ConstantInt::get(I64Ty, c)),
                         ConstantInt::get(I64Ty, c));
  Value *cmp = B.CreateICmpEQ(
      t, wantTrue ? x : B.CreateAdd(x, ConstantInt::get(I64Ty, 1)));
  return {cmp, wantTrue, 4};
}

static OpaquePredResult buildPowmod(IRBuilder<> &B, Function &F,
                                    uint64_t siteSalt, bool wantTrue,
                                    uint64_t &smState,
                                    OpaquePredContext &PredCtx,
                                    Instruction *Site,
                                    bool allowCalls,
                                    unsigned variant) {
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);

  static const uint32_t primes[] = {65521u, 65519u, 65497u,
                                    65479u, 65447u, 65437u};
  uint64_t r = ::splitmix64(smState);
  uint32_t prime = primes[r % (sizeof(primes) / sizeof(primes[0]))];

  Function *Pow = getOrCreatePowmod(M, prime, variant, PredCtx.TagCache);
  Value *input = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *res = B.CreateCall(Pow, {input},
                            getFuncletBundleFor(Site, PredCtx.Funclets));
  Value *cmp = B.CreateICmpEQ(
      res, ConstantInt::get(I32Ty, wantTrue ? 1 : 2));
  return {cmp, wantTrue, 1};
}

static OpaquePredResult buildMinorQuadric(IRBuilder<> &B, Function &F,
                                          uint64_t siteSalt, bool wantTrue,
                                          uint64_t &smState,
                                          OpaquePredContext &PredCtx,
                                          Instruction *Site,
                                          bool allowCalls,
                                          unsigned variant) {
  (void)smState;
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  Function *Minor =
      getOrCreateMinorQuadricPredicate(M, variant, PredCtx.TagCache);
  Value *input = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *res = B.CreateCall(Minor, {input},
                            getFuncletBundleFor(Site, PredCtx.Funclets));
  Value *cmp =
      B.CreateICmpEQ(res, ConstantInt::get(I64Ty, wantTrue ? 0 : 1));
  return {cmp, wantTrue, 5};
}

static OpaquePredResult buildQSeries(IRBuilder<> &B, Function &F,
                                     uint64_t siteSalt, bool wantTrue,
                                     uint64_t &smState,
                                     OpaquePredContext &PredCtx,
                                     Instruction *Site,
                                     bool allowCalls,
                                     unsigned variant) {
  (void)smState;
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  Function *QS = getOrCreateQSeriesPredicate(M, variant, PredCtx.TagCache);
  Value *input = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *res = B.CreateCall(QS, {input}, getFuncletBundleFor(Site, PredCtx.Funclets));
  Value *cmp =
      B.CreateICmpEQ(res, ConstantInt::get(I64Ty, wantTrue ? 0 : 1));
  return {cmp, wantTrue, 6};
}

static OpaquePredResult buildComposite(IRBuilder<> &B, Function &F,
                                       uint64_t siteSalt, bool wantTrue,
                                       uint64_t &smState,
                                       OpaquePredContext &PredCtx,
                                       Instruction *Site,
                                       bool allowCalls,
                                       unsigned variant) {
  (void)smState;
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  Function *Comp = getOrCreateCompositePredicate(M, variant, PredCtx.TagCache);
  Value *input = createRuntimeSeed(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *res = B.CreateCall(Comp, {input},
                            getFuncletBundleFor(Site, PredCtx.Funclets));
  Value *cmp =
      B.CreateICmpEQ(res, ConstantInt::get(I64Ty, wantTrue ? 0 : 1));
  return {cmp, wantTrue, 7};
}

static OpaquePredResult buildCollatz(IRBuilder<> &B, Function &F,
                                     uint64_t siteSalt, bool wantTrue,
                                     OpaquePredContext &PredCtx,
                                     Instruction *Site,
                                     bool allowCalls,
                                     unsigned variant) {
  Module &M = *F.getParent();
  LLVMContext &Ctx = M.getContext();
  Type *I1Ty = Type::getInt1Ty(Ctx);

  Function *Collatz = getOrCreateCollatzPredicate(M, variant, PredCtx.TagCache);
  Value *Input = createCollatzInput(B, F, siteSalt, PredCtx, Site, allowCalls);
  Value *res = B.CreateCall(Collatz, {Input},
                            getFuncletBundleFor(Site, PredCtx.Funclets));
  Value *cmp = B.CreateICmpEQ(
      res, ConstantInt::get(I1Ty, wantTrue ? 1 : 0));
  return {cmp, wantTrue, 0};
}

// Weighted random dispatch across predicate families. Mixing heavy
// (Collatz, Fermat) with cheap (DiffSquares, XorEq, identity) predicates
// balances analysis resistance against compile-time and code-size cost.
OpaquePredResult createOpaquePredicate(IRBuilder<> &B, Function &F,
                                       Instruction *Site,
                                       OpaquePredContext &Ctx) {
  uint64_t siteSalt = computeSiteSalt(F, Site, Ctx);

  uint64_t sm = siteSalt;
  uint64_t r = ::splitmix64(sm);
  bool wantTrue = ((r >> 16) & 1ULL) != 0;

  // Funclet EH blocks with ambiguous coloring can't safely emit calls.
  bool allowCalls = true;
  if (Site)
    allowCalls = !hasAmbiguousFunclet(Site, Ctx.Funclets);

  int rate = clampInt(OpaquePredRate.getValue(), 0, 100);
  if (rate < 100) {
    uint64_t gate = ::splitmix64(sm);
    if ((gate % 100ULL) >= static_cast<uint64_t>(rate)) {
      return buildCheapIdentity(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                                allowCalls);
    }
  }

  int wCollatz = std::max(0, OpaquePredWCollatz.getValue());
  int wPowmod = std::max(0, OpaquePredWPowmod.getValue());
  int wMinor = std::max(0, OpaquePredWMinorQuadric.getValue());
  int wQSeries = std::max(0, OpaquePredWQSeries.getValue());
  int wComp = std::max(0, OpaquePredWComposite.getValue());
  int wDiff = std::max(0, OpaquePredWDiffSq.getValue());
  int wXor = std::max(0, OpaquePredWXorEq.getValue());
  unsigned collatzVariants =
      std::max(1, OpaquePredCollatzVariants.getValue());
  unsigned powmodVariants =
      std::max(1, OpaquePredPowmodVariants.getValue());
  unsigned minorVariants =
      std::max(1, OpaquePredMinorVariants.getValue());
  unsigned qseriesVariants =
      std::max(1, OpaquePredQSeriesVariants.getValue());
  unsigned compVariants =
      std::max(1, OpaquePredCompositeVariants.getValue());
  int total = wCollatz + wPowmod + wMinor + wQSeries + wComp + wDiff + wXor;
  if (total <= 0) {
    return buildDiffSquares(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                            allowCalls);
  }

  uint64_t pick = ::splitmix64(sm) % static_cast<uint64_t>(total);
  if (pick < static_cast<uint64_t>(wCollatz)) {
    if (!allowCalls)
      return buildDiffSquares(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                              allowCalls);
    unsigned variant = ::splitmix64(sm) % collatzVariants;
    return buildCollatz(B, F, siteSalt, wantTrue, Ctx, Site, allowCalls,
                        variant);
  }
  pick -= wCollatz;
  if (pick < static_cast<uint64_t>(wPowmod)) {
    if (!allowCalls)
      return buildXorEq(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls);
    unsigned variant = ::splitmix64(sm) % powmodVariants;
    return buildPowmod(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls,
                       variant);
  }
  pick -= wPowmod;
  if (pick < static_cast<uint64_t>(wMinor)) {
    if (!allowCalls)
      return buildDiffSquares(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                              allowCalls);
    unsigned variant = ::splitmix64(sm) % minorVariants;
    return buildMinorQuadric(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                             allowCalls, variant);
  }
  pick -= wMinor;
  if (pick < static_cast<uint64_t>(wQSeries)) {
    if (!allowCalls)
      return buildXorEq(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls);
    unsigned variant = ::splitmix64(sm) % qseriesVariants;
    return buildQSeries(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls,
                        variant);
  }
  pick -= wQSeries;
  if (pick < static_cast<uint64_t>(wComp)) {
    if (!allowCalls)
      return buildXorEq(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls);
    unsigned variant = ::splitmix64(sm) % compVariants;
    return buildComposite(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls,
                          variant);
  }
  pick -= wComp;
  if (pick < static_cast<uint64_t>(wDiff))
    return buildDiffSquares(B, F, siteSalt, wantTrue, sm, Ctx, Site,
                            allowCalls);
  return buildXorEq(B, F, siteSalt, wantTrue, sm, Ctx, Site, allowCalls);
}
