//===- Utils.cpp - Obfuscation utilities ---------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE for details.
//
// Modifications Copyright (c) 2026 Danny Mundy
//
//===----------------------------------------------------------------------===//
//
// Shared utilities for obfuscation passes (IR helpers, tagging, and
// bookkeeping).
//
//===----------------------------------------------------------------------===//
#include "Utils.h"
#include "CryptoUtils.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/EHPersonalities.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h" // For DemoteRegToStack and DemotePHIToStack
#include <algorithm>
#include <cctype>
#include <sstream>

using namespace llvm;

#define DEBUG_TYPE "obfutils"

static cl::opt<bool>
    ObfDumpIR("obf-dump-ir", cl::init(false),
              cl::desc("Dump IR before/after obfuscation"));
static cl::opt<std::string> ObfDumpDir(
    "obf-dump-dir", cl::init(""),
    cl::desc("Directory for IR dumps (default: current directory)"));
// Growth budgets prevent compounding blowup when multiple passes stack.
// 300% BB / 500% inst are empirically safe for most real-world functions.
static cl::opt<unsigned>
    MaxBBGrowth("obf-max-bb-growth", cl::init(300),
                cl::desc("Max % basic block count growth (default 300%)"));
static cl::opt<unsigned>
    MaxInstGrowth("obf-max-inst-growth", cl::init(500),
                  cl::desc("Max % instruction count growth (default 500%)"));
static cl::opt<bool>
    ObfVerify("obf-verify", cl::init(true),
              cl::desc("Verify IR after each obfuscation pass (default true)"));
static cl::opt<bool>
    ObfOnlyAnnotated("obf-only-annotated", cl::init(false),
                     cl::desc("Apply obfuscation passes only to annotated "
                              "functions"));
static cl::opt<bool>
    ObfSymbolsOpt("obf-symbols", cl::init(true),
                  cl::desc("Obfuscate internal obfuscator/VM helper symbols"));
static cl::opt<std::string>
    ObfNamePrefix("obf-name-prefix", cl::init(""),
                  cl::desc("Prefix for obfuscated symbols (empty = random)"));

static constexpr const char *ObfBaseBBAttr = "obf.base.bb";
static constexpr const char *ObfBaseInstAttr = "obf.base.inst";
static constexpr const char *ObfTagMD = "obf.tag";
static constexpr const char *ObfNameSeedMD = "obf.name.seed";

static StringSet<> ForcedObfPasses;

void forceObfuscationPass(StringRef PassToken) {
  if (PassToken.empty())
    return;
  ForcedObfPasses.insert(PassToken.lower());
}

bool isForcedObfuscationPass(StringRef PassToken) {
  if (PassToken.empty())
    return false;
  std::string Key = PassToken.lower();
  return ForcedObfPasses.find(Key) != ForcedObfPasses.end();
}

static uint64_t fnv1a64(StringRef S, uint64_t H) {
  for (unsigned char C : S) {
    H ^= C;
    H *= 1099511628211ULL;
  }
  return H;
}

uint64_t splitmix64(uint64_t &x) {
  x += 0x9E3779B97F4A7C15ULL;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
  return z ^ (z >> 31);
}

static uint64_t getOrCreateNameSeed(Module &M) {
  if (NamedMDNode *MD = M.getNamedMetadata(ObfNameSeedMD)) {
    if (MD->getNumOperands() > 0) {
      if (auto *S = dyn_cast<MDString>(MD->getOperand(0)->getOperand(0))) {
        uint64_t Seed = 0;
        if (!S->getString().getAsInteger(16, Seed))
          return Seed;
      }
    }
  }

  uint64_t Seed = getObfuscationSeed();
  if (Seed == 0)
    Seed = cryptoutils->get_uint64_t();
  if (Seed == 0)
    Seed = 0x9E3779B97F4A7C15ULL;

  // Persist the seed so repeated passes keep names stable within the module.
  LLVMContext &Ctx = M.getContext();
  NamedMDNode *MD = M.getOrInsertNamedMetadata(ObfNameSeedMD);
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx, utohexstr(Seed)));
  MD->addOperand(Node);
  return Seed;
}

static bool hasObfTag(const GlobalObject &GO, StringRef Tag) {
  if (auto *N = GO.getMetadata(ObfTagMD)) {
    if (N->getNumOperands() > 0) {
      if (auto *S = dyn_cast<MDString>(N->getOperand(0))) {
        return S->getString() == Tag;
      }
    }
  }
  return false;
}

static StringRef getObfTagString(const GlobalObject &GO) {
  if (auto *N = GO.getMetadata(ObfTagMD)) {
    if (N->getNumOperands() > 0) {
      if (auto *S = dyn_cast<MDString>(N->getOperand(0))) {
        return S->getString();
      }
    }
  }
  return StringRef();
}

static void setObfTag(GlobalObject &GO, StringRef Tag) {
  LLVMContext &Ctx = GO.getContext();
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx, Tag));
  GO.setMetadata(ObfTagMD, Node);
}

static std::string buildObfName(Module &M, StringRef Tag, StringRef Base) {
  uint64_t Seed = getOrCreateNameSeed(M);
  std::string Prefix;
  if (!ObfNamePrefix.empty()) {
    Prefix = ObfNamePrefix;
  } else {
    // Per-build prefix so YARA-style rules can't match a fixed symbol pattern.
    uint64_t PH = fnv1a64("obf.name.prefix", Seed);
    std::string Hex = utohexstr(PH);
    Prefix = "__" + Hex.substr(0, std::min<size_t>(4, Hex.size()));
  }
  uint64_t H = fnv1a64(Tag, Seed);
  H = fnv1a64(Base, H);
  for (uint64_t Attempt = 0; Attempt < 16; ++Attempt) {
    uint64_t Mix = H ^ (Attempt * 0x9E3779B97F4A7C15ULL);
    std::string Name = Prefix + utohexstr(Mix);
    if (!M.getNamedValue(Name))
      return Name;
  }
  return Prefix + utohexstr(H);
}

void TaggedFunctionCache::rebuild(Module &M) {
  Owner = &M;
  Map.clear();
  for (Function &F : M) {
    insert(F);
  }
}

Function *TaggedFunctionCache::lookup(StringRef Tag) const {
  auto It = Map.find(Tag);
  if (It == Map.end())
    return nullptr;
  return It->second;
}

void TaggedFunctionCache::insert(Function &F) {
  StringRef Tag = getObfTagString(F);
  if (Tag.empty())
    return;
  // Preserve findTaggedFunction semantics by keeping the first function with a
  // given tag.
  Map.try_emplace(Tag, &F);
}

void TaggedFunctionCache::clear() {
  Map.clear();
  Owner = nullptr;
}

static void buildFuncletMap(Function &F, FuncletBundleContext &Ctx) {
  Ctx.FuncletPads.clear();
  Ctx.Owner = &F;
  Ctx.Built = true;

  if (!F.hasPersonalityFn())
    return;
  auto Personality = classifyEHPersonality(F.getPersonalityFn());
  if (!isFuncletEHPersonality(Personality))
    return;

  DenseMap<BasicBlock *, ColorVector> ColorMap = colorEHFunclets(F);
  if (ColorMap.empty())
    return;

  for (auto &KV : ColorMap) {
    BasicBlock *BB = KV.first;
    ColorVector &Pads = KV.second;
    if (Pads.empty())
      continue;
    auto &Out = Ctx.FuncletPads[BB];
    for (BasicBlock *Pad : Pads)
      Out.push_back(Pad);
  }
}

void ensureFuncletMap(Function &F, FuncletBundleContext &Ctx) {
  if (Ctx.Owner != &F || !Ctx.Built)
    buildFuncletMap(F, Ctx);
}

SmallVector<OperandBundleDef, 1>
getFuncletBundleFor(Instruction *Site, FuncletBundleContext &Ctx) {
  SmallVector<OperandBundleDef, 1> Bundles;
  if (!Site)
    return Bundles;
  Function *F = Site->getFunction();
  if (!F)
    return Bundles;
  ensureFuncletMap(*F, Ctx);

  auto It = Ctx.FuncletPads.find(Site->getParent());
  if (It == Ctx.FuncletPads.end())
    return Bundles;
  if (It->second.size() != 1)
    return Bundles;
  BasicBlock *Pad = It->second.front();
  Instruction *PadInst = nullptr;
  if (!Pad->empty()) {
    auto PadIt = Pad->getFirstNonPHIIt();
    if (PadIt != Pad->end())
      PadInst = &*PadIt;
  }
  if (PadInst && PadInst->isEHPad())
    Bundles.emplace_back("funclet", PadInst);
  return Bundles;
}

bool hasAmbiguousFunclet(Instruction *Site, FuncletBundleContext &Ctx) {
  if (!Site)
    return false;
  Function *F = Site->getFunction();
  if (!F)
    return false;
  ensureFuncletMap(*F, Ctx);
  auto It = Ctx.FuncletPads.find(Site->getParent());
  if (It == Ctx.FuncletPads.end())
    return false;
  return It->second.size() != 1;
}

Function *findTaggedFunction(Module &M, StringRef Tag) {
  for (Function &F : M) {
    if (hasObfTag(F, Tag))
      return &F;
  }
  return nullptr;
}

GlobalVariable *findTaggedGlobal(Module &M, StringRef Tag) {
  for (GlobalVariable &GV : M.globals()) {
    if (hasObfTag(GV, Tag))
      return &GV;
  }
  return nullptr;
}

// Tag the symbol with metadata for dedup and rename it to a hash-derived
// string so internal helper names don't leak pass structure into the binary.
void obfuscateSymbolName(GlobalObject &GO, Module &M, StringRef Tag,
                         StringRef Base) {
  setObfTag(GO, Tag);
  if (!ObfSymbolsOpt) {
    if (GO.getName().empty() && !Base.empty())
      GO.setName(Base);
    return;
  }
  std::string Name = buildObfName(M, Tag, Base);
  GO.setName(Name);
}

std::string readAnnotate(const Function *f) {
  std::string annotation = "";

  // Get annotation variable
  GlobalVariable *glob =
      f->getParent()->getGlobalVariable("llvm.global.annotations");

  if (glob != nullptr) {
    // Get the array
    if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
      for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
        // Get the struct
        if (ConstantStruct *structAn =
                dyn_cast<ConstantStruct>(ca->getOperand(i))) {
          if (structAn->getNumOperands() < 2)
            continue;

          // The first field can be either a direct function pointer (opaque
          // pointers) or a bitcasted function pointer (typed pointers).
          const Value *AnnotatedV =
              structAn->getOperand(0)->stripPointerCasts();
          if (AnnotatedV != f)
            continue;

          // The annotation string pointer can be either a direct global, or a
          // GEP into the global's data (older IR forms).
          const Constant *NoteC = structAn->getOperand(1);
          const GlobalVariable *AnnoteStr = nullptr;
          if (auto *NoteExpr = dyn_cast<ConstantExpr>(NoteC)) {
            if (NoteExpr->getOpcode() == Instruction::GetElementPtr)
              AnnoteStr = dyn_cast<GlobalVariable>(NoteExpr->getOperand(0));
            else
              AnnoteStr = dyn_cast<GlobalVariable>(NoteExpr->stripPointerCasts());
          } else {
            AnnoteStr = dyn_cast<GlobalVariable>(NoteC->stripPointerCasts());
          }
          if (!AnnoteStr || !AnnoteStr->hasInitializer())
            continue;

          auto *Data = dyn_cast<ConstantDataSequential>(AnnoteStr->getInitializer());
          if (!Data || !Data->isString())
            continue;

          // Clang emits annotation strings as C strings, which means
          // getAsString() includes a trailing NUL.
          StringRef S = Data->isCString() ? Data->getAsCString() : Data->getAsString();
          if (!S.empty() && S.back() == '\0')
            S = S.drop_back();
          annotation += S.lower();
          annotation += " ";
        }
      }
    }
  }
  return annotation;
}

std::string normalizePath(StringRef Path) {
  std::string NormPath = Path.str();
  for (char &C : NormPath) {
    if (C == '\\')
      C = '/';
  }
  return StringRef(NormPath).lower();
}

bool pathMatchesAny(StringRef Path, ArrayRef<std::string> Patterns) {
  if (Patterns.empty())
    return false;
  std::string NormPath = normalizePath(Path);
  for (const std::string &P : Patterns) {
    StringRef S = StringRef(P).trim();
    if (S.empty())
      continue;
    std::string Pat = normalizePath(S);
    if (NormPath.find(Pat) != std::string::npos)
      return true;
  }
  return false;
}

bool pathMatchesPatternList(StringRef Path, StringRef Patterns) {
  if (Patterns.empty())
    return false;
  // Use simple substring matches on normalized paths to keep this cheap and
  // platform-agnostic (no globbing).
  std::string P = Patterns.str();
  for (char &C : P) {
    if (C == ',')
      C = ';';
  }
  SmallVector<StringRef, 8> Parts;
  StringRef(P).split(Parts, ';', -1, false);
  std::string NormPath = normalizePath(Path);
  for (StringRef Part : Parts) {
    StringRef T = Part.trim();
    if (T.empty())
      continue;
    std::string Pat = normalizePath(T);
    if (NormPath.find(Pat) != std::string::npos)
      return true;
  }
  return false;
}

static bool annotationHasToken(StringRef Annotations, StringRef Token) {
  if (Annotations.empty() || Token.empty())
    return false;
  SmallVector<StringRef, 8> Parts;
  StringRef(Annotations).split(Parts, ' ', -1, false);
  std::string TokenLower = Token.lower();
  for (StringRef Part : Parts) {
    if (Part == TokenLower)
      return true;
  }
  return false;
}

bool hasAnnotation(const Function *F, StringRef Token) {
  if (!F)
    return false;
  std::string Ann = readAnnotate(F);
  return annotationHasToken(Ann, Token);
}

bool shouldSkipInstruction(const Instruction *I) {
  if (!I)
    return true;
  if (const Function *F = I->getFunction()) {
    if (shouldSkipFunction(F))
      return true;
  }
  if (auto *CB = dyn_cast<CallBase>(I)) {
    if (CB->isMustTailCall())
      return true;
    if (CB->isConvergent())
      return true;
    if (const Function *Callee = CB->getCalledFunction()) {
      if (Callee->hasFnAttribute(Attribute::Convergent))
        return true;
      if (Callee->isIntrinsic()) {
        switch (Callee->getIntrinsicID()) {
        case Intrinsic::experimental_convergence_entry:
        case Intrinsic::experimental_convergence_loop:
        case Intrinsic::experimental_convergence_anchor:
          return true;
        default:
          break;
        }
      }
      if (Callee->getName().starts_with("llvm.experimental.convergence."))
        return true;
    }
  }
  if (I->isAtomic())
    return true;
  if (auto *LI = dyn_cast<LoadInst>(I)) {
    if (LI->isVolatile())
      return true;
  }
  if (auto *SI = dyn_cast<StoreInst>(I)) {
    if (SI->isVolatile())
      return true;
  }
  if (auto *CI = dyn_cast<CallInst>(I)) {
    if (CI->isInlineAsm())
      return true;
  }
  return false;
}

bool shouldSkipBlock(const BasicBlock *BB) {
  if (!BB)
    return true;
  if (BB->isEHPad())
    return true;
  if (const Instruction *Term = BB->getTerminator()) {
    if (isa<CatchSwitchInst>(Term) || isa<CatchReturnInst>(Term) ||
        isa<CleanupReturnInst>(Term) || isa<ResumeInst>(Term) ||
        isa<InvokeInst>(Term) || isa<CallBrInst>(Term) ||
        isa<IndirectBrInst>(Term)) {
      return true;
    }
  }
  for (const Instruction &I : *BB) {
    if (shouldSkipInstruction(&I))
      return true;
  }
  return false;
}

bool shouldSkipFunction(const Function *F) {
  if (!F)
    return true;
  StringRef Name = F->getName();
  // DLL entrypoints run under the loader lock; obfuscation adds code that
  // could deadlock or violate the restricted-API contract there.
  if (Name == "DllMain" || Name == "_DllMain@12" ||
      Name == "DllMainCRTStartup" || Name == "_DllMainCRTStartup@12") {
    return true;
  }
  // CRT startup is fragile; it runs before the runtime is fully initialized.
  if (Name == "mainCRTStartup" || Name == "_mainCRTStartup" ||
      Name == "wmainCRTStartup" || Name == "_wmainCRTStartup" ||
      Name == "WinMainCRTStartup" || Name == "_WinMainCRTStartup" ||
      Name == "wWinMainCRTStartup" || Name == "_wWinMainCRTStartup" ||
      Name == "__tmainCRTStartup" || Name == "_tmainCRTStartup" ||
      Name.starts_with("__scrt_common_main") ||
      Name.starts_with("_scrt_common_main")) {
    return true;
  }
  // MSVC/Clang static init/term helpers are COMDAT-folded; obfuscating one
  // copy but not another causes ODR violations at link time.
  if (Name.starts_with("??__E") || Name.starts_with("??__F") ||
      Name.starts_with("__sti_") || Name.starts_with("__std_") ||
      Name.starts_with("__cxx_global_var_init") ||
      Name.starts_with("_GLOBAL__sub_I_") ||
      Name.starts_with("__GLOBAL__sub_I_")) {
    return true;
  }
  if (F->isDeclaration())
    return true;
  if (F->hasAvailableExternallyLinkage())
    return true;
  if (F->hasFnAttribute("no_obfuscate"))
    return true;
  if (F->hasFnAttribute("obf_skip"))
    return true;
  if (F->hasFnAttribute(Attribute::OptimizeNone) ||
      F->hasFnAttribute("optnone")) {
    return true;
  }
  std::string ann = readAnnotate(F);
  if (annotationHasToken(ann, "no_obfuscate"))
    return true;
  return false;
}


bool toObfuscate(bool flag, Function *F, StringRef AttributeToken) {
  SmallString<32> NoAttr("no");
  NoAttr += AttributeToken;
  bool Enable = flag || isForcedObfuscationPass(AttributeToken);

  if (shouldSkipFunction(F))
    return false;

  std::string Ann = readAnnotate(F);
  // Global opt-out overrides everything.
  if (annotationHasToken(Ann, "no_obfuscate"))
    return false;

  // We have to check the noX flag first because .find("x") is true for
  // a string like "x" or "nox".
  if (annotationHasToken(Ann, NoAttr))
    return false;

  // If attribute annotations explicitly opt-in.
  if (annotationHasToken(Ann, AttributeToken)) {
    ensureObfBaseline(*F);
    return true;
  }

  if (ObfOnlyAnnotated)
    return false;

  // If the pass flag is set (or forced), apply to all remaining functions.
  if (Enable) {
    ensureObfBaseline(*F);
    return true;
  }

  return false;
}

int clampInt(int v, int lo, int hi) {
  if (v < lo)
    return lo;
  if (v > hi)
    return hi;
  return v;
}

unsigned clampProb(int v) { return static_cast<unsigned>(clampInt(v, 0, 100)); }

ObfPassContext beginFunctionObfuscation(Function &F, StringRef Tag,
                                        bool DumpBefore,
                                        bool EnsureBaseline) {
  recordObfuscationSeed(*F.getParent());
  if (DumpBefore) {
    std::string Before = (Tag + ".before").str();
    maybeDumpIR(F, Before);
  }
  if (EnsureBaseline)
    ensureObfBaseline(F);
  ObfPassContext Ctx;
  Ctx.OrigBBs = countBasicBlocks(F);
  Ctx.OrigInsts = countInstructions(F);
  return Ctx;
}

void finishFunctionObfuscation(Function &F, StringRef Tag,
                               const ObfPassContext &Ctx, bool Changed,
                               bool CheckBudget, bool Verify, bool DumpAfter) {
  if (!Changed)
    return;
  if (CheckBudget)
    checkObfuscationBudget(F, Ctx.OrigBBs, Ctx.OrigInsts, Tag);
  if (Verify)
    verifyFunctionOrDie(F, Tag);
  if (DumpAfter) {
    std::string After = (Tag + ".after").str();
    maybeDumpIR(F, After);
  }
}

static bool parseSizeAttr(const Function &F, StringRef Name, std::size_t &Out) {
  if (!F.hasFnAttribute(Name))
    return false;
  Attribute Attr = F.getFnAttribute(Name);
  if (!Attr.isStringAttribute())
    return false;
  StringRef Val = Attr.getValueAsString();
  unsigned long long Parsed = 0;
  if (Val.getAsInteger(10, Parsed))
    return false;
  Out = static_cast<std::size_t>(Parsed);
  return true;
}

void ensureObfBaseline(Function &F) {
  if (!F.hasFnAttribute(ObfBaseBBAttr)) {
    F.addFnAttr(ObfBaseBBAttr, std::to_string(countBasicBlocks(F)));
  }
  if (!F.hasFnAttribute(ObfBaseInstAttr)) {
    F.addFnAttr(ObfBaseInstAttr, std::to_string(countInstructions(F)));
  }
}

std::size_t countInstructions(const Function &F) {
  std::size_t count = 0;
  for (const BasicBlock &BB : F) {
    count += BB.size();
  }
  return count;
}

std::size_t countBasicBlocks(const Function &F) { return F.size(); }

bool checkObfuscationBudget(Function &F, std::size_t origBBs,
                            std::size_t origInsts, StringRef passName) {
  if (origBBs == 0 || origInsts == 0)
    return true;

  // Use the original pre-obfuscation sizes so each pass is budgeted against
  // the same baseline, preventing cascading growth across stacked passes.
  std::size_t baseBBs = origBBs;
  std::size_t baseInsts = origInsts;
  parseSizeAttr(F, ObfBaseBBAttr, baseBBs);
  parseSizeAttr(F, ObfBaseInstAttr, baseInsts);

  std::size_t newBBs = countBasicBlocks(F);
  std::size_t newInsts = countInstructions(F);

  std::size_t maxBBs =
      (baseBBs * static_cast<std::size_t>(MaxBBGrowth)) / 100;
  std::size_t maxInsts =
      (baseInsts * static_cast<std::size_t>(MaxInstGrowth)) / 100;

  if (newBBs > maxBBs || newInsts > maxInsts) {
    LLVM_DEBUG(dbgs() << "obf: budget exceeded in " << passName << " for "
                      << F.getName() << " (BB " << newBBs << "/" << maxBBs
                      << ", Inst " << newInsts << "/" << maxInsts << ")\n");
    // Stop further transforms on this function to avoid compounding growth.
    if (!F.hasFnAttribute("no_obfuscate"))
      F.addFnAttr("no_obfuscate");
    return false;
  }
  return true;
}

void markArithObf(Instruction &I, StringRef Tag) {
  LLVMContext &Ctx = I.getContext();
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx, Tag));
  I.setMetadata("obf.arith", Node);
}

bool isArithObf(const Instruction &I) {
  return I.getMetadata("obf.arith") != nullptr;
}

void markInsertedRange(BasicBlock &BB, Instruction *Prev, Instruction *End,
                        StringRef Tag) {
  Instruction *It = nullptr;
  if (Prev) {
    It = Prev->getNextNode();
  } else if (!BB.empty()) {
    It = &*BB.begin();
  }
  while (It && It != End) {
    markArithObf(*It, Tag);
    It = It->getNextNode();
  }
}

GlobalVariable *getOrCreateObfFailCode(Module &M) {
  if (GlobalVariable *GV = findTaggedGlobal(M, "obf.fail.code"))
    return GV;

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  auto *CodeGV = new GlobalVariable(
      M, I32Ty, false, GlobalValue::PrivateLinkage,
      ConstantInt::get(I32Ty, 0), "obf_fail_code");
  CodeGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
  obfuscateSymbolName(*CodeGV, M, "obf.fail.code", "obf_fail_code");
  return CodeGV;
}

Function *getOrCreateObfFail(Module &M, TaggedFunctionCache *TagCache) {
  if (TagCache) {
    if (Function *F = TagCache->lookup("obf.fail.fn"))
      return F;
    if (Function *F = findTaggedFunction(M, "obf.fail.fn")) {
      TagCache->insert(*F);
      return F;
    }
  } else {
    if (Function *F = findTaggedFunction(M, "obf.fail.fn"))
      return F;
  }

  LLVMContext &Ctx = M.getContext();
  IntegerType *I32Ty = Type::getInt32Ty(Ctx);
  FunctionType *FT =
      FunctionType::get(Type::getVoidTy(Ctx), {I32Ty}, false);
  Function *F =
      Function::Create(FT, GlobalValue::InternalLinkage, "obf_fail", &M);
  obfuscateSymbolName(*F, M, "obf.fail.fn", "obf_fail");
  if (TagCache)
    TagCache->insert(*F);

  F->addFnAttr("no_obfuscate");
  F->addFnAttr(Attribute::NoInline);
  F->addFnAttr(Attribute::Cold);
  F->addFnAttr(Attribute::NoReturn);
  F->addFnAttr(Attribute::NoUnwind);

  GlobalVariable *CodeGV = getOrCreateObfFailCode(M);

  BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", F);
  IRBuilder<> B(Entry);
  Value *Code = F->arg_begin();
  StoreInst *S = B.CreateStore(Code, CodeGV);
  S->setVolatile(true);
  FunctionCallee Trap = Intrinsic::getOrInsertDeclaration(&M, Intrinsic::trap);
  B.CreateCall(Trap);
  B.CreateUnreachable();
  return F;
}

Function *getOrCreateObfFail(Module &M) { return getOrCreateObfFail(M, nullptr); }

static std::string sanitizeFileName(StringRef name) {
  if (name.empty())
    return "anon";
  std::string out = name.str();
  for (char &c : out) {
    if (!isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '.' &&
        c != '-') {
      c = '_';
    }
  }
  return out;
}

void maybeDumpIR(const Function &F, StringRef tag) {
  if (!ObfDumpIR)
    return;

  std::string base = sanitizeFileName(F.getName());
  SmallString<256> path;
  if (ObfDumpDir.empty()) {
    path = ".";
  } else {
    path = ObfDumpDir;
  }
  std::error_code ec = sys::fs::create_directories(path);
  if (ec) {
    LLVM_DEBUG(dbgs() << "obf: failed to create dump dir: " << ec.message()
                      << "\n");
    return;
  }
  sys::path::append(path, base + "." + tag.str() + ".ll");
  raw_fd_ostream os(path, ec, sys::fs::OF_Text);
  if (ec) {
    LLVM_DEBUG(dbgs() << "obf: failed to open dump file: " << ec.message()
                      << "\n");
    return;
  }
  F.print(os);
}

void maybeDumpIR(const Module &M, StringRef tag) {
  if (!ObfDumpIR)
    return;

  std::string base = sanitizeFileName(M.getModuleIdentifier());
  if (base == "anon" && !M.getName().empty())
    base = sanitizeFileName(M.getName());
  if (base == "anon")
    base = "module";

  SmallString<256> path;
  if (ObfDumpDir.empty()) {
    path = ".";
  } else {
    path = ObfDumpDir;
  }
  std::error_code ec = sys::fs::create_directories(path);
  if (ec) {
    LLVM_DEBUG(dbgs() << "obf: failed to create dump dir: " << ec.message()
                      << "\n");
    return;
  }
  sys::path::append(path, base + "." + tag.str() + ".ll");
  raw_fd_ostream os(path, ec, sys::fs::OF_Text);
  if (ec) {
    LLVM_DEBUG(dbgs() << "obf: failed to open dump file: " << ec.message()
                      << "\n");
    return;
  }
  M.print(os, nullptr);
}

void recordObfuscationSeed(Module &M) {
  uint64_t seed = getObfuscationSeed();
  if (seed == 0)
    return;
  if (M.getNamedMetadata("obf.seed"))
    return;

  LLVMContext &Ctx = M.getContext();
  NamedMDNode *MD = M.getOrInsertNamedMetadata("obf.seed");
  MDNode *Node = MDNode::get(Ctx, MDString::get(Ctx, getObfuscationSeedHex()));
  MD->addOperand(Node);
}

void verifyFunctionOrDie(const Function &F, StringRef passName) {
  if (!ObfVerify)
    return;
  if (verifyFunction(F, &errs())) {
    errs() << "obf: invalid IR after " << passName << " in " << F.getName()
           << "\n";
    llvm_unreachable("Invalid IR after obfuscation");
  }
}

void verifyModuleOrDie(const Module &M, StringRef passName) {
  if (!ObfVerify)
    return;
  if (verifyModule(M, &errs())) {
    errs() << "obf: invalid IR after " << passName << " in "
           << M.getModuleIdentifier() << "\n";
    llvm_unreachable("Invalid IR after obfuscation");
  }
}
