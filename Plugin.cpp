//===- Plugin.cpp - Kilij pass plugin ------------------------------------===//
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
// Registers obfuscation passes with LLVM's pass plugin interface.
//
//===----------------------------------------------------------------------===//
#include "BogusControlFlow.h"
#include "ConstObfuscation.h"
#include "Flattening.h"
#include "IATObfuscation.h"
#include "IndirectBranch.h"
#include "MBAObfuscation.h"
#include "SplitBasicBlock.h"
#include "StringObfuscation.h"
#include "Substitution.h"
#include "Utils.h"
#include "VM/VMPass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

llvm::PassPluginLibraryInfo getKilijPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "Kilij", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM,
               ArrayRef<PassBuilder::PipelineElement>) {
              // Convenience: a single pipeline element that matches the
              // OptimizerLast ordering used by the plugin callback.
              if (Name == "kilij") {
                MPM.addPass(obfvm::VMPass());
                MPM.addPass(IATObfuscationPass());
                MPM.addPass(StringObfuscationPass());
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(ConstObfuscationPass()));
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(SplitBasicBlockPass()));
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(BogusControlFlowPass()));
                MPM.addPass(createModuleToFunctionPassAdaptor(FlatteningPass()));
                MPM.addPass(createModuleToFunctionPassAdaptor(MBAObfuscationPass()));
                MPM.addPass(IndirectBranchPass());
                MPM.addPass(createModuleToFunctionPassAdaptor(SubstitutionPass()));
                return true;
              }

              // Function passes (module->function adaptor so opt -passes='fla,...'
              // works as expected).
              if (Name == "fla") {
                forceObfuscationPass("fla");
                MPM.addPass(createModuleToFunctionPassAdaptor(FlatteningPass()));
                return true;
              }
              if (Name == "bcf") {
                forceObfuscationPass("bcf");
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(BogusControlFlowPass()));
                return true;
              }
              if (Name == "split") {
                forceObfuscationPass("split");
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(SplitBasicBlockPass()));
                return true;
              }
              if (Name == "sub") {
                forceObfuscationPass("sub");
                MPM.addPass(createModuleToFunctionPassAdaptor(SubstitutionPass()));
                return true;
              }
              if (Name == "mba") {
                forceObfuscationPass("mba");
                MPM.addPass(createModuleToFunctionPassAdaptor(MBAObfuscationPass()));
                return true;
              }
              if (Name == "const" || Name == "obf-const") {
                forceObfuscationPass("const");
                MPM.addPass(
                    createModuleToFunctionPassAdaptor(ConstObfuscationPass()));
                return true;
              }

              // Module passes.
              if (Name == "str" || Name == "obf-str") {
                forceObfuscationPass("obf-str");
                MPM.addPass(StringObfuscationPass());
                return true;
              }
              if (Name == "iat" || Name == "obf-iat") {
                forceObfuscationPass("obf-iat");
                MPM.addPass(IATObfuscationPass());
                return true;
              }
              if (Name == "indbr") {
                forceObfuscationPass("indbr");
                MPM.addPass(IndirectBranchPass());
                return true;
              }
              if (Name == "indcall") {
                forceObfuscationPass("indcall");
                MPM.addPass(IndirectBranchPass());
                return true;
              }
              if (Name == "vm") {
                // VM is configured via -mllvm -vm-mode=...; parsing "vm" just
                // inserts the pass into the pipeline.
                MPM.addPass(obfvm::VMPass());
                return true;
              }
              return false;
            });

        // Run obfuscation passes late to avoid cleanup/IC folding them away.
        PB.registerOptimizerLastEPCallback([](llvm::ModulePassManager &MPM,
                                              OptimizationLevel Level,
                                              ThinOrFullLTOPhase) {
          (void)Level;
          // VM first so later passes see the transformed surface.
          MPM.addPass(obfvm::VMPass());
          MPM.addPass(IATObfuscationPass());
          MPM.addPass(StringObfuscationPass());
          MPM.addPass(
              createModuleToFunctionPassAdaptor(ConstObfuscationPass()));
          MPM.addPass(createModuleToFunctionPassAdaptor(SplitBasicBlockPass()));
          MPM.addPass(
              createModuleToFunctionPassAdaptor(BogusControlFlowPass()));
          MPM.addPass(createModuleToFunctionPassAdaptor(FlatteningPass()));
          MPM.addPass(createModuleToFunctionPassAdaptor(MBAObfuscationPass()));
          MPM.addPass(IndirectBranchPass());
          MPM.addPass(createModuleToFunctionPassAdaptor(SubstitutionPass()));
        });
      }};
}

#if !defined(LLVM_OBFUSCATION_LINK_INTO_TOOLS) || defined(KILIJ_BUILD_PASS_PLUGIN)
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return getKilijPluginInfo();
}
#endif
