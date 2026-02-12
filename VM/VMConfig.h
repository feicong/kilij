//===- VMConfig.h - VM configuration knobs -------------------------------===//
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
// Defines the configuration knobs that control VM layout, hardening, and
// debug features.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_OBFUSCATION_VMCONFIG_H
#define LLVM_OBFUSCATION_VMCONFIG_H

#include <cstdint>

namespace llvm {
namespace obfvm {

// Opcode = bytecode interpreter, BB = per-BB native stub, Region = coalesced
// native regions.  Opcode is strongest; Region is fastest.
enum class VMMode : uint8_t { None, Opcode, BB, Region };
// MBA subsumes affine; affine is cheaper but weaker against symbolic solvers.
enum class VMEncode : uint8_t { Off, Affine, MBA };
enum class VMSelect : uint8_t { None, All, Marked, Cold };
// Random shuffles handler ordering per function to prevent cross-binary diffs.
enum class VMHandlers : uint8_t { Static, Random };
// Indirect uses a function-pointer table; Switch uses a native switch.
// Switch is debuggable but trivially recoverable.
enum class VMDispatch : uint8_t { Switch, Indirect };

struct VMConfig {
  VMMode Mode = VMMode::None;
  VMEncode Encode = VMEncode::Off;
  VMSelect Select = VMSelect::All;
  VMHandlers Handlers = VMHandlers::Static;
  VMDispatch Dispatch = VMDispatch::Indirect;
  // Enables layout/dispatch hardening (encoded PC, shuffled handlers, etc).
  bool Hard = true;
  // HardRuntime toggles anti-debug/integrity checks in the runtime.
  bool HardRuntime = false;
  bool Debug = false;
  bool RuntimeDebug = false;
  bool Trace = false;
  bool BoundsCheck = false;
  bool Validate = false;
  bool Counters = false;
  bool EncodeFeistel = false;
  bool EncodeFeistelAll = false;
  unsigned FeistelRounds = 2;
  bool ObfuscateRuntime = false;
  uint32_t BogusCount = 4;
  uint64_t ColdThreshold = 0;
  uint32_t TraceLimit = 0;
};

} // namespace obfvm
} // namespace llvm

#endif
