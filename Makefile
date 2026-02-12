# Kilij - LLVM Obfuscation Pass Plugin
#
# Convenience Makefile for standalone (out-of-tree) plugin development.
#
# Usage:
#   make build        Build the Kilij pass plugin
#   make test         Run unit tests (loads standalone plugin via -fpass-plugin)
#   make fuzz         Run a quick fuzz check (20 iterations)
#   make clean        Remove build artifacts
#   make help         Show this help
#
# Environment variables:
#   LLVM_DIR          Path to LLVM CMake config directory (auto-detected if unset)
#   CMAKE_BUILD_TYPE  Build type (default: Release)
#   JOBS              Parallel build jobs (default: auto)
#
# Requires: LLVM 20 development packages, CMake >= 3.20, Ninja

.PHONY: build plugin test fuzz clean help

BUILD_DIR     := _build/standalone
CMAKE_TYPE    ?= Release
JOBS          ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# ---------------------------------------------------------------------------
# LLVM auto-detection
# ---------------------------------------------------------------------------
# Honor explicit LLVM_DIR first, then probe llvm-config-20, then llvm-config.
ifdef LLVM_DIR
  _LLVM_CMAKE_FLAG := -DLLVM_DIR="$(LLVM_DIR)"
else
  _LLVM_CONFIG := $(shell command -v llvm-config-20 2>/dev/null || command -v llvm-config 2>/dev/null)
  ifdef _LLVM_CONFIG
    _LLVM_CMAKEDIR := $(shell $(_LLVM_CONFIG) --cmakedir 2>/dev/null)
  endif
  ifdef _LLVM_CMAKEDIR
    _LLVM_CMAKE_FLAG := -DLLVM_DIR="$(_LLVM_CMAKEDIR)"
  else
    _LLVM_CMAKE_FLAG :=
  endif
endif

# LLVM tool binary directory (for --clang, --opt, etc.)
ifdef _LLVM_CONFIG
  _LLVM_BINDIR := $(shell $(_LLVM_CONFIG) --bindir 2>/dev/null)
endif

# ---------------------------------------------------------------------------
# Plugin auto-detection: find the built Kilij shared library.
# ---------------------------------------------------------------------------
# After `make plugin`, one of these should exist in BUILD_DIR (or a subdirectory).
_PLUGIN_PATH := $(firstword $(wildcard \
    $(BUILD_DIR)/Kilij.so \
    $(BUILD_DIR)/Kilij.dll \
    $(BUILD_DIR)/Kilij.dylib \
    $(BUILD_DIR)/lib/Kilij.so \
    $(BUILD_DIR)/lib/Kilij.dll \
    $(BUILD_DIR)/lib/Kilij.dylib \
))

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

## Build the Kilij pass plugin (standalone out-of-tree)
build: plugin
plugin:
	@mkdir -p $(BUILD_DIR)
	cmake -S . -B $(BUILD_DIR) -G Ninja \
		-DCMAKE_BUILD_TYPE=$(CMAKE_TYPE) \
		$(_LLVM_CMAKE_FLAG)
	ninja -C $(BUILD_DIR) -j $(JOBS)
	@echo ""
	@echo "Build complete. Plugin is in $(BUILD_DIR)/"

## Run unit tests (standalone: loads plugin via -fpass-plugin)
test: plugin
	$(eval _PLUGIN_PATH := $(firstword $(wildcard \
		$(BUILD_DIR)/Kilij.so \
		$(BUILD_DIR)/Kilij.dll \
		$(BUILD_DIR)/Kilij.dylib \
		$(BUILD_DIR)/lib/Kilij.so \
		$(BUILD_DIR)/lib/Kilij.dll \
		$(BUILD_DIR)/lib/Kilij.dylib \
	)))
	@if [ -z "$(_PLUGIN_PATH)" ]; then \
		echo "ERROR: cannot find Kilij plugin in $(BUILD_DIR)/"; \
		echo "  Expected Kilij.so, Kilij.dll, or Kilij.dylib"; \
		exit 1; \
	fi
	@echo "Using plugin: $(_PLUGIN_PATH)"
	python3 kilij-tests/unit_fuzz_run.py unit \
		--pass-plugin "$(_PLUGIN_PATH)" \
		$(if $(_LLVM_BINDIR),--clang "$(_LLVM_BINDIR)/clang") \
		$(if $(_LLVM_BINDIR),--opt "$(_LLVM_BINDIR)/opt") \
		$(if $(_LLVM_BINDIR),--llvm-dis "$(_LLVM_BINDIR)/llvm-dis")

## Run a quick fuzz pass (20 iterations)
fuzz: plugin
	$(eval _PLUGIN_PATH := $(firstword $(wildcard \
		$(BUILD_DIR)/Kilij.so \
		$(BUILD_DIR)/Kilij.dll \
		$(BUILD_DIR)/Kilij.dylib \
		$(BUILD_DIR)/lib/Kilij.so \
		$(BUILD_DIR)/lib/Kilij.dll \
		$(BUILD_DIR)/lib/Kilij.dylib \
	)))
	@if [ -z "$(_PLUGIN_PATH)" ]; then \
		echo "ERROR: cannot find Kilij plugin in $(BUILD_DIR)/"; \
		echo "  Expected Kilij.so, Kilij.dll, or Kilij.dylib"; \
		exit 1; \
	fi
	@echo "Using plugin: $(_PLUGIN_PATH)"
	python3 kilij-tests/unit_fuzz_run.py fuzz \
		--pass-plugin "$(_PLUGIN_PATH)" \
		$(if $(_LLVM_BINDIR),--clang "$(_LLVM_BINDIR)/clang") \
		$(if $(_LLVM_BINDIR),--opt "$(_LLVM_BINDIR)/opt") \
		$(if $(_LLVM_BINDIR),--llvm-stress "$(_LLVM_BINDIR)/llvm-stress") \
		$(if $(_LLVM_BINDIR),--llvm-dis "$(_LLVM_BINDIR)/llvm-dis") \
		--iterations 20

## Remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## Show available targets
help:
	@echo "Kilij - LLVM Obfuscation Pass Plugin"
	@echo ""
	@echo "Targets:"
	@echo "  make build   Build the standalone pass plugin (into $(BUILD_DIR)/)"
	@echo "  make test    Run unit tests (loads plugin via -fpass-plugin)"
	@echo "  make fuzz    Quick fuzz check (20 iterations)"
	@echo "  make clean   Remove $(BUILD_DIR)/"
	@echo "  make help    Show this help"
	@echo ""
	@echo "Environment:"
	@echo "  LLVM_DIR=<path>          LLVM CMake config directory"
	@echo "  CMAKE_BUILD_TYPE=<type>  Build type (default: Release)"
	@echo "  JOBS=<N>                 Parallel jobs (default: auto)"
