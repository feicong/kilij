if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.20)
  project(KilijObfuscation LANGUAGES CXX)
  find_package(LLVM 20 CONFIG)
  if (NOT LLVM_FOUND)
    message(FATAL_ERROR
      "Could not find LLVM 20 CMake config.\n"
      "Set -DLLVM_DIR=<prefix>/lib/cmake/llvm (the directory containing LLVMConfig.cmake).\n"
      "On Debian/Ubuntu: apt install llvm-20-dev  ->  -DLLVM_DIR=/usr/lib/llvm-20/lib/cmake/llvm\n"
      "Or use llvm-config-20 --cmakedir to find the path.")
  endif()
  if (NOT LLVM_VERSION_MAJOR STREQUAL "20")
    message(FATAL_ERROR "Kilij requires LLVM 20.x (found ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR})")
  endif()
  include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  add_definitions(${LLVM_DEFINITIONS})
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
  include(HandleLLVMOptions)

  option(KILIJ_FORCE_LLVM_ENABLE_PLUGINS
    "Force-enable LLVM_ENABLE_PLUGINS when building Kilij standalone (Windows static LLVM builds default this OFF)."
    OFF)
  if (KILIJ_FORCE_LLVM_ENABLE_PLUGINS)
    # LLVMConfig.cmake may set LLVM_ENABLE_PLUGINS based on how LLVM was built.
    # Override it so add_llvm_pass_plugin/add_llvm_library(MODULE) are not ignored.
    set(LLVM_ENABLE_PLUGINS ON)
  endif()
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(OBFUSCATION_SOURCES
  CryptoUtils.cpp
  ConstObfuscation.cpp
  StringObfuscation.cpp
  IATObfuscation.cpp
  OpaquePredicates.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  MBAObfuscation.cpp
  IndirectBranch.cpp
  Utils.cpp
  SplitBasicBlock.cpp
  Flattening.cpp
  VM/VMIR.cpp
  VM/VMInterpreter.cpp
  VM/VMLowering.cpp
  VM/VMBytecode.cpp
  VM/VMEmitUtils.cpp
  VM/VMEmitInterp.cpp
  VM/VMRegionFormation.cpp
  VM/VMEmitRegion.cpp
  VM/VMEncode.cpp
  VM/VMPass.cpp
  Plugin.cpp
)

# If we're linking LLVM into a shared library (e.g. libLLVM.so), the obfuscation
# implementation (and its command-line options) is already present in the host
# process. Building a pass plugin that re-compiles the same sources leads to
# duplicate option registrations at dlopen() time (e.g. "Option 'aesSeed'
# registered more than once"). In that case, build the plugin as a thin wrapper
# that only contains registration code and references the in-process symbols.
set(KILIJ_PLUGIN_SOURCES ${OBFUSCATION_SOURCES})
set(KILIJ_THIN_PLUGIN_DEFAULT OFF)
# Default to thin only for in-tree shared-LLVM builds (standalone builds need
# the full implementation inside the plugin).
if (NOT WIN32 AND NOT (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR) AND LLVM_LINK_LLVM_DYLIB)
  set(KILIJ_THIN_PLUGIN_DEFAULT ON)
endif()
option(KILIJ_THIN_PLUGIN
  "Build Kilij as a thin pass plugin (Plugin.cpp only). Requires Kilij to already be present in the host tool."
  ${KILIJ_THIN_PLUGIN_DEFAULT})
if (NOT WIN32 AND KILIJ_THIN_PLUGIN)
  set(KILIJ_PLUGIN_SOURCES Plugin.cpp)
endif()

add_llvm_component_library(LLVMObfuscation
  ${OBFUSCATION_SOURCES}

  LINK_COMPONENTS
  Core
  Support
  TransformUtils
  Analysis
  ScalarOpts
  Passes
  IPO
)

# On Windows static builds, LLVM pass plugins are only supported when the plugin
# imports symbols from exactly one exporting tool (see LLVM_EXPORT_SYMBOLS_FOR_PLUGINS).
# Build Kilij as a module that links against opt.exe's import library.
#
# We use a generator expression so the opt target does not need to exist yet
# when this directory is configured.
if (WIN32 AND LLVM_EXPORT_SYMBOLS_FOR_PLUGINS AND NOT LLVM_ENABLE_PLUGINS AND LLVM_TOOL_OPT_BUILD)
  add_llvm_library(Kilij MODULE NO_EXPORT
    ${KILIJ_PLUGIN_SOURCES}

    PLUGIN_TOOL $<TARGET_LINKER_FILE:opt>

    LINK_COMPONENTS
    Core
    Support
    TransformUtils
    Analysis
    ScalarOpts
    Passes
    IPO
    )
else()
  add_llvm_pass_plugin(Kilij
    ${KILIJ_PLUGIN_SOURCES}

    ADDITIONAL_HEADER_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}

    LINK_COMPONENTS
    Core
    Support
    TransformUtils
    Analysis
    ScalarOpts
    Passes
    IPO
    )
endif()

if (TARGET Kilij)
  # In some LLVM configurations (e.g. LLVM_ENABLE_PLUGINS=OFF), the helper
  # macros create a non-compilable placeholder/UTILITY target named "Kilij".
  # Guard target_* calls so CMake doesn't hard-fail in those setups.
  get_target_property(_kilij_type Kilij TYPE)
  if (_kilij_type MATCHES "^(STATIC_LIBRARY|SHARED_LIBRARY|MODULE_LIBRARY|OBJECT_LIBRARY)$")
    # Ensure the shared-library plugin exports llvmGetPassPluginInfo() even when
    # LLVM_OBFUSCATION_LINK_INTO_TOOLS is enabled (which suppresses the entry
    # point for static in-tool registration).
    target_compile_definitions(Kilij PRIVATE KILIJ_BUILD_PASS_PLUGIN)

    if (WIN32)
      # MSVC DLLs export no symbols by default; opt/clang load pass plugins by
      # looking up llvmGetPassPluginInfo().
      target_link_options(Kilij PRIVATE "/EXPORT:llvmGetPassPluginInfo")
    endif()
  endif()
endif()

if (TARGET intrinsics_gen)
  if (TARGET Kilij)
    add_dependencies(Kilij intrinsics_gen)
  endif()
  add_dependencies(LLVMObfuscation intrinsics_gen)
endif()

# When building in-tree, register Kilij as a static extension so clang/opt
# can call getKilijPluginInfo() without -fpass-plugin.
