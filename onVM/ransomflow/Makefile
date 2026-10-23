# Makefile for the ransomflow Pin tool (Windows + MSYS2 + LLVM clang-cl).
#
# Requirements
#   - Intel Pin kit (3.31+, MSVC/clang-cl flavor) — the kit's makefile.config
#     must define NEWCPP=1 (or pass COMPILER=clang-cl) so clang-cl/lld-link are used.
#   - MSYS2 (make + coreutils + cygpath)
#   - LLVM (clang-cl.exe, lld-link.exe)
#
# Defaults (all overridable via env or `make VAR=...`):
#   PIN_ROOT   = <this Makefile>/../../pin                (= <repo>/pin)
#   MSYS2_BIN  = auto-detected from common install paths  (override if elsewhere)
#   LLVM_BIN   = auto-detected from common install paths  (override if elsewhere)
#   TARGET     = intel64                                  (ia32 | intel64)
#
# Usage
#   <MSYS2_BIN>/make.exe                        # build TARGET=intel64
#   <MSYS2_BIN>/make.exe TARGET=ia32            # build 32-bit
#   <MSYS2_BIN>/make.exe both                   # build both
#   <MSYS2_BIN>/make.exe PIN_ROOT=D:/pin ...    # use a Pin kit elsewhere
#
# Output: Build/ransomflow.dll (ia32) or Build/ransomflow_x64.dll (intel64).

MAKEFILE_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

# ── Configuration (override via env or make args) ─────────────────────────────
PIN_ROOT  ?= $(MAKEFILE_DIR)/../../pin
TARGET    ?= intel64
TOOL_NAME := ransomflow

SUPPORTED_TARGETS := ia32 intel64
ifeq ($(filter $(TARGET),$(SUPPORTED_TARGETS)),)
$(error TARGET must be one of: $(SUPPORTED_TARGETS))
endif

# ── Auto-detect MSYS2 / LLVM so a fresh PC with the toolchains installed
# elsewhere doesn't fail with a misleading "PIN_ROOT could not be resolved"
# (the original symptom was cygpath.exe missing -> PIN_ROOT normalization
# silently returned empty).  Probes are sequential `ifneq ($(wildcard ...))`
# rather than `foreach + firstword` because the LLVM install path contains
# a space ("Program Files") and `firstword` would shatter it into pieces.
# User override (MSYS2_BIN=... / LLVM_BIN=...) wins — only auto-detect when
# the var is unset.
ifndef MSYS2_BIN
  ifneq ($(wildcard C:/msys64/usr/bin/make.exe),)
    MSYS2_BIN := C:/msys64/usr/bin
  else ifneq ($(wildcard C:/msys2/usr/bin/make.exe),)
    MSYS2_BIN := C:/msys2/usr/bin
  else ifneq ($(wildcard D:/msys64/usr/bin/make.exe),)
    MSYS2_BIN := D:/msys64/usr/bin
  else ifneq ($(wildcard D:/msys2/usr/bin/make.exe),)
    MSYS2_BIN := D:/msys2/usr/bin
  endif
endif
ifeq ($(strip $(MSYS2_BIN)),)
$(error MSYS2 not found in C:/msys64, C:/msys2, D:/msys64 or D:/msys2.  Install \
MSYS2 (https://www.msys2.org/) or pass MSYS2_BIN=<path-to-msys2-usr-bin>)
endif
ifeq ($(wildcard $(MSYS2_BIN)/cygpath.exe),)
$(error MSYS2_BIN=$(MSYS2_BIN) is missing cygpath.exe.  Install the MSYS2 \
base packages or point MSYS2_BIN at a directory containing cygpath.exe.)
endif

# LLVM install paths usually contain spaces ("C:/Program Files/LLVM"), which
# breaks make's $(wildcard) word-splitting.  We have MSYS2_BIN locked in by
# this point, so use bash to probe with proper quoting.  Each $(shell ...)
# call returns the first matching path or an empty string.
ifndef LLVM_BIN
  LLVM_BIN := $(shell "$(MSYS2_BIN)/bash.exe" -c '\
    for p in "C:/Program Files/LLVM/bin" "$$LOCALAPPDATA/Programs/LLVM/bin" "C:/Program Files (x86)/LLVM/bin"; do \
      if [ -f "$$p/clang-cl.exe" ]; then echo "$$p"; exit 0; fi; \
    done')
endif
ifeq ($(strip $(LLVM_BIN)),)
$(error LLVM not found in "C:/Program Files/LLVM", "$$LOCALAPPDATA/Programs/LLVM" \
or "C:/Program Files (x86)/LLVM".  Install LLVM (https://releases.llvm.org/) or \
pass LLVM_BIN=<path-to-llvm-bin>)
endif
ifeq ($(shell "$(MSYS2_BIN)/bash.exe" -c '[ -f "$(LLVM_BIN)/clang-cl.exe" ] && echo ok'),)
$(error LLVM_BIN=$(LLVM_BIN) is missing clang-cl.exe.)
endif

# Normalize PIN_ROOT to a forward-slashed Windows path. clang-cl/lld-link don't
# understand MSYS-style /c/... paths, and we disable MSYS path conversion below
# (so paths reach the compilers verbatim). cygpath -m: C:\foo or /c/foo → C:/foo.
PIN_ROOT := $(shell "$(MSYS2_BIN)/cygpath.exe" -m "$(PIN_ROOT)" 2>/dev/null)
ifeq ($(strip $(PIN_ROOT)),)
$(error PIN_ROOT could not be resolved.  Set PIN_ROOT=<path-to-pin-kit> or place the kit at <repo>/pin)
endif
ifeq ($(wildcard $(PIN_ROOT)/pin.exe),)
$(error PIN_ROOT=$(PIN_ROOT) does not contain pin.exe.  Check the Pin kit layout.)
endif
ifeq ($(wildcard $(PIN_ROOT)/source/tools/MyPinTool/makefile),)
$(error PIN_ROOT=$(PIN_ROOT) is missing source/tools/MyPinTool/makefile.  Wrong \
Pin kit flavor?  Need the MSVC/clang-cl kit (3.31+), not the gcc one.)
endif

# ── Toolchain shims ───────────────────────────────────────────────────────────
MAKE  := $(MSYS2_BIN)/make.exe

# Force bash for all recipes (make on Windows defaults to cmd.exe otherwise).
SHELL       := $(MSYS2_BIN)/bash.exe
.SHELLFLAGS := -c

# Absolute MSYS2 coreutils paths — so outer recipes work even when make is
# invoked from cmd.exe / PowerShell where /usr/bin isn't on PATH.
MKDIR := $(MSYS2_BIN)/mkdir.exe
CP    := $(MSYS2_BIN)/cp.exe
RM    := $(MSYS2_BIN)/rm.exe

# ── Build directories ─────────────────────────────────────────────────────────
STAGE_BASE       := .pin-build
STAGE_DIR        := $(STAGE_BASE)/$(TARGET)/$(TOOL_NAME)
BUILD_DIR        := Build
PIN_TEMPLATE_DIR := $(PIN_ROOT)/source/tools/MyPinTool
RULES_TEMPLATE   := ransomflow.makefile.rules

# ── Windows version (queried once at parse time) ──────────────────────────────
WIN_VER_MAJOR    := $(shell powershell -NoProfile -Command "[System.Environment]::OSVersion.Version.Major")
WIN_VER_MINOR    := $(shell powershell -NoProfile -Command "[System.Environment]::OSVersion.Version.Minor")
WIN_BUILD_NUMBER := $(shell powershell -NoProfile -Command "[System.Environment]::OSVersion.Version.Build")

# ── Output names ──────────────────────────────────────────────────────────────
TOOL_STAGE_NAME  := $(TOOL_NAME).dll
TOOL_OUT_ia32    := $(TOOL_NAME).dll
TOOL_OUT_intel64 := $(TOOL_NAME)_x64.dll
TOOL_OUT         := $(TOOL_OUT_$(TARGET))

STAGE_TOOL := $(STAGE_DIR)/obj-$(TARGET)/$(TOOL_STAGE_NAME)
FINAL_TOOL := $(BUILD_DIR)/$(TOOL_OUT)

# ── Environment ───────────────────────────────────────────────────────────────
# Stop MSYS2 from mangling Windows-style paths/flags passed to subprocesses.
# Without these, clang-cl sees /nologo as C:\msys64\nologo, etc.
export MSYS2_ARG_CONV_EXCL := *
export MSYS_NO_PATHCONV    := 1
# Keep an outer MSVC/VS env from polluting clang-cl's include/lib resolution.
unexport LIB
unexport LIBPATH
unexport INCLUDE

# ── Staged source files ───────────────────────────────────────────────────────
STAGE_INCLUDES := \
	$(STAGE_DIR)/include/api_hooks.hpp \
	$(STAGE_DIR)/include/common.hpp \
	$(STAGE_DIR)/include/key_tracking.hpp \
	$(STAGE_DIR)/include/loop_detection.hpp \
	$(STAGE_DIR)/include/rule_catalog.hpp \
	$(STAGE_DIR)/include/snapshot.hpp \
	$(STAGE_DIR)/include/util.hpp \
	$(STAGE_DIR)/include/windows_api.hpp

STAGE_SRCS := \
	$(STAGE_DIR)/src/api_hooks.cpp \
	$(STAGE_DIR)/src/key_tracking.cpp \
	$(STAGE_DIR)/src/loop_detection.cpp \
	$(STAGE_DIR)/src/loop_lifecycle.cpp \
	$(STAGE_DIR)/src/rule_catalog.cpp \
	$(STAGE_DIR)/src/snapshot.cpp \
	$(STAGE_DIR)/src/util.cpp \
	$(STAGE_DIR)/src/win_const.h

STAGE_FILES := \
	$(STAGE_DIR)/makefile \
	$(STAGE_DIR)/makefile.rules \
	$(STAGE_DIR)/$(TOOL_NAME).cpp \
	$(STAGE_INCLUDES) \
	$(STAGE_SRCS)

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all both ia32 intel64 prepare clean help

all: $(FINAL_TOOL)

ia32:
	"$(MAKE)" TARGET=ia32 all

intel64:
	"$(MAKE)" TARGET=intel64 all

both: ia32 intel64

help:
	@echo "Targets: all (default), ia32, intel64, both, clean"
	@echo "Vars:    PIN_ROOT, MSYS2_BIN, LLVM_BIN, TARGET=ia32|intel64"
	@echo "Example: \"$(MAKE)\" PIN_ROOT=D:/pin TARGET=intel64"

# ── Directories ───────────────────────────────────────────────────────────────
$(STAGE_BASE):
	$(MKDIR) -p "$@"

$(STAGE_DIR): | $(STAGE_BASE)
	$(MKDIR) -p "$@"

$(STAGE_DIR)/include: | $(STAGE_DIR)
	$(MKDIR) -p "$@"

$(STAGE_DIR)/src: | $(STAGE_DIR)
	$(MKDIR) -p "$@"

$(BUILD_DIR):
	$(MKDIR) -p "$@"

# ── Stage: Pin template files ─────────────────────────────────────────────────
$(STAGE_DIR)/makefile: $(PIN_TEMPLATE_DIR)/makefile | $(STAGE_DIR)
	$(CP) -f "$<" "$@"

$(STAGE_DIR)/makefile.rules: $(RULES_TEMPLATE) | $(STAGE_DIR)
	$(CP) -f "$<" "$@"

$(STAGE_DIR)/$(TOOL_NAME).cpp: $(TOOL_NAME).cpp | $(STAGE_DIR)
	$(CP) -f "$<" "$@"

# ── Stage: headers / sources (pattern rules) ──────────────────────────────────
$(STAGE_DIR)/include/%.hpp: include/%.hpp | $(STAGE_DIR)/include
	$(CP) -f "$<" "$@"

$(STAGE_DIR)/src/%.cpp: src/%.cpp | $(STAGE_DIR)/src
	$(CP) -f "$<" "$@"

$(STAGE_DIR)/src/%.h: src/%.h | $(STAGE_DIR)/src
	$(CP) -f "$<" "$@"

prepare: $(STAGE_FILES)

# ── Inner Pin build ───────────────────────────────────────────────────────────
# Put LLVM in front of PATH so clang-cl / lld-link are found before any system
# tooling. PIN_ROOT is already a Windows-style path; the inner makefile passes
# it into -I/-LIBPATH unmodified.
$(STAGE_TOOL): prepare
	PATH="$(MSYS2_BIN):$(LLVM_BIN):$$PATH" \
	"$(MAKE)" -C "$(STAGE_DIR)" \
		OS=Windows_NT \
		HOST_ARCH=intel64 \
		TARGET=$(TARGET) \
		PIN_ROOT="$(PIN_ROOT)" \
		WIN_VER_MAJOR=$(WIN_VER_MAJOR) \
		WIN_VER_MINOR=$(WIN_VER_MINOR) \
		WIN_BUILD_NUMBER=$(WIN_BUILD_NUMBER) \
		tools

$(FINAL_TOOL): $(STAGE_TOOL) | $(BUILD_DIR)
	$(CP) -f "$<" "$@"

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	$(RM) -rf "$(STAGE_BASE)" "$(BUILD_DIR)"
