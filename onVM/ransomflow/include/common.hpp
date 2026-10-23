#pragma once

#ifdef _MSC_VER
#pragma warning(disable : 5208)
#endif

// VS 2022 14.38+ dropped CRT export macros referenced by yvals.h; restore them before any standard-library headers are pulled in.
#if defined(_MSC_VER)
#  ifndef _CRTIMP2
#    define _CRTIMP2  __declspec(dllimport)
#  endif
#  ifndef _MRTIMP2
#    define _MRTIMP2  __declspec(dllimport)
#  endif
#  ifndef _CRTIMP2_NOIA64
#    define _CRTIMP2_NOIA64  __declspec(dllimport)
#  endif
#  ifndef _MRTIMP2_NIA64
#    define _MRTIMP2_NIA64   __declspec(dllimport)
#  endif
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "pin.H"
#include "windows_api.hpp"

using namespace std;

using WinApi::CloseHandle;
using WinApi::CREATE_ALWAYS;
using WinApi::CreateDirectoryA;
using WinApi::CreateFileA;
using WinApi::ExitProcess;
using WinApi::DWORD;
using WinApi::FILE_APPEND_DATA;
using WinApi::FILE_ATTRIBUTE_NORMAL;
using WinApi::FILE_SHARE_READ;
using WinApi::FILE_SHARE_WRITE;
using WinApi::GENERIC_WRITE;
using WinApi::GetCurrentDirectoryA;
using WinApi::GetCurrentProcess;
using WinApi::GetLastError;
using WinApi::GetTickCount64;
using WinApi::GetModuleFileNameA;
using WinApi::HANDLE;
using WinApi::INVALID_HANDLE_VALUE;
using WinApi::K32GetProcessMemoryInfo;
using WinApi::MEMORY_BASIC_INFORMATION;
using WinApi::MoveFileA;
using WinApi::OPEN_ALWAYS;
using WinApi::PROCESS_MEMORY_COUNTERS_EX;
using WinApi::SetConsoleCtrlHandler;
using WinApi::VirtualQuery;
using WinApi::WriteFile;

#if defined(TARGET_IA32E)
static const char *kArchSuffix = "x64";
// Pin's REG_R8..R15 enumerators clash with Windows clang-cl macros, so we synthesise stable aliases from REG_GAX instead.
static const REG RansackRegR8  = static_cast<REG>(REG_GAX + 1);
static const REG RansackRegR9  = static_cast<REG>(REG_GAX + 2);
static const REG RansackRegR10 = static_cast<REG>(REG_GAX + 3);
static const REG RansackRegR11 = static_cast<REG>(REG_GAX + 4);
static const REG RansackRegR12 = static_cast<REG>(REG_GAX + 5);
static const REG RansackRegR13 = static_cast<REG>(REG_GAX + 6);
static const REG RansackRegR14 = static_cast<REG>(REG_GAX + 7);
static const REG RansackRegR15 = static_cast<REG>(REG_GAX + 8);
#define RANSACK_STACK_PTR_REG REG_STACK_PTR
#define RANSACK_FRAME_PTR_REG REG_GBP
#define RANSACK_EXTRA_REG_PARAMS                                              \
  , ADDRINT r8, ADDRINT r9, ADDRINT r10, ADDRINT r11, ADDRINT r12,            \
      ADDRINT r13, ADDRINT r14, ADDRINT r15
#define RANSACK_EXTRA_REG_ARGS                                                \
  , IARG_REG_VALUE, RansackRegR8, IARG_REG_VALUE, RansackRegR9,               \
      IARG_REG_VALUE, RansackRegR10, IARG_REG_VALUE, RansackRegR11,           \
      IARG_REG_VALUE, RansackRegR12, IARG_REG_VALUE, RansackRegR13,           \
      IARG_REG_VALUE, RansackRegR14, IARG_REG_VALUE, RansackRegR15
#define RANSACK_EXTRA_REG_FORWARD , r8, r9, r10, r11, r12, r13, r14, r15
#define RANSACK_APPEND_EXTRA_REGS(p)                                          \
  do {                                                                        \
    *p++ = ','; FastHexAddr(p, r8);                                           \
    *p++ = ','; FastHexAddr(p, r9);                                           \
    *p++ = ','; FastHexAddr(p, r10);                                          \
    *p++ = ','; FastHexAddr(p, r11);                                          \
    *p++ = ','; FastHexAddr(p, r12);                                          \
    *p++ = ','; FastHexAddr(p, r13);                                          \
    *p++ = ','; FastHexAddr(p, r14);                                          \
    *p++ = ','; FastHexAddr(p, r15);                                          \
  } while (0)
#else
static const char *kArchSuffix = "x86";
#define RANSACK_STACK_PTR_REG REG_STACK_PTR
#define RANSACK_FRAME_PTR_REG REG_GBP
#define RANSACK_EXTRA_REG_PARAMS
#define RANSACK_EXTRA_REG_ARGS
#define RANSACK_EXTRA_REG_FORWARD
#define RANSACK_APPEND_EXTRA_REGS(p) do {} while (0)
#endif

struct LoopKey {
  ADDRINT header, backedge, loop_end;

  LoopKey() : header(0), backedge(0), loop_end(0) {}

  bool operator<(const LoopKey &o) const {
    if (header != o.header) return header < o.header;
    if (backedge != o.backedge) return backedge < o.backedge;
    return loop_end < o.loop_end;
  }
};

struct InstructionMeta {
  ADDRINT address;
  ADDRINT next_address;
  UINT32 size;
  string image_path;
  string function_name;
  string disassembly;
  bool is_control_flow;
  bool is_branch;
  bool is_call;
  bool is_return;
  bool has_fallthrough;
  bool is_direct_control_flow;
  ADDRINT static_target;

  InstructionMeta()
      : address(0), next_address(0), size(0), is_control_flow(false),
        is_branch(false), is_call(false), is_return(false),
        has_fallthrough(false), is_direct_control_flow(false),
        static_target(0) {
  }
};

struct ControlFlowObservation {
  bool seen, multiple_targets;
  ADDRINT target;

  ControlFlowObservation() : seen(false), multiple_targets(false), target(0) {}
};

struct ThreadLoopState {
  UINT64 iterations;
  UINT64 reported_iterations;
  bool capture_emitted;
  UINT32 capture_id;
  UINT64 capture_iteration;
  map<ADDRINT, ControlFlowObservation> observed_targets;

  ThreadLoopState() : iterations(0), reported_iterations(0), capture_emitted(false), capture_id(0), capture_iteration(0) {}
};

struct LoopCaptureSummary {
  LoopKey key;
  UINT32 capture_thread_id;
  UINT32 capture_pin_thread_id;
  UINT64 capture_iteration;
  UINT64 total_iterations;
  string meta_file;
  string snapshot_file;
  set<UINT32> contributor_thread_ids;
  bool capture_recorded;

  LoopCaptureSummary() : capture_thread_id(0), capture_pin_thread_id(0), capture_iteration(0), total_iterations(0), capture_recorded(false) {}
};

// In-memory accumulator that flushes atomically to <base>_<N><suffix> every chunk_bytes, so each chunk file on disk is complete the moment it appears.
struct ChunkedLog {
  string base_path;
  string suffix;
  size_t chunk_bytes;
  string buffer;
  UINT32 next_index;
  bool   active;
  PIN_LOCK lock;

  ChunkedLog() : chunk_bytes(0), next_index(1), active(false) {}
};

struct CryptoRule;

struct PendingCryptoCall {
  const CryptoRule *rule;
  ADDRINT args[8];
  UINT64 call_id;
  UINT32 capture_id;
  LoopKey active_loop;
  bool has_loop;
  ADDRINT handle_in;
  ADDRINT handle_out_ptr;

  PendingCryptoCall() : rule(NULL), call_id(0), capture_id(0), has_loop(false), handle_in(0), handle_out_ptr(0) {
    for (int i = 0; i < 8; ++i) args[i] = 0;
    active_loop.header = 0; active_loop.backedge = 0; active_loop.loop_end = 0;
  }
};

struct ThreadState {
  THREADID pin_tid;
  UINT32 os_tid;
  map<LoopKey, ThreadLoopState> loops;
  vector<LoopKey> active_loops;
  vector<PendingCryptoCall> pending_crypto_calls;

  ThreadState() : pin_tid(0), os_tid(0) {}
};

extern KNOB<string> KnobOutDir;
extern KNOB<string> KnobRulesDir;
extern KNOB<UINT32> KnobLoopTriggerIters;
extern KNOB<UINT32> KnobMaxBackedgeDist;
extern KNOB<bool> KnobDebug;
extern KNOB<bool> KnobTraceSystemImages;
extern KNOB<UINT32> KnobChunkBytes;
extern KNOB<bool>   KnobFollowChildProcesses;
extern KNOB<bool>   KnobFollowMemcpy;
extern KNOB<string> KnobSession;
extern KNOB<UINT32> KnobTop;
extern KNOB<UINT32> KnobCapMaxIns;
extern KNOB<UINT32> KnobKeySnapshotBytes;

extern bool gIsManaged;
extern volatile int gAutoFlushStop;

extern TLS_KEY gTlsKey;

extern PIN_LOCK gFileLock;
extern PIN_LOCK gMetaLock;
extern PIN_LOCK gCaptureLock;
extern PIN_LOCK gModuleLock;
extern PIN_LOCK gStatsLock;
extern PIN_LOCK gTraceLock;
extern PIN_LOCK gFirstSeenLock;
extern PIN_LOCK gGlobalSeqLock;

struct StaticMeta;

extern map<pair<ADDRINT, ADDRINT>, UINT32> *gLoopFirstSeen;
extern UINT32 gGlobalLoopSeq;
extern map<ADDRINT, StaticMeta *> *gMeta;

struct TData;

static void BufferedWriteText(TData *td, const string &text);
static void FlushBuffer(TData *td);

extern HANDLE gTraceHandle;
extern string gTracePath;
extern string gGlobalBuffer;

static void WriteGlobalTrace(const string &s);
static void FlushGlobalBuffer();
static string GetCurrentTracePath(bool tmp);

extern map<ADDRINT, InstructionMeta *> *gInstructionMeta;
extern map<LoopKey, UINT32> *gCapturedLoopIds;
extern map<UINT32, LoopCaptureSummary> *gLoopCaptureSummaries;
extern UINT32 gNextCaptureId;
extern std::size_t gPeakWorkingSetBytes;
extern WinApi::ULONGLONG gLastMemorySampleTickMs;

extern ChunkedLog gImageLog;
extern ChunkedLog gIoLog;
extern ChunkedLog gCryptoLog;
extern ChunkedLog gKeyResidueLog;

extern string gOutputDirectory;
extern string gImageLogPath;
extern string gIoLogPath;
extern string gCryptoLogPath;
extern string gLoopLogPath;
extern string gDllSummaryPath;
extern string gDoneSignalPath;
extern string gMainImagePath;
extern string gKeyResidueLogPath;
extern WinApi::ULONGLONG gStartTickMs;

#include "util.hpp"
