#include "include/api_hooks.hpp"
#include "include/common.hpp"
#include "include/key_tracking.hpp"
#include "include/loop_detection.hpp"
#include "include/rule_catalog.hpp"
#include "include/snapshot.hpp"
#include "src/win_const.h"  // PAGE_* / MEM_* (PinTool is -nostdinc, no winnt.h)

// clang-format off
KNOB<string> KnobOutDir              (KNOB_MODE_WRITEONCE, "pintool", "out_dir",                 "ransomflow_out", "Output directory for image, IO, and loop artifacts.");
KNOB<string> KnobRulesDir            (KNOB_MODE_WRITEONCE, "pintool", "rules_dir",               "",               "Directory containing io_activity.json + crypto_api.json + dll_roles.json.");
KNOB<string> KnobSession             (KNOB_MODE_WRITEONCE, "pintool", "session",                 "",               "Optional session label embedded into the start row of crypto_events_*.jsonl.");
KNOB<bool>   KnobDebug               (KNOB_MODE_WRITEONCE, "pintool", "debug",                   "0",              "Emit verbose trace-side logs and write global_trace.tmp/.done.");
KNOB<bool>   KnobTraceSystemImages   (KNOB_MODE_WRITEONCE, "pintool", "trace_system_images",     "0",              "Also instrument loops inside Windows system images (very noisy).");
KNOB<bool>   KnobFollowChildProcesses(KNOB_MODE_WRITEONCE, "pintool", "follow_children",         "1",              "Attach this pintool to spawned children; each writes to its own proc_<pid>/.");
KNOB<bool>   KnobFollowMemcpy        (KNOB_MODE_WRITEONCE, "pintool", "follow_memcpy",           "1",              "Hook memcpy-family routines (RtlMoveMemory, memcpy, memmove).");
KNOB<UINT32> KnobLoopTriggerIters    (KNOB_MODE_WRITEONCE, "pintool", "loop_trigger_iters",      "4",              "Capture a loop after this many back-edge iterations.");
KNOB<UINT32> KnobMaxBackedgeDist     (KNOB_MODE_WRITEONCE, "pintool", "max_backedge_dist",       "65536",          "Maximum backward branch distance still considered a loop.");
KNOB<UINT32> KnobChunkBytes          (KNOB_MODE_WRITEONCE, "pintool", "chunk_bytes",             "131072",         "Streaming JSONL chunk flush size (default 128 KB).");
KNOB<UINT32> KnobTop                 (KNOB_MODE_WRITEONCE, "pintool", "top",                     "65536",          "Per-thread cap on the number of loops captured at the snapshot tier.");
KNOB<UINT32> KnobCapMaxIns           (KNOB_MODE_WRITEONCE, "pintool", "cap_max_ins",             "65536",          "Per-capture instruction-count safety cap (commits the capture when reached).");
KNOB<UINT32> KnobKeySnapshotBytes    (KNOB_MODE_WRITEONCE, "pintool", "key_snapshot_bytes",      "4096",           "Region size PIN_SafeCopied around each key-birth buffer (0 disables key-residue snapshots).");
// clang-format on

static string gTopOutputDirectory;

bool gIsManaged = false;

TLS_KEY gTlsKey;

PIN_LOCK gFileLock, gMetaLock, gCaptureLock, gModuleLock, gStatsLock, gTraceLock;

HANDLE gTraceHandle = INVALID_HANDLE_VALUE;
string gTracePath;
string gGlobalBuffer;

PIN_LOCK gFirstSeenLock, gGlobalSeqLock;
map<pair<ADDRINT, ADDRINT>, UINT32> *gLoopFirstSeen = NULL;
UINT32 gGlobalLoopSeq = 0;
map<ADDRINT, StaticMeta *> *gMeta = NULL;

map<ADDRINT, InstructionMeta *> *gInstructionMeta = NULL;
map<LoopKey, UINT32> *gCapturedLoopIds = NULL;
map<UINT32, LoopCaptureSummary> *gLoopCaptureSummaries = NULL;
UINT32 gNextCaptureId = 1;
WinApi::ULONGLONG gStartTickMs = 0;
std::size_t gPeakWorkingSetBytes = 0;
WinApi::ULONGLONG gLastMemorySampleTickMs = 0;

ChunkedLog gImageLog, gIoLog, gCryptoLog, gKeyResidueLog;

string gOutputDirectory;
string gImageLogPath, gIoLogPath, gCryptoLogPath, gLoopLogPath;
string gDllSummaryPath, gDoneSignalPath, gMainImagePath, gKeyResidueLogPath;

static bool InitializeOutputFiles() {
  gTopOutputDirectory = KnobOutDir.Value();
  if (gTopOutputDirectory.empty()) gTopOutputDirectory = ".";
  EnsureDirectoryChain(gTopOutputDirectory);

  {
    std::ostringstream pidOss;
    pidOss << "proc_" << PIN_GetPid();
    gOutputDirectory = JoinPath(gTopOutputDirectory, pidOss.str());
  }
  EnsureDirectoryChain(gOutputDirectory);

  gImageLogPath      = JoinPath(gOutputDirectory, "images.jsonl");
  gIoLogPath         = JoinPath(gOutputDirectory, "io_events.jsonl");
  gCryptoLogPath     = JoinPath(gOutputDirectory, "crypto_events.jsonl");
  gLoopLogPath       = JoinPath(gOutputDirectory, "loop_events.jsonl");
  gDllSummaryPath    = JoinPath(gOutputDirectory, "loaded_dlls.json");
  gDoneSignalPath    = JoinPath(gOutputDirectory, "ransomflow_done.json");
  gKeyResidueLogPath = JoinPath(gOutputDirectory, "key_residue_snapshots.jsonl");

  const size_t chunkBytes = (size_t)KnobChunkBytes.Value();
  if (!InitChunkedLog(&gIoLog, gIoLogPath, chunkBytes)) return false;
  if (!InitChunkedLog(&gCryptoLog, gCryptoLogPath, chunkBytes)) return false;
  if (KnobKeySnapshotBytes.Value() > 0) {
    if (!InitChunkedLog(&gKeyResidueLog, gKeyResidueLogPath, chunkBytes)) return false;
  }
  if (!InitChunkedLog(&gImageLog, gImageLogPath, chunkBytes)) return false;
  return true;
}


// Unity build: each .cpp below is included into this single TU in order.
#include "src/api_hooks.cpp"
#include "src/key_tracking.cpp"
#include "src/loop_detection.cpp"
#include "src/loop_lifecycle.cpp"
#include "src/rule_catalog.cpp"
#include "src/snapshot.cpp"
#include "src/util.cpp"

static BOOL OnFollowChild(CHILD_PROCESS cProcess, VOID *) {
  if (!KnobFollowChildProcesses.Value()) return FALSE;

  if (KnobDebug.Value()) {
    const CHAR *const *argv = NULL;
    INT argc = 0;
    CHILD_PROCESS_GetCommandLine(cProcess, &argc, &argv);
    std::ostringstream cmd;
    for (INT i = 0; i < argc; ++i) {
      if (i != 0) cmd << " ";
      cmd << (argv[i] ? argv[i] : "NULL");
    }
    LogDebug("child", DebugLogBuilder("following child process").Field("child_pid", (UINT64)CHILD_PROCESS_GetId(cProcess)).Field("cmd", cmd.str()));
  }
  return TRUE;
}

int main(int argc, char *argv[]) {
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return Usage();

  PIN_InitLock(&gFileLock);
  PIN_InitLock(&gMetaLock);
  PIN_InitLock(&gCaptureLock);
  PIN_InitLock(&gModuleLock);
  PIN_InitLock(&gStatsLock);
  PIN_InitLock(&gTraceLock);
  PIN_InitLock(&gFirstSeenLock);
  PIN_InitLock(&gGlobalSeqLock);
  gLoopFirstSeen = new map<pair<ADDRINT, ADDRINT>, UINT32>();
  gMeta = new map<ADDRINT, StaticMeta *>();

  gTlsKey = PIN_CreateThreadDataKey(0);
  gInstructionMeta = new map<ADDRINT, InstructionMeta *>();
  gCapturedLoopIds = new map<LoopKey, UINT32>();
  gLoopCaptureSummaries = new map<UINT32, LoopCaptureSummary>();

  if (!InitializeOutputFiles()) return -1;
  WriteProcInfo();

  InitializeRuleCatalog();
  InitializeKeyTracking();

  gStartTickMs = GetTickCount64();
  MaybeSampleProcessMemory();
  InstallConsoleControlHandler();
  StartAutoFlushThread();

  IMG_AddInstrumentFunction(OnImgLoad, 0);
  TRACE_AddInstrumentFunction(OnTrace, 0);
  PIN_AddThreadStartFunction(OnThreadStart, 0);
  PIN_AddThreadFiniFunction(OnThreadFini, 0);
  PIN_AddFiniFunction(OnFini, 0);
  PIN_AddFollowChildProcessFunction(OnFollowChild, 0);

  PIN_StartProgram();
  return 0;
}
