namespace {

static void FillLoopNamesFromHeader(const LoopKey &key, LoopAgg *agg) {
  if (!agg || (!agg->func.empty() && !agg->img.empty())) return;

  PIN_GetLock(&gMetaLock, 1);
  map<ADDRINT, StaticMeta *>::iterator it = gMeta->find(key.header);
  StaticMeta *meta = (it != gMeta->end()) ? it->second : NULL;
  PIN_ReleaseLock(&gMetaLock);

  if (agg->func.empty()) agg->func = meta ? meta->funcName : "?";
  if (agg->img.empty())  agg->img  = meta ? meta->imgName  : "?";
}

static void FlushPendingLoopSummaries(TData *td) {
  for (map<LoopKey, LoopAgg>::iterator it = td->loops.begin(); it != td->loops.end(); ++it) {
    const LoopKey &key = it->first;
    LoopAgg &agg = it->second;
    if (agg.iters == 0) continue;
    FillLoopNamesFromHeader(key, &agg);
    WriteLoopFinish(td, key, agg, agg.iters);
    WriteLoopSummary(td, key, agg);
  }
}

}

static VOID OnThreadStart(THREADID tid, CONTEXT *, INT32, VOID *) {
  TData *td = new TData();
  td->tid = tid;
  td->os_tid = PIN_GetTid();
  PIN_SetThreadData(gTlsKey, td, tid);

  if (KnobDebug.Value()) LogDebug("thread", DebugLogBuilder("thread started").Field("pin_tid", (UINT64)tid).Field("os_tid", (UINT64)td->os_tid));
}

static VOID OnThreadFini(THREADID tid, const CONTEXT *, INT32, VOID *) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td) return;

  if (td->cap.recording) StopAndCommitCapture(td, "thread_fini");
  FlushPendingLoopSummaries(td);
  FlushBuffer(td);

  if (KnobDebug.Value()) LogDebug("thread", DebugLogBuilder("thread finished").Field("pin_tid", (UINT64)tid).Field("os_tid", (UINT64)td->os_tid).Field("loop_count", (UINT64)td->loops.size()).Field("captured", (UINT64)td->capturedCount));

  delete td;
  PIN_SetThreadData(gTlsKey, 0, tid);
}

// Render gLoopCaptureSummaries to loop_events.jsonl once per run.
static void RenderLoopCaptureSummaries() {
  if (!gLoopCaptureSummaries || gLoopLogPath.empty()) return;

  std::ostringstream out;
  const UINT32 pid = (UINT32)PIN_GetPid();
  PIN_GetLock(&gCaptureLock, 1);
  for (map<UINT32, LoopCaptureSummary>::const_iterator it = gLoopCaptureSummaries->begin(); it != gLoopCaptureSummaries->end(); ++it) {
    const UINT32 captureId = it->first;
    const LoopCaptureSummary &s = it->second;
    out << "{"
        << "\"pid\":" << pid
        << ",\"loop_id\":" << captureId
        << ",\"thread_id\":" << s.capture_thread_id
        << ",\"pin_thread_id\":" << s.capture_pin_thread_id
        << ",\"header\":\"" << HexAddr(s.key.header) << "\""
        << ",\"backedge\":\"" << HexAddr(s.key.backedge) << "\""
        << ",\"loop_end\":\"" << HexAddr(s.key.loop_end) << "\""
        << ",\"capture_iteration\":" << s.capture_iteration
        << ",\"total_iterations\":" << s.total_iterations
        << "}\n";
  }
  PIN_ReleaseLock(&gCaptureLock);
  WriteWholeTextFile(gLoopLogPath, out.str());
}

// Drop ransomflow_done.json in both per-proc and top-level out_dir.
static void WriteDoneSignalFile() {
  MaybeSampleProcessMemory();

  WinApi::ULONGLONG endTick = GetTickCount64();
  double runtimeSeconds = 0.0;
  if (gStartTickMs && endTick >= gStartTickMs) runtimeSeconds = (double)(endTick - gStartTickMs) / 1000.0;

  std::ostringstream payload;
  payload << "{"
          << "\"pid\":" << PIN_GetPid()
          << ",\"image\":\"" << JsonEscape(gMainImagePath) << "\""
          << ",\"runtime_seconds\":" << std::fixed << std::setprecision(3) << runtimeSeconds
          << ",\"peak_working_set_bytes\":" << (UINT64)GetPeakWorkingSetBytes()
          << ",\"end_tick_ms\":" << endTick
          << "}\n";
  string body = payload.str();
  if (!gDoneSignalPath.empty()) WriteWholeTextFile(gDoneSignalPath, body);
  if (!gTopOutputDirectory.empty()) WriteWholeTextFile(JoinPath(gTopOutputDirectory, "ransomflow_done.json"), body);
}

static void WriteProcInfo() {
  if (gOutputDirectory.empty()) return;
  char buf[1024];
  buf[0] = '\0';
  GetModuleFileNameA(NULL, buf, (DWORD)sizeof(buf));
  if (buf[0] != '\0') gMainImagePath = buf;

  std::ostringstream payload;
  payload << "{\"pid\":" << PIN_GetPid()
          << ",\"image\":\"" << JsonEscape(gMainImagePath) << "\""
          << ",\"start_tick_ms\":" << GetTickCount64()
          << "}\n";
  WriteWholeTextFile(JoinPath(gOutputDirectory, "proc_info.json"), payload.str());
}

static VOID OnFini(INT32, VOID *) {
  if (KnobDebug.Value()) LogDebug("shutdown", "shutdown sequence entered");

  extern volatile int gAutoFlushStop;
  gAutoFlushStop = 1;

  ShutdownKeyTracking();
  // Flush every ChunkedLog before dropping locks; short runs that never crossed the chunk threshold would otherwise lose in-memory buffers.
  FlushCurrentOutputs();

  PIN_GetLock(&gTraceLock, 1);
  FlushGlobalBuffer();
  if (gTraceHandle != INVALID_HANDLE_VALUE) {
    CloseHandle(gTraceHandle);
    gTraceHandle = INVALID_HANDLE_VALUE;
    MoveFileA(GetCurrentTracePath(true).c_str(), GetCurrentTracePath(false).c_str());
  }
  PIN_ReleaseLock(&gTraceLock);

  RenderLoopCaptureSummaries();
  WriteDoneSignalFile();

  if (KnobDebug.Value()) LogDebug("shutdown", "shutdown sequence complete");
}

static INT32 Usage() {
  if (KnobDebug.Value()) LogDebug("boot", "Pin initialization failed due to invalid arguments");
  return -1;
}
