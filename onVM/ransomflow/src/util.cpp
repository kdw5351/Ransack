static string ToLowerStr(const string &s) {
  string t = s;
  for (size_t i = 0; i < t.size(); ++i) t[i] = (char)std::tolower((unsigned char)t[i]);
  return t;
}

static string Trim(const string &s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == string::npos) return "";
  size_t e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

static void CsvWriteEscaped(FILE *fp, const string &s) {
  bool need = false;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == ',' || c == '"' || c == '\n' || c == '\r') { need = true; break; }
  }
  if (!need) { std::fputs(s.c_str(), fp); return; }
  std::fputc('"', fp);
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    if (c == '"') std::fputc('"', fp);
    std::fputc(c, fp);
  }
  std::fputc('"', fp);
}

static string HexAddr(ADDRINT x, bool withPrefix, bool fixedWidth) {
  std::ostringstream oss;
  if (withPrefix) oss << "0x";
  if (fixedWidth) oss << std::setw(sizeof(ADDRINT) * 2) << std::setfill('0');
  oss << std::hex << (unsigned long long)x;
  return oss.str();
}

static string HexBytes(const unsigned char *bytes, size_t len) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (unsigned)bytes[i];
  return oss.str();
}

static string BaseNameLower(const string &path) {
  size_t p1 = path.find_last_of('\\'), p2 = path.find_last_of('/');
  size_t p = string::npos;
  if (p1 != string::npos && p2 != string::npos) p = (p1 > p2) ? p1 : p2;
  else if (p1 != string::npos) p = p1;
  else p = p2;
  string base = (p == string::npos) ? path : path.substr(p + 1);
  return ToLowerStr(base);
}

static void SplitSemicolonLower(const string &s, vector<string> &out) {
  out.clear();
  std::istringstream iss(s);
  string tok;
  while (std::getline(iss, tok, ';')) {
    tok = Trim(tok);
    if (!tok.empty()) out.push_back(ToLowerStr(tok));
  }
}

static string JsonEscape(const string &s) {
  std::ostringstream oss;
  for (size_t i = 0; i < s.size(); ++i) {
    char c = s[i];
    switch (c) {
    case '"':  oss << "\\\""; break;
    case '\\': oss << "\\\\"; break;
    case '\n': oss << "\\n";  break;
    case '\r': oss << "\\r";  break;
    case '\t': oss << "\\t";  break;
    default:
      if ((unsigned char)c < 0x20) oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
      else oss << c;
      break;
    }
  }
  return oss.str();
}

static string QuoteDebugValue(const string &value) {
  std::ostringstream oss;
  oss << '"';
  for (size_t i = 0; i < value.size(); ++i) {
    const char c = value[i];
    switch (c) {
    case '\\': oss << "\\\\"; break;
    case '"':  oss << "\\\""; break;
    case '\r': oss << "\\r";  break;
    case '\n': oss << "\\n";  break;
    case '\t': oss << "\\t";  break;
    default:   oss << c;      break;
    }
  }
  oss << '"';
  return oss.str();
}

DebugLogBuilder::DebugLogBuilder() {}
DebugLogBuilder::DebugLogBuilder(const string &message) { message_ = message; }
DebugLogBuilder::DebugLogBuilder(const char *message) { message_ = message ? message : ""; }
DebugLogBuilder &DebugLogBuilder::Message(const string &text) { message_ = text; return *this; }

DebugLogBuilder &DebugLogBuilder::AppendField(const char *key, const string &value, bool quoted) {
  std::ostringstream oss;
  oss << key << "=";
  if (quoted) oss << QuoteDebugValue(value);
  else oss << value;
  fields_.push_back(oss.str());
  return *this;
}

DebugLogBuilder &DebugLogBuilder::Field(const char *key, const string &value) { return AppendField(key, value, true); }
DebugLogBuilder &DebugLogBuilder::Field(const char *key, const char *value) { return Field(key, string(value ? value : "")); }
DebugLogBuilder &DebugLogBuilder::Field(const char *key, UINT64 value) { std::ostringstream oss; oss << value; return AppendField(key, oss.str(), false); }
DebugLogBuilder &DebugLogBuilder::Hex(const char *key, ADDRINT value) { return AppendField(key, HexAddr(value), false); }
DebugLogBuilder &DebugLogBuilder::Flag(const char *key, bool value) { return AppendField(key, value ? "1" : "0", false); }

string DebugLogBuilder::Build() const {
  std::ostringstream oss;
  oss << message_;
  for (size_t i = 0; i < fields_.size(); ++i) {
    if (!message_.empty() || i > 0) oss << " ";
    oss << fields_[i];
  }
  return Trim(oss.str());
}

static string FormatDebugArgs(int argc, char *argv[]) {
  std::ostringstream oss;
  oss << "[";
  for (int i = 0; i < argc; ++i) {
    if (i != 0) oss << ", ";
    oss << QuoteDebugValue(argv[i] ? argv[i] : "NULL");
  }
  oss << "]";
  return oss.str();
}

static string BuildDebugPrefix(const char *scope) {
  std::ostringstream oss;
  oss << "[" << std::setw(10) << std::setfill('0') << GetTickCount64() << "ms]" << "[" << kArchSuffix << "]";
  if (scope && *scope) oss << "[" << scope << "]";
  return oss.str();
}

static string GetDebugLogPath() {
  // reject USERPROFILE with path-traversal artefacts
  // or excessive length before using it in a path. PIN tools may run with elevated
  // privileges; an attacker-controlled env var must not let debug_log.txt land at
  // an arbitrary location.
  const char *userProfile = getenv("USERPROFILE");
  if (userProfile && *userProfile
      && strstr(userProfile, "..") == NULL
      && strlen(userProfile) < 400) {
    return string(userProfile) + "\\trace\\debug_log.txt";
  }
  return "debug_log.txt";
}

static void WriteDebugLine(const string &line) {
  const string logPath = GetDebugLogPath();
  // FILE_SHARE_WRITE removed. ransomware that enumerates the
  // trace dir cannot open the same file for write -> sharing violation.
  // FILE_SHARE_DELETE is absent too, so DeleteFile / MoveFileEx fail while we
  // hold the handle. trace file content is safe until OnFini closes the handle.
  HANDLE hFile = CreateFileA(logPath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile != INVALID_HANDLE_VALUE) {
    DWORD written;
    WriteFile(hFile, line.c_str(), (DWORD)line.length(), &written, NULL);
    WriteFile(hFile, "\n", 1, &written, NULL);
    CloseHandle(hFile);
  }
}

static void LogDebug(const char *scope, const string &message) {
  if (!KnobDebug.Value()) return;
  WriteDebugLine(BuildDebugPrefix(scope) + " " + message);
}

static void LogDebug(const char *scope, const DebugLogBuilder &builder) { LogDebug(scope, builder.Build()); }

static const char HEX_DIGITS[] = "0123456789abcdef";

static inline void FastHex32(char *&p, UINT32 v) {
  if (v == 0) { *p++ = '0'; return; }
  char buf[8];
  int i = 0;
  while (v) { buf[i++] = HEX_DIGITS[v & 0xF]; v >>= 4; }
  while (i > 0) *p++ = buf[--i];
}

static inline void FastHexAddr(char *&p, ADDRINT v) {
  if (v == 0) { *p++ = '0'; return; }
  char buf[16];
  int i = 0;
  while (v) { buf[i++] = HEX_DIGITS[v & 0xF]; v >>= 4; }
  while (i > 0) *p++ = buf[--i];
}

static string EscapeCsv(const string &s) {
  if (s.find_first_of(",\"\n\r") == string::npos) return s;
  string ret = "\"";
  for (size_t i = 0; i < s.size(); ++i) {
    if (s[i] == '"') ret += "\"\"";
    else ret += s[i];
  }
  ret += "\"";
  return ret;
}

// .tmp while in progress, renamed to .done on OnFini.
static string GetCurrentTracePath(bool tmp) {
  const string base = JoinPath(gOutputDirectory, "global_trace");
  return base + (tmp ? ".tmp" : ".done");
}

// Refuse to materialise the trace file when -debug is off.
static bool EnsureGlobalTraceHandle() {
  if (!KnobDebug.Value()) return false;
  if (gTraceHandle != INVALID_HANDLE_VALUE) return true;
  if (gOutputDirectory.empty()) return false;
  gTracePath = GetCurrentTracePath(true);
  // see WriteDebugLine. FILE_SHARE_WRITE removed.
  gTraceHandle = CreateFileA(gTracePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  return gTraceHandle != INVALID_HANDLE_VALUE;
}

// Caller must hold gTraceLock.
static void FlushGlobalBuffer() {
  if (gGlobalBuffer.empty()) return;
  if (!EnsureGlobalTraceHandle()) { gGlobalBuffer.clear(); return; }
  DWORD written = 0;
  WriteFile(gTraceHandle, gGlobalBuffer.data(), (DWORD)gGlobalBuffer.size(), &written, NULL);
  gGlobalBuffer.clear();
}

// Debug-only; with -debug 0 returns immediately.
static void WriteGlobalTrace(const string &s) {
  if (s.empty() || !KnobDebug.Value()) return;
  PIN_GetLock(&gTraceLock, 1);
  gGlobalBuffer.append(s);
  const size_t threshold = (size_t)KnobChunkBytes.Value();
  if (threshold && gGlobalBuffer.size() >= threshold) FlushGlobalBuffer();
  PIN_ReleaseLock(&gTraceLock);
}

static void BufferedWriteText(TData *td, const string &text) {
  if (!td || text.empty() || !KnobDebug.Value()) return;
  td->loopBuf.append(text);
  const size_t threshold = (size_t)KnobChunkBytes.Value();
  if (threshold && td->loopBuf.size() >= threshold) FlushBuffer(td);
}

static void FlushBuffer(TData *td) {
  if (!td || td->loopBuf.empty()) return;
  WriteGlobalTrace(td->loopBuf);
  td->loopBuf.clear();
}

static string HexAddr(ADDRINT v) { return HexAddr(v, false, false); }

static bool EndsWithLower(const string &value, const string &suffixLower) {
  if (suffixLower.size() > value.size()) return false;
  return ToLowerStr(value.substr(value.size() - suffixLower.size())) == suffixLower;
}

static bool PathLooksSystemImage(const string &pathLower) {
  return pathLower.find("\\windows\\") != string::npos
      || pathLower.find("/windows/") != string::npos
      || pathLower.find("\\syswow64\\") != string::npos;
}

static bool EnsureDirectoryChain(const string &path) {
  if (path.empty()) return false;
  for (size_t i = 1; i <= path.size(); ++i) {
    char c = (i < path.size()) ? path[i] : '\0';
    if (c == '\\' || c == '/' || c == '\0') CreateDirectoryA(path.substr(0, i).c_str(), NULL);
  }
  return true;
}

static bool OpenOutputHandle(HANDLE *handle, const string &path) {
  if (!handle) return false;
  // FILE_SHARE_WRITE removed. THIS IS THE MAIN PROTECTION —
  // all ChunkedLog handles (crypto_events_*.jsonl, io_events_*.jsonl,
  // loop_events.jsonl, key_residue_snapshots.jsonl, images_*.jsonl) go through
  // OpenOutputHandle(). With only FILE_SHARE_READ, ransomware in the same VM
  // gets ERROR_SHARING_VIOLATION when trying to open these for write/delete.
  *handle = CreateFileA(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  return *handle != INVALID_HANDLE_VALUE;
}

static void CloseOutputHandle(HANDLE *handle) {
  if (handle && *handle != INVALID_HANDLE_VALUE) { CloseHandle(*handle); *handle = INVALID_HANDLE_VALUE; }
}

static void AppendOutputLine(HANDLE handle, const string &line) {
  if (handle == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(handle, line.data(), (DWORD)line.size(), &written, NULL);
  WriteFile(handle, "\n", 1, &written, NULL);
}

static bool WriteWholeTextFile(const string &path, const string &text) {
  HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  WriteFile(h, text.data(), (DWORD)text.size(), &written, NULL);
  CloseHandle(h);
  return true;
}

static bool WriteWholeBinaryFile(const string &path, const unsigned char *data, size_t size) {
  HANDLE h = CreateFileA(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  WriteFile(h, data, (DWORD)size, &written, NULL);
  CloseHandle(h);
  return true;
}

static bool InitChunkedLog(ChunkedLog *log, const string &full_path_with_suffix, size_t chunk_bytes) {
  if (!log) return false;
  size_t dot = full_path_with_suffix.find_last_of('.');
  if (dot == string::npos) { log->base_path = full_path_with_suffix; log->suffix = ""; }
  else { log->base_path = full_path_with_suffix.substr(0, dot); log->suffix = full_path_with_suffix.substr(dot); }
  log->chunk_bytes = chunk_bytes;
  log->next_index = 1;
  log->active = true;
  log->buffer.clear();
  PIN_InitLock(&log->lock);
  return true;
}

static void FlushChunkedLog(ChunkedLog *log) {
  if (!log || !log->active || log->buffer.empty()) return;
  std::ostringstream oss;
  oss << log->base_path << "_" << log->next_index << log->suffix;
  WriteWholeTextFile(oss.str(), log->buffer);
  log->buffer.clear();
  log->next_index++;
}

static void AppendChunkedLine(ChunkedLog *log, const string &line) {
  if (!log || !log->active) return;
  PIN_GetLock(&log->lock, 1);
  log->buffer.append(line);
  if (!line.empty() && line[line.size() - 1] != '\n') log->buffer.append("\n");
  if (log->chunk_bytes && log->buffer.size() >= log->chunk_bytes) FlushChunkedLog(log);
  PIN_ReleaseLock(&log->lock);
}

static void FlushCurrentOutputs() {
  FlushChunkedLog(&gImageLog);
  FlushChunkedLog(&gIoLog);
  FlushChunkedLog(&gCryptoLog);
  FlushChunkedLog(&gKeyResidueLog);
}

static void MaybeSampleProcessMemory() {
  PROCESS_MEMORY_COUNTERS_EX pmc;
  pmc.cb = (DWORD)sizeof(pmc);
  if (K32GetProcessMemoryInfo(GetCurrentProcess(), &pmc, pmc.cb)) {
    if ((std::size_t)pmc.PeakWorkingSetSize > gPeakWorkingSetBytes) gPeakWorkingSetBytes = (std::size_t)pmc.PeakWorkingSetSize;
  }
  gLastMemorySampleTickMs = GetTickCount64();
}

static size_t GetPeakWorkingSetBytes() { return gPeakWorkingSetBytes; }

static string ResolveSymbolName(ADDRINT address) {
  PIN_LockClient();
  string name = RTN_FindNameByAddress((ADDRINT)address);
  PIN_UnlockClient();
  return name.empty() ? "?" : name;
}

static string ResolveSymbolNameRuntime(ADDRINT address) { return ResolveSymbolName(address); }

static bool LookupImageBaseNameAndSymbolRuntime(ADDRINT address, string *baseLower, string *symbol) {
  if (baseLower) baseLower->clear();
  if (symbol) *symbol = ResolveSymbolNameRuntime(address);
  PIN_LockClient();
  IMG img = IMG_FindByAddress(address);
  PIN_UnlockClient();
  if (IMG_Valid(img) && baseLower) *baseLower = BaseNameLower(IMG_Name(img));
  return symbol && !symbol->empty();
}

static string ResolveEnclosingRoutine(ADDRINT address, const string &fallbackImage, ADDRINT) {
  (void)fallbackImage;
  return ResolveSymbolNameRuntime(address);
}

static ThreadState *GetThreadState(THREADID tid) { return (ThreadState *)PIN_GetThreadData(gTlsKey, tid); }

static bool ShouldTrackLoopImage(IMG img) {
  if (!IMG_Valid(img)) return false;
  if (IMG_IsMainExecutable(img)) return true;
  if (KnobTraceSystemImages.Value()) return true;
  return !PathLooksSystemImage(ToLowerStr(IMG_Name(img)));
}

static bool ShouldCaptureLoopSnapshotImage(const string &imagePath) {
  if (KnobTraceSystemImages.Value()) return true;
  return !PathLooksSystemImage(ToLowerStr(imagePath));
}

static UINT32 ReserveCaptureId(const LoopKey &key, bool *isNew) {
  PIN_GetLock(&gCaptureLock, 1);
  UINT32 id = 0;
  bool created = false;
  if (gCapturedLoopIds) {
    map<LoopKey, UINT32>::iterator it = gCapturedLoopIds->find(key);
    if (it != gCapturedLoopIds->end()) id = it->second;
    else { id = gNextCaptureId++; (*gCapturedLoopIds)[key] = id; created = true; }
  }
  PIN_ReleaseLock(&gCaptureLock);
  if (isNew) *isNew = created;
  return id;
}

static UINT32 LookupCaptureId(const LoopKey &key) {
  PIN_GetLock(&gCaptureLock, 1);
  UINT32 id = 0;
  if (gCapturedLoopIds) {
    map<LoopKey, UINT32>::iterator it = gCapturedLoopIds->find(key);
    if (it != gCapturedLoopIds->end()) id = it->second;
  }
  PIN_ReleaseLock(&gCaptureLock);
  return id;
}

static InstructionMeta *FindInstructionMeta(ADDRINT address) {
  if (!gInstructionMeta) return NULL;
  PIN_GetLock(&gMetaLock, 1);
  map<ADDRINT, InstructionMeta *>::iterator it = gInstructionMeta->find(address);
  InstructionMeta *m = (it != gInstructionMeta->end()) ? it->second : NULL;
  PIN_ReleaseLock(&gMetaLock);
  return m;
}

static void SyncLoopIterationSummary(ThreadState *, const LoopKey &, ThreadLoopState *) {}

// Not 'static': MSVC unity-build needs external linkage because loop_lifecycle.cpp references gAutoFlushStop before util.cpp is included.
volatile int gAutoFlushStop = 0;

static void AutoFlushOnce() {
  FlushCurrentOutputs();
  PIN_GetLock(&gTraceLock, 1);
  FlushGlobalBuffer();
  PIN_ReleaseLock(&gTraceLock);
}

// Flush every channel and drop the done marker before ExitProcess.
static WinApi::BOOL __stdcall RansomflowConsoleHandler(WinApi::DWORD) {
  gAutoFlushStop = 1;
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
  ExitProcess(0);
}

static void InstallConsoleControlHandler() { SetConsoleCtrlHandler(&RansomflowConsoleHandler, 1); }

// 30s background flusher so a hard kill loses at most ~30s of buffered events.
static VOID AutoFlushThread(VOID *) {
  const UINT32 kIntervalMs = 30000;
  while (!gAutoFlushStop) {
    PIN_Sleep(kIntervalMs);
    if (gAutoFlushStop) break;
    AutoFlushOnce();
  }
}

static void StartAutoFlushThread() {
  PIN_THREAD_UID uid;
  PIN_SpawnInternalThread(AutoFlushThread, NULL, 0, &uid);
}
