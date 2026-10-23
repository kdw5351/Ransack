#pragma once

#include "common.hpp"

class DebugLogBuilder {
public:
  DebugLogBuilder();
  explicit DebugLogBuilder(const string &message);
  explicit DebugLogBuilder(const char *message);

  DebugLogBuilder &Message(const string &text);
  DebugLogBuilder &Field(const char *key, const string &value);
  DebugLogBuilder &Field(const char *key, const char *value);
  DebugLogBuilder &Field(const char *key, UINT64 value);
  DebugLogBuilder &Hex(const char *key, ADDRINT value);
  DebugLogBuilder &Flag(const char *key, bool value);
  string Build() const;

private:
  DebugLogBuilder &AppendField(const char *key, const string &value, bool quoted);

  string message_;
  vector<string> fields_;
};

static string ToLowerStr(const string &value);
static string Trim(const string &value);
static string BaseNameLower(const string &path);

// Inline so the unity build sees one definition across translation units.
inline string JoinPath(const string &base, const string &leaf) {
  if (base.empty())
    return leaf;
  char last = base[base.size() - 1];
  if (last == '\\' || last == '/')
    return base + leaf;
  return base + "\\" + leaf;
}

static string HexAddr(ADDRINT value);
static string HexAddr(ADDRINT v, bool withPrefix, bool fixedWidth);
static string HexBytes(const unsigned char *bytes, size_t len);
static string EscapeCsv(const string &s);
static inline void FastHexAddr(char *&p, ADDRINT v);
static string JsonEscape(const string &value);
static void LogDebug(const char *scope, const string &message);
static void LogDebug(const char *scope, const DebugLogBuilder &builder);
static bool EndsWithLower(const string &value, const string &suffixLower);
static bool PathLooksSystemImage(const string &pathLower);
static bool EnsureDirectoryChain(const string &path);
static bool OpenOutputHandle(HANDLE *handle, const string &path);
static void CloseOutputHandle(HANDLE *handle);
static void AppendOutputLine(HANDLE handle, const string &line);
static bool InitChunkedLog(ChunkedLog *log,
                           const string &full_path_with_suffix,
                           size_t chunk_bytes);
static void AppendChunkedLine(ChunkedLog *log, const string &line);
static void FlushChunkedLog(ChunkedLog *log);
static bool WriteWholeTextFile(const string &path, const string &text);
static bool WriteWholeBinaryFile(const string &path, const unsigned char *data,
                                 size_t size);
static void MaybeSampleProcessMemory();
static size_t GetPeakWorkingSetBytes();
static string ResolveSymbolName(ADDRINT address);
static string ResolveSymbolNameRuntime(ADDRINT address);
static bool LookupImageBaseNameAndSymbolRuntime(ADDRINT address,
                                                string *baseLower,
                                                string *symbol);
static string ResolveEnclosingRoutine(ADDRINT address,
                                      const string &fallbackImage,
                                      ADDRINT fallbackBase);
static ThreadState *GetThreadState(THREADID tid);
static bool ShouldTrackLoopImage(IMG img);
static bool ShouldCaptureLoopSnapshotImage(const string &imagePath);
static UINT32 ReserveCaptureId(const LoopKey &key, bool *isNew);
static UINT32 LookupCaptureId(const LoopKey &key);
static InstructionMeta *FindInstructionMeta(ADDRINT address);
static void SyncLoopIterationSummary(ThreadState *threadState, const LoopKey &key,
                                     ThreadLoopState *loopState);
static void FlushCurrentOutputs();
static void InstallConsoleControlHandler();
static void WriteProcInfo();
static void WriteDoneSignalFile();
static void StartAutoFlushThread();
