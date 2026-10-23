#pragma once

#include "common.hpp"

enum OpClass { OP_NONE = 0, OP_XOR, OP_ADDSUB, OP_SHLSHR, OP_MUL };

#define MAGIC_LOOP_HEAD 0x4C4F4F50

#pragma pack(push, 1)
struct LoopHeaderEntry {
  UINT32 magic;
  UINT32 tid;
  ADDRINT header;
  ADDRINT backedge;
  UINT32 rank;
  UINT32 globalSeq;
};
#pragma pack(pop)

struct StaticMeta {
  ADDRINT addr;
  ADDRINT next_address;
  UINT32 addr32;
  string addrStr;
  string assembly;
  string funcName;
  string imgName;
  string opcLower;
  string memMeta;
  OpClass opClass;
  bool isStackMem;

  StaticMeta() : addr(0), next_address(0), addr32(0), opClass(OP_NONE), isStackMem(false) {}
};

struct LoopAgg {
  UINT64 iters;
  bool captured;
  bool summaryWritten;
  bool finishWritten;
  UINT32 globalSeq;
  UINT64 body_len;
  UINT64 memR;
  UINT64 memW;
  UINT64 stackR;
  UINT64 stackW;
  UINT64 xorCnt;
  UINT64 addsubCnt;
  UINT64 shlshrCnt;
  UINT64 mulCnt;
  string func;
  string img;
  string tracePath;

  LoopAgg() : iters(0), captured(false), summaryWritten(false), finishWritten(false), globalSeq(0), body_len(0), memR(0), memW(0), stackR(0), stackW(0), xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0) {}
};

struct CaptureState {
  bool armed;
  bool recording;
  LoopKey key;
  UINT32 rank_thread;
  UINT64 capIns;
  UINT64 capMaxIns;
  string func;
  string img;
  UINT64 body_len;
  UINT64 memR;
  UINT64 memW;
  UINT64 stackR;
  UINT64 stackW;
  UINT64 xorCnt;
  UINT64 addsubCnt;
  UINT64 shlshrCnt;
  UINT64 mulCnt;
  UINT64 reg_accum;
  bool candValid;
  LoopKey candKey;
  UINT64 candIters;

  CaptureState() : armed(false), recording(false), rank_thread(0), capIns(0), capMaxIns(0), body_len(0), memR(0), memW(0), stackR(0), stackW(0), xorCnt(0), addsubCnt(0), shlshrCnt(0), mulCnt(0), reg_accum(0), candValid(false), candIters(0) {
    key.header = 0; key.backedge = 0;
    candKey.header = 0; candKey.backedge = 0;
  }
};

struct TData {
  UINT32 tid;
  UINT32 os_tid;
  map<LoopKey, LoopAgg> loops;
  UINT32 capturedCount;
  CaptureState cap;
  vector<ADDRINT> loopStack;
  string loopBuf;

  TData() : tid(0), os_tid(0), capturedCount(0) { loopBuf.reserve(64 * 1024); }
};

static void StopAndCommitCapture(TData *td, const char *reason);
static void ArmBestCandidateIfIdle(TData *td);
static void StartCaptureAtHeader(TData *td, const StaticMeta *headerMeta);
static VOID OnTrace(TRACE trace, VOID *v);
static VOID OnThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v);
static VOID OnThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v);
static VOID OnFini(INT32 code, VOID *v);
static INT32 Usage();
