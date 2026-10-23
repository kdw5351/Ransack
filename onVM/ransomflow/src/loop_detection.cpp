static const size_t kLoopBufferFlushThreshold = 4096;
static const size_t kMaxLoopRegionDumpBytes = 4 * 1024 * 1024;

static void AppendLoopRowToCsv(UINT32 tid, UINT32 rankGlobal, ADDRINT startAddr, ADDRINT endAddr, UINT64 bodyLen, UINT64 iterCount, double score, const string &func, const string &img, UINT64 memR, UINT64 memW, UINT64 stackR, UINT64 stackW, UINT64 xorCnt, UINT64 addsubCnt, UINT64 shlshrCnt, UINT64 mulCnt) {
  std::ostringstream oss;
  oss << "EXT_CSV:" << tid << "," << rankGlobal << ",0," << std::hex
      << startAddr << "," << endAddr << std::dec << "," << bodyLen << ","
      << iterCount << "," << (long long)score << "," << EscapeCsv(func) << ","
      << EscapeCsv(img) << "," << memR << "," << memW << "," << stackR << ","
      << stackW << "," << xorCnt << "," << addsubCnt << "," << shlshrCnt << "," << mulCnt << "\n";
  WriteGlobalTrace(oss.str());
}

static OpClass ClassifyOpClass(const string &opcLower) {
  if (opcLower == "xor" || opcLower == "pxor" || opcLower == "vpxor") return OP_XOR;
  if (opcLower == "add" || opcLower == "sub" || opcLower == "adc" || opcLower == "sbb" || opcLower == "inc" || opcLower == "dec") return OP_ADDSUB;
  if (opcLower == "shl" || opcLower == "sal" || opcLower == "shr" || opcLower == "sar" || opcLower == "rol" || opcLower == "ror") return OP_SHLSHR;
  if (opcLower == "mul" || opcLower == "imul" || opcLower == "fmul") return OP_MUL;
  return OP_NONE;
}

static string ResolveOpcodeLower(const string &assembly) {
  std::istringstream iss(assembly);
  string opc;
  iss >> opc;
  return ToLowerStr(opc);
}

static void ResolveInstructionContext(INS ins, ADDRINT address, const string &fallbackImgName, ADDRINT fallbackImgLow, StaticMeta *meta) {
  string funcName;
  RTN rtn = INS_Rtn(ins);
  if (!RTN_Valid(rtn)) rtn = RTN_FindByAddress(address);

  if (RTN_Valid(rtn)) {
    string rawName = RTN_Name(rtn);
    string undecorated = PIN_UndecorateSymbolName(rawName, UNDECORATION_NAME_ONLY);
    funcName = undecorated.empty() ? rawName : undecorated;

    SEC sec = RTN_Sec(rtn);
    if (SEC_Valid(sec)) {
      IMG rtnImg = SEC_Img(sec);
      if (IMG_Valid(rtnImg)) {
        string resolvedImg = IMG_Name(rtnImg);
        if (!resolvedImg.empty()) meta->imgName = resolvedImg;
      }
    }
  } else if (!fallbackImgName.empty() && fallbackImgLow != 0) {
    std::ostringstream oss;
    oss << fallbackImgName << "+0x" << std::hex << (address - fallbackImgLow);
    funcName = oss.str();
  } else {
    std::ostringstream oss;
    oss << "func_0x" << std::hex << address;
    funcName = oss.str();
  }

  meta->funcName = funcName.empty() ? "Unknown_Func" : funcName;
}

static void DescribeMemoryOperand(INS ins, StaticMeta *meta) {
  meta->isStackMem = false;
  if (!INS_IsMemoryRead(ins) && !INS_IsMemoryWrite(ins)) return;

  REG base = INS_MemoryBaseReg(ins);
  REG index = INS_MemoryIndexReg(ins);
  UINT32 scale = INS_MemoryScale(ins);
  ADDRINT displacement = INS_MemoryDisplacement(ins);

  if (base == RANSACK_STACK_PTR_REG || base == RANSACK_FRAME_PTR_REG || index == RANSACK_STACK_PTR_REG || index == RANSACK_FRAME_PTR_REG) meta->isStackMem = true;

  std::ostringstream oss;
  oss << (REG_valid(base) ? REG_StringShort(base) : "") << "|"
      << (REG_valid(index) ? REG_StringShort(index) : "") << "|" << scale << "|" << displacement;
  meta->memMeta = oss.str();
}

static StaticMeta *GetOrCreateMeta(INS ins, ADDRINT address, const string &traceImgName, ADDRINT traceImgLow) {
  PIN_GetLock(&gMetaLock, 1);
  map<ADDRINT, StaticMeta *>::iterator found = gMeta->find(address);
  if (found != gMeta->end()) {
    StaticMeta *cached = found->second;
    PIN_ReleaseLock(&gMetaLock);
    return cached;
  }
  PIN_ReleaseLock(&gMetaLock);

  StaticMeta *meta = new StaticMeta();
  meta->addr = address;
  meta->next_address = INS_NextAddress(ins);
  meta->addr32 = (UINT32)address;
  meta->addrStr = HexAddr(address, false, true);
  meta->assembly = KnobDebug.Value() ? INS_Disassemble(ins) : "disasm_disabled";
  meta->opcLower = ResolveOpcodeLower(meta->assembly);
  meta->opClass = KnobDebug.Value() ? ClassifyOpClass(meta->opcLower) : OP_NONE;
  meta->imgName = traceImgName.empty() ? "Unmapped/Shellcode" : traceImgName;

  ResolveInstructionContext(ins, address, traceImgName, traceImgLow, meta);
  DescribeMemoryOperand(ins, meta);

  PIN_GetLock(&gMetaLock, 1);
  found = gMeta->find(address);
  if (found != gMeta->end()) {
    PIN_ReleaseLock(&gMetaLock);
    delete meta;
    return found->second;
  }

  (*gMeta)[address] = meta;
  if (KnobDebug.Value()) {
    std::ostringstream oss;
    oss << "EXT_META:" << std::hex << meta->addr << "," << EscapeCsv(meta->funcName) << "," << EscapeCsv(meta->imgName) << "," << EscapeCsv(meta->assembly) << ",";
    if (!meta->memMeta.empty()) oss << EscapeCsv(meta->memMeta);
    oss << "\n";
    WriteGlobalTrace(oss.str());
  }
  PIN_ReleaseLock(&gMetaLock);
  return meta;
}

static void WriteLoopEnter(TData *td, UINT32 tid, ADDRINT header, ADDRINT backedge, UINT32 rank, ADDRINT parent, UINT32 depth) {
  UINT32 globalSeq = 0;
  LoopKey key;
  key.header = header; key.backedge = backedge;
  map<LoopKey, LoopAgg>::iterator it = td->loops.find(key);
  if (it != td->loops.end()) globalSeq = it->second.globalSeq;

  std::ostringstream oss;
  oss << "LOOP_ENTER," << tid << "," << std::hex << header << "," << backedge
      << "," << std::dec << rank << "," << globalSeq << "," << std::hex
      << parent << "," << std::dec << depth << "\n";
  BufferedWriteText(td, oss.str());
}

static void ResetCaptureStats(CaptureState &c) {
  c.capIns = 0; c.body_len = 0;
  c.memR = 0; c.memW = 0; c.stackR = 0; c.stackW = 0;
  c.xorCnt = 0; c.addsubCnt = 0; c.shlshrCnt = 0; c.mulCnt = 0;
  c.reg_accum = 0;
  c.func.clear(); c.img.clear();
}

static inline void AccumulateOp(const StaticMeta *meta, CaptureState &capture) {
  if (!meta) return;
  if (meta->opClass == OP_XOR) capture.xorCnt++;
  else if (meta->opClass == OP_ADDSUB) capture.addsubCnt++;
  else if (meta->opClass == OP_SHLSHR) capture.shlshrCnt++;
  else if (meta->opClass == OP_MUL) capture.mulCnt++;
}

static void PopLoopHeader(TData *td, ADDRINT header) {
  if (td->loopStack.empty()) return;
  if (td->loopStack.back() == header) { td->loopStack.pop_back(); return; }
  for (size_t i = td->loopStack.size(); i > 0; --i) {
    if (td->loopStack[i - 1] == header) { td->loopStack.resize(i - 1); return; }
  }
}

static void WriteLoopFinish(TData *td, const LoopKey &key, LoopAgg &agg, UINT64 iterCount) {
  if (agg.finishWritten) return;
  std::ostringstream oss;
  oss << "LOOP_FINISH," << td->os_tid << "," << std::hex << key.header << "," << key.backedge << "," << std::dec << iterCount << "\n";
  BufferedWriteText(td, oss.str());
  agg.finishWritten = true;
}

static void WriteLoopSummary(TData *td, const LoopKey &key, LoopAgg &agg) {
  if (agg.summaryWritten) return;
  double score = (double)agg.body_len * (double)agg.iters;
  AppendLoopRowToCsv(td->os_tid, agg.globalSeq, key.header, key.backedge, agg.body_len, agg.iters, score, agg.func, agg.img, agg.memR, agg.memW, agg.stackR, agg.stackW, agg.xorCnt, agg.addsubCnt, agg.shlshrCnt, agg.mulCnt);
  agg.summaryWritten = true;
}

static void TryDumpLoopRegion(TData *td, const CaptureState &capture) {
  static volatile long gRegionDumpSeq = 0;

  MEMORY_BASIC_INFORMATION mbi;
  const ADDRINT headerAddr = capture.key.header;
  size_t mbiSize = VirtualQuery((const void *)headerAddr, &mbi, sizeof(mbi));
  // use named Win32 constants from
  // src/win_const.h (PinTool builds -nostdinc, so winnt.h is not in the
  // include path; win_const.h provides the canonical SDK values with
  // #ifndef guards).
  if (mbiSize == 0 || mbi.State != MEM_COMMIT || (mbi.Protect & RANSOMFLOW_PAGE_EXEC_MASK) == 0) return;
  if (mbi.Protect & RANSOMFLOW_PAGE_REJECT_MASK) return;

  long seq = ++gRegionDumpSeq;
  // snprintf for binPath (was sprintf), reject USERPROFILE
  // containing path-traversal artefacts.
  const char *userProfile = getenv("USERPROFILE");
  if (!userProfile || strstr(userProfile, "..") || strlen(userProfile) > 400) {
    userProfile = "C:\\Users\\user";
  }

  char binPath[512];
  int n = snprintf(binPath, sizeof(binPath), "%s\\trace\\loop_region_%03ld_%llx.bin", userProfile, seq, (unsigned long long)headerAddr);
  if (n < 0 || n >= (int)sizeof(binPath)) return;  // path truncation -> abort dump

  struct RegionBinHeader {
    unsigned int magic;
    unsigned long long headerIp, backedgeIp, regionBase, regionSize;
  };

  RegionBinHeader header;
  header.magic = 0x524C4F50u;
  header.headerIp = (unsigned long long)headerAddr;
  header.backedgeIp = (unsigned long long)capture.key.backedge;
  header.regionBase = (unsigned long long)(ADDRINT)mbi.BaseAddress;
  header.regionSize = (unsigned long long)mbi.RegionSize;

  // FILE_SHARE_WRITE removed. ransomware enumerating the
  // trace dir cannot open these loop_<id>.bin snapshots for write/delete
  // while we still hold the write handle.
  HANDLE hBin = CreateFileA(binPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hBin == INVALID_HANDLE_VALUE) return;

  // check WriteFile success; on partial write or failure,
  // mark the file as failed by closing and deleting it so downstream analysis
  // does not trust a truncated dump.
  DWORD written = 0;
  BOOL ok = WriteFile(hBin, &header, (DWORD)sizeof(header), &written, NULL);
  if (!ok || written != sizeof(header)) {
    CloseHandle(hBin);
    // NOTE: not deleting the truncated file (DeleteFileA not in PinTool include path).
    // The trailing partial dump is recognisable by the missing magic/header tail;
    // downstream analyzers should validate file size vs RegionBinHeader + dumpSize.
    return;
  }
  size_t dumpSize = mbi.RegionSize < kMaxLoopRegionDumpBytes ? mbi.RegionSize : kMaxLoopRegionDumpBytes;
  static_assert(kMaxLoopRegionDumpBytes <= 0xFFFFFFFFUL,
                "kMaxLoopRegionDumpBytes must fit in DWORD for WriteFile");
  ok = WriteFile(hBin, mbi.BaseAddress, (DWORD)dumpSize, &written, NULL);
  CloseHandle(hBin);
  if (!ok || written != dumpSize) {
    // NOTE: DeleteFileA not in PinTool include path; partial body dump is
    // recognisable by mismatching file_size vs RegionBinHeader+dumpSize.
    return;
  }

  std::ostringstream oss;
  oss << "REGION_DUMP," << td->os_tid << "," << std::hex << headerAddr
      << ",base=" << (ADDRINT)mbi.BaseAddress << ",size=" << std::dec
      << mbi.RegionSize << ",file=" << binPath << "\n";
  BufferedWriteText(td, oss.str());
}

static void RecordLoopCaptureSummary(TData *td, const LoopKey &key, const LoopAgg &agg, const string &snapshotFile, const string &metaFile) {
  if (!gLoopCaptureSummaries) return;

  PIN_GetLock(&gCaptureLock, 1);
  UINT32 captureId = 0;
  map<LoopKey, UINT32>::iterator idIt = gCapturedLoopIds->find(key);
  if (idIt != gCapturedLoopIds->end()) captureId = idIt->second;
  else { captureId = gNextCaptureId++; (*gCapturedLoopIds)[key] = captureId; }

  LoopCaptureSummary &s = (*gLoopCaptureSummaries)[captureId];
  s.key = key;
  s.capture_thread_id = (UINT32)td->os_tid;
  s.capture_pin_thread_id = (UINT32)td->tid;
  s.capture_iteration = agg.iters;
  s.total_iterations = agg.iters;
  s.meta_file = metaFile;
  s.snapshot_file = snapshotFile;
  s.contributor_thread_ids.insert((UINT32)td->os_tid);
  s.capture_recorded = true;
  PIN_ReleaseLock(&gCaptureLock);
}

static void StopAndCommitCapture(TData *td, const char *reason) {
  CaptureState &capture = td->cap;
  if (!capture.recording) return;

  FlushBuffer(td);
  capture.recording = false;

  map<LoopKey, LoopAgg>::iterator it = td->loops.find(capture.key);
  if (it != td->loops.end()) {
    LoopAgg &agg = it->second;
    agg.captured = true;
    agg.body_len = capture.body_len;
    agg.memR = capture.memR; agg.memW = capture.memW;
    agg.stackR = capture.stackR; agg.stackW = capture.stackW;
    agg.xorCnt = capture.xorCnt; agg.addsubCnt = capture.addsubCnt;
    agg.shlshrCnt = capture.shlshrCnt; agg.mulCnt = capture.mulCnt;
    agg.func = capture.func; agg.img = capture.img;
    if (!gTracePath.empty()) agg.tracePath = gTracePath;

    WriteLoopFinish(td, capture.key, agg, agg.iters);
    TryDumpLoopRegion(td, capture);
    WriteLoopSummary(td, capture.key, agg);

    {
      // Resolve loop_end so WriteLoopSnapshot has a non-empty [header, end) range.
      LoopKey snapKey = capture.key;
      if (snapKey.loop_end <= snapKey.header) {
        PIN_GetLock(&gMetaLock, 1);
        map<ADDRINT, StaticMeta *>::iterator mIt = gMeta ? gMeta->find(snapKey.backedge) : map<ADDRINT, StaticMeta *>::iterator();
        StaticMeta *bm = (gMeta && mIt != gMeta->end()) ? mIt->second : NULL;
        PIN_ReleaseLock(&gMetaLock);
        if (bm && bm->next_address > snapKey.header) snapKey.loop_end = bm->next_address;
        else snapKey.loop_end = snapKey.backedge + 16;  // longest legal x86/x64 insn
      }

      ThreadState ts;
      ts.pin_tid = (THREADID)td->tid;
      ts.os_tid = (UINT32)td->os_tid;
      ThreadLoopState ls;
      ls.iterations = agg.iters;
      ls.capture_iteration = agg.iters;
      // Name the on-disk snapshot files by the loop's GLOBAL capture id (the same
      // id RecordLoopCaptureSummary records in loop_events), NOT the per-thread
      // rank_thread counter. Two worker threads each hitting their first capture
      // both had rank_thread==1 and wrote loop_1.bin/.json into the shared output
      // dir, so the second overwrote the first (lost capture + a dangling summary
      // id with no file). ReserveCaptureId is keyed on the LoopKey, so the summary
      // lookup below resolves to this same id.
      UINT32 captureId = ReserveCaptureId(snapKey, NULL);
      if (CaptureLoopArtifacts(captureId, &ts, snapKey, ls)) RecordLoopCaptureSummary(td, snapKey, agg, "", "");
    }

    if (KnobDebug.Value()) LogDebug("loop", DebugLogBuilder("capture completed").Field("os_tid", (UINT64)td->os_tid).Field("rank", (UINT64)capture.rank_thread).Hex("header", capture.key.header).Hex("backedge", capture.key.backedge).Field("reason", reason).Field("body_len", agg.body_len).Field("iters", agg.iters));
  }

  PopLoopHeader(td, capture.key.header);
  capture.armed = false;
  capture.key.header = 0;
  capture.key.backedge = 0;
}

static void ArmBestCandidateIfIdle(TData *td) {
  CaptureState &capture = td->cap;
  if (capture.recording || td->capturedCount >= KnobTop.Value() || !capture.candValid) return;

  map<LoopKey, LoopAgg>::iterator it = td->loops.find(capture.candKey);
  if (it == td->loops.end() || it->second.captured) { capture.candValid = false; capture.candIters = 0; return; }

  capture.key = capture.candKey;
  capture.armed = true;
  // Don't reset candValid/candIters: the slot is a hottest-watermark so a hotter loop can preempt a short startup loop that fired first.
}

static void StartCaptureAtHeader(TData *td, const StaticMeta *headerMeta) {
  CaptureState &capture = td->cap;
  if (!capture.armed || capture.recording) return;

  td->capturedCount++;
  capture.rank_thread = td->capturedCount;
  ResetCaptureStats(capture);
  td->loopBuf.clear();

  capture.capMaxIns = (UINT64)KnobCapMaxIns.Value();
  capture.recording = true;
  capture.func = headerMeta ? headerMeta->funcName : "";
  capture.img = headerMeta ? headerMeta->imgName : "";

  ADDRINT parent = td->loopStack.empty() ? 0 : td->loopStack.back();
  UINT32 depth = (UINT32)td->loopStack.size();
  WriteLoopEnter(td, td->os_tid, capture.key.header, capture.key.backedge, capture.rank_thread, parent, depth);
  td->loopStack.push_back(capture.key.header);

  if (KnobDebug.Value()) LogDebug("loop", DebugLogBuilder("capture armed").Field("os_tid", (UINT64)td->os_tid).Field("rank", (UINT64)capture.rank_thread).Hex("header", capture.key.header).Hex("backedge", capture.key.backedge));

  capture.armed = false;
}

static UINT32 AssignLoopGlobalSeq(ADDRINT header, ADDRINT backedge) {
  UINT32 seq = 0;
  PIN_GetLock(&gFirstSeenLock, 1);
  pair<ADDRINT, ADDRINT> key = make_pair(header, backedge);
  map<pair<ADDRINT, ADDRINT>, UINT32>::iterator it = gLoopFirstSeen->find(key);
  if (it != gLoopFirstSeen->end()) seq = it->second;
  else {
    PIN_GetLock(&gGlobalSeqLock, 1);
    gGlobalLoopSeq++;
    seq = (UINT32)gGlobalLoopSeq;
    PIN_ReleaseLock(&gGlobalSeqLock);
    (*gLoopFirstSeen)[key] = seq;
  }
  PIN_ReleaseLock(&gFirstSeenLock);
  return seq;
}

static void UpdateCandidate(TData *td, const LoopKey &key, const LoopAgg &agg) {
  CaptureState &capture = td->cap;
  UINT64 threshold = KnobLoopTriggerIters.Value() == 0 ? 1 : (UINT64)KnobLoopTriggerIters.Value();
  if (agg.captured || agg.iters < threshold) return;
  if (!capture.candValid || agg.iters > capture.candIters) {
    capture.candValid = true;
    capture.candKey = key;
    capture.candIters = agg.iters;
  }
}

// Hot path: kept minimal (no IARG_CONTEXT, no fallthrough addr).
static VOID OnTakenBranch(THREADID tid, ADDRINT ip, ADDRINT target) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || target >= ip) return;
  if ((UINT32)(ip - target) > KnobMaxBackedgeDist.Value()) return;

  LoopKey key;
  key.header = target; key.backedge = ip;

  if (!td->loopStack.empty() && target != td->loopStack.back()) {
    for (size_t i = 0; i < td->loopStack.size(); ++i) {
      if (td->loopStack[i] == target) { td->loopStack.resize(i + 1); break; }
    }
  }

  LoopAgg &agg = td->loops[key];
  if (agg.globalSeq == 0) agg.globalSeq = AssignLoopGlobalSeq(target, ip);
  agg.iters++;

  if (td->cap.recording && td->cap.key.header == target) {
    StopAndCommitCapture(td, "iteration_end");
    ArmBestCandidateIfIdle(td);
    return;
  }

  UpdateCandidate(td, key, agg);
  if (!td->cap.recording && !td->cap.armed) ArmBestCandidateIfIdle(td);
}

static VOID OnRet(THREADID tid) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (td && td->cap.recording) StopAndCommitCapture(td, "ret_instruction");
}

static VOID LogChildLoop(THREADID tid, ADDRINT headerAddr) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !td->cap.recording || td->cap.key.header == headerAddr) return;

  char buf[128];
  char *p = buf;
  const char prefix[] = "EXT_CHILD_LOOP,";
  for (size_t i = 0; prefix[i]; ++i) *p++ = prefix[i];
  FastHexAddr(p, headerAddr);
  *p++ = '\n';
  *p = 0;

  td->loopBuf.append(buf, p - buf);
  if (td->loopBuf.size() > kLoopBufferFlushThreshold) FlushBuffer(td);
}

static VOID CapIf(THREADID tid, const StaticMeta *sm);
static void CapRecordNoMem(THREADID tid, const StaticMeta *sm, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS);
static void CapRecordMemR(THREADID tid, const StaticMeta *sm, ADDRINT ea, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS);
static void CapRecordMemW(THREADID tid, const StaticMeta *sm, ADDRINT ea, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS);

static void RecordCapturedInstruction(TData *td, const StaticMeta *sm, char recordType, bool hasMemoryEa, ADDRINT memoryEa, bool countRead, bool countWrite, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS) {
  CaptureState &capture = td->cap;

  char buf[768];
  char *p = buf;
  *p++ = recordType; *p++ = ',';
  FastHexAddr(p, sm->addr); *p++ = ',';
  if (hasMemoryEa) FastHexAddr(p, memoryEa);
  else *p++ = '0';
  *p++ = ','; FastHexAddr(p, eax);
  *p++ = ','; FastHexAddr(p, ebx);
  *p++ = ','; FastHexAddr(p, ecx);
  *p++ = ','; FastHexAddr(p, edx);
  *p++ = ','; FastHexAddr(p, esi);
  *p++ = ','; FastHexAddr(p, edi);
  *p++ = ','; FastHexAddr(p, esp);
  *p++ = ','; FastHexAddr(p, ebp);
  RANSACK_APPEND_EXTRA_REGS(p);
  *p++ = '\n'; *p = 0;

  td->loopBuf.append(buf, p - buf);
  if (td->loopBuf.size() > kLoopBufferFlushThreshold) FlushBuffer(td);

  capture.body_len++;
  if (countRead)  { capture.memR++; if (sm->isStackMem) capture.stackR++; }
  if (countWrite) { capture.memW++; if (sm->isStackMem) capture.stackW++; }
  AccumulateOp(sm, capture);

  capture.capIns++;
  if (capture.capIns >= capture.capMaxIns) StopAndCommitCapture(td, "cap_max_ins");
}

static VOID OnTrace(TRACE trace, VOID *) {
  ADDRINT traceAddress = TRACE_Address(trace);
  IMG traceImg = IMG_FindByAddress(traceAddress);
  const bool hasImg = IMG_Valid(traceImg);
  const string traceImgName = hasImg ? IMG_Name(traceImg) : "";
  const ADDRINT traceImgLow = hasImg ? IMG_LowAddress(traceImg) : 0;

  if (hasImg && !ShouldTrackLoopImage(traceImg)) return;

  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      StaticMeta *sm = GetOrCreateMeta(ins, INS_Address(ins), traceImgName, traceImgLow);

      if (INS_IsBranch(ins)) INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnTakenBranch, IARG_THREAD_ID, IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, IARG_END);

      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogChildLoop, IARG_THREAD_ID, IARG_ADDRINT, sm->addr, IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapIf,        IARG_THREAD_ID, IARG_PTR, sm,           IARG_END);

      if (INS_IsRet(ins)) INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnRet, IARG_THREAD_ID, IARG_END);

      if (INS_IsMemoryWrite(ins))     INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemW, IARG_THREAD_ID, IARG_PTR, sm, IARG_MEMORYWRITE_EA, IARG_REG_VALUE, REG_GAX, IARG_REG_VALUE, REG_GBX, IARG_REG_VALUE, REG_GCX, IARG_REG_VALUE, REG_GDX, IARG_REG_VALUE, REG_GSI, IARG_REG_VALUE, REG_GDI, IARG_REG_VALUE, REG_STACK_PTR, IARG_REG_VALUE, REG_GBP RANSACK_EXTRA_REG_ARGS, IARG_END);
      else if (INS_IsMemoryRead(ins)) INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordMemR, IARG_THREAD_ID, IARG_PTR, sm, IARG_MEMORYREAD_EA,  IARG_REG_VALUE, REG_GAX, IARG_REG_VALUE, REG_GBX, IARG_REG_VALUE, REG_GCX, IARG_REG_VALUE, REG_GDX, IARG_REG_VALUE, REG_GSI, IARG_REG_VALUE, REG_GDI, IARG_REG_VALUE, REG_STACK_PTR, IARG_REG_VALUE, REG_GBP RANSACK_EXTRA_REG_ARGS, IARG_END);
      else                            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CapRecordNoMem, IARG_THREAD_ID, IARG_PTR, sm,                       IARG_REG_VALUE, REG_GAX, IARG_REG_VALUE, REG_GBX, IARG_REG_VALUE, REG_GCX, IARG_REG_VALUE, REG_GDX, IARG_REG_VALUE, REG_GSI, IARG_REG_VALUE, REG_GDI, IARG_REG_VALUE, REG_STACK_PTR, IARG_REG_VALUE, REG_GBP RANSACK_EXTRA_REG_ARGS, IARG_END);
    }
  }
}

static VOID CapIf(THREADID tid, const StaticMeta *sm) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm) return;
  if (!td->cap.recording && td->cap.armed && sm->addr == td->cap.key.header) StartCaptureAtHeader(td, sm);
}

static void CapRecordNoMem(THREADID tid, const StaticMeta *sm, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm || !td->cap.recording) return;
  RecordCapturedInstruction(td, sm, 'I', false, 0, false, false, eax, ebx, ecx, edx, esi, edi, esp, ebp RANSACK_EXTRA_REG_FORWARD);
}

static void CapRecordMemR(THREADID tid, const StaticMeta *sm, ADDRINT ea, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm || !td->cap.recording) return;
  RecordCapturedInstruction(td, sm, 'R', true, ea, true, false, eax, ebx, ecx, edx, esi, edi, esp, ebp RANSACK_EXTRA_REG_FORWARD);
}

static void CapRecordMemW(THREADID tid, const StaticMeta *sm, ADDRINT ea, ADDRINT eax, ADDRINT ebx, ADDRINT ecx, ADDRINT edx, ADDRINT esi, ADDRINT edi, ADDRINT esp, ADDRINT ebp RANSACK_EXTRA_REG_PARAMS) {
  TData *td = (TData *)PIN_GetThreadData(gTlsKey, tid);
  if (!td || !sm || !td->cap.recording) return;
  RecordCapturedInstruction(td, sm, 'W', true, ea, false, true, eax, ebx, ecx, edx, esi, edi, esp, ebp RANSACK_EXTRA_REG_FORWARD);
}
