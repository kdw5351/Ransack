#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace KeyTrackingState {

struct Material {
  ADDRINT base;
  ADDRINT len;
  UINT32 tag;
  std::string sourceApi;
  std::string sourceKind;
  ADDRINT bornIp;
};

struct PendingCall {
  const CryptoApiRule *rule;
  ADDRINT ip, inBuf, inLen, outBuf, outLen, handleIn, handleOutPtr;
};

struct TData { std::vector<PendingCall> pending; };

static PIN_LOCK gMaterialLock, gHandleLock, gTagLock, gResidueLock;
static volatile UINT32 gNextTag = 1;
static volatile UINT32 gKeyResidueSeq = 0;
static std::map<ADDRINT, Material> *gMaterials = NULL;
static std::map<ADDRINT, UINT32> *gHandleTags = NULL;
static std::set<ADDRINT> *gKeyResidueDeduped = NULL;
static TLS_KEY gTlsKey;

// bounded-set caps. Without these,
// gMaterials/gHandleTags/gKeyResidueDeduped grow append-only across long
// traces; PIN shares the target process's address space, so unbounded
// growth eventually OOMs the analysis. Caps are generous (≈50k entries)
// — much higher than any sane ransomware trace produces — but they put a
// hard ceiling on memory and let us evict the oldest entries via a FIFO.
static const size_t kMaxMaterials       = 65536;
static const size_t kMaxHandleTags      = 65536;
static const size_t kMaxKeyResidueDedup = 65536;
static std::vector<ADDRINT> *gMaterialFifo       = NULL;   // for FIFO eviction
static std::vector<ADDRINT> *gHandleFifo         = NULL;
static std::vector<ADDRINT> *gKeyResidueFifo     = NULL;

// bounded CONTENT capture (separate from the key-residue address-dedup path).
// DumpKeyBuffer dedups per buffer ADDRESS and writes one bin per unique address, so routing
// per-file sink buffers (each a fresh address) through it explodes to 100k+ bins. These three
// kinds instead use GLOBAL WRITE-COUNT caps so they can never balloon the trace:
//   - hash_input     : password/seed fed to CryptHashData -> reproduces CryptDeriveKey output offline.
//   - sink_plaintext : first block of plaintext, captured in OnApiBefore (before in-place overwrite).
//   - sink_ciphertext: first block of ciphertext, captured in OnApiAfter.
// Together (plaintext+ciphertext+key) they enable 1:1 decryption verification without whole files.
static const size_t kContentSnapBytes    = 512;   // max bytes per content snapshot
static const size_t kMaxPlaintextSnap    = 128;
static const size_t kMaxKeyWrapSnap      = 8192;  // small enc inputs (<=64B) = wrapped symmetric key material; one per file, capture all
static const size_t kMaxCiphertextSnap   = 128;
static const size_t kMaxHashInputSnap    = 64;
static volatile UINT32 gPlaintextSnaps   = 0;     // guarded by gResidueLock
static volatile UINT32 gKeyWrapSnaps     = 0;     // guarded by gResidueLock
static volatile UINT32 gCiphertextSnaps  = 0;
static volatile UINT32 gHashInputSnaps   = 0;

static UINT32 NewTag() {
  PIN_GetLock(&gTagLock, 1);
  UINT32 tag = gNextTag++;
  PIN_ReleaseLock(&gTagLock);
  return tag;
}

static void JsonlWrite(const std::string &line) { AppendChunkedLine(&gCryptoLog, line); }

// PIN_SafeCopy a region around a key-birth buffer (dedup'd per buf); writes crypto_<seq>.bin + a row in gKeyResidueLog.
static void DumpKeyBuffer(const char *eventKind, const char *api, UINT32 tag, ADDRINT buf, ADDRINT reportedLen) {
  if (buf == 0) return;
  size_t snapSize = (size_t)KnobKeySnapshotBytes.Value();
  if (snapSize == 0) return;

  PIN_GetLock(&gResidueLock, 1);
  if (!gKeyResidueDeduped) { PIN_ReleaseLock(&gResidueLock); return; }
  if (gKeyResidueDeduped->count(buf)) { PIN_ReleaseLock(&gResidueLock); return; }
  // FIFO-evict oldest if over cap.
  if (gKeyResidueDeduped->size() >= kMaxKeyResidueDedup && gKeyResidueFifo &&
      !gKeyResidueFifo->empty()) {
    ADDRINT victim = gKeyResidueFifo->front();
    gKeyResidueFifo->erase(gKeyResidueFifo->begin());
    gKeyResidueDeduped->erase(victim);
  }
  gKeyResidueDeduped->insert(buf);
  if (gKeyResidueFifo) gKeyResidueFifo->push_back(buf);
  UINT32 seq = ++gKeyResidueSeq;
  PIN_ReleaseLock(&gResidueLock);

  std::vector<unsigned char> region(snapSize, 0);
  // &region[0] (not data()) for Pin 3.31's STLport compatibility.
  size_t copied = PIN_SafeCopy(&region[0], (const VOID *)buf, snapSize);
  if (copied == 0) {
    std::ostringstream miss;
    miss << "{\"ev\":\"key_residue\",\"seq\":" << seq
         << ",\"event_kind\":\"" << eventKind << "\""
         << ",\"api\":\"" << ::JsonEscape(api) << "\""
         << ",\"tag\":" << tag
         << ",\"buf\":\"" << ::HexAddr(buf) << "\""
         << ",\"reported_len\":" << reportedLen
         << ",\"snapshot_bytes\":0,\"snapshot_file\":null,\"reason\":\"safe_copy_zero\"}";
    AppendChunkedLine(&gKeyResidueLog, miss.str());
    return;
  }

  std::ostringstream binPath;
  binPath << gOutputDirectory << "\\crypto_" << seq << ".bin";
  ::WriteWholeBinaryFile(binPath.str(), &region[0], copied);

  std::ostringstream row;
  row << "{\"ev\":\"key_residue\",\"seq\":" << seq
      << ",\"event_kind\":\"" << eventKind << "\""
      << ",\"api\":\"" << ::JsonEscape(api) << "\""
      << ",\"tag\":" << tag
      << ",\"buf\":\"" << ::HexAddr(buf) << "\""
      << ",\"reported_len\":" << reportedLen
      << ",\"snapshot_bytes\":" << copied
      << ",\"snapshot_file\":\"crypto_" << seq << ".bin\"}";
  AppendChunkedLine(&gKeyResidueLog, row.str());
}

// globally-capped content snapshot (hash inputs / sink plaintext / sink ciphertext).
// Caps the TOTAL number of writes via *counter (not per-address dedup), so per-file sink buffers
// can never balloon the trace. Copies at most min(len, kContentSnapBytes). Shares crypto_<seq>.bin
// numbering and gKeyResidueLog with DumpKeyBuffer so onHost extraction needs no new path.
static void DumpContentSnapshot(const char *eventKind, const char *api, UINT32 tag, ADDRINT buf, ADDRINT len,
                                volatile UINT32 *counter, size_t cap) {
  if (buf == 0 || len == 0) return;
  if (*counter >= cap) return;                          // fast path (racy, re-checked under lock)
  size_t want = (size_t)len < kContentSnapBytes ? (size_t)len : kContentSnapBytes;
  if (want == 0) return;

  // Copy BEFORE consuming a cap slot or a seq number: a failed/zero copy (unreadable
  // buffer) must not burn a slot, or a few early failures would starve the low caps
  // (ciphertext/plaintext 128, hash 64) of real snapshots and leave a gap in seq.
  std::vector<unsigned char> region(want, 0);
  size_t copied = PIN_SafeCopy(&region[0], (const VOID *)buf, want);
  if (copied == 0) return;

  PIN_GetLock(&gResidueLock, 1);
  if (*counter >= cap) { PIN_ReleaseLock(&gResidueLock); return; }
  ++(*counter);
  UINT32 seq = ++gKeyResidueSeq;
  PIN_ReleaseLock(&gResidueLock);

  std::ostringstream binPath;
  binPath << gOutputDirectory << "\\crypto_" << seq << ".bin";
  ::WriteWholeBinaryFile(binPath.str(), &region[0], copied);

  std::ostringstream row;
  row << "{\"ev\":\"key_residue\",\"seq\":" << seq
      << ",\"event_kind\":\"" << eventKind << "\""
      << ",\"api\":\"" << ::JsonEscape(api) << "\""
      << ",\"tag\":" << tag
      << ",\"buf\":\"" << ::HexAddr(buf) << "\""
      << ",\"reported_len\":" << len
      << ",\"snapshot_bytes\":" << copied
      << ",\"snapshot_file\":\"crypto_" << seq << ".bin\"}";
  AppendChunkedLine(&gKeyResidueLog, row.str());
}

static void RegisterMaterial(ADDRINT base, ADDRINT len, UINT32 tag, const string &api, CryptoKind kind, ADDRINT ip) {
  if (base == 0 || len == 0 || len > 0x10000000) return;
  Material m;
  m.base = base; m.len = len; m.tag = tag;
  m.sourceApi = api; m.sourceKind = CryptoKindName(kind); m.bornIp = ip;
  PIN_GetLock(&gMaterialLock, 1);
  // The FIFO tracks each key address exactly once. Only a NEW address is pushed;
  // overwriting an existing key must not append a duplicate FIFO entry, or the FIFO
  // would grow unbounded (defeating the cap) and later evict a still-live key.
  bool isNew = (gMaterials->find(base) == gMaterials->end());
  if (isNew && gMaterials->size() >= kMaxMaterials && gMaterialFifo) {
    ADDRINT victim = gMaterialFifo->front();
    gMaterialFifo->erase(gMaterialFifo->begin());
    gMaterials->erase(victim);
  }
  (*gMaterials)[base] = m;
  if (isNew && gMaterialFifo) gMaterialFifo->push_back(base);
  PIN_ReleaseLock(&gMaterialLock);
}

static UINT32 LookupMaterial(ADDRINT base, ADDRINT len, Material *out) {
  if (base == 0) return 0;
  UINT32 found = 0;
  PIN_GetLock(&gMaterialLock, 1);
  for (std::map<ADDRINT, Material>::iterator it = gMaterials->begin(); it != gMaterials->end(); ++it) {
    const Material &m = it->second;
    ADDRINT queryEnd = base + (len ? len : 1);
    ADDRINT materialEnd = m.base + m.len;
    if (base < materialEnd && m.base < queryEnd) {
      if (out) *out = m;
      found = m.tag;
      break;
    }
  }
  PIN_ReleaseLock(&gMaterialLock);
  return found;
}

static UINT32 LookupHandle(ADDRINT handle) {
  if (handle == 0) return 0;
  UINT32 tag = 0;
  PIN_GetLock(&gHandleLock, 1);
  std::map<ADDRINT, UINT32>::iterator it = gHandleTags->find(handle);
  if (it != gHandleTags->end()) tag = it->second;
  PIN_ReleaseLock(&gHandleLock);
  return tag;
}

static void RegisterHandle(ADDRINT handle, UINT32 tag) {
  if (handle == 0 || tag == 0) return;
  PIN_GetLock(&gHandleLock, 1);
  // Only a NEW handle is pushed to the FIFO (see RegisterMaterial): re-binding an
  // existing handle must not append a duplicate entry that would grow the FIFO past
  // the cap and later evict a still-live handle.
  bool isNew = (gHandleTags->find(handle) == gHandleTags->end());
  if (isNew && gHandleTags->size() >= kMaxHandleTags && gHandleFifo) {
    ADDRINT victim = gHandleFifo->front();
    gHandleFifo->erase(gHandleFifo->begin());
    gHandleTags->erase(victim);
  }
  (*gHandleTags)[handle] = tag;
  if (isNew && gHandleFifo) gHandleFifo->push_back(handle);
  PIN_ReleaseLock(&gHandleLock);
}

static TData *GetThreadState(THREADID tid) {
  TData *state = static_cast<TData *>(PIN_GetThreadData(gTlsKey, tid));
  if (!state) { state = new TData(); PIN_SetThreadData(gTlsKey, state, tid); }
  return state;
}

static void EmitSource(const CryptoApiRule *rule, UINT32 tag, ADDRINT buf, ADDRINT len, ADDRINT ip, THREADID tid) {
  std::ostringstream oss;
  oss << "{\"ev\":\"src\",\"tag\":" << tag << ",\"api\":\"" << ::JsonEscape(rule->func)
      << "\",\"kind\":\"" << CryptoKindName(rule->kind) << "\",\"buf\":\"" << ::HexAddr(buf)
      << "\",\"len\":" << len << ",\"ip\":\"" << ::HexAddr(ip) << "\",\"tid\":" << tid << "}";
  JsonlWrite(oss.str());
}

static void EmitDeriv(const CryptoApiRule *rule, UINT32 parent, UINT32 child, ADDRINT inBuf, ADDRINT inLen, ADDRINT outBuf, ADDRINT outLen, ADDRINT ip, ADDRINT handle, THREADID tid) {
  std::ostringstream oss;
  oss << "{\"ev\":\"deriv\",\"parent\":" << parent << ",\"child\":" << child
      << ",\"api\":\"" << ::JsonEscape(rule->func) << "\",\"kind\":\"" << CryptoKindName(rule->kind)
      << "\",\"in_buf\":\"" << ::HexAddr(inBuf) << "\",\"in_len\":" << inLen
      << ",\"out_buf\":\"" << ::HexAddr(outBuf) << "\",\"out_len\":" << outLen
      << ",\"handle\":\"" << ::HexAddr(handle) << "\",\"ip\":\"" << ::HexAddr(ip) << "\",\"tid\":" << tid << "}";
  JsonlWrite(oss.str());
}

static void EmitSink(const CryptoApiRule *rule, UINT32 tag, ADDRINT inBuf, ADDRINT inLen, ADDRINT outBuf, ADDRINT outLen, ADDRINT ip, ADDRINT handle, THREADID tid) {
  std::ostringstream oss;
  oss << "{\"ev\":\"sink\",\"tag\":" << tag << ",\"api\":\"" << ::JsonEscape(rule->func)
      << "\",\"kind\":\"" << CryptoKindName(rule->kind) << "\",\"in_buf\":\"" << ::HexAddr(inBuf)
      << "\",\"in_len\":" << inLen << ",\"out_buf\":\"" << ::HexAddr(outBuf)
      << "\",\"out_len\":" << outLen << ",\"handle\":\"" << ::HexAddr(handle)
      << "\",\"ip\":\"" << ::HexAddr(ip) << "\",\"tid\":" << tid << "}";
  JsonlWrite(oss.str());
}

// maximum pending-call stack depth per thread.
// If IPOINT_AFTER was skipped (noreturn/longjmp/SEH), stale frames accumulate.
// A hard cap (32 nested crypto-API calls is already extreme — typical depth is
// 1-3) discards the oldest stale frames so the stack never wedges.
static const size_t kMaxPendingPerThread = 32;

static VOID OnApiBefore(THREADID tid, const CryptoApiRule *rule, ADDRINT ip, ADDRINT a0, ADDRINT a1, ADDRINT a2, ADDRINT a3, ADDRINT a4, ADDRINT a5, ADDRINT a6, ADDRINT a7, ADDRINT a8, ADDRINT a9) {
  ADDRINT args[10] = {a0, a1, a2, a3, a4, a5, a6, a7, a8, a9};
  PendingCall c;
  c.rule = rule; c.ip = ip;
  c.inBuf       = (rule->in_buf_arg     >= 0 && rule->in_buf_arg     < 10) ? args[rule->in_buf_arg]     : 0;
  c.inLen       = (rule->in_len_arg     >= 0 && rule->in_len_arg     < 10) ? args[rule->in_len_arg]     : 0;
  c.outBuf      = (rule->out_buf_arg    >= 0 && rule->out_buf_arg    < 10) ? args[rule->out_buf_arg]    : 0;
  c.outLen      = (rule->out_len_arg    >= 0 && rule->out_len_arg    < 10) ? args[rule->out_len_arg]    : 0;
  c.handleIn    = (rule->handle_in_arg  >= 0 && rule->handle_in_arg  < 10) ? args[rule->handle_in_arg]  : 0;
  c.handleOutPtr= (rule->handle_out_arg >= 0 && rule->handle_out_arg < 10) ? args[rule->handle_out_arg] : 0;
  TData *st = GetThreadState(tid);
  // cap stack depth, evict oldest stale.
  while (st->pending.size() >= kMaxPendingPerThread) {
    st->pending.erase(st->pending.begin());   // drop oldest
  }
  st->pending.push_back(c);

  // capture PLAINTEXT here, BEFORE the call runs — in-place ciphers (in_buf == out_buf,
  // e.g. Crypt888) overwrite in_buf with ciphertext by IPOINT_AFTER, so plaintext is only visible now.
  if (rule->kind == CRYPTO_KIND_SYM_ENC || rule->kind == CRYPTO_KIND_ASYM_ENC) {
    // a small enc input is the symmetric key material being sealed (e.g. an RSA/CNG-wrapped
    // AES key|iv, one per file) — exactly what captured-key recovery needs. Give it its own high cap so
    // the frequent, large file-plaintext snapshots cannot exhaust kMaxPlaintextSnap before every per-file
    // key is captured (root cause of partial key capture on hybrid AES+RSA families such as Chaos).
    if (c.inLen > 0 && c.inLen <= 64)
      DumpContentSnapshot("sink_plaintext", rule->func.c_str(), 0, c.inBuf, c.inLen, &gKeyWrapSnaps, kMaxKeyWrapSnap);
    else
      DumpContentSnapshot("sink_plaintext", rule->func.c_str(), 0, c.inBuf, c.inLen, &gPlaintextSnaps, kMaxPlaintextSnap);
  }
}

static ADDRINT ReadReturnedHandle(ADDRINT ptr) {
  if (ptr == 0) return 0;
  ADDRINT raw = 0;
  if (PIN_SafeCopy(&raw, (const VOID *)ptr, sizeof(ADDRINT)) != sizeof(ADDRINT)) return 0;
  return raw;
}

// Commit a tracked crypto API after it returns: emit src/deriv/sink rows and snapshot key buffers per CryptoKind.
static VOID OnApiAfter(THREADID tid, ADDRINT retval) {
  (void)retval;
  TData *state = GetThreadState(tid);
  if (state->pending.empty()) return;

  PendingCall c = state->pending.back();
  state->pending.pop_back();

  const CryptoApiRule *rule = c.rule;
  UINT32 parentTag = 0;
  if (c.inBuf) parentTag = LookupMaterial(c.inBuf, c.inLen, NULL);
  if (parentTag == 0 && c.handleIn) parentTag = LookupHandle(c.handleIn);

  ADDRINT newHandle = ReadReturnedHandle(c.handleOutPtr);

  switch (rule->kind) {
  case CRYPTO_KIND_RAND: {
    UINT32 tag = NewTag();
    RegisterMaterial(c.outBuf, c.outLen, tag, rule->func, rule->kind, c.ip);
    EmitSource(rule, tag, c.outBuf, c.outLen, c.ip, tid);
    DumpKeyBuffer("src_rand", rule->func.c_str(), tag, c.outBuf, c.outLen);
    break;
  }
  case CRYPTO_KIND_KEYGEN: {
    UINT32 child = NewTag();
    if (newHandle) RegisterHandle(newHandle, child);
    if (c.outBuf && c.outLen) RegisterMaterial(c.outBuf, c.outLen, child, rule->func, rule->kind, c.ip);
    EmitDeriv(rule, parentTag, child, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, newHandle, tid);
    // BCryptGenerateSymmetricKey-style APIs return a handle with out_buf=0, so snapshot in_buf (caller-supplied secret) too.
    DumpKeyBuffer("deriv_keygen",       rule->func.c_str(), child, c.outBuf, c.outLen);
    DumpKeyBuffer("deriv_keygen_input", rule->func.c_str(), child, c.inBuf,  c.inLen);
    break;
  }
  case CRYPTO_KIND_HASH: {
    UINT32 child = NewTag();
    if (c.handleIn) RegisterHandle(c.handleIn, child);
    EmitDeriv(rule, parentTag, child, c.inBuf, c.inLen, 0, 0, c.ip, c.handleIn, tid);
    // snapshot SMALL hash inputs (passwords/seeds feeding CryptDeriveKey); these let us
    // reproduce the CryptDeriveKey-derived file key offline. Large inputs = file-content hashing -> skip.
    if (c.inLen > 0 && c.inLen <= 512)
      DumpContentSnapshot("hash_input", rule->func.c_str(), child, c.inBuf, c.inLen, &gHashInputSnaps, kMaxHashInputSnap);
    break;
  }
  case CRYPTO_KIND_KDF: {
    UINT32 child = NewTag();
    if (c.outBuf && c.outLen) RegisterMaterial(c.outBuf, c.outLen, child, rule->func, rule->kind, c.ip);
    EmitDeriv(rule, parentTag, child, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, c.handleIn, tid);
    DumpKeyBuffer("deriv_kdf",       rule->func.c_str(), child, c.outBuf, c.outLen);
    DumpKeyBuffer("deriv_kdf_input", rule->func.c_str(), child, c.inBuf,  c.inLen);
    break;
  }
  case CRYPTO_KIND_KEY_IMPORT: {
    UINT32 child = NewTag();
    if (newHandle) RegisterHandle(newHandle, child);
    // Snapshot the imported blob too (mirror of KEY_EXPORT): a CryptImportKey /
    // BCryptImportKey of an attacker-reused PRIVATEKEYBLOB leaves a recoverable
    // RSA private key in the key-birth dump, which RC-02's capi/bcrypt byte
    // signatures can then recover. Without this the imported blob (in_buf) was
    // never PIN_SafeCopy-ed and the private key went uncaptured.
    if (c.inBuf && c.inLen) RegisterMaterial(c.inBuf, c.inLen, child, rule->func, rule->kind, c.ip);
    EmitDeriv(rule, parentTag, child, c.inBuf, c.inLen, 0, 0, c.ip, newHandle, tid);
    DumpKeyBuffer("deriv_key_import", rule->func.c_str(), child, c.inBuf, c.inLen);
    break;
  }
  case CRYPTO_KIND_KEY_EXPORT: {
    UINT32 sourceTag = LookupHandle(c.handleIn);
    UINT32 child = NewTag();
    if (c.outBuf && c.outLen) RegisterMaterial(c.outBuf, c.outLen, child, rule->func, rule->kind, c.ip);
    EmitDeriv(rule, sourceTag, child, 0, 0, c.outBuf, c.outLen, c.ip, c.handleIn, tid);
    DumpKeyBuffer("deriv_key_export", rule->func.c_str(), child, c.outBuf, c.outLen);
    break;
  }
  case CRYPTO_KIND_SYM_ENC:
  case CRYPTO_KIND_ASYM_ENC: {
    UINT32 keyTag = LookupHandle(c.handleIn);
    if (keyTag == 0 && c.inBuf) keyTag = LookupMaterial(c.inBuf, c.inLen, NULL);
    if (keyTag == 0) keyTag = NewTag();
    EmitSink(rule, keyTag, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, c.handleIn, tid);
    // capture CIPHERTEXT (out_buf, post-call). Paired with the OnApiBefore plaintext +
    // the captured key, this gives a verifiable (pt, ct, key) triple for 1:1 decryption proof.
    DumpContentSnapshot("sink_ciphertext", rule->func.c_str(), keyTag, c.outBuf, c.outLen, &gCiphertextSnaps, kMaxCiphertextSnap);
    if (c.outBuf && c.outLen) {
      UINT32 child = NewTag();
      RegisterMaterial(c.outBuf, c.outLen, child, rule->func, rule->kind, c.ip);
      EmitDeriv(rule, keyTag, child, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, c.handleIn, tid);
    }
    break;
  }
  case CRYPTO_KIND_MEMCPY: {
    if (parentTag && c.outBuf && c.outLen) {
      Material source = {};   // zero-init: LookupMaterial leaves *out untouched on a miss,
                              // so source.tag must default to 0 ("untracked source") not garbage.
      LookupMaterial(c.inBuf, c.inLen, &source);
      RegisterMaterial(c.outBuf, c.outLen, source.tag, rule->func, rule->kind, c.ip);
      if (parentTag != source.tag) EmitDeriv(rule, parentTag, source.tag, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, 0, tid);
    }
    break;
  }
  case CRYPTO_KIND_FILE_WRITE: {
    UINT32 sourceTag = LookupMaterial(c.inBuf, c.inLen, NULL);
    EmitSink(rule, sourceTag, c.inBuf, c.inLen, 0, 0, c.ip, c.handleIn, tid);
    break;
  }
  case CRYPTO_KIND_FILE_READ:
  case CRYPTO_KIND_FILE_OPEN:
  case CRYPTO_KIND_FILE_DELETE:
    EmitSink(rule, 0, c.inBuf, c.inLen, 0, 0, c.ip, c.handleIn, tid);
    break;
  case CRYPTO_KIND_NORMAL_OP:
    EmitDeriv(rule, 0, 0, c.inBuf, c.inLen, c.outBuf, c.outLen, c.ip, c.handleIn, tid);
    break;
  }
}

static bool InstallCryptoHook(IMG img, const CryptoApiRule *rule) {
  RTN rtn = RTN_FindByName(img, rule->func.c_str());
  if (!RTN_Valid(rtn)) return false;
  RTN_Open(rtn);
  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)OnApiBefore, IARG_THREAD_ID, IARG_PTR, rule, IARG_INST_PTR,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 8, IARG_FUNCARG_ENTRYPOINT_VALUE, 9, IARG_END);
  RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)OnApiAfter, IARG_THREAD_ID, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
  RTN_Close(rtn);
  return true;
}

static void EmitImageEvent(IMG img, size_t ruleCount) {
  std::ostringstream oss;
  oss << "{\"ev\":\"img\",\"path\":\"" << ::JsonEscape(IMG_Name(img))
      << "\",\"low\":\"" << ::HexAddr(IMG_LowAddress(img))
      << "\",\"high\":\"" << ::HexAddr(IMG_HighAddress(img))
      << "\",\"rules\":" << ruleCount << "}";
  JsonlWrite(oss.str());
}

static void InstallImageHooks(IMG img, const string &baseLower, bool trackedImage) {
  if (!IMG_Valid(img) || !trackedImage) return;

  vector<const CryptoApiRule *> rules;
  CollectCryptoRulesForDll(baseLower, rules);
  if (rules.empty() && !IsCryptoRoleDll(baseLower)) return;

  EmitImageEvent(img, rules.size());

  size_t installed = 0;
  for (size_t i = 0; i < rules.size(); ++i) {
    if (InstallCryptoHook(img, rules[i])) ++installed;
  }

  if (KnobDebug.Value()) ::LogDebug("key", ::DebugLogBuilder("crypto image processed").Field("image", IMG_Name(img)).Field("rules", (UINT64)rules.size()).Field("installed", (UINT64)installed));
}

static void Shutdown() {}

static VOID OnThreadStartHook(THREADID tid, CONTEXT *, INT32, VOID *) { PIN_SetThreadData(gTlsKey, new TData(), tid); }

static VOID OnThreadFiniHook(THREADID tid, const CONTEXT *, INT32, VOID *) {
  TData *state = static_cast<TData *>(PIN_GetThreadData(gTlsKey, tid));
  if (state) delete state;
  PIN_SetThreadData(gTlsKey, 0, tid);
}

static void Initialize() {
  PIN_InitLock(&gMaterialLock);
  PIN_InitLock(&gHandleLock);
  PIN_InitLock(&gTagLock);
  PIN_InitLock(&gResidueLock);

  gMaterials = new std::map<ADDRINT, Material>();
  gHandleTags = new std::map<ADDRINT, UINT32>();
  gKeyResidueDeduped = new std::set<ADDRINT>();
  // FIFO vectors for bounded eviction.
  gMaterialFifo    = new std::vector<ADDRINT>();
  gHandleFifo      = new std::vector<ADDRINT>();
  gKeyResidueFifo  = new std::vector<ADDRINT>();
  gMaterialFifo->reserve(kMaxMaterials + 16);
  gHandleFifo->reserve(kMaxHandleTags + 16);
  gKeyResidueFifo->reserve(kMaxKeyResidueDedup + 16);
  gTlsKey = PIN_CreateThreadDataKey(0);

  std::ostringstream start;
  start << "{\"ev\":\"start\",\"pid\":" << PIN_GetPid() << ",\"session\":\"" << ::JsonEscape(KnobSession.Value()) << "\"}";
  JsonlWrite(start.str());

  PIN_AddThreadStartFunction(OnThreadStartHook, 0);
  PIN_AddThreadFiniFunction(OnThreadFiniHook, 0);
}

}

static void InitializeKeyTracking() { KeyTrackingState::Initialize(); }
static void InstallKeyTrackingImageHooks(IMG img, const string &baseLower, bool trackedImage) { KeyTrackingState::InstallImageHooks(img, baseLower, trackedImage); }
static void ShutdownKeyTracking() { KeyTrackingState::Shutdown(); }
