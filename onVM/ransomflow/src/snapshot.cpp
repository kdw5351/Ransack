namespace {

struct ControlRef {
  UINT32 instruction_index;
  ADDRINT address;
  string kind;
  ADDRINT target;
  string symbol;
  string source;
  bool multiple_targets;
};

static bool InstructionAddressLess(const InstructionMeta *left, const InstructionMeta *right) {
  if (!left || !right) return left < right;
  return left->address < right->address;
}

static string BuildLoopStem(UINT32 captureId) { std::ostringstream oss; oss << "loop_" << captureId; return oss.str(); }
static string JsonBool(bool value) { return value ? "true" : "false"; }
static string JsonNullOrQuoted(const string &value) { return value.empty() ? "null" : "\"" + JsonEscape(value) + "\""; }
static string JsonNullOrHex(ADDRINT value) { return value == 0 ? "null" : "\"" + HexAddr(value) + "\""; }

static void CollectLoopInstructions(const LoopKey &key, vector<const InstructionMeta *> &out) {
  out.clear();
  PIN_GetLock(&gMetaLock, 1);
  map<ADDRINT, InstructionMeta *>::iterator it = gInstructionMeta->lower_bound(key.header);
  while (it != gInstructionMeta->end() && it->first < key.loop_end) { out.push_back(it->second); ++it; }
  PIN_ReleaseLock(&gMetaLock);
  std::sort(out.begin(), out.end(), InstructionAddressLess);
}

static void ResolveInstructionTarget(const InstructionMeta *meta, const ThreadLoopState &loopState, ADDRINT *target, string *symbol, string *source, bool *multipleTargets) {
  if (target) *target = 0;
  if (symbol) symbol->clear();
  if (source) source->clear();
  if (multipleTargets) *multipleTargets = false;
  if (!meta) return;

  map<ADDRINT, ControlFlowObservation>::const_iterator observed = loopState.observed_targets.find(meta->address);
  if (observed != loopState.observed_targets.end() && observed->second.seen) {
    if (target) *target = observed->second.target;
    if (source) *source = "observed";
    if (multipleTargets) *multipleTargets = observed->second.multiple_targets;
  } else if (meta->static_target != 0) {
    if (target) *target = meta->static_target;
    if (source) *source = "static";
  }

  if (target && *target != 0 && symbol) *symbol = ResolveSymbolNameRuntime(*target);
}

static bool WriteLoopSnapshot(UINT32 captureId, const LoopKey &key, string *snapshotName, size_t *copiedBytes) {
  if (snapshotName) snapshotName->clear();
  if (copiedBytes) *copiedBytes = 0;
  if (key.loop_end <= key.header) return false;

  size_t rangeSize = (size_t)(key.loop_end - key.header);
  vector<unsigned char> bytes(rangeSize);
  size_t copied = PIN_SafeCopy(&bytes[0], (const VOID *)key.header, rangeSize);
  if (copiedBytes) *copiedBytes = copied;
  if (copied == 0) return false;

  string name = BuildLoopStem(captureId) + ".bin";
  if (!WriteWholeBinaryFile(JoinPath(gOutputDirectory, name), &bytes[0], copied)) return false;

  if (snapshotName) *snapshotName = name;
  return true;
}

}

static bool CaptureLoopArtifacts(UINT32 captureId, ThreadState *threadState, const LoopKey &key, const ThreadLoopState &loopState) {
  vector<const InstructionMeta *> instructions;
  CollectLoopInstructions(key, instructions);

  // gInstructionMeta is usually empty; fall back to runtime IMG lookup so user loops aren't mislabelled "Unmapped/Unknown" + memset etc.
  const InstructionMeta *headerMeta = instructions.empty() ? FindInstructionMeta(key.header) : instructions[0];
  string imagePath, functionName;
  if (headerMeta) { imagePath = headerMeta->image_path; functionName = headerMeta->function_name; }
  else {
    functionName = ResolveSymbolNameRuntime(key.header);
    PIN_LockClient();
    IMG img = IMG_FindByAddress(key.header);
    if (IMG_Valid(img)) imagePath = IMG_Name(img);
    PIN_UnlockClient();
    if (imagePath.empty()) imagePath = "Unmapped/Unknown";
  }

  if (!ShouldCaptureLoopSnapshotImage(imagePath)) return false;

  string snapshotName;
  size_t copiedBytes = 0;
  bool snapshotWritten = WriteLoopSnapshot(captureId, key, &snapshotName, &copiedBytes);

  vector<ControlRef> refs;
  std::ostringstream body;
  body << "{\n"
       << "  \"loop_id\": " << captureId << ",\n"
       << "  \"thread_id\": " << (threadState ? threadState->os_tid : 0) << ",\n"
       << "  \"pin_thread_id\": " << (threadState ? threadState->pin_tid : 0) << ",\n"
       << "  \"iteration_at_capture\": " << loopState.iterations << ",\n"
       << "  \"header\": \"" << HexAddr(key.header) << "\",\n"
       << "  \"backedge\": \"" << HexAddr(key.backedge) << "\",\n"
       << "  \"loop_end\": \"" << HexAddr(key.loop_end) << "\",\n"
       << "  \"range_size\": " << (key.loop_end - key.header) << ",\n"
       << "  \"snapshot_written\": " << JsonBool(snapshotWritten) << ",\n"
       << "  \"snapshot_file\": " << JsonNullOrQuoted(snapshotName) << ",\n"
       << "  \"snapshot_bytes\": " << copiedBytes << ",\n"
       << "  \"image_path\": \"" << JsonEscape(imagePath) << "\",\n"
       << "  \"function_name\": \"" << JsonEscape(functionName) << "\",\n"
       << "  \"control_transfer_refs\": [\n";

  for (size_t i = 0; i < instructions.size(); ++i) {
    const InstructionMeta *meta = instructions[i];
    if (!meta) continue;

    ADDRINT target = 0;
    string targetSymbol, targetSource;
    bool multipleTargets = false;
    ResolveInstructionTarget(meta, loopState, &target, &targetSymbol, &targetSource, &multipleTargets);

    bool isFunctionLikeTransfer = meta->is_call || (meta->is_branch && !meta->has_fallthrough);
    if (isFunctionLikeTransfer) {
      ControlRef ref;
      ref.instruction_index = (UINT32)(i + 1);
      ref.address = meta->address;
      ref.kind = meta->is_call ? "call" : "jmp";
      ref.target = target;
      ref.symbol = targetSymbol;
      ref.source = targetSource;
      ref.multiple_targets = multipleTargets;
      refs.push_back(ref);
    }
  }

  for (size_t i = 0; i < refs.size(); ++i) {
    const ControlRef &ref = refs[i];
    body << "    {\"instruction_index\": " << ref.instruction_index
         << ", \"address\": \"" << HexAddr(ref.address) << "\""
         << ", \"kind\": \"" << ref.kind << "\""
         << ", \"target_address\": " << JsonNullOrHex(ref.target)
         << ", \"target_symbol\": " << JsonNullOrQuoted(ref.symbol)
         << ", \"target_source\": " << JsonNullOrQuoted(ref.source)
         << ", \"multiple_targets\": " << JsonBool(ref.multiple_targets)
         << "}";
    if (i + 1 != refs.size()) body << ",";
    body << "\n";
  }

  body << "  ]\n}\n";

  return WriteWholeTextFile(JoinPath(gOutputDirectory, BuildLoopStem(captureId) + ".json"), body.str());
}
