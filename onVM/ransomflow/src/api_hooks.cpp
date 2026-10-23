namespace {

// PE inspection of DataDirectory[14] (CLR Runtime Header) to detect .NET images.
static bool IsNETManagedImage(IMG img) {
  const ADDRINT base = (ADDRINT)IMG_LowAddress(img);

  UINT16 dosMagic = 0;
  if (PIN_SafeCopy(&dosMagic, (const void *)base, 2) != 2) return false;
  if (dosMagic != 0x5A4D) return false;

  UINT32 peOff = 0;
  if (PIN_SafeCopy(&peOff, (const void *)(base + 0x3C), 4) != 4) return false;
  if (peOff == 0 || peOff > 0x1000) return false;

  UINT32 peSig = 0;
  if (PIN_SafeCopy(&peSig, (const void *)(base + peOff), 4) != 4) return false;
  if (peSig != 0x00004550) return false;

  const ADDRINT optBase = base + peOff + 24;
  UINT16 optMagic = 0;
  if (PIN_SafeCopy(&optMagic, (const void *)optBase, 2) != 2) return false;

  // PE32 -> 96-byte optional header prefix; PE32+ -> 112. Index 14 * 8 -> CLR.
  ADDRINT dir14off;
  if (optMagic == 0x010B)      dir14off = optBase + 96  + 14 * 8;
  else if (optMagic == 0x020B) dir14off = optBase + 112 + 14 * 8;
  else                         return false;

  UINT32 clrRva = 0;
  if (PIN_SafeCopy(&clrRva, (const void *)dir14off, 4) != 4) return false;
  return clrRva != 0;
}

static bool ShouldTrackImage(const string &baseLower, bool isMainExe, bool *hasIoRules, bool *hasCryptoRules, bool *cryptoRole, bool *instrumentationRole) {
  const bool ioRules = HasIoRulesForDll(baseLower);
  const bool cryptoRules = HasCryptoRulesForDll(baseLower);
  const bool cryptoDll = IsCryptoRoleDll(baseLower);
  const bool instrumentationDll = IsInstrumentationRoleDll(baseLower);

  if (hasIoRules) *hasIoRules = ioRules;
  if (hasCryptoRules) *hasCryptoRules = cryptoRules;
  if (cryptoRole) *cryptoRole = cryptoDll;
  if (instrumentationRole) *instrumentationRole = instrumentationDll;

  return isMainExe || (!instrumentationDll && (ioRules || cryptoRules || cryptoDll));
}

static void EmitImageTrace(const string &fullPath, ADDRINT low, ADDRINT high, bool isMainExe, bool trackedImage, bool hasIoRules, bool hasCryptoRules, bool cryptoRole) {
  std::ostringstream json;
  json << "{\"ev\":\"img\""
       << ",\"path\":\"" << JsonEscape(fullPath) << "\""
       << ",\"low\":\"" << HexAddr(low) << "\""
       << ",\"high\":\"" << HexAddr(high) << "\""
       << ",\"main\":" << (isMainExe ? "true" : "false")
       << ",\"tracked\":" << (trackedImage ? "true" : "false")
       << ",\"io_rules\":" << (hasIoRules ? "true" : "false")
       << ",\"crypto_rules\":" << (hasCryptoRules ? "true" : "false")
       << ",\"crypto\":" << (cryptoRole ? "true" : "false")
       << "}";
  AppendChunkedLine(&gImageLog, json.str());

  std::ostringstream oss;
  oss << "EXT_IMG:" << fullPath << "," << std::hex << low << "," << high;
  if (isMainExe) oss << ",MAIN_EXE";
  if (trackedImage) oss << ",TRACKED";
  if (hasIoRules) oss << ",IO_RULES";
  if (hasCryptoRules) oss << ",CRYPTO_RULES";
  if (cryptoRole) oss << ",CRYPTO";
  oss << "\n";
  WriteGlobalTrace(oss.str());

  if (isMainExe) {
    std::ostringstream mainRow;
    mainRow << "EXT_MAIN_EXE:" << fullPath << "," << std::hex << low << "," << high << "\n";
    WriteGlobalTrace(mainRow.str());
  }
}

static void OnIoRuleCall(THREADID, const IoActivityRule *rule, ADDRINT a0, ADDRINT a1, ADDRINT a2, ADDRINT a3) {
  UINT32 osTid = (UINT32)PIN_GetTid();

  std::ostringstream json;
  json << "{\"ev\":\"io\""
       << ",\"tid\":" << osTid
       << ",\"api\":\"" << JsonEscape(rule->func) << "\""
       << ",\"group\":\"" << JsonEscape(rule->group) << "\""
       << ",\"kind\":\"" << JsonEscape(rule->kind) << "\""
       << ",\"a0\":\"" << HexAddr(a0) << "\""
       << ",\"a1\":\"" << HexAddr(a1) << "\""
       << ",\"a2\":\"" << HexAddr(a2) << "\""
       << ",\"a3\":\"" << HexAddr(a3) << "\""
       << "}";
  AppendChunkedLine(&gIoLog, json.str());

  std::ostringstream oss;
  oss << "IO:" << osTid << "," << rule->func << "," << rule->group << "," << rule->kind
      << "," << HexAddr(a0) << "," << HexAddr(a1) << "," << HexAddr(a2) << "," << HexAddr(a3) << "\n";
  WriteGlobalTrace(oss.str());
}

static bool InstallIoHook(IMG img, const IoActivityRule *rule) {
  RTN rtn = RTN_FindByName(img, rule->func.c_str());
  if (!RTN_Valid(rtn)) return false;
  RTN_Open(rtn);
  RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)OnIoRuleCall, IARG_THREAD_ID, IARG_PTR, rule,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                 IARG_END);
  RTN_Close(rtn);
  return true;
}

static void InstallIoHooksForImage(IMG img, const string &baseLower, bool trackedImage) {
  if (!trackedImage) return;
  vector<const IoActivityRule *> rules;
  CollectIoRulesForDll(baseLower, rules);
  if (rules.empty()) return;

  size_t installed = 0;
  for (size_t i = 0; i < rules.size(); ++i) {
    if (InstallIoHook(img, rules[i])) ++installed;
  }

  if (KnobDebug.Value()) LogDebug("image", DebugLogBuilder("io hooks installed").Field("image", IMG_Name(img)).Field("rules", (UINT64)rules.size()).Field("installed", (UINT64)installed));
}

static void InstallTrackedImageHooks(IMG img, const string &baseLower, bool trackedImage) {
  InstallIoHooksForImage(img, baseLower, trackedImage);
  InstallKeyTrackingImageHooks(img, baseLower, trackedImage);
}

}

static VOID OnImgLoad(IMG img, VOID *) {
  if (!IMG_Valid(img)) return;

  const string fullPath = IMG_Name(img);
  const string baseLower = BaseNameLower(fullPath);
  const bool isMainExe = IMG_IsMainExecutable(img);
  bool hasIoRules = false, hasCryptoRules = false, cryptoRole = false, instrumentationRole = false;
  const bool trackedImage = ShouldTrackImage(baseLower, isMainExe, &hasIoRules, &hasCryptoRules, &cryptoRole, &instrumentationRole);

  if (KnobDebug.Value()) LogDebug("image", DebugLogBuilder("image loaded").Field("path", fullPath).Hex("low", (ADDRINT)IMG_LowAddress(img)).Hex("high", (ADDRINT)IMG_HighAddress(img)).Flag("main", isMainExe).Flag("tracked", trackedImage).Flag("io_rules", hasIoRules).Flag("crypto_rules", hasCryptoRules).Flag("crypto_role", cryptoRole).Flag("instrumentation", instrumentationRole));

  EmitImageTrace(fullPath, (ADDRINT)IMG_LowAddress(img), (ADDRINT)IMG_HighAddress(img), isMainExe, trackedImage, hasIoRules, hasCryptoRules, cryptoRole);

  if (isMainExe && !gIsManaged && IsNETManagedImage(img)) {
    gIsManaged = true;
    std::ostringstream managed;
    managed << "{\"ev\":\"managed_exe\""
            << ",\"path\":\"" << JsonEscape(fullPath) << "\""
            << ",\"note\":\"CLR header detected; RTN hooks skipped to avoid IPOINT_AFTER conflict with .NET GC stack-walker\"}";
    AppendChunkedLine(&gImageLog, managed.str());
    if (KnobDebug.Value()) LogDebug("image", DebugLogBuilder(".NET managed binary detected — RTN hooks disabled").Field("path", fullPath));
  }

  InstallTrackedImageHooks(img, baseLower, trackedImage);
}
