namespace {

static vector<CryptoApiRule> *gCryptoRules = NULL;
static vector<IoActivityRule> *gIoRules = NULL;
static vector<DllRoleRule> *gDllRoles = NULL;
static string gRuleCatalogDirectory;

class JsonParser {
public:
  explicit JsonParser(const string &input) : input_(input), pos_(0) {}

  void SkipWs() { while (pos_ < input_.size() && std::isspace((unsigned char)input_[pos_])) ++pos_; }

  bool Consume(char ch) {
    SkipWs();
    if (pos_ < input_.size() && input_[pos_] == ch) { ++pos_; return true; }
    return false;
  }

  bool ParseString(string *out) {
    SkipWs();
    if (pos_ >= input_.size() || input_[pos_] != '"') return false;

    ++pos_;
    out->clear();
    while (pos_ < input_.size()) {
      char ch = input_[pos_++];
      if (ch == '"') return true;
      if (ch != '\\') { out->push_back(ch); continue; }
      if (pos_ >= input_.size()) return false;

      char esc = input_[pos_++];
      switch (esc) {
      case '"': case '\\': case '/': out->push_back(esc); break;
      case 'b': out->push_back('\b'); break;
      case 'f': out->push_back('\f'); break;
      case 'n': out->push_back('\n'); break;
      case 'r': out->push_back('\r'); break;
      case 't': out->push_back('\t'); break;
      case 'u': {
        if (pos_ + 4 > input_.size()) return false;
        string hex = input_.substr(pos_, 4);
        unsigned int code = 0;
        std::istringstream iss(hex);
        iss >> std::hex >> code;
        out->push_back(code < 0x80 ? (char)code : '?');
        pos_ += 4;
        break;
      }
      default: return false;
      }
    }
    return false;
  }

  bool ParseInt(int *out) {
    SkipWs();
    size_t start = pos_;
    if (pos_ < input_.size() && (input_[pos_] == '-' || input_[pos_] == '+')) ++pos_;
    if (pos_ >= input_.size() || !std::isdigit((unsigned char)input_[pos_])) return false;
    while (pos_ < input_.size() && std::isdigit((unsigned char)input_[pos_])) ++pos_;
    *out = atoi(input_.substr(start, pos_ - start).c_str());
    return true;
  }

  bool ParseBool(bool *out) {
    SkipWs();
    if (input_.compare(pos_, 4, "true")  == 0) { pos_ += 4; *out = true;  return true; }
    if (input_.compare(pos_, 5, "false") == 0) { pos_ += 5; *out = false; return true; }
    return false;
  }

  bool SkipValue() {
    SkipWs();
    if (pos_ >= input_.size()) return false;

    char ch = input_[pos_];
    if (ch == '"') { string ignored; return ParseString(&ignored); }
    if (ch == '{') {
      ++pos_;
      while (true) {
        SkipWs();
        if (Consume('}')) return true;
        string key;
        if (!ParseString(&key) || !Consume(':') || !SkipValue()) return false;
        SkipWs();
        if (Consume('}')) return true;
        if (!Consume(',')) return false;
      }
    }
    if (ch == '[') {
      ++pos_;
      while (true) {
        SkipWs();
        if (Consume(']')) return true;
        if (!SkipValue()) return false;
        SkipWs();
        if (Consume(']')) return true;
        if (!Consume(',')) return false;
      }
    }
    if (std::isdigit((unsigned char)ch) || ch == '-' || ch == '+') { int ignored = 0; return ParseInt(&ignored); }
    if (input_.compare(pos_, 4, "true")  == 0) { pos_ += 4; return true; }
    if (input_.compare(pos_, 5, "false") == 0) { pos_ += 5; return true; }
    if (input_.compare(pos_, 4, "null")  == 0) { pos_ += 4; return true; }
    return false;
  }

private:
  const string &input_;
  size_t pos_;
};

static string DirName(const string &path) {
  size_t pos = path.find_last_of("\\/");
  return pos == string::npos ? "" : path.substr(0, pos);
}

static bool FileExists(const string &path) {
  std::ifstream input(path.c_str(), std::ios::binary);
  return input.good();
}

static bool ReadTextFile(const string &path, string *out) {
  std::ifstream input(path.c_str(), std::ios::binary);
  if (!input) return false;
  std::ostringstream buffer;
  buffer << input.rdbuf();
  *out = buffer.str();
  return true;
}

static bool ParseCryptoKindToken(const string &kind, CryptoKind *out) {
  if      (kind == "rand")        *out = CRYPTO_KIND_RAND;
  else if (kind == "keygen")      *out = CRYPTO_KIND_KEYGEN;
  else if (kind == "kdf")         *out = CRYPTO_KIND_KDF;
  else if (kind == "hash")        *out = CRYPTO_KIND_HASH;
  else if (kind == "sym_enc")     *out = CRYPTO_KIND_SYM_ENC;
  else if (kind == "asym_enc")    *out = CRYPTO_KIND_ASYM_ENC;
  else if (kind == "key_import")  *out = CRYPTO_KIND_KEY_IMPORT;
  else if (kind == "key_export")  *out = CRYPTO_KIND_KEY_EXPORT;
  else if (kind == "memcpy")      *out = CRYPTO_KIND_MEMCPY;
  else if (kind == "file_write")  *out = CRYPTO_KIND_FILE_WRITE;
  else if (kind == "file_read")   *out = CRYPTO_KIND_FILE_READ;
  else if (kind == "file_open")   *out = CRYPTO_KIND_FILE_OPEN;
  else if (kind == "file_delete") *out = CRYPTO_KIND_FILE_DELETE;
  else if (kind == "normal_op")   *out = CRYPTO_KIND_NORMAL_OP;
  else return false;
  return true;
}

static bool ParseCryptoRuleObject(JsonParser *parser, CryptoApiRule *rule) {
  rule->dll.clear(); rule->func.clear();
  rule->kind = CRYPTO_KIND_NORMAL_OP;
  rule->in_buf_arg = -1; rule->in_len_arg = -1;
  rule->out_buf_arg = -1; rule->out_len_arg = -1;
  rule->handle_in_arg = -1; rule->handle_out_arg = -1;
  rule->catalog_only = false;

  if (!parser->Consume('{')) return false;

  while (true) {
    string key;
    parser->SkipWs();
    if (parser->Consume('}')) break;
    if (!parser->ParseString(&key) || !parser->Consume(':')) return false;

    if (key == "dll") {
      if (!parser->ParseString(&rule->dll)) return false;
      rule->dll = ToLowerStr(rule->dll);
    } else if (key == "func") {
      if (!parser->ParseString(&rule->func)) return false;
    } else if (key == "kind") {
      string kindToken;
      if (!parser->ParseString(&kindToken) || !ParseCryptoKindToken(kindToken, &rule->kind)) return false;
    } else if (key == "in_buf_arg")     { if (!parser->ParseInt(&rule->in_buf_arg))     return false; }
      else if (key == "in_len_arg")     { if (!parser->ParseInt(&rule->in_len_arg))     return false; }
      else if (key == "out_buf_arg")    { if (!parser->ParseInt(&rule->out_buf_arg))    return false; }
      else if (key == "out_len_arg")    { if (!parser->ParseInt(&rule->out_len_arg))    return false; }
      else if (key == "handle_in_arg")  { if (!parser->ParseInt(&rule->handle_in_arg))  return false; }
      else if (key == "handle_out_arg") { if (!parser->ParseInt(&rule->handle_out_arg)) return false; }
      else if (key == "catalog_only") {
        bool flag = false;
        if (!parser->ParseBool(&flag)) return false;
        rule->catalog_only = flag;
      }
      else if (!parser->SkipValue()) return false;

    parser->SkipWs();
    if (parser->Consume('}')) break;
    if (!parser->Consume(',')) return false;
  }

  return !rule->dll.empty() && !rule->func.empty();
}

static bool ParseIoRuleObject(JsonParser *parser, IoActivityRule *rule) {
  rule->dll.clear(); rule->func.clear(); rule->group.clear(); rule->kind.clear();

  if (!parser->Consume('{')) return false;

  while (true) {
    string key;
    parser->SkipWs();
    if (parser->Consume('}')) break;
    if (!parser->ParseString(&key) || !parser->Consume(':')) return false;

    if (key == "dll") {
      if (!parser->ParseString(&rule->dll)) return false;
      rule->dll = ToLowerStr(rule->dll);
    } else if (key == "func")  { if (!parser->ParseString(&rule->func))  return false; }
      else if (key == "group") { if (!parser->ParseString(&rule->group)) return false; }
      else if (key == "kind")  { if (!parser->ParseString(&rule->kind))  return false; }
      else if (!parser->SkipValue()) return false;

    parser->SkipWs();
    if (parser->Consume('}')) break;
    if (!parser->Consume(',')) return false;
  }

  return !rule->dll.empty() && !rule->func.empty();
}

static bool ParseCryptoRules(const string &json, vector<CryptoApiRule> *out) {
  JsonParser parser(json);
  out->clear();
  if (!parser.Consume('[')) return false;
  while (true) {
    parser.SkipWs();
    if (parser.Consume(']')) return true;
    CryptoApiRule rule;
    if (!ParseCryptoRuleObject(&parser, &rule)) return false;
    out->push_back(rule);
    parser.SkipWs();
    if (parser.Consume(']')) return true;
    if (!parser.Consume(',')) return false;
  }
}

static bool ParseIoRules(const string &json, vector<IoActivityRule> *out) {
  JsonParser parser(json);
  out->clear();
  if (!parser.Consume('[')) return false;
  while (true) {
    parser.SkipWs();
    if (parser.Consume(']')) return true;
    IoActivityRule rule;
    if (!ParseIoRuleObject(&parser, &rule)) return false;
    out->push_back(rule);
    parser.SkipWs();
    if (parser.Consume(']')) return true;
    if (!parser.Consume(',')) return false;
  }
}

static bool ParseDllRoles(const string &json, vector<DllRoleRule> *out) {
  JsonParser parser(json);
  out->clear();
  if (!parser.Consume('{')) return false;

  while (true) {
    string key;
    parser.SkipWs();
    if (parser.Consume('}')) return true;
    if (!parser.ParseString(&key) || !parser.Consume(':')) return false;

    if (key != "roles") {
      if (!parser.SkipValue()) return false;
    } else {
      if (!parser.Consume('{')) return false;
      while (true) {
        string dll;
        parser.SkipWs();
        if (parser.Consume('}')) break;
        if (!parser.ParseString(&dll) || !parser.Consume(':')) return false;

        if (!dll.empty() && dll[0] == '_') {
          if (!parser.SkipValue()) return false;
        } else {
          DllRoleRule rule;
          if (!parser.ParseString(&rule.role)) return false;
          rule.dll = ToLowerStr(dll);
          out->push_back(rule);
        }

        parser.SkipWs();
        if (parser.Consume('}')) break;
        if (!parser.Consume(',')) return false;
      }
    }

    parser.SkipWs();
    if (parser.Consume('}')) return true;
    if (!parser.Consume(',')) return false;
  }
}

static string GetToolDirectory() {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery((const void *)&GetToolDirectory, &mbi, sizeof(mbi)) == 0) return "";

  char path[1024];
  memset(path, 0, sizeof(path));
  DWORD length = GetModuleFileNameA(mbi.AllocationBase, path, (DWORD)(sizeof(path) - 1));
  if (length == 0 || length >= sizeof(path)) return "";
  return DirName(path);
}

static string GetCurrentDirectoryPath() {
  char path[1024];
  memset(path, 0, sizeof(path));
  DWORD length = GetCurrentDirectoryA((DWORD)(sizeof(path) - 1), path);
  if (length == 0 || length >= sizeof(path)) return "";
  return path;
}

static bool HasRuleFiles(const string &dir) {
  return FileExists(JoinPath(dir, "crypto_api.json"))
      && FileExists(JoinPath(dir, "io_activity.json"))
      && FileExists(JoinPath(dir, "dll_roles.json"));
}

static void AddCandidate(vector<string> *candidates, const string &path) {
  if (path.empty()) return;
  for (size_t i = 0; i < candidates->size(); ++i) {
    if ((*candidates)[i] == path) return;
  }
  candidates->push_back(path);
}

static string ResolveRuleDirectory() {
  vector<string> candidates;
  if (!KnobRulesDir.Value().empty()) AddCandidate(&candidates, KnobRulesDir.Value());

  string toolDir = GetToolDirectory();
  AddCandidate(&candidates, JoinPath(toolDir, "assets"));
  AddCandidate(&candidates, JoinPath(toolDir, "..\\assets"));
  AddCandidate(&candidates, JoinPath(toolDir, "..\\..\\assets"));

  string cwd = GetCurrentDirectoryPath();
  AddCandidate(&candidates, JoinPath(cwd, "assets"));
  AddCandidate(&candidates, JoinPath(cwd, "onVM\\assets"));
  AddCandidate(&candidates, JoinPath(cwd, "..\\assets"));

  for (size_t i = 0; i < candidates.size(); ++i) {
    if (HasRuleFiles(candidates[i])) return candidates[i];
  }
  return candidates.empty() ? "" : candidates[0];
}

}

static const char *CryptoKindName(CryptoKind kind) {
  switch (kind) {
  case CRYPTO_KIND_RAND:        return "rand";
  case CRYPTO_KIND_KEYGEN:      return "keygen";
  case CRYPTO_KIND_KDF:         return "kdf";
  case CRYPTO_KIND_HASH:        return "hash";
  case CRYPTO_KIND_SYM_ENC:     return "sym_enc";
  case CRYPTO_KIND_ASYM_ENC:    return "asym_enc";
  case CRYPTO_KIND_KEY_IMPORT:  return "key_import";
  case CRYPTO_KIND_KEY_EXPORT:  return "key_export";
  case CRYPTO_KIND_MEMCPY:      return "memcpy";
  case CRYPTO_KIND_FILE_WRITE:  return "file_write";
  case CRYPTO_KIND_FILE_READ:   return "file_read";
  case CRYPTO_KIND_FILE_OPEN:   return "file_open";
  case CRYPTO_KIND_FILE_DELETE: return "file_delete";
  case CRYPTO_KIND_NORMAL_OP:   return "normal_op";
  }
  return "unknown";
}

static bool InitializeRuleCatalog() {
  if (gCryptoRules && gIoRules && gDllRoles) return !gRuleCatalogDirectory.empty();

  vector<CryptoApiRule> cryptoRules;
  vector<IoActivityRule> ioRules;
  vector<DllRoleRule> dllRoles;

  gRuleCatalogDirectory = ResolveRuleDirectory();
  if (gRuleCatalogDirectory.empty() || !HasRuleFiles(gRuleCatalogDirectory)) return false;

  string cryptoJson, ioJson, rolesJson;
  if (!ReadTextFile(JoinPath(gRuleCatalogDirectory, "crypto_api.json"),   &cryptoJson) ||
      !ReadTextFile(JoinPath(gRuleCatalogDirectory, "io_activity.json"),  &ioJson) ||
      !ReadTextFile(JoinPath(gRuleCatalogDirectory, "dll_roles.json"),    &rolesJson)) return false;

  if (!ParseCryptoRules(cryptoJson, &cryptoRules) ||
      !ParseIoRules(ioJson, &ioRules) ||
      !ParseDllRoles(rolesJson, &dllRoles)) return false;

  if (!gCryptoRules) gCryptoRules = new vector<CryptoApiRule>();
  if (!gIoRules)     gIoRules     = new vector<IoActivityRule>();
  if (!gDllRoles)    gDllRoles    = new vector<DllRoleRule>();

  *gCryptoRules = cryptoRules;
  *gIoRules     = ioRules;
  *gDllRoles    = dllRoles;
  return true;
}

static const string &GetRuleCatalogDirectory() { return gRuleCatalogDirectory; }

static void CollectCryptoRulesForDll(const string &dllLower, vector<const CryptoApiRule *> &out) {
  out.clear();
  if (!gCryptoRules) return;
  for (size_t i = 0; i < gCryptoRules->size(); ++i) {
    const CryptoApiRule &rule = (*gCryptoRules)[i];
    if (dllLower != rule.dll) continue;
    if (rule.catalog_only) continue;
    if (rule.kind == CRYPTO_KIND_MEMCPY && !KnobFollowMemcpy.Value()) continue;
    out.push_back(&rule);
  }
}

static void CollectIoRulesForDll(const string &dllLower, vector<const IoActivityRule *> &out) {
  out.clear();
  if (!gIoRules) return;
  for (size_t i = 0; i < gIoRules->size(); ++i) {
    const IoActivityRule &rule = (*gIoRules)[i];
    if (dllLower == rule.dll) out.push_back(&rule);
  }
}

static bool HasCryptoRulesForDll(const string &dllLower) {
  if (!gCryptoRules) return false;
  for (size_t i = 0; i < gCryptoRules->size(); ++i) {
    const CryptoApiRule &rule = (*gCryptoRules)[i];
    if (dllLower != rule.dll) continue;
    if (rule.catalog_only) continue;
    if (rule.kind == CRYPTO_KIND_MEMCPY && !KnobFollowMemcpy.Value()) continue;
    return true;
  }
  return false;
}

static bool HasIoRulesForDll(const string &dllLower) {
  if (!gIoRules) return false;
  for (size_t i = 0; i < gIoRules->size(); ++i) {
    if ((*gIoRules)[i].dll == dllLower) return true;
  }
  return false;
}

static const char *FindDllRole(const string &dllLower) {
  if (!gDllRoles) return NULL;
  for (size_t i = 0; i < gDllRoles->size(); ++i) {
    if ((*gDllRoles)[i].dll == dllLower) return (*gDllRoles)[i].role.c_str();
  }
  return NULL;
}

static bool IsCryptoRoleDll(const string &dllLower) {
  const char *role = FindDllRole(dllLower);
  return role && strncmp(role, "crypto.", 7) == 0;
}

static bool IsInstrumentationRoleDll(const string &dllLower) {
  const char *role = FindDllRole(dllLower);
  return role && strcmp(role, "instrumentation") == 0;
}
