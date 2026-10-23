#pragma once

#include "common.hpp"

enum CryptoKind {
  CRYPTO_KIND_RAND = 0,
  CRYPTO_KIND_KEYGEN,
  CRYPTO_KIND_KDF,
  CRYPTO_KIND_HASH,
  CRYPTO_KIND_SYM_ENC,
  CRYPTO_KIND_ASYM_ENC,
  CRYPTO_KIND_KEY_IMPORT,
  CRYPTO_KIND_KEY_EXPORT,
  CRYPTO_KIND_MEMCPY,
  CRYPTO_KIND_FILE_WRITE,
  CRYPTO_KIND_FILE_READ,
  CRYPTO_KIND_FILE_OPEN,
  CRYPTO_KIND_FILE_DELETE,
  CRYPTO_KIND_NORMAL_OP
};

struct CryptoApiRule {
  string dll;
  string func;
  CryptoKind kind;
  int in_buf_arg;
  int in_len_arg;
  int out_buf_arg;
  int out_len_arg;
  int handle_in_arg;
  int handle_out_arg;
  // Catalog-only row (no buffer/arg metadata); hook installer skips these to avoid flooding the trace with empty events.
  bool catalog_only;
};

struct IoActivityRule {
  string dll;
  string func;
  string group;
  string kind;
};

struct DllRoleRule {
  string dll;
  string role;
};

static bool InitializeRuleCatalog();
static const string &GetRuleCatalogDirectory();
static const char *CryptoKindName(CryptoKind kind);
static void CollectCryptoRulesForDll(const string &dllLower, vector<const CryptoApiRule *> &out);
static void CollectIoRulesForDll(const string &dllLower, vector<const IoActivityRule *> &out);
static bool HasCryptoRulesForDll(const string &dllLower);
static bool HasIoRulesForDll(const string &dllLower);
static const char *FindDllRole(const string &dllLower);
static bool IsCryptoRoleDll(const string &dllLower);
static bool IsInstrumentationRoleDll(const string &dllLower);
