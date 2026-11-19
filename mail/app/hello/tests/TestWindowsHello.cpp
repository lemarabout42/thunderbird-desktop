/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../../WindowsHello.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
      std::exit(1);                                                     \
    }                                                                   \
  } while (false)

namespace {
struct Scenario {
  const wchar_t* badPolicy = nullptr;
  const wchar_t* failedSet = nullptr;
  SECURITY_STATUS providerStatus = ERROR_SUCCESS;
  SECURITY_STATUS openStatus = ERROR_SUCCESS;
  SECURITY_STATUS createStatus = ERROR_SUCCESS;
  SECURITY_STATUS finalizeStatus = ERROR_SUCCESS;
  SECURITY_STATUS signStatus = ERROR_SUCCESS;
  SECURITY_STATUS decryptStatus = ERROR_SUCCESS;
  SECURITY_STATUS verifyStatus = ERROR_SUCCESS;
  SECURITY_STATUS getStatus = ERROR_SUCCESS;
  SECURITY_STATUS exportStatus = ERROR_SUCCESS;
  SECURITY_STATUS deleteStatus = ERROR_SUCCESS;
  NTSTATUS algorithmStatus = 0;
  NTSTATUS importStatus = 0;
  bool shortPublicKey = false;
  NTSTATUS randomStatus = 0;
  bool shortPolicy = false;
  bool shortSignature = false;
  bool gesture = false;
  bool context = false;
  bool vault = false;
  DWORD decryptedSize = 32;
  int decryptCalls = 0;
  int signCalls = 0;
  int verifyCalls = 0;
  int createCalls = 0;
  int freeCalls = 0;
  int deleteCalls = 0;
} state;

SECURITY_STATUS
FakeOpenProvider(NCRYPT_PROV_HANDLE* out, LPCWSTR name, DWORD) {
  CHECK(std::wcscmp(name, L"Microsoft Passport Key Storage Provider") == 0);
  if (state.providerStatus == ERROR_SUCCESS) {
    *out = 1;
  }
  return state.providerStatus;
}
SECURITY_STATUS
FakeOpenKey(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE* out, LPCWSTR name, DWORD,
            DWORD flags) {
  CHECK(std::wcsstr(name, state.vault ? L"//ThunderbirdHello//Vault-v2-"
                                      : L"//ThunderbirdHello//Startup-v1"));
  CHECK(flags == 0);  // Opening silently can suppress the later Hello prompt.
  if (state.openStatus == ERROR_SUCCESS) {
    *out = 2;
  }
  return state.openStatus;
}
SECURITY_STATUS
FakeCreate(NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE* out, LPCWSTR algorithm,
           LPCWSTR, DWORD, DWORD flags) {
  ++state.createCalls;
  CHECK(flags == 0);  // Must never overwrite a key.
  CHECK(std::wcscmp(algorithm, BCRYPT_RSA_ALGORITHM) == 0);
  if (state.createStatus == ERROR_SUCCESS) {
    *out = 2;
  }
  return state.createStatus;
}
SECURITY_STATUS
FakeFinalize(NCRYPT_KEY_HANDLE, DWORD) { return state.finalizeStatus; }
SECURITY_STATUS
FakeSet(NCRYPT_HANDLE, LPCWSTR property, PBYTE bytes, DWORD length, DWORD) {
  if (state.failedSet && std::wcscmp(state.failedSet, property) == 0) {
    return NTE_NOT_SUPPORTED;
  }
  if (std::wcscmp(property, L"PinCacheIsGestureRequired") == 0) {
    CHECK(length == sizeof(DWORD));
    CHECK(*reinterpret_cast<DWORD*>(bytes) == 1);
    state.gesture = true;
  }
  if (std::wcscmp(property, NCRYPT_USE_CONTEXT_PROPERTY) == 0) {
    state.context = true;
  }
  return ERROR_SUCCESS;
}
SECURITY_STATUS
FakeGet(NCRYPT_HANDLE, LPCWSTR property, PBYTE bytes, DWORD length,
        DWORD* written, DWORD) {
  if (state.getStatus != ERROR_SUCCESS) {
    return state.getStatus;
  }
  DWORD value = 0;
  if (std::wcscmp(property, NCRYPT_LENGTH_PROPERTY) == 0) {
    value = 2048;
  } else if (std::wcscmp(property, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
    value = NCRYPT_ALLOW_SIGNING_FLAG;
    if (state.vault) value |= NCRYPT_ALLOW_DECRYPT_FLAG;
  } else if (std::wcscmp(property, L"NgcCacheType") == 0) {
    value = 1;
  }
  if (state.badPolicy && std::wcscmp(state.badPolicy, property) == 0) {
    value ^= 8;
  }
  CHECK(length == sizeof(value));
  std::memcpy(bytes, &value, sizeof(value));
  *written = state.shortPolicy ? 1 : sizeof(value);
  return ERROR_SUCCESS;
}
SECURITY_STATUS
FakeSign(NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD length, PBYTE signature,
         DWORD capacity, DWORD* written, DWORD flags) {
  ++state.signCalls;
  CHECK(state.gesture && state.context);
  CHECK(flags == NCRYPT_PAD_PKCS1_FLAG);
  CHECK(length == 32 && capacity == 256);
  std::memset(signature, 0xA5, capacity);
  *written = state.shortSignature ? capacity - 1 : capacity;
  return state.signStatus;
}
SECURITY_STATUS
FakeExport(NCRYPT_KEY_HANDLE, NCRYPT_KEY_HANDLE, LPCWSTR type,
           NCryptBufferDesc*, PBYTE bytes, DWORD capacity, DWORD* written,
           DWORD flags) {
  CHECK(std::wcscmp(type, BCRYPT_RSAPUBLIC_BLOB) == 0);
  CHECK(flags == NCRYPT_SILENT_FLAG && capacity >= 32);
  std::memset(bytes, 0, 32);
  *written = state.shortPublicKey ? 1 : 32;
  return state.exportStatus;
}
NTSTATUS
FakeOpenAlgorithm(BCRYPT_ALG_HANDLE* out, LPCWSTR algorithm, LPCWSTR, ULONG) {
  if (std::wcscmp(algorithm, BCRYPT_SHA256_ALGORITHM) == 0)
    return BCryptOpenAlgorithmProvider(out, algorithm, nullptr, 0);
  CHECK(std::wcscmp(algorithm, BCRYPT_RSA_ALGORITHM) == 0);
  *out = reinterpret_cast<BCRYPT_ALG_HANDLE>(3);
  return state.algorithmStatus;
}
NTSTATUS
FakeImport(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR type,
           BCRYPT_KEY_HANDLE* out, PUCHAR, ULONG, ULONG) {
  CHECK(std::wcscmp(type, BCRYPT_RSAPUBLIC_BLOB) == 0);
  *out = reinterpret_cast<BCRYPT_KEY_HANDLE>(4);
  return state.importStatus;
}

NTSTATUS FakeEncrypt(BCRYPT_KEY_HANDLE key, PUCHAR, ULONG length, VOID*, PUCHAR,
                     ULONG, PUCHAR output, ULONG capacity, ULONG* written,
                     ULONG flags) {
  CHECK(key == reinterpret_cast<BCRYPT_KEY_HANDLE>(4));
  CHECK(length == 32 && capacity == 256 && flags == BCRYPT_PAD_PKCS1);
  std::memset(output, 0xC3, capacity);
  *written = capacity;
  return 0;
}
NTSTATUS
FakeVerify(BCRYPT_KEY_HANDLE, VOID*, PUCHAR, ULONG, PUCHAR, ULONG,
           ULONG flags) {
  CHECK(flags == BCRYPT_PAD_PKCS1);
  ++state.verifyCalls;
  return state.verifyStatus;
}
NTSTATUS
FakeDestroy(BCRYPT_KEY_HANDLE key) {
  CHECK(key == reinterpret_cast<BCRYPT_KEY_HANDLE>(4));
  return 0;
}
NTSTATUS
FakeCloseAlgorithm(BCRYPT_ALG_HANDLE algorithm, ULONG) {
  return algorithm == reinterpret_cast<BCRYPT_ALG_HANDLE>(3)
             ? 0
             : BCryptCloseAlgorithmProvider(algorithm, 0);
}
SECURITY_STATUS FakeDecrypt(NCRYPT_KEY_HANDLE, PBYTE, DWORD size, VOID*,
                            PBYTE out, DWORD capacity, DWORD* written,
                            DWORD flags) {
  CHECK(state.context && state.gesture && state.verifyCalls == 1);
  CHECK(flags == NCRYPT_PAD_PKCS1_FLAG && size == 256 && capacity >= 32);
  ++state.decryptCalls;
  if (state.decryptStatus == ERROR_SUCCESS) {
    std::memset(out, 0x5A, state.decryptedSize);
    *written = state.decryptedSize;
  }
  return state.decryptStatus;
}
SECURITY_STATUS
FakeFree(NCRYPT_HANDLE handle) {
  CHECK(handle == 1 || handle == 2);
  ++state.freeCalls;
  return ERROR_SUCCESS;
}

SECURITY_STATUS FakeDelete(NCRYPT_KEY_HANDLE key, DWORD flags) {
  CHECK(key == 2 && flags == NCRYPT_SILENT_FLAG);
  ++state.deleteCalls;
  return state.deleteStatus;
}
NTSTATUS
FakeRandom(BCRYPT_ALG_HANDLE algorithm, PUCHAR bytes, ULONG length,
           ULONG flags) {
  if (state.randomStatus != 0) {
    return state.randomStatus;
  }
  return BCryptGenRandom(algorithm, bytes, length, flags);
}
}  // namespace

// Substitute the OS boundary, exercising the actual production startup logic.
// No Hello enrollment, prompt, or user key is created by this test.
#define NCryptOpenStorageProvider FakeOpenProvider
#define NCryptOpenKey FakeOpenKey
#define NCryptCreatePersistedKey FakeCreate
#define NCryptFinalizeKey FakeFinalize
#define NCryptSetProperty FakeSet
#define NCryptGetProperty FakeGet
#define NCryptSignHash FakeSign
#define NCryptDecrypt FakeDecrypt
#define NCryptExportKey FakeExport
#define NCryptFreeObject FakeFree
#define NCryptDeleteKey FakeDelete
#define BCryptGenRandom FakeRandom
#define BCryptOpenAlgorithmProvider FakeOpenAlgorithm
#define BCryptImportKeyPair FakeImport
#define BCryptEncrypt FakeEncrypt
#define BCryptVerifySignature FakeVerify
#define BCryptDestroyKey FakeDestroy
#define BCryptCloseAlgorithmProvider FakeCloseAlgorithm
#include "../../WindowsHello.cpp"

int main() {
  using thunderbird::hello::AuthenticateStartup;
  CHECK(AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 1 && state.verifyCalls == 1);
  CHECK(state.createCalls == 0 && state.freeCalls == 2);

  for (auto missing : {NTE_BAD_KEYSET, NTE_NO_KEY}) {
    state = {};
    state.openStatus = missing;
    CHECK(AuthenticateStartup().Succeeded());
    CHECK(state.createCalls == 1 && state.signCalls == 1);
  }
  for (auto status : {NTE_USER_CANCELLED, NTE_NOT_SUPPORTED, NTE_PERM}) {
    state = {};
    state.openStatus = status;
    CHECK(!AuthenticateStartup().Succeeded());
    CHECK(state.createCalls == 0 && state.signCalls == 0);
    state = {};
    state.signStatus = status;
    CHECK(!AuthenticateStartup().Succeeded());
    CHECK(state.verifyCalls == 0 && state.freeCalls == 2);
  }
  for (auto policy : {NCRYPT_LENGTH_PROPERTY, NCRYPT_KEY_USAGE_PROPERTY,
                      NCRYPT_EXPORT_POLICY_PROPERTY, L"NgcCacheType"}) {
    state = {};
    state.badPolicy = policy;
    CHECK(!AuthenticateStartup().Succeeded());
    CHECK(state.signCalls == 0);
  }
  for (auto property :
       {L"PinCacheIsGestureRequired", NCRYPT_USE_CONTEXT_PROPERTY}) {
    state = {};
    state.failedSet = property;
    CHECK(!AuthenticateStartup().Succeeded());
    CHECK(state.signCalls == 0);
  }
  state = {};
  state.providerStatus = NTE_NOT_SUPPORTED;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0 && state.freeCalls == 0);
  state = {};
  state.openStatus = NTE_NO_KEY;
  state.createStatus = NTE_USER_CANCELLED;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0 && state.freeCalls == 1);
  state = {};
  state.openStatus = NTE_NO_KEY;
  state.finalizeStatus = NTE_USER_CANCELLED;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0 && state.freeCalls == 2);
  state = {};
  state.openStatus = NTE_NO_KEY;
  state.failedSet = L"NgcCacheType";
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0);
  state = {};
  state.shortPolicy = true;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0);
  state = {};
  state.getStatus = NTE_NOT_SUPPORTED;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0);
  state = {};
  state.randomStatus = static_cast<NTSTATUS>(0xC0000001L);
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.signCalls == 0);
  state = {};
  state.shortSignature = true;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.verifyCalls == 0);
  state = {};
  state.verifyStatus = NTE_BAD_SIGNATURE;
  CHECK(!AuthenticateStartup().Succeeded());
  state = {};
  state.exportStatus = NTE_NOT_SUPPORTED;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.verifyCalls == 0);
  state = {};
  state.shortPublicKey = true;
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.verifyCalls == 0);
  state = {};
  state.algorithmStatus = static_cast<NTSTATUS>(0xC0000001L);
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.verifyCalls == 0);
  state = {};
  state.importStatus = static_cast<NTSTATUS>(0xC0000001L);
  CHECK(!AuthenticateStartup().Succeeded());
  CHECK(state.verifyCalls == 0);
  std::puts("Windows Hello startup: 28 scenarios passed (mock OS boundary).");

  using thunderbird::hello::UnlockVaultSecret;
  const thunderbird::hello::VaultId protector{};
  const std::vector<BYTE> envelope(512, 0xC3);
  thunderbird::vault::SecretKey secret;
  state = {};
  state.vault = true;
  CHECK(UnlockVaultSecret(protector, envelope, secret).Succeeded());
  CHECK(state.decryptCalls == 1 && secret.IsValid() &&
        secret.Bytes()[0] == 0x5A);
  CHECK(state.deleteCalls == 0);

  state = {};
  state.vault = true;
  state.verifyStatus = NTE_BAD_SIGNATURE;
  CHECK(!UnlockVaultSecret(protector, envelope, secret).Succeeded());
  CHECK(state.decryptCalls == 0 && !secret.IsValid());
  state = {};
  state.vault = true;
  state.failedSet = L"PinCacheIsGestureRequired";
  CHECK(!UnlockVaultSecret(protector, envelope, secret).Succeeded());
  CHECK(state.decryptCalls == 0 && !secret.IsValid());
  state = {};
  state.vault = true;
  state.badPolicy = NCRYPT_EXPORT_POLICY_PROPERTY;
  CHECK(!UnlockVaultSecret(protector, envelope, secret).Succeeded());
  CHECK(state.verifyCalls == 0 && state.decryptCalls == 0 && !secret.IsValid());
  state = {};
  state.vault = true;
  state.decryptStatus = NTE_USER_CANCELLED;
  CHECK(UnlockVaultSecret(protector, envelope, secret).status ==
        NTE_USER_CANCELLED);
  CHECK(state.decryptCalls == 1 && !secret.IsValid());
  state = {};
  state.vault = true;
  state.decryptedSize = 31;
  CHECK(!UnlockVaultSecret(protector, envelope, secret).Succeeded());
  CHECK(state.decryptCalls == 1 && !secret.IsValid());
  std::puts(
      "Vault unlock: verified signature, policy, gesture, cancellation "
      "and secret length.");

  using thunderbird::hello::CreateVaultProtector;
  using thunderbird::hello::PendingVaultProtector;
  const std::array<BYTE, 32> syntheticSecret{};
  CHECK(secret.Import(syntheticSecret.data(), syntheticSecret.size()));
  std::vector<BYTE> wrapped;
  for (bool committed : {false, true}) {
    state = {};
    state.vault = true;
    {
      PendingVaultProtector pending;
      CHECK(CreateVaultProtector(protector, secret, wrapped, pending)
                .Succeeded());
      CHECK(wrapped.size() == 512 && state.deleteCalls == 0);
      if (committed) pending.Commit();
    }
    CHECK(state.deleteCalls == (committed ? 0 : 1));
    CHECK(state.freeCalls == (committed ? 2 : 1));
  }

  for (auto failure : {&Scenario::finalizeStatus, &Scenario::exportStatus,
                       &Scenario::signStatus}) {
    state = {};
    state.vault = true;
    state.*failure = NTE_USER_CANCELLED;
    {
      PendingVaultProtector pending;
      CHECK(CreateVaultProtector(protector, secret, wrapped, pending).status ==
            NTE_USER_CANCELLED);
    }
    CHECK(wrapped.empty() && state.deleteCalls == 1 && state.freeCalls == 1);
  }

  state = {};
  state.vault = true;
  state.createStatus = NTE_EXISTS;
  {
    PendingVaultProtector pending;
    CHECK(CreateVaultProtector(protector, secret, wrapped, pending).status ==
          NTE_EXISTS);
  }
  CHECK(state.deleteCalls == 0 && state.freeCalls == 1);
  state = {};
  state.vault = true;
  state.deleteStatus = NTE_PERM;
  {
    PendingVaultProtector pending;
    CHECK(
        CreateVaultProtector(protector, secret, wrapped, pending).Succeeded());
  }
  CHECK(state.deleteCalls == 1 && state.freeCalls == 2);
  std::puts(
      "Vault protector transaction: enrollment, commit and rollback passed.");
}
