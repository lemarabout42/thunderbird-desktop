/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WindowsHello.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <sddl.h>

#include <array>
#include <string>
#include <utility>
#include <vector>

namespace thunderbird::hello {
namespace {

// Passport-specific properties are not part of the documented CNG contract.
// Treat unavailable properties as an error; never substitute a software KSP or
// a successful consent dialog. See docs/windows-hello/README.md.
constexpr wchar_t kCachePolicy[] = L"NgcCacheType";
constexpr wchar_t kRequireGesture[] = L"PinCacheIsGestureRequired";
constexpr wchar_t kPassportProvider[] =
    L"Microsoft Passport Key Storage Provider";
constexpr DWORD kAuthenticationMandatory = 1;
constexpr DWORD kRsaBits = 2048;

class CngHandle {
 public:
  ~CngHandle() {
    if (value) {
      NCryptFreeObject(value);
    }
  }
  CngHandle() = default;
  CngHandle(const CngHandle&) = delete;
  CngHandle& operator=(const CngHandle&) = delete;
  NCRYPT_HANDLE value = 0;
};

Result SetDword(NCRYPT_KEY_HANDLE key, const wchar_t* property, DWORD value) {
  return {NCryptSetProperty(key, property, reinterpret_cast<PBYTE>(&value),
                            sizeof(value), 0),
          "NCryptSetProperty"};
}

Result RequireDword(NCRYPT_KEY_HANDLE key, const wchar_t* property,
                    DWORD expected) {
  DWORD value = 0;
  DWORD size = 0;
  const SECURITY_STATUS status = NCryptGetProperty(
      key, property, reinterpret_cast<PBYTE>(&value), sizeof(value), &size, 0);
  if (status != ERROR_SUCCESS) {
    return {status, "NCryptGetProperty"};
  }
  if (size != sizeof(value) || value != expected) {
    return {NTE_BAD_KEY_STATE, "Windows Hello key policy"};
  }
  return {ERROR_SUCCESS, "Windows Hello key policy"};
}

Result KeyName(std::wstring& name) {
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return {static_cast<LONG>(GetLastError()), "OpenProcessToken"};
  }
  DWORD size = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &size);
  if (!size || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    const LONG error = static_cast<LONG>(GetLastError());
    CloseHandle(token);
    return {error ? error : ERROR_INVALID_DATA, "GetTokenInformation"};
  }
  std::vector<BYTE> buffer(size);
  const BOOL read =
      GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
  const DWORD error = read ? ERROR_SUCCESS : GetLastError();
  CloseHandle(token);
  if (!read) {
    return {static_cast<LONG>(error), "GetTokenInformation"};
  }
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(
          reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &sid)) {
    return {static_cast<LONG>(GetLastError()), "ConvertSidToStringSidW"};
  }
  name = sid;
  LocalFree(sid);
  // Separate namespace from upstream Thunderbird and any future vault key.
  name += L"//ThunderbirdHello//Startup-v1";
  return {ERROR_SUCCESS, "Windows Hello key name"};
}

Result OpenStartupKey(CngHandle& provider, CngHandle& key) {
  SECURITY_STATUS status =
      NCryptOpenStorageProvider(&provider.value, kPassportProvider, 0);
  if (status != ERROR_SUCCESS) {
    return {status, "Open Microsoft Passport provider"};
  }
  std::wstring name;
  Result result = KeyName(name);
  if (!result.Succeeded()) {
    return result;
  }
  // A silent open can also suppress the later private-operation prompt on
  // Passport. This handle must allow UI; mandatory gesture policy is checked
  // below before it can be used.
  status = NCryptOpenKey(provider.value, &key.value, name.c_str(), 0, 0);
  if (status == NTE_BAD_KEYSET || status == NTE_NO_KEY) {
    // This key authenticates startup only. It never encrypts user data, so a
    // missing key can be enrolled again without risking data loss. Do not use
    // this recovery rule for a future vault key.
    status = NCryptCreatePersistedKey(provider.value, &key.value,
                                      BCRYPT_RSA_ALGORITHM, name.c_str(), 0, 0);
    if (status != ERROR_SUCCESS) {
      return {status, "Create Windows Hello startup key"};
    }
    for (const auto& setting :
         {std::pair{NCRYPT_LENGTH_PROPERTY, kRsaBits},
          std::pair{NCRYPT_KEY_USAGE_PROPERTY,
                    DWORD{NCRYPT_ALLOW_SIGNING_FLAG}},
          std::pair{NCRYPT_EXPORT_POLICY_PROPERTY, DWORD{0}},
          std::pair{static_cast<const wchar_t*>(kCachePolicy),
                    kAuthenticationMandatory}}) {
      result = SetDword(key.value, setting.first, setting.second);
      if (!result.Succeeded()) {
        return result;
      }
    }
    status = NCryptFinalizeKey(key.value, 0);
    if (status != ERROR_SUCCESS) {
      return {status, "Finalize Windows Hello startup key"};
    }
  } else if (status != ERROR_SUCCESS) {
    return {status, "Open Windows Hello startup key"};
  }

  // Check persisted policy on every open. In particular, accepting a key with
  // the import capability or cached authentication would weaken this boundary.
  for (const auto& setting :
       {std::pair{NCRYPT_LENGTH_PROPERTY, kRsaBits},
        std::pair{NCRYPT_KEY_USAGE_PROPERTY, DWORD{NCRYPT_ALLOW_SIGNING_FLAG}},
        std::pair{NCRYPT_EXPORT_POLICY_PROPERTY, DWORD{0}},
        std::pair{static_cast<const wchar_t*>(kCachePolicy),
                  kAuthenticationMandatory}}) {
    result = RequireDword(key.value, setting.first, setting.second);
    if (!result.Succeeded()) {
      return result;
    }
  }
  return {ERROR_SUCCESS, "Open Windows Hello startup key"};
}

Result VerifyChallenge(NCRYPT_KEY_HANDLE key, const std::array<BYTE, 32>& hash,
                       const std::array<BYTE, kRsaBits / 8>& signature) {
  // Passport performs the private operation, but does not implement public
  // signature verification on all supported Windows versions. Export only the
  // public key and verify with BCrypt; the private key remains non-exportable.
  std::array<BYTE, 1024> publicBlob{};
  DWORD written = 0;
  const SECURITY_STATUS exported = NCryptExportKey(
      key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, publicBlob.data(),
      static_cast<DWORD>(publicBlob.size()), &written, NCRYPT_SILENT_FLAG);
  if (exported != ERROR_SUCCESS) {
    return {exported, "Export Windows Hello public key"};
  }
  if (written < sizeof(BCRYPT_RSAKEY_BLOB) || written > publicBlob.size()) {
    return {NTE_BAD_DATA, "Windows Hello public key size"};
  }
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
  if (status != 0) {
    return {status, "Open RSA signature verifier"};
  }
  BCRYPT_KEY_HANDLE publicKey = nullptr;
  status = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                               &publicKey, publicBlob.data(), written, 0);
  if (status == 0) {
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    status = BCryptVerifySignature(
        publicKey, &padding, const_cast<PBYTE>(hash.data()),
        static_cast<ULONG>(hash.size()), const_cast<PBYTE>(signature.data()),
        static_cast<ULONG>(signature.size()), BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(publicKey);
  }
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return {status, "Verify Windows Hello startup challenge"};
}

}  // namespace

Result AuthenticateStartup() {
  CngHandle provider;
  CngHandle key;
  Result result = OpenStartupKey(provider, key);
  if (!result.Succeeded()) {
    return result;
  }

  constexpr wchar_t message[] = L"Unlock Thunderbird with Windows Hello";
  SECURITY_STATUS status =
      NCryptSetProperty(key.value, NCRYPT_USE_CONTEXT_PROPERTY,
                        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(message)),
                        sizeof(message), 0);
  if (status != ERROR_SUCCESS) {
    return {status, "Windows Hello prompt context"};
  }
  result = SetDword(key.value, kRequireGesture, 1);
  if (!result.Succeeded()) {
    return result;
  }

  // A new, unpredictable digest per process prevents replaying a previous
  // signature. No password, PIN, biometric sample, or reusable secret enters
  // Thunderbird. This signature must never be used as an encryption key.
  std::array<BYTE, 32> challenge{};
  const NTSTATUS randomStatus = BCryptGenRandom(
      nullptr, challenge.data(), static_cast<ULONG>(challenge.size()),
      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (randomStatus != 0) {
    return {randomStatus, "Generate Windows Hello challenge"};
  }
  std::array<BYTE, kRsaBits / 8> signature{};
  BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
  DWORD written = 0;
  status = NCryptSignHash(
      key.value, &padding, challenge.data(),
      static_cast<DWORD>(challenge.size()), signature.data(),
      static_cast<DWORD>(signature.size()), &written, NCRYPT_PAD_PKCS1_FLAG);
  if (status == ERROR_SUCCESS && written != signature.size()) {
    status = NTE_BAD_SIGNATURE;
  }
  result = status == ERROR_SUCCESS
               ? VerifyChallenge(key.value, challenge, signature)
               : Result{status, "Sign Windows Hello startup challenge"};
  SecureZeroMemory(challenge.data(), challenge.size());
  SecureZeroMemory(signature.data(), signature.size());
  return result;
}

}  // namespace thunderbird::hello
