/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WindowsHello.h"

#include <bcrypt.h>
#include <ncrypt.h>
#include <sddl.h>

#include <algorithm>
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

Result KeyName(std::wstring& name, const std::wstring& label = L"Startup-v1") {
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
  name += L"//ThunderbirdHello//" + label;
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

Result OpenVaultKey(const VaultId& id, bool create, CngHandle& provider,
                    CngHandle& key) {
  std::wstring label = L"Vault-v2-";
  constexpr wchar_t digits[] = L"0123456789abcdef";
  for (BYTE byte : id) {
    label += digits[byte >> 4];
    label += digits[byte & 15];
  }
  std::wstring name;
  auto result = KeyName(name, label);
  if (!result.Succeeded()) return result;
  auto status =
      NCryptOpenStorageProvider(&provider.value, kPassportProvider, 0);
  if (status != 0) return {status, "Open vault Passport provider"};
  if (create) {
    status = NCryptCreatePersistedKey(provider.value, &key.value,
                                      BCRYPT_RSA_ALGORITHM, name.c_str(), 0, 0);
  } else {
    status = NCryptOpenKey(provider.value, &key.value, name.c_str(), 0, 0);
  }
  if (status != 0) return {status, "Open vault protector"};
  for (const auto& setting :
       {std::pair{NCRYPT_LENGTH_PROPERTY, kRsaBits},
        std::pair{NCRYPT_KEY_USAGE_PROPERTY,
                  DWORD{NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG}},
        std::pair{NCRYPT_EXPORT_POLICY_PROPERTY, DWORD{0}},
        std::pair{static_cast<const wchar_t*>(kCachePolicy),
                  kAuthenticationMandatory}}) {
    result = create ? SetDword(key.value, setting.first, setting.second)
                    : RequireDword(key.value, setting.first, setting.second);
    if (!result.Succeeded()) return result;
  }
  if (create) {
    constexpr wchar_t message[] =
        L"Create the encrypted Thunderbird test profile";
    status = NCryptSetProperty(
        key.value, NCRYPT_USE_CONTEXT_PROPERTY,
        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(message)), sizeof(message),
        0);
    if (status != 0) return {status, "Set vault enrollment context"};
    status = NCryptFinalizeKey(key.value, 0);
    if (status != 0) return {status, "Enroll vault protector"};
    for (const auto& setting :
         {std::pair{NCRYPT_LENGTH_PROPERTY, kRsaBits},
          std::pair{
              NCRYPT_KEY_USAGE_PROPERTY,
              DWORD{NCRYPT_ALLOW_DECRYPT_FLAG | NCRYPT_ALLOW_SIGNING_FLAG}},
          std::pair{NCRYPT_EXPORT_POLICY_PROPERTY, DWORD{0}},
          std::pair{static_cast<const wchar_t*>(kCachePolicy),
                    kAuthenticationMandatory}}) {
      result = RequireDword(key.value, setting.first, setting.second);
      if (!result.Succeeded()) return result;
    }
  }
  return {ERROR_SUCCESS, "Vault protector policy"};
}

Result VaultDigest(const VaultId& id, const std::vector<BYTE>& wrapped,
                   std::array<BYTE, 32>& digest) {
  constexpr char domain[] = "ThunderbirdHelloVaultWrap-v2-RSA2048-PKCS1";
  if (wrapped.size() < 256)
    return {NTE_BAD_DATA, "Invalid vault wrapping input"};
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  NTSTATUS status = BCryptOpenAlgorithmProvider(
      &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status != 0) return {status, "Open vault envelope digest"};
  BCRYPT_HASH_HANDLE hash = nullptr;
  status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
  if (status == 0)
    status = BCryptHashData(hash,
                            reinterpret_cast<PUCHAR>(const_cast<char*>(domain)),
                            sizeof(domain), 0);
  if (status == 0)
    status = BCryptHashData(hash, const_cast<PUCHAR>(id.data()),
                            static_cast<ULONG>(id.size()), 0);
  if (status == 0)
    status = BCryptHashData(hash, const_cast<PUCHAR>(wrapped.data()), 256, 0);
  if (status == 0)
    status = BCryptFinishHash(hash, digest.data(),
                              static_cast<ULONG>(digest.size()), 0);
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return {status, "Hash versioned vault key envelope"};
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

Result CreateVaultProtector(const VaultId& id, const vault::SecretKey& secret,
                            std::vector<BYTE>& wrapped) {
  wrapped.clear();
  if (!secret.IsValid()) return {NTE_BAD_DATA, "Invalid vault secret"};
  CngHandle provider;
  CngHandle key;
  auto result = OpenVaultKey(id, true, provider, key);
  if (!result.Succeeded()) return result;
  std::array<BYTE, 1024> publicBlob{};
  DWORD size = 0;
  auto status = NCryptExportKey(
      key.value, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, publicBlob.data(),
      static_cast<DWORD>(publicBlob.size()), &size, NCRYPT_SILENT_FLAG);
  if (status != 0 || size > publicBlob.size() ||
      size < sizeof(BCRYPT_RSAKEY_BLOB))
    return {status ? status : NTE_BAD_DATA, "Export vault public key"};
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  auto crypto =
      BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
  if (crypto != 0) return {crypto, "Open vault RSA wrapping provider"};
  BCRYPT_KEY_HANDLE publicKey = nullptr;
  crypto = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_RSAPUBLIC_BLOB,
                               &publicKey, publicBlob.data(), size, 0);
  if (crypto == 0) {
    // The Passport provider on supported Windows 10 devices accepts PKCS#1
    // v1.5 decryption, but can reject OAEP. This is a versioned, local wrapping
    // operation for a uniformly random 256-bit secret, never an exposed
    // decryption service. Every private attempt requires a fresh Hello gesture.
    wrapped.resize(kRsaBits / 8);
    ULONG written = 0;
    crypto = BCryptEncrypt(publicKey, const_cast<PUCHAR>(secret.Bytes().data()),
                           32, nullptr, nullptr, 0, wrapped.data(),
                           static_cast<ULONG>(wrapped.size()), &written,
                           BCRYPT_PAD_PKCS1);
    if (crypto == 0 && written != wrapped.size()) crypto = NTE_BAD_DATA;
    BCryptDestroyKey(publicKey);
  }
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (crypto != 0) {
    wrapped.clear();
    return {crypto, "Wrap vault secret with RSA-2048-PKCS1"};
  }
  std::array<BYTE, 32> digest{};
  result = VaultDigest(id, wrapped, digest);
  if (result.Succeeded()) result = SetDword(key.value, kRequireGesture, 1);
  if (!result.Succeeded()) {
    wrapped.clear();
    return result;
  }
  // Public encryption cannot prove who chose a storage key. Authenticate the
  // ciphertext with the trusted Passport object, then verify that signature
  // before any later private decryption. This prevents key substitution.
  wrapped.resize(512);
  DWORD signedSize = 0;
  BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
  status = NCryptSignHash(
      key.value, &padding, digest.data(), static_cast<DWORD>(digest.size()),
      wrapped.data() + 256, 256, &signedSize, NCRYPT_PAD_PKCS1_FLAG);
  SecureZeroMemory(digest.data(), digest.size());
  if (status == 0 && signedSize != 256) status = NTE_BAD_SIGNATURE;
  if (status != 0) wrapped.clear();
  return {status, "Authorize signed vault key envelope"};
}

Result UnlockVaultSecret(const VaultId& id, const std::vector<BYTE>& wrapped,
                         vault::SecretKey& secret, bool silentProbe) {
  secret.Clear();
  if (wrapped.size() != 512) return {NTE_BAD_DATA, "Invalid vault envelope"};
  CngHandle provider;
  CngHandle key;
  auto result = OpenVaultKey(id, false, provider, key);
  if (!result.Succeeded()) return result;
  std::array<BYTE, 32> digest{};
  result = VaultDigest(id, wrapped, digest);
  if (!result.Succeeded()) return result;
  std::array<BYTE, 256> signature{};
  std::copy_n(wrapped.begin() + 256, signature.size(), signature.begin());
  result = VerifyChallenge(key.value, digest, signature);
  SecureZeroMemory(digest.data(), digest.size());
  if (!result.Succeeded()) return result;
  constexpr wchar_t message[] = L"Unlock the encrypted Thunderbird profile";
  auto status =
      NCryptSetProperty(key.value, NCRYPT_USE_CONTEXT_PROPERTY,
                        reinterpret_cast<PBYTE>(const_cast<wchar_t*>(message)),
                        sizeof(message), 0);
  if (status != 0) return {status, "Set vault unlock context"};
  result = SetDword(key.value, kRequireGesture, 1);
  if (!result.Succeeded()) return result;
  std::array<BYTE, kRsaBits / 8> plaintext{};
  DWORD written = 0;
  status = NCryptDecrypt(
      key.value, const_cast<PBYTE>(wrapped.data()), 256, nullptr,
      plaintext.data(), static_cast<DWORD>(plaintext.size()), &written,
      NCRYPT_PAD_PKCS1_FLAG | (silentProbe ? NCRYPT_SILENT_FLAG : 0));
  if (status == 0 && (written != 32 || !secret.Import(plaintext.data(), 32)))
    status = NTE_BAD_DATA;
  SecureZeroMemory(plaintext.data(), plaintext.size());
  return {status, "Unlock vault secret with Windows Hello"};
}

}  // namespace thunderbird::hello
