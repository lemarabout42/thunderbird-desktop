/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "EncryptedBlob.h"

#include <bcrypt.h>

#include <algorithm>
#include <cstring>

namespace thunderbird::vault {
namespace {

constexpr std::array<uint8_t, 8> kMagic{'T', 'B', 'V', 'A', 'U', 'L', 'T', 1};
constexpr size_t kNonceOffset = kMagic.size();
constexpr size_t kNonceSize = 12;
constexpr size_t kLengthOffset = kNonceOffset + kNonceSize;
constexpr size_t kMaxContextSize = 4096;

class AesKey {
 public:
  ~AesKey() {
    if (mKey) {
      BCryptDestroyKey(mKey);
    }
    if (mAlgorithm) {
      BCryptCloseAlgorithmProvider(mAlgorithm, 0);
    }
  }
  AesKey() = default;
  AesKey(const AesKey&) = delete;
  AesKey& operator=(const AesKey&) = delete;

  bool Init(const SecretKey& secret) {
    if (BCryptOpenAlgorithmProvider(&mAlgorithm, BCRYPT_AES_ALGORITHM, nullptr,
                                    0) != 0) {
      return false;
    }
    if (BCryptSetProperty(mAlgorithm, BCRYPT_CHAINING_MODE,
                          reinterpret_cast<PUCHAR>(
                              const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
      return false;
    }
    return BCryptGenerateSymmetricKey(mAlgorithm, &mKey, nullptr, 0,
                                      const_cast<PUCHAR>(secret.Bytes().data()),
                                      static_cast<ULONG>(secret.Bytes().size()),
                                      0) == 0;
  }
  BCRYPT_KEY_HANDLE Get() const { return mKey; }

 private:
  BCRYPT_ALG_HANDLE mAlgorithm = nullptr;
  BCRYPT_KEY_HANDLE mKey = nullptr;
};

bool ValidContext(const std::vector<uint8_t>& context) {
  return !context.empty() && context.size() <= kMaxContextSize;
}

std::vector<uint8_t> AuthenticatedData(const std::vector<uint8_t>& encrypted,
                                       const std::vector<uint8_t>& context) {
  std::vector<uint8_t> aad(encrypted.begin(), encrypted.begin() + kHeaderSize);
  // Length-prefix the context for an unambiguous, versioned encoding.
  for (size_t i = 0; i < 4; ++i) {
    aad.push_back(static_cast<uint8_t>(context.size() >> (i * 8)));
  }
  aad.insert(aad.end(), context.begin(), context.end());
  return aad;
}

void InitAuth(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO& auth,
              std::vector<uint8_t>& header, std::vector<uint8_t>& aad) {
  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = header.data() + kNonceOffset;
  auth.cbNonce = kNonceSize;
  auth.pbAuthData = aad.data();
  auth.cbAuthData = static_cast<ULONG>(aad.size());
  auth.pbTag = header.data() + kHeaderSize;
  auth.cbTag = kTagSize;
}

}  // namespace

bool SecretKey::Generate() {
  Clear();
  mValid =
      BCryptGenRandom(nullptr, mBytes.data(), static_cast<ULONG>(mBytes.size()),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
  if (!mValid) {
    Clear();
  }
  return mValid;
}

bool SecretKey::Import(const uint8_t* bytes, size_t length) {
  if (!bytes || length != mBytes.size()) {
    Clear();
    return false;
  }
  std::array<uint8_t, 32> copy{};
  std::copy_n(bytes, copy.size(), copy.begin());
  Clear();
  mBytes = copy;
  SecureZeroMemory(copy.data(), copy.size());
  mValid = true;
  return true;
}

void SecretKey::Clear() {
  SecureZeroMemory(mBytes.data(), mBytes.size());
  mValid = false;
}

void Plaintext::Clear() {
  if (!mBytes.empty()) {
    SecureZeroMemory(mBytes.data(), mBytes.size());
    mBytes.clear();
  }
}

Error Encrypt(const SecretKey& key, const uint8_t* bytes, size_t length,
              const std::vector<uint8_t>& context,
              std::vector<uint8_t>& encrypted) {
  if (!key.IsValid() || !ValidContext(context) || length > kMaxPlaintextSize ||
      (!bytes && length)) {
    encrypted.clear();
    return Error::InvalidInput;
  }
  // Construct separately so input/context may refer to the output's old data.
  std::vector<uint8_t> blob(kHeaderSize + kTagSize + length);
  std::copy(kMagic.begin(), kMagic.end(), blob.begin());
  for (size_t i = 0; i < 8; ++i) {
    blob[kLengthOffset + i] =
        static_cast<uint8_t>(static_cast<uint64_t>(length) >> (i * 8));
  }
  if (BCryptGenRandom(nullptr, blob.data() + kNonceOffset, kNonceSize,
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    encrypted.clear();
    return Error::CryptoFailure;
  }
  AesKey aes;
  if (!aes.Init(key)) {
    encrypted.clear();
    return Error::CryptoFailure;
  }
  auto aad = AuthenticatedData(blob, context);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  InitAuth(auth, blob, aad);
  ULONG written = 0;
  // Keep non-null buffers for an empty message: a null output asks CNG for a
  // size query instead of performing authenticated encryption.
  uint8_t empty = 0;
  const NTSTATUS status =
      BCryptEncrypt(aes.Get(), length ? const_cast<PUCHAR>(bytes) : &empty,
                    static_cast<ULONG>(length), &auth, nullptr, 0,
                    length ? blob.data() + kHeaderSize + kTagSize : &empty,
                    static_cast<ULONG>(length), &written, 0);
  if (status != 0 || written != length) {
    encrypted.clear();
    return Error::CryptoFailure;
  }
  encrypted.swap(blob);
  return Error::Ok;
}

Error Decrypt(const SecretKey& key, const std::vector<uint8_t>& encrypted,
              const std::vector<uint8_t>& context, Plaintext& plaintext) {
  plaintext.Clear();
  if (!key.IsValid() || !ValidContext(context)) {
    return Error::InvalidInput;
  }
  if (encrypted.size() < kHeaderSize + kTagSize ||
      encrypted.size() > kHeaderSize + kTagSize + kMaxPlaintextSize ||
      !std::equal(kMagic.begin(), kMagic.end(), encrypted.begin())) {
    return Error::InvalidFormat;
  }
  uint64_t length = 0;
  for (size_t i = 0; i < 8; ++i) {
    length |= uint64_t{encrypted[kLengthOffset + i]} << (i * 8);
  }
  if (length != encrypted.size() - kHeaderSize - kTagSize) {
    return Error::InvalidFormat;
  }
  AesKey aes;
  if (!aes.Init(key)) {
    return Error::CryptoFailure;
  }
  // CNG takes mutable tag/nonce pointers; keep the caller's blob unchanged.
  std::vector<uint8_t> header(encrypted.begin(),
                              encrypted.begin() + kHeaderSize + kTagSize);
  auto aad = AuthenticatedData(encrypted, context);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  InitAuth(auth, header, aad);
  plaintext.mBytes.resize(static_cast<size_t>(length));
  uint8_t empty = 0;
  ULONG written = 0;
  const NTSTATUS status = BCryptDecrypt(
      aes.Get(),
      length ? const_cast<PUCHAR>(encrypted.data() + kHeaderSize + kTagSize)
             : &empty,
      static_cast<ULONG>(length), &auth, nullptr, 0,
      length ? plaintext.mBytes.data() : &empty, static_cast<ULONG>(length),
      &written, 0);
  if (status != 0 || written != length) {
    plaintext.Clear();
    return Error::CryptoFailure;
  }
  return Error::Ok;
}

}  // namespace thunderbird::vault
