/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mail_app_hello_EncryptedBlob_h
#define mail_app_hello_EncryptedBlob_h

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace thunderbird::vault {

// Experimental, bounded object format; not a live Thunderbird storage backend.
constexpr size_t kMaxPlaintextSize = 64 * 1024 * 1024;
constexpr size_t kHeaderSize = 28;
constexpr size_t kTagSize = 16;

enum class Error { Ok, InvalidInput, InvalidFormat, CryptoFailure };

class SecretKey {
 public:
  SecretKey() = default;
  ~SecretKey() { Clear(); }
  SecretKey(const SecretKey&) = delete;
  SecretKey& operator=(const SecretKey&) = delete;

  bool Generate();
  bool Import(const uint8_t* bytes, size_t length);
  void Clear();
  bool IsValid() const { return mValid; }
  const std::array<uint8_t, 32>& Bytes() const { return mBytes; }

 private:
  std::array<uint8_t, 32> mBytes{};
  bool mValid = false;
};

// Owns decrypted bytes and wipes them on failure, reuse, and destruction.
class Plaintext {
 public:
  Plaintext() = default;
  ~Plaintext() { Clear(); }
  Plaintext(const Plaintext&) = delete;
  Plaintext& operator=(const Plaintext&) = delete;

  const std::vector<uint8_t>& Bytes() const { return mBytes; }
  void Clear();

 private:
  friend Error Decrypt(const SecretKey&, const std::vector<uint8_t>&,
                       const std::vector<uint8_t>&, Plaintext&);
  std::vector<uint8_t> mBytes;
};

// Context is mandatory authenticated data chosen by the caller, e.g. a profile
// UUID, object UUID, and generation. It is not stored in the encrypted blob.
// These functions never write a file or serialize a key.
Error Encrypt(const SecretKey& key, const uint8_t* bytes, size_t length,
              const std::vector<uint8_t>& context,
              std::vector<uint8_t>& encrypted);
Error Decrypt(const SecretKey& key, const std::vector<uint8_t>& encrypted,
              const std::vector<uint8_t>& context, Plaintext& plaintext);

}  // namespace thunderbird::vault

#endif  // mail_app_hello_EncryptedBlob_h
