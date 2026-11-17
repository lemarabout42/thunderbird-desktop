/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mail_app_hello_VaultSupport_h
#define mail_app_hello_VaultSupport_h

#include <windows.h>

#include <array>
#include <string>
#include <vector>

#include "../WindowsHello.h"

namespace thunderbird::vault {

class Handle {
 public:
  Handle() = default;
  explicit Handle(HANDLE value) : value(value) {}
  ~Handle() { Reset(); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  void Reset(HANDLE next = nullptr) {
    if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value);
    value = next;
  }
  HANDLE value = nullptr;
};

struct Envelope {
  hello::VaultId vaultId{};
  hello::VaultId protectorId{};
  std::vector<BYTE> wrapped;
};

// v2 signs the wrapped ciphertext as well as encrypting the random secret.
// Unsigned prototype envelopes are rejected.
std::vector<BYTE> EncodeEnvelope(const Envelope& envelope);
bool DecodeEnvelope(const std::vector<BYTE>& bytes, Envelope& envelope);
std::string Hex(const BYTE* bytes, size_t length);
bool ParseHex(const std::string& text, BYTE* bytes, size_t length);
std::string EncodeRecovery(const hello::VaultId& id, const SecretKey& secret);
bool DecodeRecovery(const std::vector<BYTE>& bytes, const hello::VaultId& id,
                    SecretKey& secret);
bool DecodeRecoveryDocument(const std::vector<BYTE>& bytes, hello::VaultId& id,
                            SecretKey& secret);
std::wstring QuoteArgument(const std::wstring& value);
bool IsProfileOverride(const char* argument);

bool ReadSmallFile(const std::wstring& path, size_t limit,
                   std::vector<BYTE>& bytes);
bool WriteNewFile(const std::wstring& path, const BYTE* bytes, size_t size);
bool VerifySha256(const std::wstring& path, const char* expected);
bool PrivateDirectory(const std::wstring& path);

// Launches an explicit executable. The secret is inherited only through stdin,
// never argv/environment/temp files. Output is drained and discarded, since a
// third-party error message must not accidentally expose key material.
DWORD RunCommand(const std::wstring& executable,
                 const std::vector<std::wstring>& arguments,
                 const SecretKey* secret = nullptr, DWORD timeoutMs = 60000);
bool StartOwnedEngine(const std::wstring& executable, Handle& job,
                      Handle& process);

}  // namespace thunderbird::vault

#endif
