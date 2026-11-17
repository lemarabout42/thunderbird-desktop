/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../VaultSupport.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
      std::exit(1);                                                     \
    }                                                                   \
  } while (false)

int wmain(int argc, wchar_t* argv[]) {
  using namespace thunderbird::vault;
  CHECK(argc == 2);
  Envelope envelope;
  for (size_t i = 0; i < 16; ++i) {
    envelope.vaultId[i] = static_cast<BYTE>(i);
    envelope.protectorId[i] = static_cast<BYTE>(i + 16);
  }
  envelope.wrapped.resize(512, 0xC3);
  const auto encoded = EncodeEnvelope(envelope);
  Envelope decoded;
  CHECK(DecodeEnvelope(encoded, decoded));
  CHECK(decoded.vaultId == envelope.vaultId);
  CHECK(decoded.protectorId == envelope.protectorId);
  CHECK(decoded.wrapped == envelope.wrapped);
  for (size_t length = 0; length < encoded.size(); ++length)
    CHECK(!DecodeEnvelope(
        std::vector<BYTE>(encoded.begin(), encoded.begin() + length), decoded));
  auto bad = encoded;
  bad.push_back(0);
  CHECK(!DecodeEnvelope(bad, decoded));
  for (size_t i = 0; i < 8; ++i) {
    bad = encoded;
    bad[i] ^= 1;
    CHECK(!DecodeEnvelope(bad, decoded));
  }
  SecretKey key, recovered;
  std::array<BYTE, 32> fixture{};
  fixture.fill(0x5A);
  CHECK(key.Import(fixture.data(), fixture.size()));
  auto recovery = EncodeRecovery(envelope.vaultId, key);
  std::vector<BYTE> bytes(recovery.begin(), recovery.end());
  CHECK(DecodeRecovery(bytes, envelope.vaultId, recovered));
  CHECK(recovered.Bytes() == key.Bytes());
  thunderbird::hello::VaultId id{};
  CHECK(DecodeRecoveryDocument(bytes, id, recovered));
  CHECK(id == envelope.vaultId);
  id[0] ^= 1;
  CHECK(!DecodeRecovery(bytes, id, recovered));
  CHECK(!recovered.IsValid());
  for (size_t length = 0; length < bytes.size(); ++length) {
    CHECK(!DecodeRecovery(
        std::vector<BYTE>(bytes.begin(), bytes.begin() + length),
        envelope.vaultId, recovered));
    CHECK(!recovered.IsValid());
  }
  bad = bytes;
  bad[bad.size() - 2] = 'x';
  CHECK(!DecodeRecovery(bad, envelope.vaultId, recovered));
  CHECK(!recovered.IsValid());
  SecureZeroMemory(recovery.data(), recovery.size());
  SecureZeroMemory(bytes.data(), bytes.size());
  for (const char* flag : {"-profile", "--profile=x", "/P", "--APP",
                           "-xpcshell", "--reset-profile", "-backgroundtask"})
    CHECK(IsProfileOverride(flag));
  for (const char* argument :
       {"-offline", "mailto:test@example.invalid", "-mail", ""})
    CHECK(!IsProfileOverride(argument));
  CHECK(
      RunCommand(argv[1],
                 {L"--pipe-test", L"quoted \"argument\" with trailing slash\\",
                  L"Unicode-é-你好"},
                 &key) == 0);
  CHECK(RunCommand(argv[1], {L"--timeout"}, nullptr, 100) == ERROR_TIMEOUT);
  CHECK(RunCommand(L"Z:\\missing-program.exe", {}) != 0);
  std::puts(
      "Vault format/recovery parsing, profile override rejection, Windows "
      "quoting/Unicode, secret stdin transfer, timeouts and failures passed.");
}
