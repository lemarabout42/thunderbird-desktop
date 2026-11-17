/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../EncryptedBlob.h"

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

std::vector<uint8_t> FromHex(const char* text) {
  std::vector<uint8_t> result;
  const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
  for (; *text; text += 2) {
    CHECK(text[1]);
    result.push_back(
        static_cast<uint8_t>(digit(text[0]) * 16 + digit(text[1])));
  }
  return result;
}

int main() {
  using namespace thunderbird::vault;
  SecretKey key;
  SecretKey other;
  CHECK(key.Generate() && other.Generate());
  const std::vector<uint8_t> context{'p', 'r', 'o', 'f', 'i', 'l', 'e', '1'};
  const std::vector<uint8_t> message{
      'S',  'u',  'b',  'j',  'e', 'c', 't', ':', ' ', 'T', 'e', 's', 't',
      '\r', '\n', '\r', '\n', 'S', 'e', 'c', 'r', 'e', 't', 0,   0xFF};
  std::vector<uint8_t> encrypted;
  std::vector<uint8_t> second;
  Plaintext plaintext;
  // Independent known-answer fixture generated with Node/OpenSSL AES-256-GCM:
  // zero key/nonce/plaintext, 16-byte body, AAD = header || LE32(14) ||
  // context.
  SecretKey knownKey;
  const std::array<uint8_t, 32> zero{};
  CHECK(knownKey.Import(zero.data(), zero.size()));
  const auto knownContext = FromHex("6b6e6f776e2d616e737765722d7631");
  const auto knownBlob = FromHex(
      "54425641554c54010000000000000000000000001000000000000000"
      "fb11dad9cea89c4bebf97d10c8d090fa"
      "cea7403d4d606b6e074ec5d3baf39d18");
  CHECK(Decrypt(knownKey, knownBlob, knownContext, plaintext) == Error::Ok);
  CHECK(plaintext.Bytes() == std::vector<uint8_t>(16, 0));
  CHECK(knownKey.Import(knownKey.Bytes().data(), knownKey.Bytes().size()));
  CHECK(Decrypt(knownKey, knownBlob, knownContext, plaintext) == Error::Ok);
  CHECK(Encrypt(key, message.data(), message.size(), context, encrypted) ==
        Error::Ok);
  CHECK(Encrypt(key, message.data(), message.size(), context, second) ==
        Error::Ok);
  CHECK(encrypted != second);  // Independent nonces for repeated writes.
  CHECK(Decrypt(key, encrypted, context, plaintext) == Error::Ok);
  CHECK(plaintext.Bytes() == message);
  auto inPlace = message;
  CHECK(Encrypt(key, inPlace.data(), inPlace.size(), context, inPlace) ==
        Error::Ok);
  CHECK(Decrypt(key, inPlace, context, plaintext) == Error::Ok);
  CHECK(plaintext.Bytes() == message);
  CHECK(Decrypt(other, encrypted, context, plaintext) != Error::Ok);
  CHECK(plaintext.Bytes().empty());
  CHECK(Decrypt(key, encrypted, context, plaintext) == Error::Ok);
  auto wrongContext = context;
  wrongContext.push_back('2');
  CHECK(Decrypt(key, encrypted, wrongContext, plaintext) != Error::Ok);
  CHECK(plaintext.Bytes().empty());

  // Every byte belongs to a validated header or authenticated nonce/tag/body.
  for (size_t i = 0; i < encrypted.size(); ++i) {
    auto modified = encrypted;
    modified[i] ^= 1;
    CHECK(Decrypt(key, modified, context, plaintext) != Error::Ok);
    CHECK(plaintext.Bytes().empty());
  }
  for (size_t i = 0; i < encrypted.size(); ++i) {
    const std::vector<uint8_t> truncated(encrypted.begin(),
                                         encrypted.begin() + i);
    CHECK(Decrypt(key, truncated, context, plaintext) != Error::Ok);
    CHECK(plaintext.Bytes().empty());
  }
  auto appended = encrypted;
  appended.push_back(0);
  CHECK(Decrypt(key, appended, context, plaintext) == Error::InvalidFormat);
  auto invalidLength = encrypted;
  std::fill(invalidLength.begin() + 20, invalidLength.begin() + 28,
            uint8_t{0xFF});
  CHECK(Decrypt(key, invalidLength, context, plaintext) ==
        Error::InvalidFormat);

  CHECK(Encrypt(key, nullptr, 0, context, second) == Error::Ok);
  CHECK(Decrypt(key, second, context, plaintext) == Error::Ok);
  CHECK(plaintext.Bytes().empty());
  CHECK(Encrypt(key, nullptr, 10, context, second) == Error::InvalidInput);
  CHECK(second.empty());
  CHECK(Encrypt(key, message.data(), message.size(), {}, second) ==
        Error::InvalidInput);
  CHECK(Encrypt(key, message.data(), kMaxPlaintextSize + 1, context, second) ==
        Error::InvalidInput);
  CHECK(Decrypt(key, encrypted, {}, plaintext) == Error::InvalidInput);
  CHECK(plaintext.Bytes().empty());
  key.Clear();
  CHECK(!key.IsValid());
  CHECK(std::all_of(key.Bytes().begin(), key.Bytes().end(),
                    [](uint8_t byte) { return byte == 0; }));
  CHECK(Decrypt(key, encrypted, context, plaintext) == Error::InvalidInput);
  CHECK(Encrypt(key, message.data(), message.size(), context, second) ==
        Error::InvalidInput);
  CHECK(!key.Import(message.data(), message.size()));
  CHECK(!key.Import(nullptr, 32));
  std::puts(
      "AES-256-GCM: independent known-answer fixture, aliasing, round "
      "trips, binary/empty data, nonce freshness, every "
      "byte tampered, every truncation, wrong key/context, bounds, wiping "
      "and invalid state passed (real Windows CNG).");
}
