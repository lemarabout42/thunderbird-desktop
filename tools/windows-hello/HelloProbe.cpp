/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../../mail/app/WindowsHello.h"

#include <cstdio>
#include <cstring>
#include <bcrypt.h>

int main(int argc, char* argv[]) {
  if (argc == 2 && std::strcmp(argv[1], "--vault-roundtrip") == 0) {
    thunderbird::hello::VaultId id{};
    thunderbird::vault::SecretKey original;
    thunderbird::vault::SecretKey restored;
    std::vector<BYTE> wrapped;
    if (!original.Generate() ||
        BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
      return 1;
    auto result =
        thunderbird::hello::CreateVaultProtector(id, original, wrapped);
    std::printf("%s: 0x%08lX\n", result.operation,
                static_cast<unsigned long>(result.status));
    if (!result.Succeeded()) return 1;
    result = thunderbird::hello::UnlockVaultSecret(id, wrapped, restored);
    std::printf("%s: 0x%08lX\n", result.operation,
                static_cast<unsigned long>(result.status));
    if (!result.Succeeded() || original.Bytes() != restored.Bytes()) return 1;
    result = thunderbird::hello::UnlockVaultSecret(id, wrapped, restored, true);
    std::printf("Silent decryption: 0x%08lX (must be blocked)\n",
                static_cast<unsigned long>(result.status));
    if (result.status != NTE_SILENT_CONTEXT || restored.IsValid()) return 1;
    wrapped[0] ^= 1;
    result = thunderbird::hello::UnlockVaultSecret(id, wrapped, restored, true);
    std::printf("Modified envelope: rejected before decryption = %s\n",
                !result.Succeeded() && result.status != NTE_SILENT_CONTEXT &&
                        !restored.IsValid()
                    ? "yes"
                    : "no");
    return !result.Succeeded() && result.status != NTE_SILENT_CONTEXT &&
                   !restored.IsValid()
               ? 0
               : 1;
  }
  if (argc != 2 || std::strcmp(argv[1], "--authenticate") != 0) {
    std::puts(
        "Usage: HelloProbe.exe --authenticate | --vault-roundtrip\n"
        "Enrolls/opens the app's startup key and requests Windows Hello.\n"
        "Complete the Windows dialog yourself. No mail profile is opened.");
    return 2;
  }
  const auto result = thunderbird::hello::AuthenticateStartup();
  std::printf("%s: 0x%08lX\n", result.operation,
              static_cast<unsigned long>(result.status));
  return result.Succeeded() ? 0 : 1;
}
