/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mail_app_WindowsHello_h
#define mail_app_WindowsHello_h

#include <windows.h>

#include <array>
#include <vector>

#include "hello/EncryptedBlob.h"

namespace thunderbird::hello {

struct Result {
  LONG status;
  const char* operation;
  bool Succeeded() const { return status == ERROR_SUCCESS; }
};

// Runs before XPCOM/profile startup, in the parent process only. Cancellation,
// unsupported providers, and policy failures all deny startup.
Result AuthenticateStartup();

using VaultId = std::array<BYTE, 16>;

// A vault protector is separate from the replaceable startup signing key.
// Creation never overwrites a persisted key. Unlock never creates a missing
// key. The ciphertext is signed to prevent substitution through public-key
// encryption; its signature is checked before every private decryption.
Result CreateVaultProtector(const VaultId& id, const vault::SecretKey& secret,
                            std::vector<BYTE>& wrapped);
Result UnlockVaultSecret(const VaultId& id, const std::vector<BYTE>& wrapped,
                         vault::SecretKey& secret, bool silentProbe = false);

}  // namespace thunderbird::hello

#endif  // mail_app_WindowsHello_h
