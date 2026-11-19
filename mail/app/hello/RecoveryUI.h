/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#ifndef mail_app_hello_RecoveryUI_h
#define mail_app_hello_RecoveryUI_h

#include "EncryptedBlob.h"

namespace thunderbird::vault {
// The code is shown to the user, never automatically saved on the same PC.
bool ConfirmRecoveryCode(const SecretKey& secret);
bool EnterRecoveryCode(SecretKey& secret);
}  // namespace thunderbird::vault

#endif
