/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mail_app_WindowsHello_h
#define mail_app_WindowsHello_h

#include <windows.h>

namespace thunderbird::hello {

struct Result {
  LONG status;
  const char* operation;
  bool Succeeded() const { return status == ERROR_SUCCESS; }
};

// Runs before XPCOM/profile startup, in the parent process only. Cancellation,
// unsupported providers, and policy failures all deny startup.
Result AuthenticateStartup();

}  // namespace thunderbird::hello

#endif  // mail_app_WindowsHello_h
