/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../../mail/app/WindowsHello.h"

#include <cstdio>
#include <cstring>

int main(int argc, char* argv[]) {
  if (argc != 2 || std::strcmp(argv[1], "--authenticate") != 0) {
    std::puts(
        "Usage: HelloProbe.exe --authenticate\n"
        "Enrolls/opens the app's startup key and requests Windows Hello.\n"
        "Complete the Windows dialog yourself. No mail profile is opened.");
    return 2;
  }
  const auto result = thunderbird::hello::AuthenticateStartup();
  std::printf("%s: 0x%08lX\n", result.operation,
              static_cast<unsigned long>(result.status));
  return result.Succeeded() ? 0 : 1;
}
