/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <windows.h>
#include <array>
#include <cstdio>
#include <cstring>

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 2 && wcscmp(argv[1], L"--timeout") == 0) {
    Sleep(30000);
    return 1;
  }
  if (argc != 4 || wcscmp(argv[1], L"--pipe-test") != 0 ||
      wcscmp(argv[2], L"quoted \"argument\" with trailing slash\\") != 0 ||
      wcscmp(argv[3], L"Unicode-é-你好") != 0)
    return 3;
  std::array<char, 65> input{};
  DWORD read = 0;
  if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), input.data(), input.size(),
                &read, nullptr) ||
      read != input.size() || input.back() != '\n')
    return 4;
  for (size_t i = 0; i < 64; i += 2) {
    if (input[i] != '5' || input[i + 1] != 'a') return 5;
  }
  // The test fixture is known, and must only appear on stdin, not in the PEB.
  if (wcsstr(GetCommandLineW(), L"5a5a5a5a5a5a5a5a")) return 6;
  SecureZeroMemory(input.data(), input.size());
  std::puts("The parent must drain this output without persisting it.");
  return 0;
}
