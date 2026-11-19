/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <windows.h>

int wmain(int argc, wchar_t* argv[]) {
  if (argc == 2 && wcsncmp(argv[1], L"--info=", 7) == 0) {
    const std::wstring_view fixture(argv[1] + 7);
    std::wstring report =
        L"Mode:                  forward\r\n"
        L"Data Encryption:       AES256-GCM\r\n"
        L"Deny other sessions:   Yes\r\n";
    report += fixture == L"plain-names"
                  ? L"File Name Encryption:  none\r\n"
                  : L"File Name Encryption:  AES256-EME\r\n";
    if (fixture != L"missing") report += L"Deny services:         Yes\r\n";
    if (fixture == L"conflict") report += L"Deny services:         No\r\n";
    if (fixture == L"oversized") report.append(140000, L'x');
    const auto length = static_cast<DWORD>(report.size() * sizeof(wchar_t));
    DWORD written = 0;
    return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), report.data(), length,
                     &written, nullptr) &&
                   written == length
               ? 0
               : 1;
  }
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
  if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), input.data(),
                static_cast<DWORD>(input.size()), &read, nullptr) ||
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
