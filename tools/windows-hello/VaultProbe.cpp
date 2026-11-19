/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "../../mail/app/hello/ProfileVault.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace {
bool ExerciseArguments(thunderbird::vault::ProfileVaultSession& session) {
  for (const wchar_t* name :
       {L"XRE_PROFILE_PATH", L"XRE_PROFILE_LOCAL_PATH", L"XUL_APP_FILE",
        L"selectable_profile_reset_path"}) {
    if (_wputenv_s(name, L"C:\\unprotected-dummy-path") != 0 ||
        !SetEnvironmentVariableW(name, L"C:\\unprotected-dummy-path"))
      return false;
  }
  char executable[] = "VaultProbe";
  char* initial[]{executable, nullptr};
  char** arguments = initial;
  int count = 1;
  if (!session.PrepareArguments(count, arguments) || count != 4 ||
      arguments[4] || std::strcmp(arguments[1], "-no-remote") != 0 ||
      std::strcmp(arguments[2], "-profile") != 0 ||
      std::strcmp(arguments[3], "Z:\\Profile") != 0)
    return false;
  for (const auto& entry :
       {std::pair{L"XRE_PROFILE_PATH", L"Z:\\Profile"},
        std::pair{L"XRE_PROFILE_LOCAL_PATH", L"Z:\\Profile"},
        std::pair{L"TEMP", L"Z:\\Temp"}, std::pair{L"TMP", L"Z:\\Temp"}}) {
    std::array<wchar_t, 128> value{};
    std::array<wchar_t, 128> crt{};
    size_t required = 0;
    if (_wgetenv_s(&required, crt.data(), crt.size(), entry.first) != 0 ||
        !required || wcscmp(crt.data(), entry.second) != 0 ||
        !GetEnvironmentVariableW(entry.first, value.data(),
                                 static_cast<DWORD>(value.size())) ||
        wcscmp(value.data(), entry.second) != 0)
      return false;
  }
  for (const wchar_t* name :
       {L"XUL_APP_FILE", L"SELECTABLE_PROFILE_RESET_PATH"}) {
    wchar_t value[2]{};
    size_t required = 0;
    if (GetEnvironmentVariableW(name, value, 2) != 0 ||
        _wgetenv_s(&required, nullptr, 0, name) != 0 || required)
      return false;
  }
  return true;
}

struct Sqlite;
bool ExerciseSqlite(const std::wstring& profile) {
  HMODULE library =
      LoadLibraryExW(L"winsqlite3.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!library) return false;
  using Open = int(__cdecl*)(const void*, Sqlite**);
  using Exec =
      int(__cdecl*)(Sqlite*, const char*,
                    int(__cdecl*)(void*, int, char**, char**), void*, char**);
  using Close = int(__cdecl*)(Sqlite*);
  const auto open = reinterpret_cast<Open>(
      reinterpret_cast<void*>(GetProcAddress(library, "sqlite3_open16")));
  const auto exec = reinterpret_cast<Exec>(
      reinterpret_cast<void*>(GetProcAddress(library, "sqlite3_exec")));
  const auto close = reinterpret_cast<Close>(
      reinterpret_cast<void*>(GetProcAddress(library, "sqlite3_close")));
  Sqlite* db = nullptr;
  bool valid = open && exec && close &&
               open((profile + L"\\sqlite-wal-test.sqlite").c_str(), &db) == 0;
  if (valid)
    valid = exec(db,
                 "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS "
                 "vault_test(value TEXT);"
                 "BEGIN IMMEDIATE; DELETE FROM vault_test;"
                 "INSERT INTO vault_test "
                 "VALUES('TB-SQLITE-SENTINEL-09fd74617a'); COMMIT;",
                 nullptr, nullptr, nullptr) == 0;
  bool found = false;
  if (valid)
    valid =
        exec(
            db, "SELECT value FROM vault_test;",
            [](void* state, int count, char** values, char**) -> int {
              *static_cast<bool*>(state) =
                  count == 1 && values[0] &&
                  std::strcmp(values[0], "TB-SQLITE-SENTINEL-09fd74617a") == 0;
              return 0;
            },
            &found, nullptr) == 0 &&
        found;
  if (db && close) valid = close(db) == 0 && valid;
  FreeLibrary(library);
  return valid;
}
}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  const bool hold = argc == 5 && wcscmp(argv[1], L"--hold") == 0;
  const bool interactive = argc == 4 && wcscmp(argv[1], L"--interactive") == 0;
  if (!interactive &&
      (argc != 5 || (!hold && wcscmp(argv[1], L"--roundtrip") != 0))) {
    std::puts(
        "Usage: VaultProbe.exe --roundtrip RUNTIME_DIR NEW_TEST_ROOT "
        "RECOVERY_FILE\n"
        "       VaultProbe.exe --interactive RUNTIME_DIR NEW_TEST_ROOT\n"
        "Uses a separate test vault. Opens Windows Hello. Requires Dokan.");
    return 2;
  }
  thunderbird::vault::ProfileVaultSession session;
  const auto result =
      session.Open(argv[2], argv[3], interactive ? L"" : argv[4]);
  std::printf("%s: 0x%08lX\n", result.operation,
              static_cast<unsigned long>(result.status));
  if (!result.Succeeded()) return 1;
  if (!ExerciseArguments(session)) {
    std::puts("Profile/cache/temp environment confinement test failed.");
    return 1;
  }
  const std::wstring file = session.ProfilePath() + L"\\dummy-mail.eml";
  constexpr char message[] =
      "Subject: Thunderbird encrypted profile test\r\n\r\n"
      "TB-VAULT-SENTINEL-746917fe9810421e\r\n";
  if (!thunderbird::vault::WriteNewFile(
          file, reinterpret_cast<const BYTE*>(message), sizeof(message) - 1)) {
    std::vector<BYTE> bytes;
    if (!thunderbird::vault::ReadSmallFile(file, sizeof(message), bytes) ||
        bytes.size() != sizeof(message) - 1 ||
        std::memcmp(bytes.data(), message, bytes.size()) != 0)
      return 1;
  }
  std::vector<BYTE> bytes;
  if (!thunderbird::vault::ReadSmallFile(file, sizeof(message), bytes) ||
      bytes.size() != sizeof(message) - 1 ||
      std::memcmp(bytes.data(), message, bytes.size()) != 0)
    return 1;
  if (!ExerciseSqlite(session.ProfilePath())) {
    std::puts("SQLite WAL/transaction test failed.");
    return 1;
  }
  if (hold) {
    const std::wstring ready = std::wstring(argv[3]) + L"\\mount-ready";
    constexpr BYTE marker = 1;
    if (!thunderbird::vault::WriteNewFile(ready, &marker, 1)) return 1;
    Sleep(30000);
  }
  session.Close();
  std::puts(
      "Mounted mail and SQLite WAL write/read succeeded; encrypted volume "
      "withdrawn.");
  return 0;
}
