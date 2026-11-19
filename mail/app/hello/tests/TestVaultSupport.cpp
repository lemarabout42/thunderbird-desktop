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

namespace {
using namespace thunderbird::vault;

void CheckSharing(const std::wstring& path, DWORD access, bool allowed) {
  Handle handle(
      CreateFileW(path.c_str(), access,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (allowed) {
    CHECK(handle.value != INVALID_HANDLE_VALUE);
  } else {
    CHECK(handle.value == INVALID_HANDLE_VALUE);
    CHECK(GetLastError() == ERROR_SHARING_VIOLATION);
  }
}

void TestRuntimePins(const wchar_t* child) {
  wchar_t parent[MAX_PATH]{};
  CHECK(GetTempFileNameW(L".", L"pin", 0, parent));
  CHECK(DeleteFileW(parent));
  CHECK(CreateDirectoryW(parent, nullptr));
  const std::wstring directory = std::wstring(parent) + L"\\runtime é";
  CHECK(CreateDirectoryW(directory.c_str(), nullptr));
  const std::wstring file = directory + L"\\fixture.bin";
  const std::wstring executable = directory + L"\\child.exe";
  constexpr BYTE contents[]{'a', 'b', 'c'};
  constexpr char digest[] =
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  CHECK(WriteNewFile(file, contents, sizeof(contents)));
  CHECK(CopyFileW(child, executable.c_str(), TRUE));

  std::wstring launchDirectory;
  std::vector<Handle> pins;
  CHECK(!PinVerifiedRuntime(directory, {}, launchDirectory, pins));
  CHECK(!PinVerifiedRuntime(directory, {{L"fixture.bin", "wrong"}},
                            launchDirectory, pins));
  CHECK(!PinVerifiedRuntime(directory, {{L"..\\fixture.bin", digest}},
                            launchDirectory, pins));
  const std::wstring link = directory + L"\\link.bin";
  if (CreateSymbolicLinkW(link.c_str(), L"fixture.bin",
                          SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
    CHECK(!PinVerifiedRuntime(directory, {{L"link.bin", digest}},
                              launchDirectory, pins));
    CHECK(DeleteFileW(link.c_str()));
  } else {
    const DWORD error = GetLastError();
    CHECK(error == ERROR_PRIVILEGE_NOT_HELD ||
          error == ERROR_INVALID_PARAMETER || error == ERROR_ACCESS_DENIED);
  }
  {
    Handle writer(
        CreateFileW(file.c_str(), GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    CHECK(writer.value != INVALID_HANDLE_VALUE);
    CHECK(!PinVerifiedRuntime(directory, {{L"fixture.bin", digest}},
                              launchDirectory, pins));
  }

  CHECK(PinVerifiedRuntime(directory, {{L"fixture.bin", digest}},
                           launchDirectory, pins));
  CHECK(launchDirectory.find(L"\\\\?\\GLOBALROOT\\Device\\") == 0);
  CheckSharing(file, GENERIC_READ, true);
  CheckSharing(file, GENERIC_WRITE, false);
  CheckSharing(file, DELETE, false);
  CheckSharing(directory, DELETE, false);
  CheckSharing(parent, DELETE, false);
  CHECK(RunCommand(launchDirectory + L"\\child.exe", {L"--info=valid"}) == 0);
  pins.clear();
  CheckSharing(file, GENERIC_WRITE | DELETE, true);
  CheckSharing(directory, DELETE, true);
  CheckSharing(parent, DELETE, true);
  CHECK(DeleteFileW(executable.c_str()));
  CHECK(DeleteFileW(file.c_str()));
  CHECK(RemoveDirectoryW(directory.c_str()));
  CHECK(RemoveDirectoryW(parent));
}

void TestEngineSession() {
  const DWORD process = GetCurrentProcessId();
  DWORD session = 0;
  CHECK(ProcessIdToSessionId(process, &session));
  CHECK(IsEngineInSession(L"CPPCRYPTFS.EXE", process, session));
  CHECK(!IsEngineInSession(L"cppcryptfs.exe", process, session ^ 1));
  CHECK(!IsEngineInSession(L"other.exe", process, session));
}
}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  using namespace thunderbird::vault;
  CHECK(argc == 2);
  if (wcscmp(argv[1], L"--watch-exit") == 0) {
    Handle signal(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    EngineWatch watch;
    CHECK(watch.Start(signal.value));
    CHECK(SetEvent(signal.value));
    Sleep(5000);
    return 1;
  }
  Handle signal(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  EngineWatch watch;
  CHECK(watch.Start(signal.value));
  watch.Stop();
  CHECK(SetEvent(signal.value));
  CHECK(!watch.Start(signal.value));
  CHECK(RunCommand(argv[0], {L"--watch-exit"}) == ERROR_DEVICE_NOT_CONNECTED);
  TestRuntimePins(argv[1]);
  TestEngineSession();
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
  CHECK(RunVerifiedMount(argv[1], L"unused", L"Z:", key, GetCurrentProcess()) ==
        ERROR_INVALID_IMAGE_HASH);
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
  CHECK(VerifyMountedPolicy(argv[1], L"protected"));
  for (const wchar_t* policyFixture :
       {L"plain-names", L"missing", L"conflict", L"oversized"})
    CHECK(!VerifyMountedPolicy(argv[1], policyFixture));
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
