/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdio>
#include <cstdlib>
#include <thread>

#include "../ProfileVault.cpp"
#include "../RecoveryUI.cpp"

#define CHECK(condition)                                                \
  do {                                                                  \
    if (!(condition)) {                                                 \
      std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
      std::exit(1);                                                     \
    }                                                                   \
  } while (false)

namespace thunderbird::hello {
static unsigned enrollments = 0;
static unsigned rollbacks = 0;

PendingVaultProtector::~PendingVaultProtector() {
  CHECK(!mKey || mProvider == 1);
  if (mKey && !mCommitted) ++rollbacks;
}

// Exercise the metadata transition independently of Windows Hello hardware.
Result CreateVaultProtector(const VaultId&, const vault::SecretKey& secret,
                            std::vector<BYTE>& wrapped,
                            PendingVaultProtector& pending) {
  CHECK(secret.IsValid());
  ++enrollments;
  pending.mProvider = 1;
  pending.mKey = 1;
  wrapped.assign(512, 0xB2);
  return {ERROR_SUCCESS, "Test protector"};
}

Result UnlockVaultSecret(const VaultId&, const std::vector<BYTE>&,
                         vault::SecretKey&, bool) {
  std::abort();
}
}  // namespace thunderbird::hello

namespace thunderbird::vault {
namespace {
void TestPipeReadiness() {
  hello::VaultId unique{};
  CHECK(RandomId(unique));
  const auto suffix = Hex(unique.data(), unique.size());
  const auto name = L"\\\\.\\pipe\\VaultRecoveryTest-" +
                    std::wstring(suffix.begin(), suffix.end());
  const auto newInstance = [&]() {
    return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT |
                                PIPE_REJECT_REMOTE_CLIENTS,
                            1, 128, 128, 0, nullptr);
  };
  Handle first(newInstance());
  Handle listening(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  CHECK(first.value != INVALID_HANDLE_VALUE && listening.value);
  std::thread server([&]() {
    // The empty ownership probe can disconnect before ConnectNamedPipe runs.
    if (ConnectNamedPipe(first.value, nullptr) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
      BYTE byte = 0;
      DWORD read = 0;
      CHECK(!ReadFile(first.value, &byte, 1, &read, nullptr) && !read);
    } else {
      CHECK(GetLastError() == ERROR_NO_DATA);
    }
    first.Reset();
    Sleep(150);
    Handle second(newInstance());
    CHECK(second.value != INVALID_HANDLE_VALUE);
    CHECK(SetEvent(listening.value));
    CHECK(ConnectNamedPipe(second.value, nullptr) ||
          GetLastError() == ERROR_PIPE_CONNECTED);
    BYTE command = 0;
    DWORD read = 0;
    CHECK(ReadFile(second.value, &command, 1, &read, nullptr) && read == 1 &&
          command == 42);
  });
  CHECK(WaitForVerifiedPipe(GetCurrentProcess(), name, 5000).Succeeded());
  CHECK(WaitForSingleObject(listening.value, 0) == WAIT_OBJECT_0);
  Handle client(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                            nullptr, OPEN_EXISTING, 0, nullptr));
  CHECK(client.value != INVALID_HANDLE_VALUE);
  const BYTE command = 42;
  DWORD written = 0;
  CHECK(WriteFile(client.value, &command, 1, &written, nullptr) &&
        written == 1);
  client.Reset();
  server.join();
  CHECK(WaitForVerifiedPipe(GetCurrentProcess(), name, 50).status ==
        ERROR_TIMEOUT);
}

void TestEnvelope() {
  hello::VaultId unique{};
  CHECK(RandomId(unique));
  const auto suffix = Hex(unique.data(), unique.size());
  const auto name =
      L"VaultRecovery-" + std::wstring(suffix.begin(), suffix.end());
  // The native runner may execute under a deeply nested temporary directory.
  std::array<wchar_t, 32768> path{};
  const DWORD length = GetFullPathNameW(
      name.c_str(), static_cast<DWORD>(path.size()), path.data(), nullptr);
  CHECK(length && length < path.size());
  std::wstring root(path.data(), length);
  if (root.compare(0, 4, L"\\\\?\\") != 0)
    root = root.compare(0, 2, L"\\\\") == 0 ? L"\\\\?\\UNC\\" + root.substr(2)
                                            : L"\\\\?\\" + root;
  CHECK(CreateDirectoryW(root.c_str(), nullptr));
  const auto marker = root + kMarker;
  const auto metadata = root + L"\\hello.key";

  Envelope original;
  original.vaultId.fill(0x1A);
  original.protectorId.fill(0x2B);
  original.wrapped.assign(512, 0xA1);
  Envelope damaged = original;
  damaged.vaultId.front() ^= 1;
  const auto encoded = EncodeEnvelope(damaged);
  CHECK(WriteNewFile(metadata, encoded.data(), encoded.size()));
  SecretKey recovery;
  CHECK(recovery.Generate());

  CHECK(!UpdateEnvelopeFromMount(root, marker, damaged, nullptr).Succeeded());
  CHECK(!UpdateEnvelopeFromMount(root, marker, damaged, &recovery).Succeeded());
  CHECK(GetFileAttributesW(marker.c_str()) == INVALID_FILE_ATTRIBUTES);
  CHECK(WriteNewFile(marker, original.vaultId.data(), 1));
  CHECK(!UpdateEnvelopeFromMount(root, marker, damaged, &recovery).Succeeded());
  CHECK(hello::enrollments == 0);
  CHECK(DeleteFileW(marker.c_str()));
  CHECK(WriteNewFile(marker, original.vaultId.data(), original.vaultId.size()));

  std::vector<BYTE> bytes;
  // A sharing failure must leave the original envelope recoverable. A normal
  // reopen with a matching identity should succeed without replacing it.
  {
    Handle lock(CreateFileW(metadata.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr));
    CHECK(lock.value != INVALID_HANDLE_VALUE);
    auto attempt = damaged;
    CHECK(!UpdateEnvelopeFromMount(root, marker, attempt, nullptr).Succeeded());
    CHECK(ReadSmallFile(metadata, encoded.size(), bytes) && bytes == encoded);
  }
  CHECK(UpdateEnvelopeFromMount(root, marker, damaged, nullptr).Succeeded());
  CHECK(ReadSmallFile(metadata, encoded.size(), bytes) &&
        bytes == EncodeEnvelope(original));
  {
    Handle lock(CreateFileW(metadata.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr));
    CHECK(lock.value != INVALID_HANDLE_VALUE);
    CHECK(UpdateEnvelopeFromMount(root, marker, original, nullptr).Succeeded());
  }
  CHECK(hello::enrollments == 0);

  // A validly encoded outer ID can also be damaged when the Hello protector
  // itself has been lost. Only the authenticated marker supplies the new ID.
  CHECK(DeleteFileW(metadata.c_str()));
  CHECK(WriteNewFile(metadata, encoded.data(), encoded.size()));
  CHECK(DecodeEnvelope(encoded, damaged));
  {
    SecretKey interrupted;
    CHECK(interrupted.Generate());
    Handle lock(CreateFileW(metadata.c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                            nullptr));
    CHECK(lock.value != INVALID_HANDLE_VALUE);
    auto attempt = damaged;
    CHECK(!UpdateEnvelopeFromMount(root, marker, attempt, &interrupted)
               .Succeeded());
    CHECK(ReadSmallFile(metadata, encoded.size(), bytes) && bytes == encoded);
    CHECK(hello::enrollments == 1 && hello::rollbacks == 1);
  }
  CHECK(UpdateEnvelopeFromMount(root, marker, damaged, &recovery).Succeeded());
  CHECK(hello::enrollments == 2 && hello::rollbacks == 1 &&
        !recovery.IsValid());
  CHECK(ReadSmallFile(metadata, encoded.size(), bytes));
  CHECK(DecodeEnvelope(bytes, damaged));
  CHECK(damaged.vaultId == original.vaultId &&
        damaged.protectorId != original.protectorId &&
        damaged.wrapped == std::vector<BYTE>(512, 0xB2));
  CHECK(DeleteFileW(metadata.c_str()));
  CHECK(DeleteFileW(marker.c_str()));
  CHECK(RemoveDirectoryW(root.c_str()));
}

void TestRecoveryControls(bool display) {
  struct alignas(DWORD) {
    DLGTEMPLATE dialog;
    WORD menu;
    WORD windowClass;
    WORD title;
  } value{};
  value.dialog.style = WS_POPUP;
  value.dialog.cx = 330;
  value.dialog.cy = 132;
  DialogState state;
  state.display = display;
  std::fill_n(state.code.begin(), 64, L'1');
  const HWND window = CreateDialogIndirectParamW(
      GetModuleHandleW(nullptr), &value.dialog, nullptr, RecoveryProc,
      reinterpret_cast<LPARAM>(&state));
  CHECK(window && !IsWindowVisible(window));
  const HWND field = GetDlgItem(window, kCode);
  wchar_t className[16]{};
  CHECK(GetClassNameW(field, className, 16));
  const auto style = GetWindowLongPtrW(field, GWL_STYLE);
  if (display) {
    CHECK(_wcsicmp(className, L"Static") == 0 && !(style & SS_NOTIFY));
    wchar_t text[67]{};
    CHECK(GetWindowTextW(field, text, 67) == 66);
    CHECK(std::wstring(text) ==
          std::wstring(32, L'1') + L"\r\n" + std::wstring(32, L'1'));
    RECT bounds{};
    SIZE row{};
    const HDC dc = GetDC(field);
    CHECK(dc);
    const auto font =
        reinterpret_cast<HFONT>(SendMessageW(field, WM_GETFONT, 0, 0));
    const auto previousFont = SelectObject(dc, font);
    CHECK(GetTextExtentPoint32W(dc, text, 32, &row));
    CHECK(GetClientRect(field, &bounds) && row.cx <= bounds.right &&
          2 * row.cy <= bounds.bottom);
    SelectObject(dc, previousFont);
    ReleaseDC(field, dc);
  } else {
    CHECK(_wcsicmp(className, L"Edit") == 0 && (style & ES_PASSWORD) &&
          !(style & ES_READONLY));
    CHECK(SendMessageW(field, EM_GETLIMITTEXT, 0, 0) == 64);
  }
  CHECK(DestroyWindow(window));
}
}  // namespace
}  // namespace thunderbird::vault

int main() {
  CHECK(!thunderbird::vault::Fail("No extended Windows error", 0).Succeeded());
  CHECK(thunderbird::vault::Fail("Canceled", ERROR_CANCELLED).status ==
        ERROR_CANCELLED);
  thunderbird::vault::TestPipeReadiness();
  thunderbird::vault::TestEnvelope();
  thunderbird::vault::TestRecoveryControls(true);
  thunderbird::vault::TestRecoveryControls(false);
  std::puts(
      "Vault pipe readiness, identity repair, atomic recovery and recovery "
      "controls passed.");
}
