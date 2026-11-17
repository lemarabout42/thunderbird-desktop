/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ProfileVault.h"
#include "RecoveryUI.h"

#include <bcrypt.h>
#include <shlobj.h>

#include <algorithm>
#include <cstdlib>

namespace thunderbird::vault {
namespace {

hello::Result Fail(const char* operation, DWORD error = ERROR_INVALID_DATA) {
  return {static_cast<LONG>(error), operation};
}

bool RandomId(hello::VaultId& id) {
  return BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

bool Exists(const std::wstring& path) {
  return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool Environment(const wchar_t* name, const std::wstring& value) {
  return _wputenv_s(name, value.c_str()) == 0 &&
         SetEnvironmentVariableW(name, value.empty() ? nullptr : value.c_str());
}

bool RuntimeVerified(const std::wstring& path) {
  // Pinned upstream releases, verified before any secret can enter a helper.
  return VerifySha256(path + L"\\cppcryptfs.exe",
                      "e8721d8ad7f6c1c9c4b07442adf3a309e3e65516e1e9c579e1840817"
                      "d4974b1f") &&
         VerifySha256(path + L"\\cppcryptfsctl.exe",
                      "587be2317a762ba8bc0f374cff97530d38bafa9db033ad7690a9dc52"
                      "1d2651f5") &&
         VerifySha256(path + L"\\dokan2.dll",
                      "75600aba867acbdfdb85fcd142b524da769bdc611b855a760aeb0c6e"
                      "2eaae17a");
}

bool DriverInstalled() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (!manager) return false;
  SC_HANDLE service = OpenServiceW(manager, L"Dokan2", SERVICE_QUERY_STATUS);
  const bool installed = service != nullptr;
  if (service) CloseServiceHandle(service);
  CloseServiceHandle(manager);
  return installed;
}

bool OutsideRoot(const std::wstring& file, const std::wstring& root) {
  std::array<wchar_t, 32768> fullFile{}, fullRoot{};
  const DWORD a =
      GetFullPathNameW(file.c_str(), fullFile.size(), fullFile.data(), nullptr);
  const DWORD b =
      GetFullPathNameW(root.c_str(), fullRoot.size(), fullRoot.data(), nullptr);
  if (!a || !b || a >= fullFile.size() || b >= fullRoot.size()) return false;
  std::wstring prefix = fullRoot.data();
  if (prefix.back() != L'\\') prefix += L'\\';
  return _wcsnicmp(fullFile.data(), prefix.c_str(), prefix.size()) != 0 &&
         _wcsicmp(fullFile.data(), fullRoot.data()) != 0;
}

bool ExportRecovery(const std::wstring& path, const std::wstring& root,
                    const Envelope& envelope, const SecretKey& secret) {
  if (!OutsideRoot(path, root)) return false;
  auto text = EncodeRecovery(envelope.vaultId, secret);
  const bool written = WriteNewFile(
      path, reinterpret_cast<const BYTE*>(text.data()), text.size());
  SecureZeroMemory(text.data(), text.size());
  std::vector<BYTE> check;
  SecretKey recovered;
  bool valid = written && ReadSmallFile(path, 256, check) &&
               DecodeRecovery(check, envelope.vaultId, recovered) &&
               recovered.Bytes() == secret.Bytes();
  if (!check.empty()) SecureZeroMemory(check.data(), check.size());
  return valid;
}

std::wstring ExecutableDirectory() {
  std::array<wchar_t, 32768> path{};
  const DWORD size = GetModuleFileNameW(nullptr, path.data(), path.size());
  if (!size || size >= path.size()) return {};
  std::wstring result(path.data(), size);
  const auto slash = result.find_last_of(L"\\/");
  return slash == std::wstring::npos ? L"" : result.substr(0, slash);
}

std::wstring DefaultRoot() {
  PWSTR local = nullptr;
  if (SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &local) != S_OK)
    return {};
  std::wstring root(local);
  CoTaskMemFree(local);
  root += L"\\ThunderbirdHello";
  if (!PrivateDirectory(root)) return {};
  root += L"\\TestProfile-v2";
  return PrivateDirectory(root) ? root : L"";
}

bool ConfirmEnginePipe(HANDLE process) {
  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return false;
  const std::wstring pipe =
      L"\\\\.\\pipe\\cppcryptfs_cmd_" + std::to_wstring(session);
  // Open only for identification. No password or command is transmitted.
  Handle connection(CreateFileW(pipe.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr));
  if (connection.value == INVALID_HANDLE_VALUE) return false;
  ULONG server = 0;
  return GetNamedPipeServerProcessId(connection.value, &server) &&
         server == GetProcessId(process) &&
         WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

}  // namespace

ProfileVaultSession::~ProfileVaultSession() {
  // Normal shutdown calls Close after Gecko has released all profile files.
  // If startup fails or the process crashes, closing the job terminates only
  // our own engine; Dokan withdraws its mount when that process exits.
  if (mMounted)
    RunCommand(mRuntime + L"\\cppcryptfsctl.exe", {L"--unmount=" + mDrive},
               nullptr, 10000);
}

hello::Result ProfileVaultSession::Create(const std::wstring& root,
                                          const std::wstring& recoveryExport) {
  Envelope envelope;
  SecretKey secret;
  if (!RandomId(envelope.vaultId) || !RandomId(envelope.protectorId) ||
      !secret.Generate())
    return Fail("Generate vault keys");
  const std::string identifier =
      Hex(envelope.vaultId.data(), envelope.vaultId.size());
  const std::wstring pending =
      root + L"\\pending-" + std::wstring(identifier.begin(), identifier.end());
  if (!PrivateDirectory(pending) || !PrivateDirectory(pending + L"\\data"))
    return Fail("Create private vault directory", GetLastError());
  auto result = hello::CreateVaultProtector(envelope.protectorId, secret,
                                            envelope.wrapped);
  if (!result.Succeeded()) return result;
  const DWORD initialized =
      RunCommand(mRuntime + L"\\cppcryptfsctl.exe",
                 {L"--init=" + pending + L"\\data", L"--scryptn=17"}, &secret);
  if (initialized) return Fail("Initialize encrypted filesystem", initialized);
  if (recoveryExport.empty()) {
    if (!ConfirmRecoveryCode(secret))
      return Fail("Recovery confirmation canceled", ERROR_CANCELLED);
  } else if (!ExportRecovery(recoveryExport, root, envelope, secret)) {
    // Only the diagnostic harness passes an explicit path for its generated
    // dummy profile. The application never saves a plaintext recovery key.
    return Fail(
        "Recovery fixture must be new, verified, and outside the vault");
  }
  const auto bytes = EncodeEnvelope(envelope);
  if (!WriteNewFile(pending + L"\\hello.key", bytes.data(), bytes.size()) ||
      !MoveFileExW(pending.c_str(), mVault.c_str(), MOVEFILE_WRITE_THROUGH))
    return Fail("Commit initialized vault", GetLastError());
  return {ERROR_SUCCESS, "Create encrypted test profile"};
}

hello::Result ProfileVaultSession::Recover(Envelope& envelope,
                                           SecretKey& secret,
                                           bool knownIdentity) {
  if (MessageBoxW(nullptr,
                  L"Windows Hello n'a pas ouvert la clé de ce coffre. "
                  L"Voulez-vous utiliser "
                  L"votre clé de récupération pour l'associer à nouveau à "
                  L"Windows Hello ?",
                  L"Thunderbird — récupération",
                  MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) != IDYES)
    return Fail("Vault unlock canceled", ERROR_CANCELLED);
  if (!EnterRecoveryCode(secret))
    return Fail("Recovery canceled or invalid", ERROR_CANCELLED);
  if (!knownIdentity) envelope.vaultId.fill(0);
  // Keep the stable vault ID, rotate only the protector ID. Existing encrypted
  // mail and old recovery files continue to use the same random filesystem key.
  if (!RandomId(envelope.protectorId))
    return Fail("Generate replacement protector");
  // Verify the code by mounting before asking Hello to enroll a replacement.
  return {ERROR_SUCCESS, "Recovery code supplied"};
}

hello::Result ProfileVaultSession::Open(const std::wstring& runtimeDirectory,
                                        const std::wstring& dataRoot,
                                        const std::wstring& recoveryExport) {
  mRuntime = runtimeDirectory.empty()
                 ? ExecutableDirectory() + L"\\vault-runtime"
                 : runtimeDirectory;
  if (!RuntimeVerified(mRuntime))
    return Fail("Missing or modified vault runtime");
  if (!DriverInstalled())
    return Fail("Install the bundled signed Dokan driver",
                ERROR_SERVICE_DOES_NOT_EXIST);
  const std::wstring root = dataRoot.empty() ? DefaultRoot() : dataRoot;
  if (root.empty() || !PrivateDirectory(root))
    return Fail("Open private vault root");
  // File sharing protects across processes/sessions, not just this executable.
  const auto lockStarted = GetTickCount64();
  do {
    mLock.Reset(CreateFileW((root + L"\\session.lock").c_str(),
                            GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (mLock.value != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_SHARING_VIOLATION)
      break;
    Sleep(100);
  } while (GetTickCount64() - lockStarted < 15000);
  if (mLock.value == INVALID_HANDLE_VALUE)
    return Fail("Vault already in use", ERROR_SHARING_VIOLATION);
  mVault = root + L"\\vault";
  if (!Exists(mVault)) {
    const auto result = Create(root, recoveryExport);
    if (!result.Succeeded()) return result;
  }
  if ((GetFileAttributesW(mVault.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT) ||
      (GetFileAttributesW((mVault + L"\\data").c_str()) &
       FILE_ATTRIBUTE_REPARSE_POINT))
    return Fail("Vault cannot be a reparse point");
  Envelope envelope;
  std::vector<BYTE> bytes;
  const bool validEnvelope =
      ReadSmallFile(mVault + L"\\hello.key", 552, bytes) &&
      DecodeEnvelope(bytes, envelope);
  SecretKey secret;
  auto result = validEnvelope
                    ? hello::UnlockVaultSecret(envelope.protectorId,
                                               envelope.wrapped, secret)
                    : Fail("Missing or damaged vault envelope");
  bool recovered = false;
  if (!result.Succeeded()) {
    if (result.status == NTE_USER_CANCELLED || result.status == ERROR_CANCELLED)
      return result;
    result = Recover(envelope, secret, validEnvelope);
    if (!result.Succeeded()) return result;
    recovered = true;
  }
  if (!Environment(L"CPPCRYPTFS_SESSIONID", L""))
    return Fail("Clear helper pipe override");
  if (!StartOwnedEngine(mRuntime + L"\\cppcryptfs.exe", mJob, mEngine))
    return Fail("Cannot own an exclusive cppcryptfs instance", GetLastError());
  bool ready = false;
  const ULONGLONG start = GetTickCount64();
  while (GetTickCount64() - start < 15000) {
    if (WaitForSingleObject(mEngine.value, 100) != WAIT_TIMEOUT) break;
    // The pipe is created before the engine's main window finishes starting.
    // Require a successful public command as well, before sending any secret.
    if (ConfirmEnginePipe(mEngine.value) &&
        RunCommand(mRuntime + L"\\cppcryptfsctl.exe", {L"--list"}, nullptr,
                   3000) == 0) {
      ready = true;
      break;
    }
  }
  if (!ready) return Fail("Encrypted filesystem engine did not become ready");
  // Thunderbird persists absolute paths in account preferences. Changing the
  // mount letter between launches could redirect those paths outside the vault.
  // This test build reserves Z: and refuses to open if it is already occupied.
  mDrive = L"Z:";
  if (GetLogicalDrives() & (DWORD{1} << (L'Z' - L'A')))
    return Fail("The encrypted test profile requires a free Z: drive",
                ERROR_ALREADY_ASSIGNED);
  const DWORD mounted =
      RunCommand(mRuntime + L"\\cppcryptfsctl.exe",
                 {L"--mount=" + mVault + L"\\data", L"--drive=" + mDrive,
                  L"--deny-other-sessions=1", L"--deny-services=1"},
                 &secret);
  if (!recovered) secret.Clear();
  if (mounted || WaitForSingleObject(mEngine.value, 0) != WAIT_TIMEOUT)
    return Fail("Mount encrypted profile",
                mounted ? mounted : ERROR_PROCESS_ABORTED);
  mMounted = true;
  const auto markerPath = mDrive + L"\\.thunderbird-vault-id";
  if (Exists(markerPath)) {
    if (!ReadSmallFile(markerPath, 16, bytes) || bytes.size() != 16)
      return Fail("Mounted profile identity mismatch");
    if (recovered && !validEnvelope)
      std::copy_n(bytes.begin(), 16, envelope.vaultId.begin());
    else if (!std::equal(bytes.begin(), bytes.end(), envelope.vaultId.begin()))
      return Fail("Mounted profile identity mismatch");
  } else if (recovered || !WriteNewFile(markerPath, envelope.vaultId.data(),
                                        envelope.vaultId.size()))
    return Fail("Write encrypted profile identity");
  if (recovered) {
    result = hello::CreateVaultProtector(envelope.protectorId, secret,
                                         envelope.wrapped);
    secret.Clear();
    if (!result.Succeeded()) return result;
    const auto encoded = EncodeEnvelope(envelope);
    hello::VaultId random{};
    if (!RandomId(random)) return Fail("Generate recovery transaction name");
    const auto suffix = Hex(random.data(), random.size());
    const auto temporary =
        mVault + L"\\hello-new-" + std::wstring(suffix.begin(), suffix.end());
    if (!WriteNewFile(temporary, encoded.data(), encoded.size()) ||
        !MoveFileExW(temporary.c_str(), (mVault + L"\\hello.key").c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
      return Fail("Commit replacement protector", GetLastError());
  }
  mProfile = mDrive + L"\\Profile";
  if (!PrivateDirectory(mProfile) || !PrivateDirectory(mDrive + L"\\Temp"))
    return Fail("Create encrypted profile directories");
  return {ERROR_SUCCESS, "Encrypted profile mounted"};
}

bool ProfileVaultSession::InstallEnvironment() {
  // Gecko examines inherited restart variables before -profile. Clear them in
  // both the CRT and Win32 environments; only the mounted profile may be used.
  LPWCH environment = GetEnvironmentStringsW();
  if (!environment) return false;
  std::vector<std::wstring> reset;
  for (const wchar_t* entry = environment; *entry; entry += wcslen(entry) + 1) {
    if (_wcsnicmp(entry, L"SELECTABLE_PROFILE_RESET_", 25) == 0) {
      const wchar_t* equals = wcschr(entry, L'=');
      if (equals) reset.emplace_back(entry, equals);
    }
  }
  FreeEnvironmentStringsW(environment);
  for (const auto& name : reset)
    if (!Environment(name.c_str(), L"")) return false;
  return Environment(L"XUL_APP_FILE", L"") &&
         Environment(L"XRE_PROFILE_PATH", mProfile) &&
         Environment(L"XRE_PROFILE_LOCAL_PATH", mProfile) &&
         Environment(L"XRE_PROFILE_NAME", L"ThunderbirdHelloTest") &&
         Environment(L"TEMP", mDrive + L"\\Temp") &&
         Environment(L"TMP", mDrive + L"\\Temp") &&
         Environment(L"MOZ_CRASHREPORTER_DISABLE", L"1");
}

bool ProfileVaultSession::PrepareArguments(int& argc, char**& argv) {
  if (!mMounted || !InstallEnvironment()) return false;
  for (int i = 1; i < argc; ++i)
    if (IsProfileOverride(argv[i])) return false;
  mArguments.clear();
  mPointers.clear();
  for (int i = 0; i < argc; ++i) mArguments.emplace_back(argv[i]);
  mArguments.emplace_back("-no-remote");
  mArguments.emplace_back("-profile");
  // The mount/profile components are deliberately ASCII and stable for Gecko.
  mArguments.emplace_back(mProfile.begin(), mProfile.end());
  for (auto& argument : mArguments) mPointers.push_back(argument.data());
  argc = static_cast<int>(mPointers.size());
  mPointers.push_back(nullptr);
  argv = mPointers.data();
  return true;
}

void ProfileVaultSession::Close() {
  while (mMounted) {
    const DWORD result = RunCommand(mRuntime + L"\\cppcryptfsctl.exe",
                                    {L"--unmount=" + mDrive}, nullptr, 10000);
    if (!result && !(GetLogicalDrives() & (DWORD{1} << (mDrive[0] - L'A')))) {
      mMounted = false;
      break;
    }
    MessageBoxW(nullptr,
                L"Le coffre est encore ouvert. Fermez les fichiers ou pièces "
                L"jointes ouverts "
                L"dans d'autres applications, puis cliquez sur OK pour "
                L"réessayer de verrouiller.",
                L"Thunderbird — fermeture du coffre", MB_OK | MB_ICONWARNING);
  }
  mJob.Reset();
  if (mEngine.value) WaitForSingleObject(mEngine.value, 5000);
  mEngine.Reset();
  mLock.Reset();
}

}  // namespace thunderbird::vault
