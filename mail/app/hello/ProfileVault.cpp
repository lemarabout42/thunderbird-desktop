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
  return {static_cast<LONG>(error ? error : ERROR_INVALID_DATA), operation};
}

bool RandomId(hello::VaultId& id) {
  return BCryptGenRandom(nullptr, id.data(), static_cast<ULONG>(id.size()),
                         BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

bool Environment(const wchar_t* name, const std::wstring& value) {
  return _wputenv_s(name, value.c_str()) == 0 &&
         SetEnvironmentVariableW(name, value.empty() ? nullptr : value.c_str());
}

bool PinRuntime(const std::wstring& directory, std::wstring& launchDirectory,
                std::vector<Handle>& pins) {
  return PinVerifiedRuntime(
      directory,
      {{L"cppcryptfs.exe",
        "e8721d8ad7f6c1c9c4b07442adf3a309e3e65516e1e9c579e1840817d4974b1f"},
       {L"cppcryptfsctl.exe",
        "587be2317a762ba8bc0f374cff97530d38bafa9db033ad7690a9dc521d2651f5"},
       {L"dokan2.dll",
        "75600aba867acbdfdb85fcd142b524da769bdc611b855a760aeb0c6e2eaae17a"}},
      launchDirectory, pins);
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
      GetFullPathNameW(file.c_str(), static_cast<DWORD>(fullFile.size()),
                       fullFile.data(), nullptr);
  const DWORD b =
      GetFullPathNameW(root.c_str(), static_cast<DWORD>(fullRoot.size()),
                       fullRoot.data(), nullptr);
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
  const DWORD size =
      GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
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

hello::Result WaitForVerifiedPipe(HANDLE process, const std::wstring& pipe,
                                  DWORD timeout) {
  const DWORD owner = GetProcessId(process);
  if (!owner) return Fail("Identify owned filesystem engine", GetLastError());
  const auto start = GetTickCount64();
  bool identified = false;
  for (;;) {
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
      return Fail("Filesystem engine exited", ERROR_PROCESS_ABORTED);
    const auto elapsed = GetTickCount64() - start;
    if (elapsed >= timeout)
      return Fail("Wait for owned filesystem command pipe", ERROR_TIMEOUT);
    const DWORD remaining = timeout - static_cast<DWORD>(elapsed);
    if (identified) {
      // cppcryptfs processes the identity probe, closes that pipe instance,
      // then listens again. Leave the next connection for its signed client.
      if (WaitNamedPipeW(pipe.c_str(), (std::min)(remaining, DWORD{100}))) {
        if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT)
          return Fail("Filesystem engine exited", ERROR_PROCESS_ABORTED);
        return {ERROR_SUCCESS, "Verified filesystem command pipe is ready"};
      }
    } else {
      Handle connection(CreateFileW(pipe.c_str(), GENERIC_READ | GENERIC_WRITE,
                                    0, nullptr, OPEN_EXISTING, 0, nullptr));
      if (connection.value != INVALID_HANDLE_VALUE) {
        ULONG server = 0;
        if (!GetNamedPipeServerProcessId(connection.value, &server))
          return Fail("Identify filesystem command pipe", GetLastError());
        if (server != owner)
          return Fail("Filesystem command pipe owner mismatch",
                      ERROR_ACCESS_DENIED);
        identified = true;
        continue;
      }
    }
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY &&
        error != ERROR_NO_DATA && error != ERROR_PIPE_NOT_CONNECTED &&
        error != ERROR_SEM_TIMEOUT)
      return Fail("Open owned filesystem command pipe", error);
    const auto used = GetTickCount64() - start;
    if (used < timeout)
      Sleep((std::min)(timeout - static_cast<DWORD>(used), DWORD{50}));
  }
}

hello::Result WaitForEnginePipe(HANDLE process, DWORD timeout) {
  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session))
    return Fail("Identify filesystem engine session", GetLastError());
  return WaitForVerifiedPipe(
      process, L"\\\\.\\pipe\\cppcryptfs_cmd_" + std::to_wstring(session),
      timeout);
}

constexpr DWORD kDriveMask = DWORD{1} << (L'Z' - L'A');
constexpr wchar_t kMarker[] = L"\\.thunderbird-vault-id";

std::wstring DriveTarget(const std::wstring& drive) {
  std::array<wchar_t, 32768> target{};
  if (!QueryDosDeviceW(drive.c_str(), target.data(),
                       static_cast<DWORD>(target.size())))
    return {};
  return target.data();
}

hello::Result UpdateEnvelopeFromMount(const std::wstring& vault,
                                      const std::wstring& marker,
                                      Envelope& envelope,
                                      SecretKey* recoverySecret) {
  std::vector<BYTE> bytes;
  if (!ReadSmallFile(marker, envelope.vaultId.size(), bytes) ||
      bytes.size() != envelope.vaultId.size())
    return Fail("Missing or damaged encrypted profile identity");
  const bool matches =
      std::equal(bytes.begin(), bytes.end(), envelope.vaultId.begin());
  if (matches && !recoverySecret)
    return {ERROR_SUCCESS, "Verified encrypted profile identity"};

  // The encrypted marker was authenticated by the mounted filesystem. The
  // stable ID in a v2 envelope is public and is outside its signature.
  std::copy(bytes.begin(), bytes.end(), envelope.vaultId.begin());
  hello::PendingVaultProtector pending;
  if (recoverySecret) {
    if (!RandomId(envelope.protectorId))
      return Fail("Generate replacement protector");
    auto result = hello::CreateVaultProtector(
        envelope.protectorId, *recoverySecret, envelope.wrapped, pending);
    recoverySecret->Clear();
    if (!result.Succeeded()) return result;
  }

  hello::VaultId random{};
  if (!RandomId(random)) return Fail("Generate recovery transaction name");
  const auto suffix = Hex(random.data(), random.size());
  const auto temporary =
      vault + L"\\hello-new-" + std::wstring(suffix.begin(), suffix.end());
  const auto encoded = EncodeEnvelope(envelope);
  if (encoded.empty() ||
      !WriteNewFile(temporary, encoded.data(), encoded.size()))
    return Fail("Write repaired vault envelope");
  if (!MoveFileExW(temporary.c_str(), (vault + L"\\hello.key").c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    const DWORD error = GetLastError();
    DeleteFileW(temporary.c_str());
    return Fail("Commit repaired vault envelope", error);
  }
  pending.Commit();
  return {ERROR_SUCCESS, "Repaired vault envelope"};
}

}  // namespace

ProfileVaultSession::~ProfileVaultSession() { Close(); }

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
  // The private parent supplies the DACL. Require a new transaction directory
  // so only this enrollment can initialize its encrypted identity.
  if (!CreateDirectoryW(pending.c_str(), nullptr) ||
      !PrivateDirectory(pending + L"\\data"))
    return Fail("Create private vault directory", GetLastError());
  const DWORD initialized =
      RunCommand(mRuntime + L"\\cppcryptfsctl.exe",
                 {L"--init=" + pending + L"\\data", L"--scryptn=17"}, &secret);
  if (initialized) return Fail("Initialize encrypted filesystem", initialized);
  auto result = Mount(pending + L"\\data", secret);
  if (!result.Succeeded()) return result;
  if (!WriteNewFile(mDrive + kMarker, envelope.vaultId.data(),
                    envelope.vaultId.size()))
    return Fail("Initialize encrypted profile identity", GetLastError());
  result = Unmount();
  if (!result.Succeeded()) return result;
  StopEngine();
  if (recoveryExport.empty()) {
    if (!ConfirmRecoveryCode(secret))
      return Fail("Recovery confirmation canceled", ERROR_CANCELLED);
  } else if (!ExportRecovery(recoveryExport, root, envelope, secret)) {
    // Only the diagnostic harness passes an explicit path for its generated
    // dummy profile. The application never saves a plaintext recovery key.
    return Fail(
        "Recovery fixture must be new, verified, and outside the vault");
  }
  hello::PendingVaultProtector protector;
  result = hello::CreateVaultProtector(envelope.protectorId, secret,
                                       envelope.wrapped, protector);
  if (!result.Succeeded()) return result;
  const auto bytes = EncodeEnvelope(envelope);
  if (bytes.empty() ||
      !WriteNewFile(pending + L"\\hello.key", bytes.data(), bytes.size()) ||
      !MoveFileExW(pending.c_str(), mVault.c_str(), MOVEFILE_WRITE_THROUGH))
    return Fail("Commit initialized vault", GetLastError());
  protector.Commit();
  return {ERROR_SUCCESS, "Create encrypted test profile"};
}

hello::Result ProfileVaultSession::Open(const std::wstring& runtimeDirectory,
                                        const std::wstring& dataRoot,
                                        const std::wstring& recoveryExport) {
  if (mMounted || mEngine.value) return Fail("Vault session already active");
  const auto directory = runtimeDirectory.empty()
                             ? ExecutableDirectory() + L"\\vault-runtime"
                             : runtimeDirectory;
  if (!PinRuntime(directory, mRuntime, mRuntimePins))
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
  const auto result = OpenLocked(root, recoveryExport);
  if (!result.Succeeded()) {
    StopEngine();
    mLock.Reset();
  }
  return result;
}

hello::Result ProfileVaultSession::OpenLocked(
    const std::wstring& root, const std::wstring& recoveryExport) {
  if (!Environment(L"CPPCRYPTFS_SESSIONID", L""))
    return Fail("Clear helper pipe override");
  mVault = root + L"\\vault";
  if (GetFileAttributesW(mVault.c_str()) == INVALID_FILE_ATTRIBUTES) {
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
      return Fail("Inspect encrypted vault", error);
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
  const bool recovered = !result.Succeeded();
  if (recovered) {
    if (result.status == NTE_USER_CANCELLED || result.status == ERROR_CANCELLED)
      return result;
    if (MessageBoxW(nullptr,
                    L"Windows Hello n'a pas ouvert la clé de ce coffre. "
                    L"Voulez-vous utiliser votre clé de récupération pour "
                    L"l'associer à nouveau à Windows Hello ?",
                    L"Thunderbird — récupération",
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) != IDYES)
      return Fail("Vault unlock canceled", ERROR_CANCELLED);
    if (!EnterRecoveryCode(secret))
      return Fail("Recovery canceled or invalid", ERROR_CANCELLED);
  }
  result = Mount(mVault + L"\\data", secret);
  if (!recovered) secret.Clear();
  if (!result.Succeeded()) return result;
  result = UpdateEnvelopeFromMount(mVault, mDrive + kMarker, envelope,
                                   recovered ? &secret : nullptr);
  if (!result.Succeeded()) return result;
  // Enrolling a replacement can spend time in the system Hello dialog.
  if (!OwnsMount()) return Fail("Encrypted filesystem is no longer mounted");
  mProfile = mDrive + L"\\Profile";
  if (!PrivateDirectory(mProfile) || !PrivateDirectory(mDrive + L"\\Temp"))
    return Fail("Create encrypted profile directories");
  return {ERROR_SUCCESS, "Encrypted profile mounted"};
}

hello::Result ProfileVaultSession::Mount(const std::wstring& data,
                                         const SecretKey& secret) {
  const auto controller = mRuntime + L"\\cppcryptfsctl.exe";
  if (!StartOwnedEngine(mRuntime + L"\\cppcryptfs.exe", mJob, mEngine))
    return Fail("Cannot own an exclusive cppcryptfs instance", GetLastError());
  const ULONGLONG start = GetTickCount64();
  auto ready = WaitForEnginePipe(mEngine.value, 30000);
  while (ready.Succeeded()) {
    // The command pipe can exist before the engine is ready to serve mounts.
    const DWORD listed = RunCommand(controller, {L"--list"}, nullptr, 3000);
    if (!listed) break;
    if (GetTickCount64() - start >= 30000)
      return Fail("Filesystem engine did not accept the readiness query",
                  listed);
    Sleep(100);
    ready = WaitForEnginePipe(mEngine.value, 5000);
  }
  if (!ready.Succeeded()) return ready;
  // Thunderbird persists absolute paths in account preferences. Changing the
  // mount letter between launches could redirect those paths outside the vault.
  // This test build reserves Z: and refuses to open if it is already occupied.
  ready = WaitForEnginePipe(mEngine.value, 5000);
  if (!ready.Succeeded()) return ready;
  const DWORD drives = GetLogicalDrives();
  if (!drives)
    return Fail("Check encrypted drive availability", GetLastError());
  if (drives & kDriveMask)
    return Fail("The encrypted test profile requires a free Z: drive",
                ERROR_ALREADY_ASSIGNED);
  const DWORD mounted =
      RunVerifiedMount(controller, data, mDrive, secret, mEngine.value);
  if (mounted || WaitForSingleObject(mEngine.value, 0) != WAIT_TIMEOUT)
    return Fail("Mount encrypted profile",
                mounted ? mounted : ERROR_PROCESS_ABORTED);
  mMounted = true;
  mDriveTarget = DriveTarget(mDrive);
  ready = WaitForEnginePipe(mEngine.value, 5000);
  if (!ready.Succeeded()) return ready;
  if (!VerifyMountedPolicy(controller, mDrive))
    return Fail("Verify encrypted filesystem policy");
  if (!OwnsMount()) return Fail("Confirm encrypted drive mapping");
  return {ERROR_SUCCESS, "Verified encrypted filesystem mount"};
}

bool ProfileVaultSession::OwnsMount() const {
  return mMounted && !mDriveTarget.empty() &&
         WaitForSingleObject(mEngine.value, 0) == WAIT_TIMEOUT &&
         DriveTarget(mDrive) == mDriveTarget;
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
  if (!OwnsMount() || !InstallEnvironment()) return false;
  for (int i = 1; i < argc; ++i)
    if (IsProfileOverride(argv[i])) return false;
  mArguments.clear();
  mPointers.clear();
  for (int i = 0; i < argc; ++i) mArguments.emplace_back(argv[i]);
  mArguments.emplace_back("-no-remote");
  mArguments.emplace_back("-profile");
  // The mount/profile components are deliberately ASCII and stable for Gecko.
  mArguments.emplace_back();
  for (wchar_t c : mProfile) mArguments.back() += static_cast<char>(c);
  for (auto& argument : mArguments) mPointers.push_back(argument.data());
  argc = static_cast<int>(mPointers.size());
  mPointers.push_back(nullptr);
  argv = mPointers.data();
  return true;
}

hello::Result ProfileVaultSession::Unmount() {
  const auto start = GetTickCount64();
  for (;;) {
    const auto ready = WaitForEnginePipe(mEngine.value, 5000);
    if (!ready.Succeeded()) return ready;
    if (!OwnsMount())
      return Fail("Identify owned drive before unmount",
                  ERROR_DEVICE_NOT_CONNECTED);
    const DWORD status = RunCommand(mRuntime + L"\\cppcryptfsctl.exe",
                                    {L"--unmount=" + mDrive}, nullptr, 10000);
    if (!status) break;
    if (GetTickCount64() - start >= 10000)
      return Fail("Request unmount from the owned filesystem engine", status);
    Sleep(200);
  }
  // The controller acknowledges unmount before the driver has necessarily
  // withdrawn its DOS device. Never publish a new vault until it is gone.
  const auto acknowledged = GetTickCount64();
  do {
    const DWORD drives = GetLogicalDrives();
    if (drives && !(drives & kDriveMask)) {
      mMounted = false;
      return {ERROR_SUCCESS, "Encrypted drive withdrawn"};
    }
    const auto target = DriveTarget(mDrive);
    if (!target.empty() && target != mDriveTarget)
      return Fail("Drive letter reassigned during unmount", ERROR_WRONG_DISK);
    Sleep(50);
  } while (GetTickCount64() - acknowledged < 15000);
  return Fail("Wait for encrypted drive withdrawal", ERROR_TIMEOUT);
}

void ProfileVaultSession::StopEngine() {
  // Closing the job withdraws only the mounts owned by this session, even
  // when startup failed or the engine is no longer answering its pipe.
  mJob.Reset();
  if (mEngine.value) WaitForSingleObject(mEngine.value, 5000);
  mEngine.Reset();
  mMounted = false;
  mDriveTarget.clear();
}

void ProfileVaultSession::Close() {
  mEngineWatch.Stop();
  // Give other applications time to finish I/O, then close our own job even
  // if an external handle still prevents a graceful unmount.
  if (mMounted) Unmount();
  StopEngine();
  mLock.Reset();
}

}  // namespace thunderbird::vault
