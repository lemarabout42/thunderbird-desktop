/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "VaultSupport.h"

#include <bcrypt.h>
#include <psapi.h>
#include <sddl.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wintrust.h>

#include <algorithm>
#include <cstring>
#include <string_view>
#include <utility>

namespace thunderbird::vault {
namespace {
constexpr std::array<BYTE, 8> kEnvelopeMagic{'T', 'B', 'H', 'K',
                                             'E', 'Y', 2,   1};
constexpr char kRecoveryMagic[] = "THUNDERBIRD-HELLO-RECOVERY-V1\n";

std::wstring CommandLine(const std::wstring& executable,
                         const std::vector<std::wstring>& args) {
  std::wstring line = QuoteArgument(executable);
  for (const auto& arg : args) line += L" " + QuoteArgument(arg);
  return line;
}
}  // namespace

std::string Hex(const BYTE* bytes, size_t length) {
  constexpr char digits[] = "0123456789abcdef";
  std::string result;
  result.reserve(length * 2);
  for (size_t i = 0; i < length; ++i) {
    result += digits[bytes[i] >> 4];
    result += digits[bytes[i] & 15];
  }
  return result;
}

bool ParseHex(const std::string& text, BYTE* bytes, size_t length) {
  if (text.size() != length * 2) return false;
  const auto digit = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
  };
  for (size_t i = 0; i < length; ++i) {
    const int high = digit(text[i * 2]);
    const int low = digit(text[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    bytes[i] = static_cast<BYTE>(high * 16 + low);
  }
  return true;
}

std::vector<BYTE> EncodeEnvelope(const Envelope& envelope) {
  if (envelope.wrapped.size() != 512) return {};
  std::vector<BYTE> bytes(kEnvelopeMagic.begin(), kEnvelopeMagic.end());
  bytes.insert(bytes.end(), envelope.vaultId.begin(), envelope.vaultId.end());
  bytes.insert(bytes.end(), envelope.protectorId.begin(),
               envelope.protectorId.end());
  bytes.insert(bytes.end(), envelope.wrapped.begin(), envelope.wrapped.end());
  return bytes;
}

bool DecodeEnvelope(const std::vector<BYTE>& bytes, Envelope& envelope) {
  if (bytes.size() != 552 ||
      !std::equal(kEnvelopeMagic.begin(), kEnvelopeMagic.end(), bytes.begin()))
    return false;
  std::copy_n(bytes.begin() + 8, 16, envelope.vaultId.begin());
  std::copy_n(bytes.begin() + 24, 16, envelope.protectorId.begin());
  envelope.wrapped.assign(bytes.begin() + 40, bytes.end());
  return true;
}

std::string EncodeRecovery(const hello::VaultId& id, const SecretKey& secret) {
  if (!secret.IsValid()) return {};
  return std::string(kRecoveryMagic) + Hex(id.data(), id.size()) + "\n" +
         Hex(secret.Bytes().data(), secret.Bytes().size()) + "\n";
}

bool DecodeRecovery(const std::vector<BYTE>& bytes, const hello::VaultId& id,
                    SecretKey& secret) {
  hello::VaultId recovered{};
  const bool valid =
      DecodeRecoveryDocument(bytes, recovered, secret) && recovered == id;
  if (!valid) secret.Clear();
  return valid;
}

bool DecodeRecoveryDocument(const std::vector<BYTE>& bytes, hello::VaultId& id,
                            SecretKey& secret) {
  secret.Clear();
  // Fixed encoding prevents accepting a truncated key or a different vault.
  if (bytes.size() != sizeof(kRecoveryMagic) - 1 + 32 + 1 + 64 + 1)
    return false;
  std::string text(bytes.begin(), bytes.end());
  const std::string prefix = kRecoveryMagic;
  std::array<BYTE, 32> raw{};
  bool valid =
      text.compare(0, prefix.size(), prefix) == 0 &&
      text[prefix.size() + 32] == '\n' && text.back() == '\n' &&
      ParseHex(text.substr(prefix.size(), 32), id.data(), id.size()) &&
      ParseHex(text.substr(prefix.size() + 33, 64), raw.data(), raw.size());
  if (valid) valid = secret.Import(raw.data(), raw.size());
  SecureZeroMemory(raw.data(), raw.size());
  SecureZeroMemory(text.data(), text.size());
  return valid;
}

std::wstring QuoteArgument(const std::wstring& value) {
  std::wstring result = L"\"";
  size_t slashes = 0;
  for (wchar_t c : value) {
    if (c == L'\\') {
      ++slashes;
    } else {
      result.append(slashes * (c == L'\"' ? 2 : 1), L'\\');
      slashes = 0;
      if (c == L'\"') result += L'\\';
      result += c;
    }
  }
  result.append(slashes * 2, L'\\');
  return result + L'\"';
}

bool IsProfileOverride(const char* argument) {
  if (!argument || (*argument != '-' && *argument != '/')) return false;
  ++argument;
  if (*argument == '-') ++argument;
  std::string name(argument);
  const auto separator = name.find_first_of("=:");
  if (separator != std::string::npos) name.resize(separator);
  for (char& c : name)
    if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
  for (const char* blocked :
       {"profile", "p", "profilemanager", "createprofile", "app", "xpcshell",
        "migration", "reset-profile", "backgroundtask"}) {
    if (name == blocked) return true;
  }
  return false;
}

bool ReadSmallFile(const std::wstring& path, size_t limit,
                   std::vector<BYTE>& bytes) {
  bytes.clear();
  Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT,
                          nullptr));
  if (file.value == INVALID_HANDLE_VALUE) return false;
  BY_HANDLE_FILE_INFORMATION info{};
  LARGE_INTEGER size{};
  if (!GetFileInformationByHandle(file.value, &info) ||
      (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
      !GetFileSizeEx(file.value, &size) || size.QuadPart < 0 ||
      static_cast<ULONGLONG>(size.QuadPart) > limit)
    return false;
  bytes.resize(static_cast<size_t>(size.QuadPart));
  DWORD read = 0;
  if (!ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()),
                &read, nullptr) ||
      read != bytes.size()) {
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    bytes.clear();
    return false;
  }
  return true;
}

bool WriteNewFile(const std::wstring& path, const BYTE* bytes, size_t size) {
  Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                          nullptr));
  if (file.value == INVALID_HANDLE_VALUE || size > MAXDWORD) return false;
  DWORD written = 0;
  return WriteFile(file.value, bytes, static_cast<DWORD>(size), &written,
                   nullptr) &&
         written == size && FlushFileBuffers(file.value);
}

namespace {
bool VerifySha256(HANDLE file, const char* expected) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) != 0)
    return false;
  BCRYPT_HASH_HANDLE hash = nullptr;
  bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0;
  std::array<BYTE, 65536> buffer{};
  DWORD read = 0;
  while (ok) {
    if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                  nullptr)) {
      ok = false;
      break;
    }
    if (!read) break;
    ok = BCryptHashData(hash, buffer.data(), read, 0) == 0;
  }
  std::array<BYTE, 32> digest{};
  if (ok)
    ok = BCryptFinishHash(hash, digest.data(),
                          static_cast<ULONG>(digest.size()), 0) == 0;
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return ok && Hex(digest.data(), digest.size()) == expected;
}

bool OpenRuntimePath(const std::wstring& path, bool directory, Handle& pin) {
  const DWORD access =
      directory ? FILE_TRAVERSE | FILE_READ_ATTRIBUTES : GENERIC_READ;
  const DWORD flags =
      directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_FLAG_SEQUENTIAL_SCAN;
  pin.Reset(CreateFileW(path.c_str(), access, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, flags | FILE_FLAG_OPEN_REPARSE_POINT,
                        nullptr));
  FILE_ATTRIBUTE_TAG_INFO info{};
  return pin.value != INVALID_HANDLE_VALUE &&
         GetFileType(pin.value) == FILE_TYPE_DISK &&
         GetFileInformationByHandleEx(pin.value, FileAttributeTagInfo, &info,
                                      sizeof(info)) &&
         bool(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == directory &&
         (!(info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
          !IsReparseTagNameSurrogate(info.ReparseTag));
}

std::wstring HandlePath(HANDLE file, DWORD volumeFormat) {
  const DWORD size = GetFinalPathNameByHandleW(file, nullptr, 0, volumeFormat);
  if (!size) return {};
  std::wstring path(size, L'\0');
  const DWORD length =
      GetFinalPathNameByHandleW(file, path.data(), size, volumeFormat);
  if (!length || length >= size) return {};
  path.resize(length);
  return path;
}
}  // namespace

bool PinVerifiedRuntime(const std::wstring& directory,
                        std::initializer_list<RuntimeFile> files,
                        std::wstring& launchDirectory,
                        std::vector<Handle>& pins) {
  if (!files.size()) return false;
  // Resolve drive aliases and directory junctions once. Require a local
  // mount-manager volume and pin the files in its global kernel namespace.
  Handle location(
      CreateFileW(directory.c_str(), FILE_READ_ATTRIBUTES,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (location.value == INVALID_HANDLE_VALUE ||
      !GetFinalPathNameByHandleW(location.value, nullptr, 0,
                                 VOLUME_NAME_GUID)) {
    return false;
  }
  auto path = HandlePath(location.value, VOLUME_NAME_NT);
  if (path.empty()) return false;
  path.insert(0, L"\\\\?\\GLOBALROOT");
  constexpr std::wstring_view deviceRoot = L"\\\\?\\GLOBALROOT\\Device\\";
  const auto root = path.find(L'\\', deviceRoot.size());
  if (path.compare(0, deviceRoot.size(), deviceRoot) != 0 ||
      root == std::wstring::npos) {
    return false;
  }

  // Pin the names from the volume root downwards before looking up any file.
  // A file handle alone cannot prevent substitution of a parent directory.
  std::vector<Handle> held;
  for (size_t start = root + 1; start < path.size();) {
    const auto end = path.find(L'\\', start);
    Handle parent;
    if (!OpenRuntimePath(path.substr(0, end), true, parent)) return false;
    held.push_back(std::move(parent));
    if (end == std::wstring::npos) break;
    start = end + 1;
  }
  if (path.back() == L'\\') path.pop_back();
  for (const auto& file : files) {
    if (!file.name || !*file.name || wcspbrk(file.name, L"\\/:") ||
        !wcscmp(file.name, L".") || !wcscmp(file.name, L"..") || !file.sha256) {
      return false;
    }
    Handle pin;
    if (!OpenRuntimePath(path + L"\\" + file.name, false, pin) ||
        !VerifySha256(pin.value, file.sha256)) {
      return false;
    }
    held.push_back(std::move(pin));
  }
  launchDirectory = std::move(path);
  pins = std::move(held);
  return true;
}

bool PrivateDirectory(const std::wstring& path) {
  Handle token;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value))
    return false;
  DWORD needed = 0;
  GetTokenInformation(token.value, TokenUser, nullptr, 0, &needed);
  if (!needed) return false;
  std::vector<BYTE> user(needed);
  if (!GetTokenInformation(token.value, TokenUser, user.data(), needed,
                           &needed))
    return false;
  LPWSTR sid = nullptr;
  if (!ConvertSidToStringSidW(
          reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid))
    return false;
  const std::wstring sddl =
      L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    return false;
  SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
  bool ok = CreateDirectoryW(path.c_str(), &security) ||
            GetLastError() == ERROR_ALREADY_EXISTS;
  const DWORD attributes = GetFileAttributesW(path.c_str());
  ok = ok && attributes != INVALID_FILE_ATTRIBUTES &&
       (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
       !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
  if (ok)
    ok = SetFileSecurityW(
             path.c_str(),
             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
             descriptor) != FALSE;
  LocalFree(descriptor);
  return ok;
}

namespace {
bool HasTrustedControllerSignature(HANDLE process) {
  // Use the same path lookup and size limit as cppcryptfsctl so it can
  // authenticate its own signature even when the package path is long.
  wchar_t path[MAX_PATH]{};
  const DWORD length =
      K32GetModuleFileNameExW(process, nullptr, path, MAX_PATH);
  if (!length || length >= MAX_PATH) return false;
  WINTRUST_FILE_INFO file{};
  file.cbStruct = sizeof(file);
  file.pcwszFilePath = path;
  WINTRUST_DATA trust{};
  trust.cbStruct = sizeof(trust);
  trust.dwUIChoice = WTD_UI_NONE;
  trust.fdwRevocationChecks = WTD_REVOKE_NONE;
  trust.dwUnionChoice = WTD_CHOICE_FILE;
  trust.pFile = &file;
  trust.dwStateAction = WTD_STATEACTION_VERIFY;
  GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  const auto module =
      LoadLibraryExW(L"wintrust.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!module) return false;
  const auto address = GetProcAddress(module, "WinVerifyTrust");
  decltype(&WinVerifyTrust) verify = nullptr;
  static_assert(sizeof(verify) == sizeof(address));
  std::memcpy(&verify, &address, sizeof(verify));
  LONG status = TRUST_E_PROVIDER_UNKNOWN;
  if (verify) {
    status = verify(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    verify(nullptr, &policy, &trust);
  }
  FreeLibrary(module);
  return status == ERROR_SUCCESS;
}

// The signed helpers require a Win32 drive path for their manifests. Check
// the image Windows actually mapped against the pinned kernel path before
// allowing either the engine or the controller to execute.
bool CreateSuspendedHelper(const std::wstring& executable,
                           const std::vector<std::wstring>& arguments,
                           BOOL inheritHandles, DWORD flags,
                           STARTUPINFOW* startup, PROCESS_INFORMATION& info,
                           bool requireTrustedSignature = false) {
  Handle image;
  if (!OpenRuntimePath(executable, false, image)) return false;
  const auto expected = HandlePath(image.value, VOLUME_NAME_NT);
  auto path = HandlePath(image.value, VOLUME_NAME_DOS);
  if (expected.empty() || path.compare(0, 4, L"\\\\?\\") != 0 ||
      path.size() < 7 || path[5] != L':' || path[6] != L'\\') {
    SetLastError(ERROR_BAD_PATHNAME);
    return false;
  }
  path.erase(0, 4);
  auto line = CommandLine(path, arguments);
  const auto directory = path.substr(0, path.find_last_of(L'\\') + 1);
  if (!CreateProcessW(path.c_str(), line.data(), nullptr, nullptr,
                      inheritHandles, flags | CREATE_SUSPENDED, nullptr,
                      directory.c_str(), startup, &info)) {
    return false;
  }
  std::wstring mapped(32768, L'\0');
  DWORD length = static_cast<DWORD>(mapped.size());
  if (QueryFullProcessImageNameW(info.hProcess, PROCESS_NAME_NATIVE,
                                 mapped.data(), &length) &&
      expected == std::wstring_view(mapped.data(), length) &&
      (!requireTrustedSignature ||
       HasTrustedControllerSignature(info.hProcess))) {
    return true;
  }
  TerminateProcess(info.hProcess, ERROR_INVALID_IMAGE_HASH);
  CloseHandle(info.hThread);
  CloseHandle(info.hProcess);
  SetLastError(ERROR_INVALID_IMAGE_HASH);
  return false;
}

DWORD RunCommandInternal(const std::wstring& executable,
                         const std::vector<std::wstring>& arguments,
                         const SecretKey* secret, DWORD timeoutMs,
                         std::vector<BYTE>* mountInfo,
                         HANDLE engine = nullptr) {
  if (secret && !secret->IsValid()) return ERROR_INVALID_DATA;
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  Handle inputRead, inputWrite, outputRead, outputWrite;
  if (!CreatePipe(&inputRead.value, &inputWrite.value, &security, 4096) ||
      !CreatePipe(&outputRead.value, &outputWrite.value, &security, 4096) ||
      !SetHandleInformation(inputWrite.value, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(outputRead.value, HANDLE_FLAG_INHERIT, 0))
    return GetLastError();
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 2, 0, &size);
  std::vector<BYTE> attributes(size);
  auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
  if (!InitializeProcThreadAttributeList(list, 2, 0, &size))
    return GetLastError();
  HANDLE allowed[]{inputRead.value, outputWrite.value};
  // The controller depends only on Windows DLLs, including WinTrust.
  DWORD64 imagePolicy =
      PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
  const bool configured =
      UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                allowed, sizeof(allowed), nullptr, nullptr) &&
      UpdateProcThreadAttribute(
          list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &imagePolicy,
          sizeof(imagePolicy), nullptr, nullptr);
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = inputRead.value;
  startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError =
      outputWrite.value;
  startup.lpAttributeList = list;
  PROCESS_INFORMATION info{};
  const BOOL created =
      configured &&
      CreateSuspendedHelper(executable, arguments, TRUE,
                            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                            &startup.StartupInfo, info, engine != nullptr);
  DWORD error = created ? ERROR_SUCCESS : GetLastError();
  DeleteProcThreadAttributeList(list);
  if (!created) return error ? error : ERROR_OPEN_FAILED;
  Handle process(info.hProcess), thread(info.hThread);
  if (engine && WaitForSingleObject(engine, 0) != WAIT_TIMEOUT) {
    TerminateProcess(process.value, ERROR_PROCESS_ABORTED);
    return ERROR_PROCESS_ABORTED;
  }
  if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) {
    error = GetLastError();
    TerminateProcess(process.value, ERROR_PROCESS_ABORTED);
    return error ? error : ERROR_PROCESS_ABORTED;
  }
  inputRead.Reset();
  outputWrite.Reset();
  if (secret) {
    std::array<char, 65> password{};
    constexpr char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
      password[i * 2] = digits[secret->Bytes()[i] >> 4];
      password[i * 2 + 1] = digits[secret->Bytes()[i] & 15];
    }
    password.back() = '\n';
    DWORD written = 0;
    const BOOL sent =
        WriteFile(inputWrite.value, password.data(),
                  static_cast<DWORD>(password.size()), &written, nullptr);
    SecureZeroMemory(password.data(), password.size());
    if (!sent || written != password.size()) error = ERROR_WRITE_FAULT;
  }
  inputWrite.Reset();
  const ULONGLONG started = GetTickCount64();
  const HANDLE processes[]{process.value, engine};
  bool exited = false;
  while (true) {
    DWORD available = 0;
    if (!PeekNamedPipe(outputRead.value, nullptr, 0, nullptr, &available,
                       nullptr)) {
      const DWORD pipeError = GetLastError();
      if (pipeError != ERROR_BROKEN_PIPE) error = pipeError;
    }
    if (available) {
      std::array<BYTE, 4096> buffer{};
      DWORD read = 0;
      if (!ReadFile(outputRead.value, buffer.data(),
                    (std::min)(available, static_cast<DWORD>(buffer.size())),
                    &read, nullptr) ||
          !read) {
        error = ERROR_READ_FAULT;
      } else if (mountInfo) {
        constexpr size_t maxInfoBytes = 256 * 1024;
        if (read > maxInfoBytes - mountInfo->size()) {
          error = ERROR_BUFFER_OVERFLOW;
        } else {
          mountInfo->insert(mountInfo->end(), buffer.begin(),
                            buffer.begin() + read);
        }
      }
      SecureZeroMemory(buffer.data(), buffer.size());
    } else if (exited) {
      break;
    }
    if (GetTickCount64() - started > timeoutMs || error != ERROR_SUCCESS) {
      TerminateProcess(process.value, error ? error : ERROR_TIMEOUT);
      WaitForSingleObject(process.value, 5000);
      return error ? error : ERROR_TIMEOUT;
    }
    const DWORD interval = available ? 0 : 20;
    const DWORD wait =
        engine ? WaitForMultipleObjects(2, processes, FALSE, interval)
               : WaitForSingleObject(process.value, interval);
    if (wait == WAIT_FAILED) {
      error = GetLastError();
    } else if (wait == WAIT_OBJECT_0 + 1) {
      error = ERROR_PROCESS_ABORTED;
    }
    exited = wait == WAIT_OBJECT_0;
  }
  DWORD exitCode = 1;
  if (error) return error;
  return GetExitCodeProcess(process.value, &exitCode) ? exitCode
                                                      : GetLastError();
}

// The pinned controller emits UTF-16LE. Its public --info response describes
// the mounted filesystem, including options read from its on-disk config.
bool ProtectedMountInfo(const std::vector<BYTE>& bytes) {
  if (bytes.empty() || bytes.size() % sizeof(wchar_t)) return false;
  std::wstring info(bytes.size() / sizeof(wchar_t), L'\0');
  std::memcpy(info.data(), bytes.data(), bytes.size());
  if (info.find(L'\0') != std::wstring::npos) return false;

  using Field = std::pair<std::wstring_view, std::wstring_view>;
  constexpr Field required[] = {{L"Mode", L"forward"},
                                {L"Data Encryption", L"AES256-GCM"},
                                {L"File Name Encryption", L"AES256-EME"},
                                {L"Deny other sessions", L"Yes"},
                                {L"Deny services", L"Yes"}};
  std::array<bool, std::size(required)> seen{};
  std::wstring_view remaining(info);
  if (remaining.front() == L'\uFEFF') remaining.remove_prefix(1);
  while (!remaining.empty()) {
    const auto newline = remaining.find(L'\n');
    const auto line = remaining.substr(0, newline);
    remaining.remove_prefix(newline == remaining.npos ? remaining.size()
                                                      : newline + 1);
    const auto colon = line.find(L':');
    if (colon == line.npos) continue;
    const auto name = line.substr(0, colon);
    for (size_t i = 0; i < seen.size(); ++i) {
      if (name != required[i].first) continue;
      const auto value = line.substr(colon + 1);
      const auto first = value.find_first_not_of(L" \t");
      const auto last = value.find_last_not_of(L" \t\r");
      if (seen[i] || first == value.npos || last == value.npos ||
          value.substr(first, last - first + 1) != required[i].second) {
        return false;
      }
      seen[i] = true;
    }
  }
  return std::all_of(seen.begin(), seen.end(),
                     [](bool found) { return found; });
}
}  // namespace

DWORD RunCommand(const std::wstring& executable,
                 const std::vector<std::wstring>& arguments,
                 const SecretKey* secret, DWORD timeoutMs) {
  return RunCommandInternal(executable, arguments, secret, timeoutMs, nullptr);
}

DWORD RunVerifiedMount(const std::wstring& controller, const std::wstring& data,
                       const std::wstring& drive, const SecretKey& secret,
                       HANDLE engine) {
  if (!engine) return ERROR_INVALID_HANDLE;
  // cppcryptfsctl authenticates its actual pipe peer only when Windows
  // trusts its own executable's signature.
  return RunCommandInternal(controller,
                            {L"--mount=" + data, L"--drive=" + drive,
                             L"--deny-other-sessions=1", L"--deny-services=1"},
                            &secret, 60000, nullptr, engine);
}

bool VerifyMountedPolicy(const std::wstring& executable,
                         const std::wstring& drive) {
  std::vector<BYTE> info;
  return RunCommandInternal(executable, {L"--info=" + drive}, nullptr, 10000,
                            &info) == ERROR_SUCCESS &&
         ProtectedMountInfo(info);
}

bool IsEngineInSession(const wchar_t* imageName, DWORD processId,
                       DWORD session) {
  DWORD processSession = 0;
  return _wcsicmp(imageName, L"cppcryptfs.exe") == 0 &&
         ProcessIdToSessionId(processId, &processSession) &&
         processSession == session;
}

bool StartOwnedEngine(const std::wstring& executable, Handle& job,
                      Handle& process) {
  // cppcryptfs names its control pipe by Windows session. An instance in
  // another session has its own endpoint and can continue independently.
  DWORD session = 0;
  if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return false;
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (snapshot.value == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot.value, &entry)) do {
      if (IsEngineInSession(entry.szExeFile, entry.th32ProcessID, session)) {
        SetLastError(ERROR_ALREADY_EXISTS);
        return false;
      }
    } while (Process32NextW(snapshot.value, &entry));
  job.Reset(CreateJobObjectW(nullptr, nullptr));
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job.value ||
      !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation,
                               &limits, sizeof(limits)))
    return false;
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION info{};
  if (!CreateSuspendedHelper(executable, {L"--tray"}, FALSE, 0, &startup, info))
    return false;
  process.Reset(info.hProcess);
  Handle thread(info.hThread);
  if (!AssignProcessToJobObject(job.value, process.value)) {
    TerminateProcess(process.value, ERROR_ACCESS_DENIED);
    return false;
  }
  return ResumeThread(thread.value) != static_cast<DWORD>(-1);
}

namespace {
void CALLBACK EngineExited(PTP_CALLBACK_INSTANCE, void*, PTP_WAIT,
                           TP_WAIT_RESULT) {
  // Gecko can reopen files by their drive letter. Once its filesystem engine
  // dies, even ordinary shutdown writes could target a reassigned letter.
  TerminateProcess(GetCurrentProcess(), ERROR_DEVICE_NOT_CONNECTED);
}
}  // namespace

bool EngineWatch::Start(HANDLE engine) {
  if (mWait || !engine || WaitForSingleObject(engine, 0) != WAIT_TIMEOUT)
    return false;
  mWait = CreateThreadpoolWait(EngineExited, nullptr, nullptr);
  if (!mWait) return false;
  SetThreadpoolWait(mWait, engine, nullptr);
  return WaitForSingleObject(engine, 0) == WAIT_TIMEOUT;
}

void EngineWatch::Stop() {
  if (!mWait) return;
  SetThreadpoolWait(mWait, nullptr, nullptr);
  WaitForThreadpoolWaitCallbacks(mWait, TRUE);
  CloseThreadpoolWait(mWait);
  mWait = nullptr;
}

}  // namespace thunderbird::vault
