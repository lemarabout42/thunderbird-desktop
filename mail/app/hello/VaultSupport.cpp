/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "VaultSupport.h"

#include <bcrypt.h>
#include <sddl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstring>

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

bool VerifySha256(const std::wstring& path, const char* expected) {
  Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
  if (file.value == INVALID_HANDLE_VALUE) return false;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) != 0)
    return false;
  BCRYPT_HASH_HANDLE hash = nullptr;
  bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0;
  std::array<BYTE, 65536> buffer{};
  DWORD read = 0;
  while (ok) {
    if (!ReadFile(file.value, buffer.data(), static_cast<DWORD>(buffer.size()),
                  &read, nullptr)) {
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

DWORD RunCommand(const std::wstring& executable,
                 const std::vector<std::wstring>& arguments,
                 const SecretKey* secret, DWORD timeoutMs) {
  if (secret && !secret->IsValid()) return ERROR_INVALID_DATA;
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  Handle inputRead, inputWrite, outputRead, outputWrite;
  if (!CreatePipe(&inputRead.value, &inputWrite.value, &security, 4096) ||
      !CreatePipe(&outputRead.value, &outputWrite.value, &security, 4096) ||
      !SetHandleInformation(inputWrite.value, HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(outputRead.value, HANDLE_FLAG_INHERIT, 0))
    return GetLastError();
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  std::vector<BYTE> attributes(size);
  auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
  if (!InitializeProcThreadAttributeList(list, 1, 0, &size))
    return GetLastError();
  HANDLE allowed[]{inputRead.value, outputWrite.value};
  bool configured = UpdateProcThreadAttribute(
                        list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, allowed,
                        sizeof(allowed), nullptr, nullptr) != FALSE;
  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  startup.StartupInfo.wShowWindow = SW_HIDE;
  startup.StartupInfo.hStdInput = inputRead.value;
  startup.StartupInfo.hStdOutput = startup.StartupInfo.hStdError =
      outputWrite.value;
  startup.lpAttributeList = list;
  auto line = CommandLine(executable, arguments);
  const auto directory = executable.substr(0, executable.find_last_of(L"\\/"));
  PROCESS_INFORMATION info{};
  const BOOL created =
      configured &&
      CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, TRUE,
                     CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr,
                     directory.c_str(), &startup.StartupInfo, &info);
  DWORD error = created ? ERROR_SUCCESS : GetLastError();
  DeleteProcThreadAttributeList(list);
  if (!created) return error;
  Handle process(info.hProcess), thread(info.hThread);
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
  while (true) {
    DWORD available = 0;
    if (PeekNamedPipe(outputRead.value, nullptr, 0, nullptr, &available,
                      nullptr) &&
        available) {
      std::array<BYTE, 4096> discard{};
      DWORD read = 0;
      ReadFile(outputRead.value, discard.data(),
               (std::min)(available, static_cast<DWORD>(discard.size())), &read,
               nullptr);
      SecureZeroMemory(discard.data(), discard.size());
    }
    if (WaitForSingleObject(process.value, 20) == WAIT_OBJECT_0) break;
    if (GetTickCount64() - started > timeoutMs || error != ERROR_SUCCESS) {
      TerminateProcess(process.value, ERROR_TIMEOUT);
      WaitForSingleObject(process.value, 5000);
      return error ? error : ERROR_TIMEOUT;
    }
  }
  DWORD exitCode = 1;
  if (error) return error;
  return GetExitCodeProcess(process.value, &exitCode) ? exitCode
                                                      : GetLastError();
}

bool StartOwnedEngine(const std::wstring& executable, Handle& job,
                      Handle& process) {
  // cppcryptfs is single-instance per user. Never share or terminate an engine
  // belonging to another session, including a pre-existing personal mount.
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (snapshot.value == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot.value, &entry)) do {
      if (_wcsicmp(entry.szExeFile, L"cppcryptfs.exe") == 0) {
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
  auto line = CommandLine(executable, {L"--tray"});
  const auto directory = executable.substr(0, executable.find_last_of(L"\\/"));
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(executable.c_str(), line.data(), nullptr, nullptr, FALSE,
                      CREATE_SUSPENDED, nullptr, directory.c_str(), &startup,
                      &info))
    return false;
  process.Reset(info.hProcess);
  Handle thread(info.hThread);
  if (!AssignProcessToJobObject(job.value, process.value)) {
    TerminateProcess(process.value, ERROR_ACCESS_DENIED);
    return false;
  }
  return ResumeThread(thread.value) != static_cast<DWORD>(-1);
}

}  // namespace thunderbird::vault
