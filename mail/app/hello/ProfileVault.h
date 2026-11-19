/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mail_app_hello_ProfileVault_h
#define mail_app_hello_ProfileVault_h

#include "VaultSupport.h"

namespace thunderbird::vault {

class ProfileVaultSession {
 public:
  ProfileVaultSession() = default;
  ~ProfileVaultSession();
  ProfileVaultSession(const ProfileVaultSession&) = delete;
  ProfileVaultSession& operator=(const ProfileVaultSession&) = delete;

  // The default root is a new, isolated test profile under LocalAppData.
  // Explicit paths are for the native integration harness, not app arguments.
  hello::Result Open(const std::wstring& runtimeDirectory = L"",
                     const std::wstring& dataRoot = L"",
                     const std::wstring& recoveryExport = L"");
  bool PrepareArguments(int& argc, char**& argv);
  bool WatchEngine() { return mMounted && mEngineWatch.Start(mEngine.value); }
  void Close();
  const std::wstring& ProfilePath() const { return mProfile; }
  const std::wstring& VaultPath() const { return mVault; }

 private:
  hello::Result OpenLocked(const std::wstring& root,
                           const std::wstring& recoveryExport);
  hello::Result Create(const std::wstring& root,
                       const std::wstring& recoveryExport);
  hello::Result Mount(const std::wstring& data, const SecretKey& secret);
  bool OwnsMount() const;
  hello::Result Unmount();
  void StopEngine();
  bool InstallEnvironment();
  std::wstring mRuntime;
  std::vector<Handle> mRuntimePins;
  std::wstring mVault;
  const std::wstring mDrive = L"Z:";
  std::wstring mDriveTarget;
  std::wstring mProfile;
  Handle mLock;
  Handle mJob;
  Handle mEngine;
  bool mMounted = false;
  std::vector<std::string> mArguments;
  std::vector<char*> mPointers;
  EngineWatch mEngineWatch;
};

}  // namespace thunderbird::vault

#endif
