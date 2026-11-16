# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

[CmdletBinding()]
param(
    [string]$ZigPath,
    [string]$OutDir = (Join-Path ([System.IO.Path]::GetTempPath()) 'ThunderbirdHelloNativeTests')
)

$ErrorActionPreference = 'Stop'
if ($ZigPath) {
    $ZigPath = (Resolve-Path -LiteralPath $ZigPath).Path
}
$taskRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$taskOutput = (Resolve-Path -LiteralPath $OutDir).Path
$taskTests = @(
    @{
        Name = 'TestWindowsHello'
        Sources = @('mail/app/hello/tests/TestWindowsHello.cpp')
        Run = $true
    },
    @{
        Name = 'TestEncryptedBlob'
        Sources = @('mail/app/hello/tests/TestEncryptedBlob.cpp', 'mail/app/hello/EncryptedBlob.cpp')
        Run = $true
    },
    @{
        Name = 'HelloProbe'
        Sources = @('tools/windows-hello/HelloProbe.cpp', 'mail/app/WindowsHello.cpp')
        Run = $false
    }
)

Push-Location -LiteralPath $taskOutput
try {
    foreach ($taskTest in $taskTests) {
        $taskExe = Join-Path $taskOutput ($taskTest.Name + '.exe')
        $taskSources = @($taskTest.Sources | ForEach-Object { Join-Path $taskRepoRoot $_ })
        if ($ZigPath) {
            & $ZigPath c++ -std=c++17 -Wall -Wextra -Werror @taskSources -lbcrypt -lncrypt -ladvapi32 -o $taskExe
        } else {
            # Run from a Visual Studio Developer PowerShell. No Gecko SDK needed.
            & cl.exe /nologo /std:c++17 /EHsc /W4 /WX @taskSources /link bcrypt.lib ncrypt.lib advapi32.lib "/OUT:$taskExe"
        }
        if ($LASTEXITCODE -ne 0) {
            throw "Native compilation failed: $($taskTest.Name)"
        }
        if ($taskTest.Run) {
            & $taskExe
            if ($LASTEXITCODE -ne 0) {
                throw "Native test failed: $($taskTest.Name)"
            }
        }
    }
} finally {
    Pop-Location
}

Write-Output "Both native test executables passed. No user profile or Hello key was modified."
Write-Output "Manual hardware test (opens Windows Hello): $(Join-Path $taskOutput 'HelloProbe.exe') --authenticate"
