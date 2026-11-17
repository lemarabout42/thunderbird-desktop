# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Destination,
    [string]$Cache = (Join-Path $env:LOCALAPPDATA 'Codex\thunderbird-build-tools\vendor')
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Cache, $Destination -Force | Out-Null
$taskFiles = @(
    @{
        Name = 'cppcryptfs.exe'
        Url = 'https://github.com/bailey27/cppcryptfs/releases/download/v1.4.5.2/cppcryptfs.exe'
        Hash = 'e8721d8ad7f6c1c9c4b07442adf3a309e3e65516e1e9c579e1840817d4974b1f'
        Signed = $true
    },
    @{
        Name = 'cppcryptfsctl.exe'
        Url = 'https://github.com/bailey27/cppcryptfs/releases/download/v1.4.5.2/cppcryptfsctl.exe'
        Hash = '587be2317a762ba8bc0f374cff97530d38bafa9db033ad7690a9dc521d2651f5'
        Signed = $true
    },
    @{
        Name = 'Dokan_x64.msi'
        Url = 'https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/Dokan_x64.msi'
        Hash = '69ff8cb37bfec3a75921c85ffd1c6370b50a9ec4ecef2cf3a009d488dcbf5465'
        Signed = $true
    },
    @{
        Name = 'dokan.zip'
        Url = 'https://github.com/dokan-dev/dokany/releases/download/v2.3.1.1000/dokan.zip'
        Hash = 'cbfb89718d4e671f8dd65187912c1141fde0e5197f40ac2979b3216753d42c7c'
        Signed = $false
    }
)

foreach ($taskItem in $taskFiles) {
    $taskFile = Join-Path $Cache $taskItem.Name
    if (-not (Test-Path -LiteralPath $taskFile)) {
        Invoke-WebRequest -Uri $taskItem.Url -OutFile $taskFile
    }
    if ((Get-FileHash -LiteralPath $taskFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $taskItem.Hash) {
        throw "Checksum mismatch: $($taskItem.Name)"
    }
    if ($taskItem.Signed -and (Get-AuthenticodeSignature -LiteralPath $taskFile).Status -ne 'Valid') {
        throw "Invalid Authenticode signature: $($taskItem.Name)"
    }
    if ($taskItem.Name -ne 'dokan.zip') {
        Copy-Item -LiteralPath $taskFile -Destination (Join-Path $Destination $taskItem.Name) -Force
    }
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$taskZip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $Cache 'dokan.zip'))
try {
    $taskEntry = $taskZip.GetEntry('x64/Release/dokan2.dll')
    if (-not $taskEntry) { throw 'The pinned Dokan archive is missing its x64 DLL.' }
    $taskDll = Join-Path $Destination 'dokan2.dll'
    $taskInput = $taskEntry.Open()
    $taskOutput = [System.IO.File]::Create($taskDll)
    try { $taskInput.CopyTo($taskOutput) } finally { $taskOutput.Dispose(); $taskInput.Dispose() }
} finally { $taskZip.Dispose() }

if ((Get-FileHash -LiteralPath $taskDll -Algorithm SHA256).Hash.ToLowerInvariant() -ne
    '75600aba867acbdfdb85fcd142b524da769bdc611b855a760aeb0c6e2eaae17a' -or
    (Get-AuthenticodeSignature -LiteralPath $taskDll).Status -ne 'Valid') {
    throw 'Dokan DLL validation failed.'
}

# Dependency versions are deliberately pinned. This script never installs the
# driver or changes system configuration; installation belongs to the user.
$taskFiles | Select-Object Name, Url, Hash | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $Destination 'provenance.json') -Encoding utf8
$taskLicenses = @(
    @{Name='cppcryptfs-LICENSE.txt';Url='https://raw.githubusercontent.com/bailey27/cppcryptfs/v1.4.5.2/LICENSE.txt'},
    @{Name='Dokan-LGPL.txt';Url='https://raw.githubusercontent.com/dokan-dev/dokany/v2.3.1.1000/license.lgpl.txt'},
    @{Name='Dokan-MIT.txt';Url='https://raw.githubusercontent.com/dokan-dev/dokany/v2.3.1.1000/license.mit.txt'}
)
foreach ($taskLicense in $taskLicenses) {
    Invoke-WebRequest -Uri $taskLicense.Url -OutFile (Join-Path $Destination $taskLicense.Name)
}
Write-Output "Verified cppcryptfs 1.4.5.2 and Dokan 2.3.1 runtime prepared: $Destination"
