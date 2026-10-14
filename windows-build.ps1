#Requires -Version 7.0
<#
Builds a credential-free Windows x64 client. The only enrollment input is a
32-byte PUBLIC verification key. Private profiles are attached locally later.
This script does not sign, publish, install, or launch the produced client.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$NativeDir,
    [Parameter(Mandatory = $true)][string]$PublicKeyFile,
    [Parameter(Mandatory = $true)][string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$RustDeskCommit = '6c578292e8ebbbec708b76986ba8c4bc7c509747'
$HbbCommonCommit = '7e1c392c62d39c364127307cd408421dd5f8cfb0'
$VcpkgCommit = '120deac3062162151622ca4860575a33844ba10b'
$EngineUrl = 'https://github.com/rustdesk/engine/releases/download/main/windows-x64-release.zip'
# Observed 2026-10-14: upstream release asset 210168939, 63,301,215 bytes.
# The mutable URL must never silently select different engine bytes.
$EngineSha256 = 'ec8cabf36ee4ff24c8d98de25b00e70781eb03876265aee84d0fe554a110036e'
$ExpectedRust = '1.93.0'
$ExpectedFlutter = '3.24.5'

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE." }
}

function Get-CheckedText {
    param([string]$Program, [string[]]$Arguments)
    $result = & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE." }
    return ($result -join "`n").Trim()
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-File([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Required file is missing: $Path" }
}

if (-not $IsWindows -or -not [Environment]::Is64BitOperatingSystem) {
    throw 'This build requires Windows x64 and PowerShell 7.'
}
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path
$NativeDir = (Resolve-Path -LiteralPath $NativeDir).Path
$PublicKeyFile = (Resolve-Path -LiteralPath $PublicKeyFile).Path
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$keyBytes = [IO.File]::ReadAllBytes($PublicKeyFile)
if ($keyBytes.Length -ne 32 -or @($keyBytes | Where-Object { $_ -ne 0 }).Count -eq 0) {
    throw 'A nonzero 32-byte public verification key is required.'
}
Assert-File (Join-Path $NativeDir 'apply_patch.py')
Assert-File (Join-Path $NativeDir 'make_source_bundle.py')
if (Test-Path -LiteralPath $OutputDir) {
    if (@(Get-ChildItem -LiteralPath $OutputDir -Force).Count -ne 0) {
        throw 'OutputDir must be empty; existing release files are never overwritten.'
    }
} else { New-Item -ItemType Directory -Path $OutputDir | Out-Null }

$actualCommit = Get-CheckedText 'git' @('-C', $SourceDir, 'rev-parse', 'HEAD')
$actualHbb = Get-CheckedText 'git' @('-C', (Join-Path $SourceDir 'libs/hbb_common'), 'rev-parse', 'HEAD')
if ($actualCommit -cne $RustDeskCommit -or $actualHbb -cne $HbbCommonCommit) {
    throw 'RustDesk or hbb_common source does not match the audited commits.'
}
if ((Get-CheckedText 'rustc' @('--version')) -notmatch "^rustc $([regex]::Escape($ExpectedRust)) ") {
    throw "Install the pinned Rust $ExpectedRust toolchain before building."
}
Invoke-Checked 'python' @('-c', 'import sys; assert sys.version_info >= (3,11), "Python 3.11+ is required"')
$clang = (Get-Command 'clang.exe' -CommandType Application -ErrorAction Stop).Source
if ((Get-CheckedText $clang @('--version')) -notmatch '^clang version 15\.0\.6\b') {
    throw 'Install the pinned LLVM 15.0.6 toolchain before building.'
}
$env:LIBCLANG_PATH = Split-Path -Parent $clang
if (-not $env:FLUTTER_ROOT) { throw 'FLUTTER_ROOT must name the pinned Flutter SDK.' }
$flutterRoot = (Resolve-Path -LiteralPath $env:FLUTTER_ROOT).Path
$flutter = Join-Path $flutterRoot 'bin/flutter.bat'
$flutterInfo = (Get-CheckedText $flutter @('--version', '--machine')) | ConvertFrom-Json
if ($flutterInfo.frameworkVersion -cne $ExpectedFlutter) { throw 'Unexpected Flutter SDK version.' }

$toolRoot = Join-Path ([IO.Path]::GetTempPath()) ('retailcontrol-native-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $toolRoot | Out-Null
$env:VCPKG_ROOT = Join-Path $toolRoot 'vcpkg'
$env:VCPKG_BINARY_SOURCES = 'clear'
$env:VCPKG_DEFAULT_TRIPLET = 'x64-windows-static'
$env:VCPKG_DEFAULT_HOST_TRIPLET = 'x64-windows-static'
$env:VCPKG_FEATURE_FLAGS = 'manifests,versions'
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
$env:DART_SUPPRESS_ANALYTICS = 'true'

Push-Location $SourceDir
try {
    Write-Host 'Preparing the public source and verification key.'
    Invoke-Checked 'python' @((Join-Path $NativeDir 'apply_patch.py'), '--source-dir', $SourceDir, '--public-key-file', $PublicKeyFile)
    # Both applications belong to the root Cargo workspace. Resolve the new
    # local dependency without a blanket update of unrelated locked packages.
    Invoke-Checked 'cargo' @('update', '--workspace')
    # Cargo ignores this historical child lock inside the workspace. Keep its
    # shipped copy synchronized so the source offer is not misleading.
    Copy-Item -LiteralPath (Join-Path $SourceDir 'Cargo.lock') -Destination (Join-Path $SourceDir 'libs/portable/Cargo.lock') -Force
    Invoke-Checked 'cargo' @('test', '--locked', '-p', 'retailcontrol-profile')

    Write-Host 'Preparing the pinned native and Flutter dependencies.'
    Invoke-Checked 'git' @('clone', '--filter=blob:none', '--no-checkout', 'https://github.com/microsoft/vcpkg.git', $env:VCPKG_ROOT)
    Invoke-Checked 'git' @('-C', $env:VCPKG_ROOT, 'checkout', '--detach', $VcpkgCommit)
    if ((Get-CheckedText 'git' @('-C', $env:VCPKG_ROOT, 'rev-parse', 'HEAD')) -cne $VcpkgCommit) {
        throw 'Unexpected vcpkg checkout.'
    }
    Invoke-Checked (Join-Path $env:VCPKG_ROOT 'bootstrap-vcpkg.bat') @('-disableMetrics')
    # This support client uses software codecs. Do not compile optional GPU
    # codecs or download virtual-monitor, printer, or privacy-mode drivers.
    $vcpkgManifestPath = Join-Path $SourceDir 'vcpkg.json'
    $vcpkgManifest = Get-Content -LiteralPath $vcpkgManifestPath -Raw | ConvertFrom-Json
    if ($vcpkgManifest.'vcpkg-configuration'.'default-registry'.baseline -cne $VcpkgCommit) {
        throw 'The source vcpkg baseline does not match the pinned build toolchain.'
    }
    $vcpkgManifest.dependencies = @($vcpkgManifest.dependencies | Where-Object {
        $dependencyName = if ($_ -is [string]) { $_ } else { $_.name }
        $dependencyName -notin @('ffmpeg', 'mfx-dispatch')
    })
    [IO.File]::WriteAllText($vcpkgManifestPath, ($vcpkgManifest | ConvertTo-Json -Depth 30) + "`n", [Text.UTF8Encoding]::new($false))
    Invoke-Checked (Join-Path $env:VCPKG_ROOT 'vcpkg.exe') @('install', '--triplet', 'x64-windows-static', "--x-install-root=$env:VCPKG_ROOT/installed", '--clean-after-build')

    Invoke-Checked $flutter @('config', '--no-analytics')
    Invoke-Checked $flutter @('precache', '--windows')
    $engineZip = Join-Path $toolRoot 'windows-x64-release.zip'
    Invoke-WebRequest -Uri $EngineUrl -OutFile $engineZip
    if ((Get-Sha256 $engineZip) -cne $EngineSha256) { throw 'Flutter engine checksum mismatch.' }
    $engineExtracted = Join-Path $toolRoot 'engine'
    Expand-Archive -LiteralPath $engineZip -DestinationPath $engineExtracted
    $engineDestination = Join-Path $flutterRoot 'bin/cache/artifacts/engine/windows-x64-release'
    Copy-Item -Path (Join-Path $engineExtracted '*') -Destination $engineDestination -Recurse -Force
    $flutterPatch = Join-Path $SourceDir '.github/patches/flutter_3.24.4_dropdown_menu_enableFilter.diff'
    Invoke-Checked 'git' @('-C', $flutterRoot, 'apply', '--check', $flutterPatch)
    Invoke-Checked 'git' @('-C', $flutterRoot, 'apply', $flutterPatch)

    Invoke-Checked 'cargo' @('install', 'cargo-expand', '--version', '1.0.95', '--locked')
    Invoke-Checked 'cargo' @('install', 'flutter_rust_bridge_codegen', '--version', '1.80.1', '--features', 'uuid', '--locked')
    Push-Location (Join-Path $SourceDir 'flutter')
    try { Invoke-Checked $flutter @('pub', 'get') } finally { Pop-Location }
    Invoke-Checked 'flutter_rust_bridge_codegen' @('--rust-input', './src/flutter_ffi.rs', '--dart-output', './flutter/lib/generated_bridge.dart', '--c-output', './flutter/macos/Runner/bridge_generated.h')
    Copy-Item -LiteralPath './flutter/macos/Runner/bridge_generated.h' -Destination './flutter/ios/Runner/bridge_generated.h' -Force
    foreach ($generated in @('src/bridge_generated.rs', 'src/bridge_generated.io.rs', 'flutter/lib/generated_bridge.dart', 'flutter/lib/generated_bridge.freezed.dart')) {
        Assert-File (Join-Path $SourceDir $generated)
    }

    Write-Host 'Compiling the native Windows client.'
    Invoke-Checked 'python' @('./build.py', '--portable', '--flutter', '--skip-portable-pack')
    $payloadDir = Join-Path $SourceDir 'flutter/build/windows/x64/runner/Release'
    Assert-File (Join-Path $payloadDir 'rustdesk.exe')
    Assert-File (Join-Path $payloadDir 'librustdesk.dll')
    # Match upstream's portable manifest preparation before the source snapshot.
    $manifestPath = Join-Path $SourceDir 'res/manifest.xml'
    $manifestLines = @(Get-Content -LiteralPath $manifestPath | Where-Object { $_ -notmatch 'dpiAware' })
    [IO.File]::WriteAllText($manifestPath, ($manifestLines -join "`n") + "`n", [Text.UTF8Encoding]::new($false))

    Write-Host 'Bundling the exact source and license before portable packaging.'
    $sourceOfferDir = Join-Path $toolRoot 'source-offer'
    Invoke-Checked 'python' @((Join-Path $NativeDir 'make_source_bundle.py'), '--source-dir', $SourceDir, '--output-dir', $sourceOfferDir, '--native-dir', $NativeDir)
    foreach ($name in @('RustDesk-Source.tar.gz', 'LICENSE.txt', 'SOURCE.txt')) {
        Assert-File (Join-Path $sourceOfferDir $name)
        Copy-Item -LiteralPath (Join-Path $sourceOfferDir $name) -Destination (Join-Path $payloadDir $name)
        Copy-Item -LiteralPath (Join-Path $sourceOfferDir $name) -Destination (Join-Path $OutputDir $name)
    }
    Invoke-Checked 'python' @('-m', 'pip', 'install', '--disable-pip-version-check', 'brotli==1.1.0')
    Push-Location (Join-Path $SourceDir 'libs/portable')
    try {
        Invoke-Checked 'python' @('./generate.py', '-f', $payloadDir, '-o', '.', '-e', (Join-Path $payloadDir 'rustdesk.exe'))
    } finally { Pop-Location }
    $compiled = Join-Path $SourceDir 'target/release/rustdesk-portable-packer.exe'
    Assert-File $compiled
    $baseName = 'RetailControlRemoteSupport-base.exe'
    $basePath = Join-Path $OutputDir $baseName
    Copy-Item -LiteralPath $compiled -Destination $basePath

    $receipt = [ordered]@{
        schema_version = 1
        app_identity = 'RetailControlRemoteSupport'
        rustdesk_commit = $RustDeskCommit
        hbb_common_commit = $HbbCommonCommit
        base_file = $baseName
        base_sha256 = Get-Sha256 $basePath
        profile_public_key_sha256 = Get-Sha256 $PublicKeyFile
        credential_free = $true
        windows_acceptance = 'not-tested'
        authenticode = 'unsigned'
        rust_version = $ExpectedRust
        flutter_version = $ExpectedFlutter
        llvm_version = '15.0.6'
        flutter_engine_sha256 = $EngineSha256
        vcpkg_commit = $VcpkgCommit
        cargo_lock_sha256 = Get-Sha256 (Join-Path $SourceDir 'Cargo.lock')
        pubspec_lock_sha256 = Get-Sha256 (Join-Path $SourceDir 'flutter/pubspec.lock')
        source_bundle_sha256 = Get-Sha256 (Join-Path $OutputDir 'RustDesk-Source.tar.gz')
        profile_tests = 'passed-on-windows'
        features = @('flutter', 'software-codecs')
        excluded_components = @('gpu-codecs', 'printer-driver', 'virtual-monitor-driver', 'privacy-mode-helper')
        built_at_utc = [DateTime]::UtcNow.ToString('o')
    }
    $receiptPath = Join-Path $OutputDir 'build-receipt.json'
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 10) + "`n", [Text.UTF8Encoding]::new($false))
    $sums = @($baseName, 'build-receipt.json', 'RustDesk-Source.tar.gz', 'LICENSE.txt', 'SOURCE.txt') | ForEach-Object {
        "$(Get-Sha256 (Join-Path $OutputDir $_))  $_"
    }
    [IO.File]::WriteAllText((Join-Path $OutputDir 'SHA256SUMS'), ($sums -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Credential-free build created in $OutputDir. Desktop installation and unattended access have not been tested."
} finally {
    Pop-Location
    # Keep the uniquely owned scratch directory for local failure diagnosis.
    # GitHub's ephemeral runner removes it when the job ends; no shared cache or
    # Actions artifact storage is used.
    Write-Host "Build scratch directory: $toolRoot"
}
