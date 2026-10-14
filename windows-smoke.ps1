#Requires -Version 7.0
<#
Isolated GitHub-hosted Windows smoke test. Run in the SAME PowerShell step after
windows-build.ps1 so its pinned VCPKG_ROOT and LIBCLANG_PATH remain available.
The public release is frozen. Only a separate synthetic-key DLL and portable
payload are executed. No production profile, preset, signing key or server is
used. The success report is written only after checks AND cleanup complete.

This does not test interactive installation/UAC, Windows 10/11, actual reboot,
remote authentication, desktop control, or the Mac address book. Hosted Windows
runners have UAC disabled; this script does not change that setting.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourceDir,
    [Parameter(Mandatory = $true)][string]$NativeDir,
    [Parameter(Mandatory = $true)][string]$OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

function Assert-Smoke([bool]$Condition, [string]$Message) {
    if (-not $Condition) { $script:smokeReason = $Message; throw $Message }
}
function Set-SmokeStage([string]$Name) {
    $script:stage = $Name
    $script:smokeReason = $null
    $script:lastSmokeProcessExitCode = $null
}
function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    Assert-Smoke ($LASTEXITCODE -eq 0) 'Synthetic build or fixture preparation failed.'
}
function Wait-Condition([scriptblock]$Check, [string]$Message, [int]$Seconds = 90) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (& $Check) { return }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    $script:smokeReason = $Message
    throw $Message
}
function Invoke-RootProcess {
    param([string]$File, [string[]]$Arguments, [int]$Seconds = 30, [switch]$Capture)
    # Start-Process -Wait waits for the entire tree, including the tray/service.
    # Wait only for this root, then independently inspect actual installed state.
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.WorkingDirectory = $testRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $Capture.IsPresent
    $info.RedirectStandardError = $Capture.IsPresent
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        Assert-Smoke ($process.Start()) 'A smoke-test process could not start.'
        $null = $process.Handle
        if ($Capture) {
            $outTask = $process.StandardOutput.ReadToEndAsync()
            $errTask = $process.StandardError.ReadToEndAsync()
        }
        if (-not $process.WaitForExit($Seconds * 1000)) {
            $process.Kill() # Root only; test-owned descendants are cleaned below.
            Assert-Smoke $false 'A smoke-test process did not exit within its deadline.'
        }
        $script:lastSmokeProcessExitCode = [int]$process.ExitCode
        $textOut = ''; $textErr = ''
        if ($Capture) {
            # Capture is used only for commands that do not spawn a child tree.
            Assert-Smoke ($outTask.Wait(3000) -and $errTask.Wait(3000)) 'A CLI output stream did not close.'
            $textOut = $outTask.Result; $textErr = $errTask.Result
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $textOut; Stderr = $textErr }
    } finally { $process.Dispose() }
}
function Get-TestService {
    Get-CimInstance Win32_Service -Filter "Name='RetailControlRemoteSupport'"
}
function Write-InstallDiagnostics {
    # A fixed, bounded schema only. Never emit command lines, paths, config,
    # arbitrary exception messages, profile data, or child stdout/stderr.
    $details = [ordered]@{
        installed_expected_exe_exists = $false
        installed_unrenamed_exe_exists = $false
        installed_profile_exists = $false
        service_exists = $false
        service_state = 'absent'
        service_exit_code = $null
        service_specific_exit_code = $null
        service_pid = $null
        service_image_path_matches_expected = $null
        running_image_path_matches_expected = $null
        last_process_exit_code = $script:lastSmokeProcessExitCode
        snapshot_incomplete = $false
    }
    try {
        $details.installed_expected_exe_exists = Test-Path -LiteralPath $installedExe -PathType Leaf
        $details.installed_unrenamed_exe_exists = Test-Path -LiteralPath (Join-Path $installedDir 'rustdesk.exe') -PathType Leaf
        $details.installed_profile_exists = Test-Path -LiteralPath $installedProfile -PathType Leaf
        $service = Get-CimInstance Win32_Service -Filter "Name='RetailControlRemoteSupport'" -OperationTimeoutSec 5
        if ($null -ne $service) {
            $details.service_exists = $true
            $details.service_state = if ($service.State -in @('Stopped', 'Start Pending', 'Stop Pending', 'Running', 'Continue Pending', 'Pause Pending', 'Paused', 'Unknown')) {
                [string]$service.State
            } else { 'unrecognized' }
            $details.service_exit_code = [uint32]$service.ExitCode
            $details.service_specific_exit_code = [uint32]$service.ServiceSpecificExitCode
            $details.service_pid = [uint32]$service.ProcessId
            $details.service_image_path_matches_expected = $service.PathName -ieq ('"' + $installedExe + '" --service')
            if ($service.ProcessId -gt 0) {
                $running = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" -OperationTimeoutSec 5
                $details.running_image_path_matches_expected = $null -ne $running -and $running.ExecutablePath -ieq $installedExe
            }
        }
    } catch { $details.snapshot_incomplete = $true }
    Write-Host ('Native installation diagnostic: ' + ($details | ConvertTo-Json -Depth 2 -Compress))
}
function Test-Pipe([string]$Suffix) {
    $available = [RetailControlSmoke.Native]::WaitNamedPipe("\\.\pipe\RetailControlRemoteSupport\query$Suffix", 1)
    # ERROR_SEM_TIMEOUT also proves a busy endpoint exists. No IPC connection is
    # opened and no authorization is bypassed by this endpoint-presence probe.
    return $available -or [Runtime.InteropServices.Marshal]::GetLastWin32Error() -eq 121
}
function Assert-ServiceReady {
    Wait-Condition {
        $service = Get-TestService
        $null -ne $service -and $service.State -eq 'Running' -and (Test-Pipe '_service')
    } 'The native service did not become ready.'
    $service = Get-TestService
    Assert-Smoke ($service.StartMode -eq 'Auto' -and $service.StartName -eq 'LocalSystem') 'The service account or autostart setting is incorrect.'
    Assert-Smoke ($service.PathName -ieq ('"' + $installedExe + '" --service')) 'The service does not target the installed native executable.'
    $serviceProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)"
    Assert-Smoke ($null -ne $serviceProcess -and $serviceProcess.ExecutablePath -ieq $installedExe) 'The running service is not the installed executable.'
    Assert-Smoke ((Get-Sha256 $installedProfile) -ceq $fixture.profile_sha256) 'The installed profile was not preserved.'
    if ([RetailControlSmoke.Native]::WTSGetActiveConsoleSessionId() -ne [uint32]::MaxValue) {
        Wait-Condition {
            $servers = @(Get-CimInstance Win32_Process -Filter "Name='RetailControlRemoteSupport.exe'" |
                Where-Object { $_.ExecutablePath -ieq $installedExe -and $_.CommandLine -match '(?:^|\s)--server(?:\s|$)' })
            $servers.Count -gt 0 -and (Test-Pipe '')
        } 'The service did not start its native session daemon.'
        $script:daemonResult = 'passed'
    }
    # Upstream CLI option reads can fall back to local config. They prove profile
    # application, not an authenticated response from the service/session daemon.
    $expected = @{
        'custom-rendezvous-server' = $fixture.rendezvous_server
        'api-server' = $fixture.api_server
        'key' = $fixture.server_key
        'verification-method' = 'use-permanent-password'
        'approve-mode' = 'password'
        'access-mode' = 'full'
    }
    foreach ($name in $expected.Keys) {
        $result = Invoke-RootProcess $installedExe @('--option', $name) -Capture
        Assert-Smoke ($result.ExitCode -eq 0 -and $result.Stdout.Trim() -ceq $expected[$name]) 'Installed native settings do not match the synthetic profile.'
    }
    return [uint32]$service.ProcessId
}
function Stop-TestService {
    $service = Get-TestService
    if ($null -ne $service -and $service.State -ne 'Stopped') {
        $null = Invoke-RootProcess 'sc.exe' @('stop', $appName) -Capture
        Wait-Condition { (Get-TestService).State -eq 'Stopped' } 'The test service did not stop.'
    }
}
function Stop-TestProcesses {
    # Never kill stock RustDesk or arbitrary matching names. All roots below
    # were absent before this ephemeral test, and executable paths must match.
    $stopped = [Collections.Generic.List[int]]::new()
    foreach ($process in @(Get-CimInstance Win32_Process)) {
        $path = [string]$process.ExecutablePath
        if ($path -and @($testRoot, $cacheDir, $installedDir).Where({
            $path.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
            $stopped.Add([int]$process.ProcessId)
        }
    }
    foreach ($processId in $stopped) {
        $remaining = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($null -ne $remaining) {
            try { Assert-Smoke ($remaining.WaitForExit(10000)) 'A test-owned process did not stop before cleanup.' }
            finally { $remaining.Dispose() }
        }
    }
}
function Invoke-NativeUninstall {
    if (Test-Path -LiteralPath $installedExe -PathType Leaf) {
        # Always restore the valid synthetic profile before the normal uninstaller.
        Copy-Item -LiteralPath $validProfile -Destination $installedProfile -Force
        $null = Invoke-RootProcess $installedExe @('--uninstall') -Seconds 45
    }
    Wait-Condition {
        $null -eq (Get-TestService) -and
        -not (Test-Path -LiteralPath $installedDir) -and
        -not (Test-Path -LiteralPath $uninstallKey) -and
        -not (Test-Path -LiteralPath $trayShortcut)
    } 'The native uninstaller left installation state behind.'
}

Assert-Smoke ($IsWindows -and [Environment]::Is64BitOperatingSystem) 'This smoke test requires Windows x64.'
Assert-Smoke ($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted') 'This test only runs on an ephemeral GitHub-hosted runner.'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
Assert-Smoke ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'The ephemeral runner must already be an administrator.'
$SourceDir = (Resolve-Path -LiteralPath $SourceDir).Path
$NativeDir = (Resolve-Path -LiteralPath $NativeDir).Path
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
Assert-Smoke (-not (Test-Path -LiteralPath (Join-Path $OutputDir 'windows-smoke.json'))) 'A smoke report already exists.'
Assert-Smoke ([bool]$env:VCPKG_ROOT -and [bool]$env:LIBCLANG_PATH) 'Run immediately after the native build in the same PowerShell step.'

$appName = 'RetailControlRemoteSupport'
$installedDir = Join-Path $env:ProgramFiles $appName
$installedExe = Join-Path $installedDir ($appName + '.exe')
$installedProfile = Join-Path $installedDir 'retailcontrol-profile.bin'
$uninstallKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $appName
$trayShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup\$appName Tray.lnk"
$cacheRoot = Join-Path $env:LOCALAPPDATA 'retailcontrol-remotesupport'
$configDirs = @(
    (Join-Path $env:APPDATA $appName),
    (Join-Path $env:LOCALAPPDATA $appName),
    (Join-Path $env:WINDIR "ServiceProfiles\LocalService\AppData\Roaming\$appName"),
    (Join-Path $env:WINDIR "ServiceProfiles\LocalService\AppData\Local\$appName"),
    (Join-Path $env:WINDIR "System32\config\systemprofile\AppData\Roaming\$appName"),
    (Join-Path $env:WINDIR "System32\config\systemprofile\AppData\Local\$appName")
)
$ownedPaths = @($installedDir, $cacheRoot, $trayShortcut,
    (Join-Path $env:PUBLIC "Desktop\$appName.lnk"),
    (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\$appName")) + $configDirs
foreach ($path in $ownedPaths) { Assert-Smoke (-not (Test-Path -LiteralPath $path)) 'Pre-existing RetailControl data prevents isolated smoke testing.' }
foreach ($name in @($appName, 'RustDesk')) {
    Assert-Smoke ($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue)) 'An existing remote-access service prevents isolated smoke testing.'
}
foreach ($prefix in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    foreach ($name in @($appName, 'RustDesk', '{54E86BC2-6C85-41F3-A9EB-1A94AC9B1F93}_is1')) {
        Assert-Smoke (-not (Test-Path -LiteralPath "$prefix\$name")) 'An existing remote-access installation prevents isolated smoke testing.'
    }
}
foreach ($name in @('retailcontrolremotesupport', '.retailcontrolremotesupport')) {
    Assert-Smoke (-not (Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\$name")) 'Pre-existing protocol registration prevents isolated smoke testing.'
}
Assert-Smoke (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count -eq 0) 'Firewall profiles must already be enabled for the network-isolated test.'
Assert-Smoke (@(Get-NetFirewallRule -DisplayName "$appName Service" -ErrorAction SilentlyContinue).Count -eq 0) 'Pre-existing firewall rules prevent isolated smoke testing.'

Add-Type @'
using System;
using System.Runtime.InteropServices;
namespace RetailControlSmoke {
  public static class Native {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WaitNamedPipe(string name, uint timeout);
    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();
  }
}
'@

$publicHashes = @{}
foreach ($file in Get-ChildItem -LiteralPath $OutputDir -File -Recurse) { $publicHashes[$file.FullName] = Get-Sha256 $file.FullName }
Assert-Smoke ($publicHashes.Count -ge 6) 'The complete frozen generic release is required.'
$sourceKey = Join-Path $SourceDir 'profile-public-key.bin'
$receipt = Get-Content -LiteralPath (Join-Path $OutputDir 'build-receipt.json') -Raw | ConvertFrom-Json
Assert-Smoke ($receipt.credential_free -eq $true -and $receipt.profile_public_key_sha256 -ceq (Get-Sha256 $sourceKey)) 'The source verifier does not match the frozen generic release.'
Assert-Smoke ($receipt.base_sha256 -ceq (Get-Sha256 (Join-Path $OutputDir 'RetailControlRemoteSupport-base.exe'))) 'The generic release hash does not match its receipt.'

$testRoot = Join-Path $env:RUNNER_TEMP ('retailcontrol-native-smoke-' + [guid]::NewGuid().ToString('N'))
$testPayload = Join-Path $testRoot 'payload'
$fixtureDir = Join-Path $testRoot 'fixtures'
$validProfile = Join-Path $fixtureDir 'valid.bin'
$portableDir = Join-Path $SourceDir 'libs\portable'
$publicPayload = Join-Path $SourceDir 'flutter\build\windows\x64\runner\Release'
$sourceDll = Join-Path $SourceDir 'target\release\librustdesk.dll'
$sourcePortable = Join-Path $SourceDir 'target\release\rustdesk-portable-packer.exe'
$helper = Join-Path $NativeDir 'tests\windows_smoke_profile.py'
$backups = @{}
$blockRules = [Collections.Generic.List[string]]::new()
$testStarted = $false
$normalUninstallPassed = $false
$checksPassed = $false
$cleanupFailures = [Collections.Generic.List[string]]::new()
$failure = $null
Set-SmokeStage 'preparation'
$daemonResult = 'not-tested-no-active-console-session'
$sasRegistrySubKey = 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
$sasKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sasRegistrySubKey, $false)
Assert-Smoke ($null -ne $sasKey) 'The existing SAS policy key could not be read.'
try {
    $sasExisted = $sasKey.GetValueNames() -contains 'SoftwareSASGeneration'
    $sasValue = $sasKey.GetValue('SoftwareSASGeneration', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $sasKind = if ($sasExisted) { $sasKey.GetValueKind('SoftwareSASGeneration') } else { $null }
} finally { $sasKey.Dispose() }
New-Item -ItemType Directory -Path $testRoot | Out-Null
$cacheDir = $cacheRoot # Replaced by this fixture's exact child before any launch.
try {
    foreach ($path in @($sourceKey, $sourceDll, $sourcePortable, (Join-Path $portableDir 'data.bin'), (Join-Path $portableDir 'app_metadata.toml'))) {
        Assert-Smoke (Test-Path -LiteralPath $path -PathType Leaf) 'A required generic build input is missing.'
        $backup = Join-Path $testRoot ('backup-' + $backups.Count)
        Copy-Item -LiteralPath $path -Destination $backup
        $backups[$path] = @{ Path = $backup; Hash = (Get-Sha256 $path) }
    }
    Invoke-Checked 'python' @($helper, 'create', '--directory', $fixtureDir)
    $fixture = Get-Content -LiteralPath (Join-Path $fixtureDir 'manifest.json') -Raw | ConvertFrom-Json
    $cacheDir = Join-Path $cacheRoot $fixture.build_id
    Copy-Item -LiteralPath $publicPayload -Destination $testPayload -Recurse
    Copy-Item -LiteralPath (Join-Path $fixtureDir 'public-key.bin') -Destination $sourceKey -Force

    Set-SmokeStage 'synthetic-native-build'
    Write-Host 'Building the isolated synthetic-key smoke client; public release files stay frozen.'
    Push-Location $SourceDir
    try { Invoke-Checked 'cargo' @('build', '--locked', '--offline', '--features', 'flutter', '--lib', '--release') }
    finally { Pop-Location }
    Copy-Item -LiteralPath $sourceDll -Destination (Join-Path $testPayload 'librustdesk.dll') -Force
    $syntheticDllHash = Get-Sha256 $sourceDll
    Push-Location $portableDir
    try {
        # Compression level affects only packaging size/time; extracted bytes and
        # actual native launcher/service code are identical to the release path.
        Invoke-Checked 'python' @('./generate.py', '-f', $testPayload, '-o', '.', '-e', (Join-Path $testPayload 'rustdesk.exe'), '-l', '1')
    } finally { Pop-Location }
    $testInstaller = Join-Path $testRoot 'RetailControlRemoteSupport-smoke-install.exe'
    Invoke-Checked 'python' @($helper, 'append', '--directory', $fixtureDir, '--base', $sourcePortable, '--output', $testInstaller)

    # Explicit program blocks take priority over native installer's allow rules.
    # No global firewall/UAC policy is changed. The signed synthetic route is
    # loopback-only even if Windows treats loopback specially under its firewall.
    foreach ($program in @((Join-Path $testPayload 'rustdesk.exe'), (Join-Path $cacheDir 'rustdesk.exe'), $installedExe)) {
        foreach ($direction in @('Inbound', 'Outbound')) {
            $name = 'RC-Smoke-' + [guid]::NewGuid().ToString('N')
            New-NetFirewallRule -Name $name -DisplayName $name -Direction $direction -Action Block -Program $program -Profile Any | Out-Null
            $blockRules.Add($name)
        }
    }
    $testStarted = $true
    Set-SmokeStage 'native-profile-refusal'
    $payloadProfile = Join-Path $testPayload 'retailcontrol-profile.bin'
    Copy-Item -LiteralPath $validProfile -Destination $payloadProfile
    $version = Invoke-RootProcess (Join-Path $testPayload 'rustdesk.exe') @('--version') -Capture
    Assert-Smoke ($version.ExitCode -eq 0 -and $version.Stdout.Trim() -eq '1.4.9') 'The valid native client did not load its DLL and profile.'
    foreach ($badProfile in @('wrong-key.bin', 'tampered.bin', 'missing')) {
        Remove-Item -LiteralPath $payloadProfile -Force
        if ($badProfile -ne 'missing') { Copy-Item -LiteralPath (Join-Path $fixtureDir $badProfile) -Destination $payloadProfile }
        $refusal = Invoke-RootProcess (Join-Path $testPayload 'rustdesk.exe') @('--service') -Capture
        Assert-Smoke ($refusal.ExitCode -eq 1 -and $refusal.Stderr.Contains('RetailControl setup profile verification failed.')) 'The actual native client did not refuse an invalid profile.'
        if ($badProfile -eq 'missing') { break }
    }

    Set-SmokeStage 'native-install'
    $launch = Invoke-RootProcess $testInstaller @('--silent-install', 'printer=0') -Seconds 90
    Assert-Smoke ($launch.ExitCode -eq 0) 'The native portable launcher failed.'
    # Its successful exit means only that it spawned the inner app. Installation
    # itself must produce the expected real SCM registration and live endpoint.
    Wait-Condition { Test-Path -LiteralPath $installedExe -PathType Leaf } 'The native installer did not create the branded installed executable.'
    $firstServicePid = Assert-ServiceReady
    Assert-Smoke ((Get-Sha256 (Join-Path $installedDir 'librustdesk.dll')) -ceq $syntheticDllHash) 'The installer did not copy the synthetic native DLL.'
    Assert-Smoke ((Get-Sha256 (Join-Path $cacheDir 'retailcontrol-profile.bin')) -ceq $fixture.profile_sha256) 'Portable extraction did not preserve the profile.'
    Assert-Smoke ((Test-Path -LiteralPath $uninstallKey) -and (Test-Path -LiteralPath $trayShortcut)) 'Native uninstall or startup registration is missing.'

    Set-SmokeStage 'installed-profile-persistence'
    Stop-TestService
    Stop-TestProcesses
    Remove-Item -LiteralPath $cacheRoot -Recurse -Force
    Remove-Item -LiteralPath $testInstaller -Force
    Remove-Item -LiteralPath $testPayload -Recurse -Force
    $start = Invoke-RootProcess 'sc.exe' @('start', $appName) -Capture
    Assert-Smoke ($start.ExitCode -eq 0) 'The installed service could not restart without its download/extraction tree.'
    $secondServicePid = Assert-ServiceReady
    Assert-Smoke ($secondServicePid -ne $firstServicePid) 'The restart did not create a fresh service process.'

    Set-SmokeStage 'installed-tamper-refusal'
    Stop-TestService
    Stop-TestProcesses
    Copy-Item -LiteralPath (Join-Path $fixtureDir 'tampered.bin') -Destination $installedProfile -Force
    $rejectedStart = Invoke-RootProcess 'sc.exe' @('start', $appName) -Seconds 45 -Capture
    Wait-Condition { (Get-TestService).State -eq 'Stopped' } 'The service did not refuse its tampered installed profile.' -Seconds 45
    Assert-Smoke ($rejectedStart.ExitCode -ne 0 -and -not (Test-Pipe '_service')) 'A tampered installed profile was accepted by the service.'
    Copy-Item -LiteralPath $validProfile -Destination $installedProfile -Force
    $start = Invoke-RootProcess 'sc.exe' @('start', $appName) -Capture
    Assert-Smoke ($start.ExitCode -eq 0) 'The service did not recover after restoring its signed test profile.'
    $null = Assert-ServiceReady

    Set-SmokeStage 'native-uninstall'
    Invoke-NativeUninstall
    $normalUninstallPassed = $true
    $checksPassed = $true
} catch {
    # Fixed stage names only: never copy arbitrary process output into reports.
    $reason = if ($smokeReason) { $smokeReason } else { 'Unexpected harness operation failed.' }
    $failure = 'Windows native smoke failed at stage: ' + $stage + '. ' + $reason
    Write-Host $failure
    if ($testStarted) { Write-InstallDiagnostics }
} finally {
    if ($testStarted) {
        try {
            if (-not $normalUninstallPassed) { Invoke-NativeUninstall }
        } catch { $cleanupFailures.Add('native-uninstall') }
        try {
            # Fallback is cleanup only on this guarded ephemeral VM, never proof
            # of a passing native uninstall or a production repair path.
            if ($null -ne (Get-TestService)) {
                $null = Invoke-RootProcess 'sc.exe' @('stop', $appName) -Capture
                Stop-TestProcesses
                $null = Invoke-RootProcess 'sc.exe' @('delete', $appName) -Capture
            }
            Stop-TestProcesses
            foreach ($path in $ownedPaths) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -Recurse }
            }
            foreach ($path in @($uninstallKey, 'Registry::HKEY_CLASSES_ROOT\retailcontrolremotesupport', 'Registry::HKEY_CLASSES_ROOT\.retailcontrolremotesupport')) {
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -Recurse }
            }
            Get-NetFirewallRule -DisplayName "$appName Service" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        } catch { $cleanupFailures.Add('test-installation-state') }
        try {
            # Get-Item returns a read-only RegistryKey even for administrators.
            # Open this existing test-touched key explicitly writable, and close
            # it regardless of whether restoration or verification succeeds.
            $sasKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($sasRegistrySubKey, $true)
            Assert-Smoke ($null -ne $sasKey) 'The existing SAS policy key could not be opened for restoration.'
            try {
                if ($sasExisted) {
                    $sasKey.SetValue('SoftwareSASGeneration', $sasValue, $sasKind)
                    $restoredValue = $sasKey.GetValue('SoftwareSASGeneration', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    Assert-Smoke ($sasKey.GetValueKind('SoftwareSASGeneration') -eq $sasKind -and
                        [Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($restoredValue, $sasValue)) 'The original SAS policy was not restored exactly.'
                } elseif ($sasKey.GetValueNames() -contains 'SoftwareSASGeneration') {
                    # Native setup creates this single DWORD with value 1. Do
                    # not delete an unexpected value introduced by another actor.
                    Assert-Smoke ($sasKey.GetValueKind('SoftwareSASGeneration') -eq [Microsoft.Win32.RegistryValueKind]::DWord -and
                        $sasKey.GetValue('SoftwareSASGeneration') -eq 1) 'The new SAS policy value differs from the native test value.'
                    $sasKey.DeleteValue('SoftwareSASGeneration', $false)
                    Assert-Smoke (-not ($sasKey.GetValueNames() -contains 'SoftwareSASGeneration')) 'The synthetic SAS policy value was not removed.'
                }
            } finally { $sasKey.Dispose() }
        } catch { $cleanupFailures.Add('sas-policy-restoration') }
    }
    foreach ($name in $blockRules) {
        try { Remove-NetFirewallRule -Name $name }
        catch { $cleanupFailures.Add('test-network-rule') }
    }
    foreach ($path in $backups.Keys) {
        try {
            Copy-Item -LiteralPath $backups[$path].Path -Destination $path -Force
            Assert-Smoke ((Get-Sha256 $path) -ceq $backups[$path].Hash) 'A generic build input could not be restored.'
        } catch { $cleanupFailures.Add('generic-build-input') }
    }
    try {
        Assert-Smoke (@(Get-ChildItem -LiteralPath $OutputDir -File -Recurse).Count -eq $publicHashes.Count) 'The frozen public release file set changed.'
        foreach ($path in $publicHashes.Keys) {
            Assert-Smoke ((Get-Sha256 $path) -ceq $publicHashes[$path]) 'A frozen public release file changed.'
        }
    } catch { $cleanupFailures.Add('public-release-integrity') }
    try { Remove-Item -LiteralPath $testRoot -Recurse -Force }
    catch { $cleanupFailures.Add('synthetic-fixtures') }
}

if ($cleanupFailures.Count -gt 0) {
    $cleanupMessage = 'Smoke cleanup failed: ' + ($cleanupFailures -join ', ') + '. No success report was written.'
    if ($failure) { throw ($failure + ' ' + $cleanupMessage) }
    throw $cleanupMessage
}
if (-not $checksPassed) { throw $failure }
Assert-Smoke ($null -eq (Get-TestService)) 'The smoke service still exists after cleanup.'
foreach ($path in $ownedPaths) { Assert-Smoke (-not (Test-Path -LiteralPath $path)) 'Test-owned installation data remains after cleanup.' }

$report = [ordered]@{
    schema_version = 1
    result = 'passed'
    scope = 'synthetic-key native lifecycle on an isolated GitHub-hosted Windows runner'
    operating_system = [Environment]::OSVersion.VersionString
    generic_base_sha256 = $receipt.base_sha256
    public_release_files_unchanged = $true
    synthetic_key_and_profile_deleted = $true
    native_profile_missing_wrong_key_and_tamper_refusal = 'passed'
    portable_extraction_and_native_silent_install = 'passed'
    service_system_account_autostart_and_installed_image = 'passed'
    service_endpoint_presence = 'passed'
    session_daemon_and_endpoint_presence = $daemonResult
    installed_profile_persistence_without_download_or_cache = 'passed'
    service_restart_and_tampered_installed_profile_refusal = 'passed'
    loopback_settings_readback = 'passed; upstream CLI may use local fallback'
    native_uninstall_and_cleanup = 'passed'
    production_profile_or_private_key_used = $false
    untested = @('interactive install and UAC', 'Windows 10/11', 'actual reboot',
        'preset remote authentication', 'desktop control', 'Mac address-book enrollment',
        'invalid outer-launcher interactive error dialog')
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDir 'windows-smoke.json') -Encoding utf8
Write-Host 'Synthetic native Windows lifecycle smoke passed; public release bytes are unchanged.'
