<#
.SYNOPSIS
    Set up (or tear down) the security-on path for `pcicfg dump`: Microsoft's own
    signed Kernel Local Debugging Driver, with Memory Integrity left on.

.DESCRIPTION
    `pcicfg dump` needs a kernel driver, because both hardware routes to PCI
    configuration space are ring 0. This script installs the only one that is
    both Microsoft-signed and not on the vulnerable-driver blocklist:
    kldbgdrv.sys, which ships as a resource inside the Windows SDK's kd.exe.

    Nothing here disables Memory Integrity (HVCI), turns off the
    vulnerable-driver blocklist, enables test signing, or loads an unsigned,
    renamed or patched driver. The driver's Authenticode signature is verified
    before it is installed and the script refuses to continue if it is not Valid
    -- which matters, because the copy inside the Microsoft Store WinDbg package
    is signed by an internal Microsoft root that retail Windows does not trust.

    It does make one real security change: -EnableDebugBoot runs
    `bcdedit /debug on`, which arms the local kernel debugging interface for
    administrators from the next boot onward. Read the tradeoff section of
    docs/security-on-path.md before using it, and note that on a BitLocker
    machine that change triggers a recovery-key prompt at the next boot unless
    protection is suspended first.

.EXAMPLE
    .\kldbg-setup.ps1 -Install -EnableDebugBoot
    Verify and install the driver, then turn on debug boot. Reboot afterwards.

.EXAMPLE
    .\kldbg-setup.ps1 -Uninstall -DisableDebugBoot
    Put the machine back exactly as it was. Reboot afterwards.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$EnableDebugBoot,
    [switch]$DisableDebugBoot,
    [string]$KdPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'kldbgdrv'
$DriverPath = Join-Path $env:SystemRoot 'System32\kldbgdrv.sys'

function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) { throw "This script must be run from an elevated prompt (Run as Administrator)." }
}

function Find-KdExe {
    if ($KdPath) {
        if (-not (Test-Path $KdPath)) { throw "kd.exe not found at $KdPath" }
        return $KdPath
    }
    # The Windows SDK's own copy. This is the one whose embedded driver is signed by
    # "Microsoft Corporation" under "Microsoft Code Signing PCA" and verifies Valid.
    $candidates = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\kd.exe",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\kd.exe"
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    throw @"
kd.exe not found. Install the Windows SDK's Debugging Tools, or pass -KdPath.

Note: do NOT use the kd.exe from the Microsoft Store WinDbg package
(Microsoft.WinDbg). The kldbgdrv.sys embedded in that build is signed by
"Windows Internal Build Tools PCA 2020", a root retail Windows does not trust,
so the driver fails to load. See docs/security-on-path.md.
"@
}

# kldbgdrv.sys is embedded in kd.exe as resource type 0x4444, name 0x7777.
Add-Type -Namespace Win32 -Name Res -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
public static extern IntPtr LoadLibraryExW(string f, IntPtr h, uint flags);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr FindResourceW(IntPtr h, IntPtr name, IntPtr type);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr LoadResource(IntPtr h, IntPtr res);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr LockResource(IntPtr data);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern uint SizeofResource(IntPtr h, IntPtr res);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool FreeLibrary(IntPtr h);
'@

function Export-KldbgDriver([string]$kd, [string]$outFile) {
    $LOAD_AS_DATAFILE_EXCLUSIVE = 0x40; $LOAD_AS_IMAGE_RESOURCE = 0x20
    $mod = [Win32.Res]::LoadLibraryExW($kd, [IntPtr]::Zero, $LOAD_AS_DATAFILE_EXCLUSIVE -bor $LOAD_AS_IMAGE_RESOURCE)
    if ($mod -eq [IntPtr]::Zero) { throw "Cannot open $kd as a resource file (error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
    try {
        $info = [Win32.Res]::FindResourceW($mod, [IntPtr]0x7777, [IntPtr]0x4444)
        if ($info -eq [IntPtr]::Zero) { throw "No kldbgdrv.sys resource (0x7777/0x4444) in $kd" }
        $size = [Win32.Res]::SizeofResource($mod, $info)
        $ptr = [Win32.Res]::LockResource([Win32.Res]::LoadResource($mod, $info))
        $bytes = New-Object byte[] $size
        [Runtime.InteropServices.Marshal]::Copy($ptr, $bytes, 0, $size)
        [IO.File]::WriteAllBytes($outFile, $bytes)
        Write-Host "  extracted $size bytes from $kd"
    } finally { [void][Win32.Res]::FreeLibrary($mod) }
}

function Assert-DriverIsMicrosoftSigned([string]$file) {
    $sig = Get-AuthenticodeSignature $file
    Write-Host "  signer : $($sig.SignerCertificate.Subject)"
    Write-Host "  issuer : $($sig.SignerCertificate.Issuer)"
    Write-Host "  status : $($sig.Status)"
    if ($sig.Status -ne 'Valid') {
        throw @"
Refusing to install: this kldbgdrv.sys does not carry a valid Authenticode
signature on this machine ($($sig.Status): $($sig.StatusMessage)).

The copy inside the Microsoft Store WinDbg package is signed by an internal
Microsoft root that retail Windows does not trust, and will not load. Use the
Windows SDK's kd.exe instead (see docs/security-on-path.md).
"@
    }
    if ($sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Refusing to install: signer is not Microsoft Corporation."
    }
}

function Get-DebugBootState {
    # What the running kernel reports, which is the state that actually matters.
    $out = & bcdedit /enum '{current}' 2>&1 | Out-String
    if ($out -match '(?m)^debug\s+Yes') { return $true }
    return $false
}

function Warn-BitLocker {
    $risky = @()
    try {
        foreach ($v in (Get-BitLockerVolume -ErrorAction Stop)) {
            if ($v.ProtectionStatus -eq 'On') { $risky += $v.MountPoint }
        }
    } catch { Write-Warning "Could not read BitLocker status: $($_.Exception.Message)" }
    if ($risky.Count) {
        Write-Warning @"
BitLocker protection is ON for: $($risky -join ', ')

Turning kernel debugging on changes the measured boot configuration, so the NEXT
BOOT will ask for your BitLocker recovery key unless you suspend protection first:

    manage-bde -protectors -disable C: -RebootCount 2

Make sure you have the recovery key to hand either way:
    manage-bde -protectors -get C:
"@
        if (-not $Force) {
            $answer = Read-Host "Continue and enable debug boot anyway? (type YES to continue)"
            if ($answer -ne 'YES') { throw "Stopped at your request; nothing was changed." }
        }
    }
}

if (-not ($Install -or $Uninstall -or $EnableDebugBoot -or $DisableDebugBoot)) {
    Write-Host "Nothing to do. Pass -Install, -Uninstall, -EnableDebugBoot or -DisableDebugBoot."
    Write-Host "Current state:"
    Write-Host "  kldbgdrv service : $(if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { 'installed' } else { 'not installed' })"
    Write-Host "  driver file      : $(if (Test-Path $DriverPath) { $DriverPath } else { 'absent' })"
    exit 0
}

Assert-Elevated

if ($Install) {
    Write-Host "Installing Microsoft's Kernel Local Debugging Driver..."
    $kd = Find-KdExe
    $staged = Join-Path $env:TEMP 'kldbgdrv.staged.sys'
    Export-KldbgDriver $kd $staged
    Assert-DriverIsMicrosoftSigned $staged

    if ((Test-Path $DriverPath) -and -not $Force) {
        Write-Host "  $DriverPath already exists; leaving it alone (pass -Force to replace)."
    } else {
        Copy-Item $staged $DriverPath -Force
        Write-Host "  installed to $DriverPath"
    }
    Remove-Item $staged -Force -ErrorAction SilentlyContinue

    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "  service $ServiceName already registered"
    } else {
        # A demand-start kernel service: it is loaded when something opens \\.\kldbgdrv,
        # and it does nothing at all unless the machine was booted with debugging on.
        $out = (& sc.exe create $ServiceName type= kernel start= demand binPath= "System32\kldbgdrv.sys" DisplayName= "Kernel Local Debugging Driver" 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "sc.exe create failed with $LASTEXITCODE`n$out" }
        Write-Host "  service $ServiceName registered (kernel, demand start)"
    }
}

if ($EnableDebugBoot) {
    if (Get-DebugBootState) {
        Write-Host "Debug boot is already on."
    } else {
        Warn-BitLocker
        $out = (& bcdedit /debug on 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug on failed with $LASTEXITCODE`n$out" }
        if ($out) { Write-Host "  $out" }
        Write-Host "Debug boot enabled. A REBOOT is required before it takes effect."
    }
}

if ($DisableDebugBoot) {
    $out = (& bcdedit /debug off 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "bcdedit /debug off failed with $LASTEXITCODE`n$out" }
    if ($out) { Write-Host "  $out" }
    Write-Host "Debug boot disabled. A reboot is required before it takes effect."
}

if ($Uninstall) {
    Write-Host "Removing the driver..."
    if (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        & sc.exe stop $ServiceName 2>&1 | Out-Null   # not running is fine
        & sc.exe delete $ServiceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed with $LASTEXITCODE" }
        Write-Host "  service $ServiceName deleted"
    } else { Write-Host "  service $ServiceName not present" }
    if (Test-Path $DriverPath) {
        Remove-Item $DriverPath -Force
        Write-Host "  removed $DriverPath"
    } else { Write-Host "  $DriverPath not present" }
}

Write-Host ""
Write-Host "State now:"
Write-Host "  kldbgdrv service : $(if (Get-Service $ServiceName -ErrorAction SilentlyContinue) { 'installed' } else { 'not installed' })"
Write-Host "  debug boot (BCD) : $(if (Get-DebugBootState) { 'on' } else { 'off' })  [takes effect at next boot]"
Write-Host "  Memory Integrity : unchanged by this script"
