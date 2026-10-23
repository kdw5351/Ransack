[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$SampleExe = "",

    # Override $TraceRoot from the command line. The trace output still
    # lands in a timestamped subdirectory under this path.
    [Parameter()]
    [string]$OutputDir = "",

    # Pin runtime cap in seconds. Host orchestrator (ransack.ps1) passes
    # this explicitly so timing can be tuned without re-snapshotting the
    # guest. 0 = no timeout (wait until sample exits on its own).
    [Parameter()]
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────
# CONFIG — edit this block for the VM environment, then run:
#     .\run.ps1                          (uses $DefaultSamplePath)
#     .\run.ps1 test.exe                 (resolves under $DefaultSampleDir)
#     .\run.ps1 C:\full\path\sample.exe  (absolute path)
#
# Unified single launcher. No external options — bitness / Pin runtime pick
# is always automatic:
#   1) Detect effective runtime bitness via PE header + CLR CorFlags.
#   2) Run Pin with the matching DLL (ransomflow.dll / ransomflow_x64.dll).
#   3) On failure (Pin exit != 0 OR no ransomflow_done.json produced), retry
#      automatically with the opposite-bitness DLL. The two attempts share
#      the same trace dir but ransomflow already segregates output under
#      proc_<pid>/, so artifacts from different attempts don't mix.
#
# Canonical layout (single Ransack root, repo-style):
#   <RansackRoot>\
#     ├── assets\                  (shared by host + VM — shipped here)
#     ├── pin\pin.exe              (Intel Pin kit, top-level)
#     ├── onVM\
#     │   ├── run.ps1              (this script — $PSScriptRoot)
#     │   ├── traces\              (run output lands here)
#     │   └── ransomflow\Build\    (pintool dlls)
#     └── onHost\analysis\         (host-side analyzer, not used in VM)
#
# RansackRoot is fixed to the parent of $PSScriptRoot — i.e. one level above
# onVM\.  Pin and assets are resolved against RansackRoot; ransomflow build
# and traces live inside onVM\ and are resolved against $PSScriptRoot.
#
# Trace layout produced by the pintool (one folder per sample, one
# subfolder per process — parent + every followed child):
#   trace_<sample>\
#     ├── ransomflow_done.json         (top-level marker, last writer wins)
#     └── proc_<pid>\
#         ├── proc_info.json           (pid, image, start tick)
#         ├── ransomflow_done.json     (per-proc done marker)
#         ├── images_<N>.jsonl         (img-load events: path, low, high, flags)
#         ├── io_events_<N>.jsonl      (file/section IO API hits)
#         ├── crypto_events_<N>.jsonl  (crypto API src/deriv/sink rows + key bytes)
#         ├── loop_events.jsonl        (one-shot at OnFini)
#         ├── loop_<id>.json           (per-loop snapshot metadata)
#         └── loop_<id>.bin            (per-loop raw memory dump)
# When -debug 1 is passed, additionally:
#         ├── global_trace.done        (EXT_* raw text rows for post-mortem)
# ─────────────────────────────────────────────────────────────────────────

# Canonical paths.  RansackRoot is the parent of onVM\; the Pin kit + shared
# assets live there.  Pintool build artifacts and per-run trace output live
# inside onVM\ itself.
$RansackRoot = Split-Path -Parent $PSScriptRoot

$PinPath   = Join-Path $RansackRoot  "pin\pin.exe"
$RulesDir  = Join-Path $RansackRoot  "assets"
$ToolDll64 = Join-Path $PSScriptRoot "ransomflow\Build\ransomflow_x64.dll"
$ToolDll32 = Join-Path $PSScriptRoot "ransomflow\Build\ransomflow.dll"

# Sample to run when no CLI argument was given. Samples are intentionally
# outside onVM so the tooling can be redeployed without touching samples.
$DefaultSampleDir = Join-Path $env:USERPROFILE "Desktop\samples"
$DefaultSamplePath = Join-Path $DefaultSampleDir "test.exe"

# Output: a fresh subdirectory under $TraceRoot, named after the sample
# (any previous trace_<sample>\ for the same sample is wiped on start).
# Trace dir lives inside onVM\ so the host-side live-pull (which expects
# <GuestOnVmRoot>\traces) finds it at the right place in the guest.
$TraceRoot = Join-Path $PSScriptRoot "traces"

# PinTool knobs (forwarded to Pin as -<knob> <value>).
# Anything not listed here uses the pintool's own default. Knobs removed
# from the tool entirely (Pin will reject them as unknown switches):
#   -log_meta, -hot_iters, -crypto_buf_cap, -snapshot_region_bytes,
#   -snapshot_max_count, -dump_bytes, -dump_max, -key_dump_bytes,
#   -max_captured_loops, -capture_known_dll_loops,
#   -loop_break_iters       (removed: forced fallthrough on unconditional
#                            jmp back-edges crashed targets; the IARG_CONTEXT
#                            it required also added 5-100x per-branch
#                            overhead. Anti-analysis spin defense is now
#                            run.ps1's $TimeoutSeconds.)
$LoopTriggerIters = 2           # was 4 — lowered to capture short cipher rounds
$KeySnapshotBytes = 4096        # region (in bytes) PIN_SafeCopied around each key-birth buffer; 0 disables
$TraceSystemImages = 0           # 1: also instrument System32 DLLs (very noisy)
$FollowChildren = 1           # 0: do not attach to spawned children
$FollowMemcpy = 1           # 0: skip RtlMoveMemory/memcpy/memmove hooks (noisy)
$Session = ""          # optional label written into the start JSONL row
$TraceDebug = $false      # toggles -debug 1 (verbose logs + global_trace.tmp)

# $TimeoutSeconds is now supplied via the script parameter above (default 300).
$GracefulShutdownSeconds = 15

# ─────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────
function Show-UsageAndExit {
    Write-Host "Usage:"
    Write-Host "  .\run.ps1                                       (uses default sample, auto-detect arch)"
    Write-Host "  .\run.ps1 <sample.exe>                          (resolves under `$DefaultSampleDir)"
    Write-Host "  .\run.ps1 C:\full\path\sample.exe               (absolute sample path)"
    Write-Host "  .\run.ps1 sample.exe -OutputDir D:\my\traces    (override trace root)"
    Write-Host "  .\run.ps1 sample.exe -TimeoutSeconds 600        (Pin runtime cap, 0 = no cap)"
    Write-Host ""
    Write-Host "Edit the CONFIG block at the top of run.ps1 first."
    exit 2
}

function Resolve-SamplePath {
    param([string]$SamplePath)

    if ([string]::IsNullOrWhiteSpace($SamplePath)) {
        if (-not (Test-Path -LiteralPath $DefaultSamplePath)) {
            Write-Error "DefaultSamplePath not found: $DefaultSamplePath"
            Show-UsageAndExit
        }
        return (Resolve-Path -LiteralPath $DefaultSamplePath).Path
    }

    if ([System.IO.Path]::IsPathRooted($SamplePath)) {
        if (-not (Test-Path -LiteralPath $SamplePath)) {
            Write-Error "Sample not found: $SamplePath"
            exit 2
        }
        return (Resolve-Path -LiteralPath $SamplePath).Path
    }

    $userProfile = $env:USERPROFILE
    $candidates = @(
        (Join-Path $DefaultSampleDir $SamplePath),
        (Join-Path $userProfile "Desktop\$SamplePath"),
        (Join-Path (Split-Path $DefaultSamplePath -Parent) $SamplePath)
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
            return (Resolve-Path -LiteralPath $c).Path
        }
    }
    Write-Error "Sample not found among: $($candidates -join '; ')"
    exit 2
}

function New-OutDir {
    param([string]$SamplePath)
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($SamplePath)
    $dir = Join-Path $TraceRoot ("trace_{0}" -f $stem)

    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    return (Resolve-Path -LiteralPath $dir).Path
}

function Get-PeBitness {
    # Returns the EFFECTIVE runtime bitness (32 or 64) on 64-bit Windows.
    #
    # For native PE: IMAGE_FILE_HEADER.Machine alone determines bitness.
    #   0x014c (i386)  → 32
    #   0x8664 (amd64) → 64
    #
    # For .NET assemblies (CLR header present), AnyCPU runs as 64-bit on a
    # 64-bit OS regardless of the PE Machine field.  We must inspect the
    # IMAGE_COR20_HEADER.Flags (CorFlags) to know which architecture the CLR
    # loader will pick.  Values from corhdr.h:
    #   COMIMAGE_FLAGS_ILONLY        = 0x00000001
    #   COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002
    #   COMIMAGE_FLAGS_32BITPREFERRED= 0x00020000
    #
    # Rule on 64-bit Windows:
    #   - Machine x64                          → 64
    #   - Machine x86 + no CLR header (native) → 32
    #   - Machine x86 + CLR header + 32BITREQUIRED or 32BITPREFERRED → 32
    #   - Machine x86 + CLR header + neither (AnyCPU)                → 64
    #
    # Falls back to 64 on any read error.
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader -ArgumentList @($fs)

            # DOS header → PE signature offset
            $fs.Position = 0x3C
            $peOff = $br.ReadInt32()
            if ($peOff -le 0 -or $peOff -gt 0x1000) { return 64 }

            # IMAGE_FILE_HEADER.Machine
            $fs.Position = $peOff + 4
            $machine = $br.ReadUInt16()
            if ($machine -eq 0x8664) { return 64 }
            if ($machine -ne 0x014c) { return 64 }

            # x86 PE: distinguish native-32 from .NET-AnyCPU
            $fs.Position = $peOff + 4 + 2;  $numSections   = $br.ReadUInt16()
            $fs.Position = $peOff + 4 + 16; $sizeOptHeader = $br.ReadUInt16()

            $optBase = $peOff + 4 + 20
            $fs.Position = $optBase
            $optMagic = $br.ReadUInt16()
            $ddOffset = if ($optMagic -eq 0x020B) { 112 } else { 96 }

            # DataDirectory[14] = CLR Runtime Header
            $fs.Position = $optBase + $ddOffset + 14 * 8
            $clrRva  = $br.ReadUInt32()
            $clrSize = $br.ReadUInt32()
            if ($clrRva -eq 0) { return 32 }   # native x86

            # Walk section table to translate CLR-header RVA → file offset
            $sectionTable = $optBase + $sizeOptHeader
            $clrFileOff = 0
            for ($i = 0; $i -lt $numSections; $i++) {
                $secStart = $sectionTable + $i * 40
                $fs.Position = $secStart + 8
                $vSize = $br.ReadUInt32()
                $vAddr = $br.ReadUInt32()
                $rSize = $br.ReadUInt32()
                $rOff  = $br.ReadUInt32()
                $vEnd  = $vAddr + [Math]::Max($vSize, $rSize)
                if ($clrRva -ge $vAddr -and $clrRva -lt $vEnd) {
                    $clrFileOff = $rOff + ($clrRva - $vAddr)
                    break
                }
            }
            if ($clrFileOff -eq 0) { return 32 }

            # IMAGE_COR20_HEADER.Flags at offset 0x10
            $fs.Position = $clrFileOff + 0x10
            $corFlags = $br.ReadUInt32()

            $is32Required  = ($corFlags -band 0x00000002) -ne 0
            $is32Preferred = ($corFlags -band 0x00020000) -ne 0
            if ($is32Required -or $is32Preferred) { return 32 }
            return 64   # AnyCPU on 64-bit OS
        }
        finally {
            $fs.Close()
        }
    }
    catch {
        return 64
    }
}

function Get-PeIsManaged {
    # Returns $true when DataDirectory[14] (CLR Runtime Header) has a non-zero
    # RVA — the authoritative indicator of a .NET managed executable.
    # Pin JIT mode conflicts with the CLR's own JIT; use -probe for managed binaries.
    param([string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            # e_lfanew at 0x3C
            $fs.Position = 0x3C
            $peOffset = $br.ReadInt32()
            if ($peOffset -le 0 -or $peOffset -gt 0x1000) { return $false }
            # Skip PE\0\0 (4) + IMAGE_FILE_HEADER (20) = 24 bytes
            $fs.Position = $peOffset + 24
            $optMagic = $br.ReadUInt16()
            # DataDirectory array offset from start of optional header:
            #   PE32  (0x010B): 96 bytes   PE32+ (0x020B): 112 bytes
            $ddOffset = if ($optMagic -eq 0x020B) { 112 } else { 96 }
            # DataDirectory[14] = COM descriptor (CLR header); each entry = 8 bytes
            $fs.Position = $peOffset + 24 + $ddOffset + 14 * 8
            $clrRva = $br.ReadUInt32()
            return ($clrRva -ne 0)
        }
        finally {
            $fs.Close()
        }
    }
    catch {
        return $false
    }
}

function Resolve-ToolDllForBits {
    # bitness -> pintool DLL path. Returns $null when the DLL is missing,
    # which the auto-fallback path then surfaces as a missing-fallback warning.
    param([int]$Bits)
    if ($Bits -eq 32) {
        if (Test-Path -LiteralPath $ToolDll32) { return (Resolve-Path -LiteralPath $ToolDll32).Path }
        return $null
    }
    if (Test-Path -LiteralPath $ToolDll64) { return (Resolve-Path -LiteralPath $ToolDll64).Path }
    return $null
}

function Select-ToolDll {
    # Compute the detected effective bitness from the PE header (native 32/64)
    # and CLR CorFlags (.NET AnyCPU resolves to 64). Returns the matching
    # ransomflow*.dll as the first-attempt candidate.
    param([string]$SamplePath)
    $bits = Get-PeBitness -Path $SamplePath
    $dll  = Resolve-ToolDllForBits -Bits $bits
    if (-not $dll) {
        Write-Error ("Pintool DLL missing for {0}-bit: check ransomflow\Build\" -f $bits)
        exit 2
    }
    return @{ Path = $dll; Bits = $bits }
}

# ─────────────────────────────────────────────────────────────────────────
# Resolve inputs
# ─────────────────────────────────────────────────────────────────────────
if (-not (Test-Path -LiteralPath $PinPath)) { Write-Error "Pin not found: $PinPath"; Show-UsageAndExit }
if (-not (Test-Path -LiteralPath $RulesDir)) { Write-Error "RulesDir not found: $RulesDir"; Show-UsageAndExit }

# CLI -OutputDir wins over the config default.
if (-not [string]::IsNullOrWhiteSpace($OutputDir)) {
    $TraceRoot = $OutputDir
}
New-Item -ItemType Directory -Path $TraceRoot -Force | Out-Null

$SamplePath = Resolve-SamplePath -SamplePath $SampleExe
$OutDir = New-OutDir -SamplePath $SamplePath
$tool = Select-ToolDll -SamplePath $SamplePath
$ToolDll = $tool.Path

# .NET managed-binary detection (informational only).  Pin 3.31 injects
# into .NET processes natively in JIT mode — no probe-mode workaround needed
# (Pin 4.x had this incompatibility, Pin 3.31 does not).  The flag is still
# read so the banner shows what the sample is.
$IsManaged = Get-PeIsManaged -Path $SamplePath

# The pintool now segregates every process into its own
# proc_<pid>\ subdirectory under -out_dir, so artifacts live at
# $OutDir\proc_<pid>\<file>.  The summary block below searches
# recursively to handle the parent + any followed children.

# ─────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────
Write-Host "================================================================"
Write-Host " ransomflow VM run"
Write-Host "================================================================"
Write-Host (" RansackRoot : {0}" -f $RansackRoot)
Write-Host (" Sample      : {0} ({1}-bit, {2})" -f $SamplePath, $tool.Bits, $(if ($IsManaged) { ".NET managed" } else { "native PE" }))
Write-Host (" Pin         : {0}" -f $PinPath)
Write-Host (" Pintool     : {0}" -f $ToolDll)
Write-Host (" Rules dir   : {0}" -f $RulesDir)
Write-Host (" Trace dir   : {0}" -f $OutDir)
Write-Host " Knobs       :"
Write-Host ("    loop_trigger_iters       = {0}" -f $LoopTriggerIters)
Write-Host ("    key_snapshot_bytes       = {0}" -f $KeySnapshotBytes)
Write-Host ("    trace_system_images      = {0}" -f $TraceSystemImages)
Write-Host ("    follow_children          = {0}" -f $FollowChildren)
Write-Host ("    follow_memcpy            = {0}" -f $FollowMemcpy)
Write-Host ("    session                  = '{0}'" -f $Session)
Write-Host ("    debug                    = {0}" -f $TraceDebug)
Write-Host ("    timeout_seconds          = {0} (0 = no timeout)" -f $TimeoutSeconds)
Write-Host ("    graceful_shutdown_secs   = {0}" -f $GracefulShutdownSeconds)
Write-Host "================================================================"

# ─────────────────────────────────────────────────────────────────────────
# Ctrl+C helper — required so the timeout path can ask Pin to flush
# cleanly instead of force-killing it. Pattern: detach our own console,
# attach to the target's console, suppress our own Ctrl+C handler so we
# don't get killed alongside the child, raise CTRL_C_EVENT, then restore.
# ─────────────────────────────────────────────────────────────────────────
$script:CtrlCHelperLoaded = $false
function Initialize-CtrlCHelper {
    if ($script:CtrlCHelperLoaded) { return }
    Add-Type -Namespace 'Ransomflow' -Name 'Win32' -MemberDefinition @'
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleCtrlHandler(System.IntPtr HandlerRoutine, bool Add);
'@
    $script:CtrlCHelperLoaded = $true
}

function Send-CtrlCToProcess {
    param([int]$ProcessId)
    Initialize-CtrlCHelper
    [Ransomflow.Win32]::FreeConsole() | Out-Null
    if (-not [Ransomflow.Win32]::AttachConsole([uint32]$ProcessId)) {
        Write-Warning ("AttachConsole(PID={0}) failed; caller should fall back to taskkill" -f $ProcessId)
        return $false
    }
    # NULL handler with Add=TRUE  →  ignore Ctrl+C in *this* process while
    # we signal the console group. Without this, GenerateConsoleCtrlEvent
    # would kill PowerShell along with Pin.
    [Ransomflow.Win32]::SetConsoleCtrlHandler([System.IntPtr]::Zero, $true) | Out-Null
    $sent = [Ransomflow.Win32]::GenerateConsoleCtrlEvent(0, 0)   # 0 = CTRL_C_EVENT, 0 = current console group
    # Give the console subsystem a beat to deliver the event before we
    # detach — without this, AttachConsole'd events occasionally race.
    Start-Sleep -Milliseconds 200
    [Ransomflow.Win32]::FreeConsole() | Out-Null
    [Ransomflow.Win32]::SetConsoleCtrlHandler([System.IntPtr]::Zero, $false) | Out-Null
    return $sent
}

# ─────────────────────────────────────────────────────────────────────────
# Run Pin once with the given bitness DLL. Returns the Pin exit code; the
# fallback logic combines that with the presence of ransomflow_done.json to
# decide whether the attempt counted as a success.
# ─────────────────────────────────────────────────────────────────────────
function Invoke-PinAttempt {
    param(
        [Parameter(Mandatory)] [string]$ToolDllPath,
        [Parameter(Mandatory)] [int]   $Bits,
        [Parameter(Mandatory)] [string]$SamplePath,
        [Parameter(Mandatory)] [string]$OutDir,
        [Parameter(Mandatory)] [int]   $TimeoutSeconds,
        [Parameter(Mandatory)] [int]   $GracefulShutdownSeconds
    )

    # Pin-LEVEL flags must precede -t. -follow_execv 1 is what actually makes Pin
    # inject itself (and this tool) into spawned child processes, so the registered
    # PIN_AddFollowChildProcessFunction (OnFollowChild) fires and the child writes
    # its own proc_<pid>/. The tool-level -follow_children knob alone is NOT enough:
    # without -follow_execv, Pin never reaches the child, so ransomware that drops +
    # runs a separate encryptor child (e.g. Thanos) is traced only in the launcher
    # process and the child's crypto keys are never captured.
    $pinArgs = @()
    if ($FollowChildren -eq 1) { $pinArgs += @("-follow_execv", "1") }
    $pinArgs += @(
        "-t", $ToolDllPath,
        "-out_dir", $OutDir,
        "-rules_dir", $RulesDir,
        "-loop_trigger_iters", "$LoopTriggerIters",
        "-key_snapshot_bytes", "$KeySnapshotBytes",
        "-trace_system_images", "$TraceSystemImages",
        "-follow_children", "$FollowChildren",
        "-follow_memcpy", "$FollowMemcpy"
    )
    if (-not [string]::IsNullOrEmpty($Session)) { $pinArgs += @("-session", $Session) }
    if ($TraceDebug) { $pinArgs += @("-debug", "1") }
    $pinArgs += @("--", $SamplePath)

    $pinStdout = Join-Path $OutDir ("pin_stdout_{0}bit.log" -f $Bits)
    $pinStderr = Join-Path $OutDir ("pin_stderr_{0}bit.log" -f $Bits)

    Write-Host ("[*] launching Pin ({0}-bit DLL): {1}" -f $Bits, $ToolDllPath)
    $proc = Start-Process -FilePath $PinPath -ArgumentList $pinArgs `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $pinStdout `
        -RedirectStandardError  $pinStderr

    Write-Host ("[*] Pin detached, PID={0}" -f $proc.Id)
    Write-Host ("[*] stdout → {0}" -f $pinStdout)
    Write-Host ("[*] stderr → {0}" -f $pinStderr)

    if ($TimeoutSeconds -gt 0) {
        $wdCmd = ("timeout /t {0} /nobreak >nul && taskkill /F /PID {1} >nul 2>&1" -f $TimeoutSeconds, $proc.Id)
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $wdCmd -WindowStyle Hidden | Out-Null
        Write-Host ("[*] watchdog armed: will taskkill /F PID {0} after {1}s" -f $proc.Id, $TimeoutSeconds)
    }

    if ($TimeoutSeconds -le 0) {
        $proc.WaitForExit()
    }
    else {
        if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
            Write-Host ("[*] timeout reached ({0}s) — sending Ctrl+C to PID {1}" -f $TimeoutSeconds, $proc.Id)
            $sent = Send-CtrlCToProcess -ProcessId $proc.Id
            if ($sent) {
                if (-not $proc.WaitForExit($GracefulShutdownSeconds * 1000)) {
                    Write-Warning ("Pin did not exit {0}s after Ctrl+C — force-killing" -f $GracefulShutdownSeconds)
                    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                    $proc.WaitForExit()
                }
                else {
                    Write-Host "[*] pin exited cleanly after Ctrl+C"
                }
            }
            else {
                Write-Warning "Ctrl+C signal failed — force-killing"
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                $proc.WaitForExit()
            }
        }
    }

    $exitCode = $proc.ExitCode
    Write-Host ("[*] pin exit code ({0}-bit): {1}" -f $Bits, $exitCode)
    return $exitCode
}

function Test-AttemptSuccess {
    param([string]$OutDir)
    $dones = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "ransomflow_done.json" -ErrorAction SilentlyContinue)
    return ($dones.Count -gt 0)
}

# ─────────────────────────────────────────────────────────────────────────
# First attempt (detected bitness) -> auto-fallback to the opposite bitness
# on failure.  When Pin immediately fails on an arch mismatch, it doesn't
# produce ransomflow_done.json; that absence is the signal we use to retry
# with the other-bitness DLL.
# ─────────────────────────────────────────────────────────────────────────
$pinExitCode = Invoke-PinAttempt -ToolDllPath $ToolDll -Bits $tool.Bits `
    -SamplePath $SamplePath -OutDir $OutDir `
    -TimeoutSeconds $TimeoutSeconds -GracefulShutdownSeconds $GracefulShutdownSeconds

if (-not (Test-AttemptSuccess -OutDir $OutDir)) {
    $fallbackBits = if ($tool.Bits -eq 32) { 64 } else { 32 }
    $fallbackDll  = Resolve-ToolDllForBits -Bits $fallbackBits
    if (-not $fallbackDll) {
        Write-Warning ("[!] primary {0}-bit attempt produced no ransomflow_done.json; fallback {1}-bit DLL not found — giving up" `
            -f $tool.Bits, $fallbackBits)
    } else {
        Write-Warning ("[!] primary {0}-bit attempt produced no ransomflow_done.json; retrying with {1}-bit DLL: {2}" `
            -f $tool.Bits, $fallbackBits, $fallbackDll)
        $pinExitCode = Invoke-PinAttempt -ToolDllPath $fallbackDll -Bits $fallbackBits `
            -SamplePath $SamplePath -OutDir $OutDir `
            -TimeoutSeconds $TimeoutSeconds -GracefulShutdownSeconds $GracefulShutdownSeconds
    }
}

# ─────────────────────────────────────────────────────────────────────────
# Summarize
# ─────────────────────────────────────────────────────────────────────────
$procDirs = @(Get-ChildItem -LiteralPath $OutDir -Directory -Filter "proc_*" -ErrorAction SilentlyContinue)
if ($procDirs.Count -eq 0) {
    Write-Warning "No proc_<pid> subdirectories found under: $OutDir"
}
else {
    foreach ($pd in $procDirs) {
        $donePath = Join-Path $pd.FullName "ransomflow_done.json"
        if (Test-Path -LiteralPath $donePath) {
            try {
                $done = Get-Content -LiteralPath $donePath -Raw | ConvertFrom-Json
                Write-Host ("[*] {0}: runtime_seconds       = {1}" -f $pd.Name, $done.runtime_seconds)
                Write-Host ("[*] {0}: peak_working_set_bytes= {1}" -f $pd.Name, $done.peak_working_set_bytes)
            }
            catch {
                Write-Warning "Could not parse $donePath"
            }
        }
        else {
            Write-Warning ("Done file not produced for {0}: {1}" -f $pd.Name, $donePath)
        }
    }
}

Write-Host ""

# Quick file-count summary so the analyst sees what landed.
# Unified naming: every artifact is <name>_<N>.<ext> under each
# proc_<pid> subdirectory of $OutDir (the pintool segregates per
# process — parent + every followed child).
$loopMeta = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "loop_*.json"           -ErrorAction SilentlyContinue)
$loopBins = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "loop_*.bin"            -ErrorAction SilentlyContinue)
$imageChunks = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "images_*.jsonl"        -ErrorAction SilentlyContinue)
$cryptoChunks = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "crypto_events_*.jsonl" -ErrorAction SilentlyContinue)
$ioChunks = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Filter "io_events_*.jsonl"     -ErrorAction SilentlyContinue)

function CountLinesAcross($items) {
    $total = 0
    foreach ($it in $items) {
        if (Test-Path -LiteralPath $it.FullName) {
            $total += (Get-Content -LiteralPath $it.FullName | Measure-Object -Line).Lines
        }
    }
    return $total
}

Write-Host "[*] trace summary:"
Write-Host ("       proc_<pid> dirs           = {0}" -f $procDirs.Count)
Write-Host ("       loops captured            = {0} (json) / {1} (bin)" -f $loopMeta.Count, $loopBins.Count)
Write-Host ("       crypto events             = {0} (across {1} chunks)" -f (CountLinesAcross $cryptoChunks), $cryptoChunks.Count)
Write-Host ("       io events                 = {0} (across {1} chunks)" -f (CountLinesAcross $ioChunks), $ioChunks.Count)
Write-Host ("       image loads               = {0} (across {1} chunks)" -f (CountLinesAcross $imageChunks), $imageChunks.Count)
Write-Host ""

exit $pinExitCode
