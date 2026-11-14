<#
.SYNOPSIS
    Merge the split OVA parts (vcf-aiops-2.1.0.ova.part00, .part01, ...) into one file and verify its SHA-256.

.DESCRIPTION
    1. Finds vcf-aiops-2.1.0.ova.partNN files in -Path (default: the folder this script is in).
    2. Checks that part numbers are contiguous (part00 .. partNN, no gaps).
    3. Concatenates the parts in numeric order into a temporary file, then renames it to
       vcf-aiops-2.1.0.ova (an interrupted run never leaves a half-written file behind).
    4. Verifies the result against the SHA-256 in SHA256SUMS (if present) or the hash
       built into this script, and checks the total size.
    Exit code: 0 = merged and verified, 1 = any error or checksum mismatch.

.PARAMETER Path
    Folder containing the parts and SHA256SUMS. Default: the script folder.

.PARAMETER Output
    Output file path. Default: <Path>\vcf-aiops-2.1.0.ova

.PARAMETER Force
    Rebuild the output even if it already exists with a different hash.

.PARAMETER DeleteParts
    Delete the .partNN files after the merged file passes verification.

.PARAMETER SkipVerify
    Merge only, do not verify the checksum (not recommended).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Merge-Ova.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Merge-Ova.ps1 -Path D:\Downloads\vcf-aiops -DeleteParts

.NOTES
    Works with Windows PowerShell 5.1 and PowerShell 7+. No external tools required.
    This file is plain ASCII on purpose so it parses correctly in Windows PowerShell 5.1.
#>
[CmdletBinding()]
param(
    [string]$Path = $PSScriptRoot,
    [string]$Output = "",
    [switch]$Force,
    [switch]$DeleteParts,
    [switch]$SkipVerify
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------- release constants
$FileName     = "vcf-aiops-2.1.0.ova"
$BuiltInHash  = "94f5bd6df143fe26130450ba01f96cb2d4e7a6a270c81eecd9dd63e232b8132f"
$ExpectedSize = 300236800
$SumsName     = "SHA256SUMS"

function Write-Info([string]$m) { Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Pass([string]$m) { Write-Host "[ OK ] $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Fail([string]$m) { Write-Host "[FAIL] $m" -ForegroundColor Red }
function Format-Size([long]$b) {
    if ($b -ge 1GB) { return "{0:N2} GB" -f ($b / 1GB) }
    if ($b -ge 1MB) { return "{0:N1} MB" -f ($b / 1MB) }
    return "{0:N0} KB" -f ($b / 1KB)
}
function Get-Sha256([string]$file) { return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }

$tmp = $null
try {
    if (-not $Path) { $Path = (Get-Location).Path }
    $Path = (Resolve-Path -LiteralPath $Path).Path
    if (-not $Output) { $Output = Join-Path $Path $FileName }
    Write-Host ""
    Write-Host "=== OVA merge: $FileName ===" -ForegroundColor White
    Write-Info "Folder : $Path"
    Write-Info "Output : $Output"

    # ------------------------------------------------------------ expected hash
    $expected = $BuiltInHash
    $hashSource = "built-in"
    $sumsPath = Join-Path $Path $SumsName
    if (Test-Path -LiteralPath $sumsPath) {
        foreach ($line in Get-Content -LiteralPath $sumsPath) {
            if ($line -match '^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$' -and $Matches[2] -eq $FileName) {
                $expected = $Matches[1].ToLowerInvariant(); $hashSource = $SumsName
            }
        }
        if ($hashSource -eq $SumsName -and $expected -ne $BuiltInHash) {
            Write-Warn "$SumsName hash differs from the built-in hash - using $SumsName"
        }
    }
    Write-Info ("Expected SHA-256 ({0}): {1}" -f $hashSource, $expected)

    # ------------------------------------------------------------ collect parts
    $rx = '^' + [regex]::Escape($FileName) + '\.part(\d+)$'
    $parts = @(Get-ChildItem -LiteralPath $Path -File | Where-Object { $_.Name -match $rx } |
        ForEach-Object { [pscustomobject]@{ Index = [int]([regex]::Match($_.Name, $rx).Groups[1].Value); File = $_ } } |
        Sort-Object Index)

    # Already merged and valid?
    if (Test-Path -LiteralPath $Output) {
        $h = Get-Sha256 $Output
        if ($h -eq $expected) {
            Write-Pass "Output already exists and the checksum matches - nothing to do."
            if ($DeleteParts -and $parts.Count -gt 0) {
                $parts | ForEach-Object { Remove-Item -LiteralPath $_.File.FullName -Force }
                Write-Pass ("Deleted {0} part file(s)." -f $parts.Count)
            }
            exit 0
        }
        if (-not $Force) {
            Write-Fail "Output already exists but its checksum does not match. Re-run with -Force to rebuild it."
            Write-Host  "       actual: $h"
            exit 1
        }
        Write-Warn "Existing output has a wrong checksum - rebuilding (-Force)."
    }

    if ($parts.Count -eq 0) {
        Write-Fail "No part files found ($FileName.part00, .part01, ...) in $Path"
        exit 1
    }

    # Contiguity check: part00 .. partN
    $missing = @()
    $max = [int](($parts | Measure-Object -Property Index -Maximum).Maximum)
    for ($i = 0; $i -le $max; $i++) {
        if (-not ($parts | Where-Object { $_.Index -eq $i })) { $missing += ("part{0:D2}" -f $i) }
    }
    if ($missing.Count -gt 0) {
        Write-Fail ("Missing part file(s): {0}" -f ($missing -join ", "))
        exit 1
    }
    $total = [long]0
    foreach ($p in $parts) { $total += $p.File.Length }
    Write-Info ("Found {0} part(s): part00 .. part{1:D2}, total {2}" -f $parts.Count, $max, (Format-Size $total))
    if ($ExpectedSize -gt 0 -and $total -ne $ExpectedSize) {
        Write-Fail ("Total size of parts is {0:N0} bytes, expected {1:N0} bytes - a part is incomplete or extra." -f $total, $ExpectedSize)
        exit 1
    }

    # Free space check
    try {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($Output))
        $free = (New-Object System.IO.DriveInfo($root)).AvailableFreeSpace
        if ($free -lt $total) { Write-Fail ("Not enough free space on {0}: need {1}, have {2}" -f $root, (Format-Size $total), (Format-Size $free)); exit 1 }
    } catch { }

    # ------------------------------------------------------------ merge (stream copy)
    $tmp = "$Output.merging"
    $buffer = New-Object byte[] (4MB)
    $done = [long]0
    $out = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        foreach ($p in $parts) {
            $in = [System.IO.File]::Open($p.File.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                while (($n = $in.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $out.Write($buffer, 0, $n)
                    $done += $n
                }
            } finally { $in.Dispose() }
            Write-Progress -Activity "Merging $FileName" -Status $p.File.Name -PercentComplete ([int](100 * $done / [Math]::Max([long]1, $total)))
        }
        $out.Flush()
    } finally {
        $out.Dispose()
        Write-Progress -Activity "Merging $FileName" -Completed
    }
    if (Test-Path -LiteralPath $Output) { Remove-Item -LiteralPath $Output -Force }
    Move-Item -LiteralPath $tmp -Destination $Output
    $size = (Get-Item -LiteralPath $Output).Length
    if ($size -ne $total) { Write-Fail ("Merged size {0:N0} != sum of parts {1:N0}" -f $size, $total); exit 1 }
    Write-Pass ("Merged {0} part(s) -> {1} ({2})" -f $parts.Count, $FileName, (Format-Size $size))

    # ------------------------------------------------------------ verify
    if ($SkipVerify) {
        Write-Warn "Checksum verification skipped (-SkipVerify)."
        exit 0
    }
    Write-Info "Computing SHA-256 ..."
    $actual = Get-Sha256 $Output
    if ($actual -ne $expected) {
        Write-Fail "Checksum MISMATCH - do not use this file. Re-download the parts and run again."
        Write-Host  "       expected: $expected"
        Write-Host  "       actual  : $actual"
        exit 1
    }
    Write-Pass "SHA-256 verified: $actual"

    if ($DeleteParts) {
        $parts | ForEach-Object { Remove-Item -LiteralPath $_.File.FullName -Force }
        Write-Pass ("Deleted {0} part file(s)." -f $parts.Count)
    }
    Write-Host ""
    Write-Host "Done. Deploy in vSphere Client: Deploy OVF Template > vcf-aiops-2.1.0.ova" -ForegroundColor White
    exit 0
}
catch {
    Write-Fail $_.Exception.Message
    if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    exit 1
}
