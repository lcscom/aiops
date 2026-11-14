# 공통 함수 — 다른 스크립트에서 dot-source:  . "$PSScriptRoot\common.ps1"
$ErrorActionPreference = 'Stop'
$Script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Write-Step([string]$msg) { Write-Host "`n▶ $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "  ✔ $msg" -ForegroundColor Green }
function Write-Warn2([string]$msg){ Write-Host "  ! $msg" -ForegroundColor Yellow }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CondaExe {
    $cmd = Get-Command conda.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if ($env:CONDA_EXE -and (Test-Path $env:CONDA_EXE)) { return $env:CONDA_EXE }
    $roots = @("$env:ProgramData\miniforge3", "$env:USERPROFILE\miniforge3", "$env:LOCALAPPDATA\miniforge3",
               "$env:ProgramData\miniconda3", "$env:USERPROFILE\miniconda3",
               "$env:ProgramData\anaconda3", "$env:USERPROFILE\anaconda3", "C:\miniforge3", "C:\miniconda3")
    foreach ($r in $roots) {
        $exe = "$r\Scripts\conda.exe"
        if (Test-Path $exe) { return $exe }
    }
    return $null
}

function Get-EnvPrefix([string]$CondaExe, [string]$EnvName) {
    $json = & $CondaExe env list --json | Out-String | ConvertFrom-Json
    foreach ($p in $json.envs) {
        if ((Split-Path $p -Leaf) -ieq $EnvName) { return $p }
    }
    return $null
}

function Get-EnvPython([string]$EnvName = 'vcf-aiops') {
    $conda = Get-CondaExe
    if (-not $conda) { throw "conda를 찾을 수 없습니다. 먼저 scripts\windows\setup.ps1 -InstallMiniforge 를 실행하세요." }
    $prefix = Get-EnvPrefix $conda $EnvName
    if (-not $prefix) { throw "conda 환경 '$EnvName' 이 없습니다. scripts\windows\setup.ps1 을 먼저 실행하세요." }
    $py = Join-Path $prefix 'python.exe'
    if (-not (Test-Path $py)) { throw "python.exe 없음: $py" }
    return $py
}
