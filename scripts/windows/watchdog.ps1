<#
.SYNOPSIS
  VCF AIops 응답 감시(워치독) — 작업 스케줄러가 1분마다 SYSTEM 으로 실행.
  WinSW 는 프로세스가 '종료'될 때만 재시작한다. 프로세스는 살아 있지만 응답이 없는(멈춘) 경우를 잡기 위해
  /healthz(생존)·/readyz(준비)를 확인해 연속 실패 시 서비스를 재시작하고 Windows 이벤트 로그·logs\watchdog.log 에 남긴다.

  · /healthz 무응답 3회 연속(약 3분)          → 재시작 (이벤트 루프 정지·교착)
  · /readyz 503 5회 연속(약 5분)              → 재시작 (핵심 내부 작업 정지·DB 쓰기 장기 실패)
  · 재시작 후 10분은 재시작하지 않음(재시작 폭주 방지), 하루 최대 6회

.EXAMPLE
  .\scripts\windows\service.ps1 install      # 서비스 등록 시 워치독 작업도 함께 등록(-NoWatchdog 로 생략)
  .\scripts\windows\watchdog.ps1 -Once       # 수동 1회 점검
#>
[CmdletBinding()]
param(
    [string]$ServiceId = 'VCF-AIOps',
    [int]$LiveFails = 3,
    [int]$ReadyFails = 5,
    [int]$CooldownMin = 10,
    [int]$MaxPerDay = 6,
    [switch]$Once
)
$ErrorActionPreference = 'Continue'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$stateFile = Join-Path $Root 'data\watchdog.json'
$logFile = Join-Path $Root 'logs\watchdog.log'
New-Item -ItemType Directory -Force -Path (Split-Path $logFile), (Split-Path $stateFile) | Out-Null

function Log([string]$m) {
    $line = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    if ($Once) { Write-Host $line }
}
function Event([string]$m, [string]$type = 'Warning') {
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('VCF-AIOps-Watchdog')) { New-EventLog -LogName Application -Source 'VCF-AIOps-Watchdog' }
        Write-EventLog -LogName Application -Source 'VCF-AIOps-Watchdog' -EventId 9100 -EntryType $type -Message $m
    } catch { }
}

# 포트·TLS(config.yaml server.port, certs\aiops.*)
$port = 8630
$cfg = Join-Path $Root 'config.yaml'
if (Test-Path $cfg) {
    $mm = Select-String -Path $cfg -Pattern '^\s{2}port:\s*(\d+)' | Select-Object -First 1
    if ($mm) { $port = [int]$mm.Matches[0].Groups[1].Value }
}
$https = (Test-Path "$Root\certs\aiops.crt") -and (Test-Path "$Root\certs\aiops.key")
$base = if ($https) { "https://127.0.0.1:$port" } else { "http://127.0.0.1:$port" }
if ($https -and $PSVersionTable.PSVersion.Major -lt 6) {
    Add-Type -TypeDefinition @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class AiopsWdTrust : ICertificatePolicy { public bool CheckValidationResult(ServicePoint a, X509Certificate b, WebRequest c, int d) { return true; } }
"@ -ErrorAction SilentlyContinue
    [Net.ServicePointManager]::CertificatePolicy = New-Object AiopsWdTrust
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}
function Probe([string]$path) {
    # 반환: 200/503 등 HTTP 코드, 0 = 무응답
    try {
        $p = @{ Uri = "$base$path"; TimeoutSec = 10; UseBasicParsing = $true }
        if ($PSVersionTable.PSVersion.Major -ge 6) { $p.SkipCertificateCheck = $true }
        $r = Invoke-WebRequest @p
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

$st = @{ live = 0; ready = 0; last_restart = 0; day = ''; count = 0 }
if (Test-Path $stateFile) {
    try { $j = Get-Content $stateFile -Raw | ConvertFrom-Json; foreach ($k in $st.Keys.Clone()) { if ($null -ne $j.$k) { $st[$k] = $j.$k } } } catch { }
}
$today = Get-Date -Format 'yyyy-MM-dd'
if ($st.day -ne $today) { $st.day = $today; $st.count = 0 }

$svc = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
if (-not $svc) { Log "서비스 $ServiceId 미등록 — 점검 생략"; exit 0 }
if ($svc.Status -ne 'Running') {
    # 정지 상태는 WinSW 복구 동작·운영자 판단 영역 — 의도적 정지일 수 있으므로 시작하지 않음
    $st.live = 0; $st.ready = 0
    $st | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8
    exit 0
}

$live = Probe '/healthz'
$ready = if ($live -eq 200) { Probe '/readyz' } else { 0 }
if ($live -eq 200) { $st.live = 0 } else { $st.live++ }
if ($ready -eq 200) { $st.ready = 0 } elseif ($live -eq 200) { $st.ready++ }
$now = [int][double]::Parse((Get-Date -UFormat %s))
$reason = ''
if ($st.live -ge $LiveFails) { $reason = "/healthz 무응답 $($st.live)회 연속(프로세스 응답 정지)" }
elseif ($st.ready -ge $ReadyFails) { $reason = "/readyz 실패 $($st.ready)회 연속(HTTP $ready — 핵심 내부 작업 정지 또는 DB 쓰기 실패)" }
if ($Once) { Log "점검: healthz=$live readyz=$ready 연속실패 live=$($st.live) ready=$($st.ready)" }

if ($reason) {
    if ($now - [int]$st.last_restart -lt $CooldownMin * 60) {
        Log "재시작 보류(최근 재시작 후 $CooldownMin 분 이내): $reason"
    } elseif ($st.count -ge $MaxPerDay) {
        Log "재시작 보류(오늘 $($st.count)회 — 일일 한도): $reason"
        Event "VCF AIops 워치독: 일일 재시작 한도 초과 — 수동 점검 필요. $reason" 'Error'
    } else {
        Log "서비스 재시작: $reason"
        Event "VCF AIops 워치독이 서비스를 재시작합니다: $reason"
        try {
            Restart-Service $ServiceId -Force -ErrorAction Stop
        } catch {
            # 중지 응답 없음 → 프로세스 강제 종료 후 시작(WinSW 자식 python 포함)
            $w = Get-CimInstance Win32_Service -Filter "Name='$ServiceId'"
            if ($w.ProcessId) { Stop-Process -Id $w.ProcessId -Force -ErrorAction SilentlyContinue }
            Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -match 'app\.serve' } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 3
            Start-Service $ServiceId
        }
        $st.last_restart = $now; $st.count++; $st.live = 0; $st.ready = 0
    }
}
$st | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8
