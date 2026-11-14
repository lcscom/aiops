<#
.SYNOPSIS
  VCF AIops Windows 서비스 관리 — WinSW v2.12.0 (MIT, scripts\windows\bin 동봉) 래퍼.
  서비스 = conda 환경 python.exe -m app.serve (단일 프로세스, :8630)

.EXAMPLE
  .\scripts\windows\service.ps1 install                       # 등록 + 시작 (LocalSystem)
  .\scripts\windows\service.ps1 install -Account LocalService # 최소 권한 계정 + 폴더 ACL 자동 부여
  .\scripts\windows\service.ps1 restart | stop | start | status | logs | uninstall
  .\scripts\windows\service.ps1 install -NoWatchdog              # 응답 감시(워치독) 작업 등록 생략
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][ValidateSet('install', 'uninstall', 'start', 'stop', 'restart', 'status', 'logs')]
    [string]$Action = 'status',
    [string]$EnvName = 'vcf-aiops',
    [string]$ServiceId = 'VCF-AIOps',
    [ValidateSet('LocalSystem', 'LocalService', 'NetworkService')][string]$Account = 'LocalSystem',
    [int]$LogSizeKB = 20480,
    [int]$LogKeep = 10,
    [switch]$NoWatchdog
)
. "$PSScriptRoot\common.ps1"

$svcDir = Join-Path $Root 'service'
$exe = Join-Path $svcDir 'vcf-aiops-service.exe'
$xml = Join-Path $svcDir 'vcf-aiops-service.xml'

function Get-Port {
    $cfg = Join-Path $Root 'config.yaml'
    if (Test-Path $cfg) {
        $m = Select-String -Path $cfg -Pattern '^\s{2}port:\s*(\d+)' | Select-Object -First 1
        if ($m) { return [int]$m.Matches[0].Groups[1].Value }
    }
    return 8630
}

$wdTask = "$ServiceId-Watchdog"
function Register-Watchdog {
    # 1분마다 SYSTEM 으로 watchdog.ps1 — 프로세스는 살아 있지만 응답 없는(멈춘) 상태를 재시작(WinSW 는 종료 시에만 재시작)
    $ps = (Get-Command powershell.exe).Source
    $act = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$PSScriptRoot\watchdog.ps1`" -ServiceId $ServiceId"
    $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew -StartWhenAvailable
    $pr = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $wdTask -Action $act -Trigger $trg -Settings $set -Principal $pr -Force | Out-Null
    Write-Ok "응답 감시 작업 등록: $wdTask (1분 주기 · /healthz 3분 무응답 또는 /readyz 5분 실패 시 재시작 · logs\watchdog.log)"
}
function Unregister-Watchdog {
    if (Get-ScheduledTask -TaskName $wdTask -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $wdTask -Confirm:$false
        Write-Ok "응답 감시 작업 해제: $wdTask"
    }
}

function Test-Health([int]$Seconds = 40) {
    $port = Get-Port
    $https = (Test-Path "$Root\certs\aiops.crt") -and (Test-Path "$Root\certs\aiops.key")
    $url = if ($https) { "https://127.0.0.1:$port/healthz" } else { "http://127.0.0.1:$port/healthz" }
    if ($https -and $PSVersionTable.PSVersion.Major -lt 6) {
        Add-Type -TypeDefinition @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class AiopsTrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint a, X509Certificate b, WebRequest c, int d) { return true; } }
"@ -ErrorAction SilentlyContinue
        [Net.ServicePointManager]::CertificatePolicy = New-Object AiopsTrustAll
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    foreach ($i in 1..$Seconds) {
        try {
            $r = if ($PSVersionTable.PSVersion.Major -ge 6) { Invoke-RestMethod $url -TimeoutSec 2 -SkipCertificateCheck }
                 else { Invoke-RestMethod $url -TimeoutSec 2 }
            Write-Ok "응답 OK — $url (LLM: $($r.llm))"
            return $true
        } catch { Start-Sleep -Seconds 1 }
    }
    Write-Warn2 "응답 없음 — logs\vcf-aiops-service.err.log 확인"
    Get-Content "$Root\logs\vcf-aiops-service.err.log" -Tail 25 -ErrorAction SilentlyContinue
    return $false
}

function Grant-Acl([string]$Principal) {
    # 실행 계정에 프로젝트 읽기, data/logs 쓰기, conda 환경 읽기 권한
    $py = Get-EnvPython $EnvName
    $envDir = Split-Path $py -Parent
    & icacls $Root /grant "${Principal}:(OI)(CI)RX" /T /C /Q | Out-Null
    foreach ($d in 'data', 'logs') {
        New-Item -ItemType Directory -Force -Path "$Root\$d" | Out-Null
        & icacls "$Root\$d" /grant "${Principal}:(OI)(CI)M" /T /C /Q | Out-Null
    }
    & icacls $envDir /grant "${Principal}:(OI)(CI)RX" /T /C /Q | Out-Null
    Write-Ok "ACL 부여: $Principal (프로젝트·conda 환경 읽기, data·logs 수정)"
}

function Protect-Sensitive([string]$Principal) {
    # data(DB·백업·초기 비밀번호·암호화 키), certs, config.yaml, .env — 상속 제거 후 SYSTEM·Administrators·서비스 계정만 허용
    # (DPAPI LOCAL_MACHINE 범위 암호문을 일반 로컬 사용자가 읽지 못하도록 파일 ACL 로 보호)  SID 사용: 언어 무관
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    if ($Principal) { $grants += "${Principal}:(OI)(CI)M" }
    foreach ($d in 'data', 'certs') {
        New-Item -ItemType Directory -Force -Path "$Root\$d" | Out-Null
        & icacls "$Root\$d" /inheritance:r /grant:r $grants /T /C /Q | Out-Null
    }
    $fileGrants = @('*S-1-5-18:F', '*S-1-5-32-544:F'); if ($Principal) { $fileGrants += "${Principal}:R" }
    foreach ($f in 'config.yaml', '.env') {
        if (Test-Path "$Root\$f") { & icacls "$Root\$f" /inheritance:r /grant:r $fileGrants /C /Q | Out-Null }
    }
    Write-Ok "민감 경로 ACL 강화: data·certs·config.yaml·.env (SYSTEM·Administrators$(if ($Principal) { '·' + $Principal }))"
}

function Write-Xml {
    $py = Get-EnvPython $EnvName
    $accountXml = switch ($Account) {
        'LocalService'   { "<serviceaccount><domain>NT AUTHORITY</domain><user>LocalService</user></serviceaccount>" }
        'NetworkService' { "<serviceaccount><domain>NT AUTHORITY</domain><user>NetworkService</user></serviceaccount>" }
        default          { "" }      # LocalSystem (WinSW 기본)
    }
    $content = @"
<!-- 자동 생성: scripts\windows\service.ps1 install  (직접 수정 시 다음 install 때 덮어씀) -->
<service>
  <id>$ServiceId</id>
  <name>VCF AIops</name>
  <description>VMware Cloud Foundation 로그 수집·이상탐지·Private AI 분석 (FastAPI :$(Get-Port), syslog 514, SNMP 162)</description>
  <executable>$py</executable>
  <arguments>-X utf8 -O -m app.serve</arguments>
  <workingdirectory>$Root</workingdirectory>
  <env name="AIOPS_CONFIG" value="$Root\config.yaml"/>
  <env name="AIOPS_ENV_FILE" value="$Root\.env"/>
  <env name="PYTHONUNBUFFERED" value="1"/>
  <env name="PYTHONDONTWRITEBYTECODE" value="1"/>
  <startmode>Automatic</startmode>
  <delayedAutoStart/>
  <depend>Tcpip</depend>
  <onfailure action="restart" delay="5 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <resetfailure>1 hour</resetfailure>
  <stoptimeout>20 sec</stoptimeout>
  <logpath>$Root\logs</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>$LogSizeKB</sizeThreshold>
    <keepFiles>$LogKeep</keepFiles>
  </log>
  $accountXml
</service>
"@
    Set-Content -Path $xml -Value $content -Encoding UTF8
}

function Invoke-WinSW([string]$cmd) {
    & $exe $cmd
    if ($LASTEXITCODE -ne 0 -and $cmd -notin 'status') { throw "WinSW $cmd 실패 (exit $LASTEXITCODE)" }
}

$svc = Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
switch ($Action) {
    'install' {
        if (-not (Test-Admin)) { throw "관리자 PowerShell에서 실행하세요." }
        if (-not (Test-Path "$Root\config.yaml")) { throw "config.yaml 이 없습니다. setup.ps1 을 먼저 실행하세요." }
        New-Item -ItemType Directory -Force -Path $svcDir, "$Root\logs", "$Root\data" | Out-Null
        if ($svc) {
            Write-Step "기존 서비스 교체"
            if ($svc.Status -ne 'Stopped') { Stop-Service $ServiceId -Force; (Get-Service $ServiceId).WaitForStatus('Stopped', '00:00:30') }
            Invoke-WinSW 'uninstall'
            Start-Sleep -Seconds 2
        }
        Copy-Item "$PSScriptRoot\bin\WinSW.NET461.exe" $exe -Force
        Write-Xml
        # 계정 이름은 OS 언어·표기(LOCAL SERVICE)에 따라 달라 SID 로 지정
        $acctSid = @{ LocalService = '*S-1-5-19'; NetworkService = '*S-1-5-20' }[$Account]
        if ($acctSid) { Grant-Acl $acctSid; Protect-Sensitive $acctSid } else { Protect-Sensitive '' }
        Write-Step "서비스 등록: $ServiceId ($Account, 자동-지연 시작, 실패 시 5s/30s/60s 재시작, 로그 ${LogSizeKB}KB×$LogKeep 순환)"
        Invoke-WinSW 'install'
        & sc.exe failureflag $ServiceId 1 | Out-Null          # 비정상 종료 코드에도 복구 동작 적용
        Start-Service $ServiceId
        Write-Ok "시작됨"
        [void](Test-Health)
        if (-not $NoWatchdog) { Register-Watchdog } else { Unregister-Watchdog }
        if (Test-Path "$Root\data\initial-admin.txt") {
            Write-Warn2 "초기 관리자 비밀번호: $Root\data\initial-admin.txt (관리자만 열람 가능) — 최초 로그인 시 변경 후 파일을 삭제하세요."
        }
    }
    'uninstall' {
        if (-not (Test-Admin)) { throw "관리자 PowerShell에서 실행하세요." }
        if (-not $svc) { Write-Ok "등록된 서비스 없음"; return }
        Unregister-Watchdog
        if ($svc.Status -ne 'Stopped') { Stop-Service $ServiceId -Force }
        Invoke-WinSW 'uninstall'
        Write-Ok "$ServiceId 해제"
    }
    'start'   { Start-Service $ServiceId; [void](Test-Health) }
    'stop'    { Stop-Service $ServiceId -Force; Write-Ok "중지" }
    'restart' { Restart-Service $ServiceId -Force; [void](Test-Health) }
    'status'  {
        if (-not $svc) { Write-Warn2 "서비스 미등록 — service.ps1 install"; return }
        $w = Get-CimInstance Win32_Service -Filter "Name='$ServiceId'"
        Write-Host ("  상태 {0} · 시작 {1} · 계정 {2} · PID {3}" -f $svc.Status, $w.StartMode, $w.StartName, $w.ProcessId)
        if ($svc.Status -eq 'Running') { [void](Test-Health 5) }
    }
    'logs'    {
        Get-ChildItem "$Root\logs\vcf-aiops-service*.log" | Sort-Object LastWriteTime | Select-Object -Last 2 |
            ForEach-Object { Write-Step $_.Name; Get-Content $_.FullName -Tail 40 }
    }
}
