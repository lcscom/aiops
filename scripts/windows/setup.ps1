<#
.SYNOPSIS
  VCF AIops — Windows Server 신규 설치 (conda 환경 생성 → 패키지 → 설정 파일 → 방화벽 → 포트 점검)

.EXAMPLE
  # 관리자 PowerShell, 프로젝트 폴더에서
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\scripts\windows\setup.ps1 -InstallMiniforge          # conda가 없을 때 Miniforge 설치부터
  .\scripts\windows\setup.ps1                             # conda가 이미 있을 때
  .\scripts\windows\setup.ps1 -DisableSnmpTrapService     # Windows 'SNMP Trap' 서비스가 162를 점유할 때
  .\scripts\windows\setup.ps1 -DefenderExclusion -HighPerformancePower   # 운영 최적화(선택)
#>
[CmdletBinding()]
param(
    [string]$EnvName = 'vcf-aiops',
    [switch]$InstallMiniforge,
    [string]$MiniforgeDir = "$env:ProgramData\miniforge3",
    [string]$MiniforgeInstaller = '',          # 폐쇄망: 미리 받아둔 Miniforge3-Windows-x86_64.exe 경로
    [switch]$SkipFirewall,
    [switch]$DisableSnmpTrapService,
    [switch]$DefenderExclusion,               # data·logs 폴더 실시간 검사 제외(SQLite WAL 쓰기 지연 방지) — 보안 정책 확인 후 사용
    [switch]$HighPerformancePower,            # 전원 옵션 '고성능' (기본 '균형'의 코어 파킹/클럭 저하로 인한 지연 제거)
    [int[]]$TcpPorts = @(8630, 514, 6514),
    [int[]]$UdpPorts = @(514, 162)
)
. "$PSScriptRoot\common.ps1"
Set-Location $Root
$isAdmin = Test-Admin
if (-not $isAdmin) { Write-Warn2 "관리자 권한이 아닙니다. 방화벽 규칙·서비스 변경·AllUsers 설치는 건너뜁니다." }

# ------------------------------------------------------------------ 1. conda
Write-Step "conda 확인"
$conda = Get-CondaExe
if (-not $conda) {
    if (-not $InstallMiniforge) {
        throw "conda가 없습니다. -InstallMiniforge 옵션으로 다시 실행하거나 Miniforge를 설치하세요."
    }
    $inst = $MiniforgeInstaller
    if (-not $inst) {
        $inst = Join-Path $env:TEMP 'Miniforge3-Windows-x86_64.exe'
        $url = 'https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Windows-x86_64.exe'
        Write-Host "  다운로드: $url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $inst -UseBasicParsing
    }
    $type = if ($isAdmin) { 'AllUsers' } else { 'JustMe' }
    if (-not $isAdmin -and $MiniforgeDir -like "$env:ProgramData*") { $MiniforgeDir = "$env:USERPROFILE\miniforge3" }
    Write-Host "  설치: $MiniforgeDir ($type, 무인 설치)"
    $p = Start-Process -FilePath $inst -Wait -PassThru -ArgumentList @(
        '/S', "/InstallationType=$type", '/RegisterPython=0', '/AddToPath=0', "/D=$MiniforgeDir")
    if ($p.ExitCode -ne 0) { throw "Miniforge 설치 실패 (exit $($p.ExitCode))" }
    $conda = Join-Path $MiniforgeDir 'Scripts\conda.exe'
    if (-not (Test-Path $conda)) { throw "설치 후 conda.exe를 찾지 못했습니다: $conda" }
}
Write-Ok "conda: $conda  ($(& $conda --version))"

# defaults 채널 대신 conda-forge만 사용(환경 파일에 지정) — 채널 우선순위 strict
& $conda config --set channel_priority strict | Out-Null

# ------------------------------------------------------------------ 2. 환경 생성/갱신
Write-Step "conda 환경 '$EnvName' 생성/갱신 (python 3.12 + requirements.txt)"
$prefix = Get-EnvPrefix $conda $EnvName
if ($prefix) {
    Write-Host "  기존 환경 갱신: $prefix"
    & $conda env update -n $EnvName -f "$Root\environment.yml" --prune
} else {
    & $conda env create -n $EnvName -f "$Root\environment.yml"
}
if ($LASTEXITCODE -ne 0) { throw "conda 환경 생성 실패 (exit $LASTEXITCODE)" }
$py = Get-EnvPython $EnvName
Write-Ok "python: $py ($(& $py --version))"

# ------------------------------------------------------------------ 3. 설치 검증
Write-Step "패키지 import 검증"
$check = @'
import importlib, sys
mods = ["fastapi", "uvicorn", "httptools", "websockets", "httpx", "pyVmomi", "yaml", "pysnmp", "cryptography", "numpy", "bs4", "pypdf", "ldap3"]
bad = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception as e:
        bad.append(f"{m}: {e}")
import app.main  # 앱 모듈 로드(설정 파일 없이도 기본값으로 로드)
print("FAIL " + " | ".join(bad) if bad else "OK")
'@
# Windows PowerShell 5.1은 네이티브 인자 내 큰따옴표를 깨뜨리므로 임시 .py 파일로 실행
$tmpPy = Join-Path $env:TEMP 'vcf_aiops_check.py'
Set-Content -Path $tmpPy -Value $check -Encoding UTF8
$env:AIOPS_CONFIG = Join-Path $Root 'config.example.yaml'
$res = & $py $tmpPy | Select-Object -Last 1   # stderr 리다이렉트 금지(PS 5.1 + Stop 에서 예외 발생)
Remove-Item Env:\AIOPS_CONFIG
Remove-Item $tmpPy -ErrorAction SilentlyContinue
if ("$res" -notmatch '^OK') { throw "패키지 검증 실패: $res" }
Write-Ok "모든 모듈 로드 성공"
& $py -O -m compileall -q "$Root\app" | Out-Null   # -O 바이트코드(.opt-1.pyc) 사전 컴파일 — 서비스(-O) 첫 기동 단축
Write-Ok "바이트코드 사전 컴파일"

# ------------------------------------------------------------------ 4. 설정 파일
Write-Step "설정 파일"
foreach ($pair in @(@('config.example.yaml', 'config.yaml'), @('.env.example', '.env'))) {
    $src = Join-Path $Root $pair[0]; $dst = Join-Path $Root $pair[1]
    if (Test-Path $dst) { Write-Ok "$($pair[1]) 유지(이미 있음)" }
    else { Copy-Item $src $dst; Write-Ok "$($pair[1]) 생성 — 접속 정보·비밀번호를 입력하세요" }
}
New-Item -ItemType Directory -Force -Path "$Root\data", "$Root\logs", "$Root\certs" | Out-Null

# ------------------------------------------------------------------ 5. 포트 점검 (SNMP Trap / Syslog)
Write-Step "수신 포트 점검"
$svc = Get-Service -Name SNMPTRAP -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
        if ($DisableSnmpTrapService -and $isAdmin) {
            Stop-Service SNMPTRAP -Force -ErrorAction SilentlyContinue
            Set-Service SNMPTRAP -StartupType Disabled
            Write-Ok "Windows 'SNMP Trap'(SNMPTRAP) 서비스 중지·비활성화 — UDP 162 확보"
        } else {
            Write-Warn2 "Windows 'SNMP Trap' 서비스가 있습니다(상태 $($svc.Status), 시작 $($svc.StartType)). 실행되면 UDP 162를 점유하니 -DisableSnmpTrapService 로 비활성화하세요."
        }
    }
}
foreach ($u in $UdpPorts) {
    $ep = Get-NetUDPEndpoint -LocalPort $u -ErrorAction SilentlyContinue
    if ($ep) {
        $owner = ($ep | Select-Object -First 1).OwningProcess
        $name = (Get-Process -Id $owner -ErrorAction SilentlyContinue).ProcessName
        Write-Warn2 "UDP $u 사용 중 — PID $owner ($name). config.yaml 에서 포트를 바꾸거나 해당 프로세스를 정리하세요."
    } else { Write-Ok "UDP $u 사용 가능" }
}
foreach ($t in $TcpPorts) {
    $ep = Get-NetTCPConnection -LocalPort $t -State Listen -ErrorAction SilentlyContinue
    if ($ep) { Write-Warn2 "TCP $t 사용 중 — PID $(($ep | Select-Object -First 1).OwningProcess)" } else { Write-Ok "TCP $t 사용 가능" }
}

# ------------------------------------------------------------------ 6. 방화벽
if (-not $SkipFirewall -and $isAdmin) {
    Write-Step "Windows 방화벽 인바운드 규칙"
    $rules = @()
    foreach ($t in $TcpPorts) { $rules += [pscustomobject]@{ P = 'TCP'; Port = $t } }
    foreach ($u in $UdpPorts) { $rules += [pscustomobject]@{ P = 'UDP'; Port = $u } }
    foreach ($r in $rules) {
        $name = "VCF AIops $($r.P) $($r.Port)"
        if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { Write-Ok "$name (이미 있음)"; continue }
        New-NetFirewallRule -DisplayName $name -Group 'VCF AIops' -Direction Inbound -Protocol $r.P -LocalPort $r.Port `
            -Action Allow -Profile Domain,Private | Out-Null
        Write-Ok $name
    }
    Write-Host "  (Public 프로필은 열지 않음. 필요 시: Set-NetFirewallRule -Group 'VCF AIops' -Profile Any)"
}

# ------------------------------------------------------------------ 7. 운영 최적화(선택)
if ($DefenderExclusion -and $isAdmin) {
    Write-Step "Microsoft Defender 실시간 검사 제외"
    try {
        Add-MpPreference -ExclusionPath "$Root\data", "$Root\logs"
        Write-Ok "제외: data\, logs\ (SQLite·로그 고빈도 쓰기)"
    } catch { Write-Warn2 "Defender 설정 실패(그룹 정책 관리 중일 수 있음): $($_.Exception.Message)" }
}
if ($HighPerformancePower -and $isAdmin) {
    Write-Step "전원 옵션"
    & powercfg /setactive SCHEME_MIN
    Write-Ok "고성능(SCHEME_MIN) 적용"
}

Write-Host "`n완료." -ForegroundColor Green
Write-Host "  1) config.yaml / .env 편집 (PAIS·임베딩·커넥터 접속 정보)"
Write-Host "  2) 점검:       .\scripts\windows\run.ps1 -Demo       (콘솔 실행, Ctrl+C 종료)"
Write-Host "  3) HTTPS(선택): .\scripts\windows\export-cert.ps1 -Thumbprint <사내CA 인증서 지문>"
Write-Host "  4) 서비스:     .\scripts\windows\service.ps1 install   (자동 시작·장애 시 재시작·로그 순환)"
Write-Host "  대시보드 http(s)://<서버>:8630"
