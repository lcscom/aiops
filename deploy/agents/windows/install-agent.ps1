<#
.SYNOPSIS
  VCF AIops 에이전트 — Windows VM 게스트 · 물리 서버 이벤트 로그 실시간 전송 (Fluent Bit winevtlog → HTTPS /api/ingest)

  수집: System · Application · Security(로그온 실패·잠금·계정 변경 등 보안 핵심 이벤트만) + 선택 채널(-ExtraChannels) + 선택 파일(-Files)
  하트비트 60초 · 디스크 버퍼(기본 1GB) · 서비스 자동 시작/실패 시 재시작

.EXAMPLE
  # 관리자 PowerShell (AIOps 화면 › VM·서버 에이전트 › 등록 이 명령을 생성해 줍니다)
  .\install-agent.ps1 -Server https://aiops.vcf.lab:8630 -Token aiops_xxx -Kind vm -Role DB
  .\install-agent.ps1 -Server https://aiops.vcf.lab:8630 -Token aiops_xxx -CaFile C:\corp-ca.pem `
      -ExtraChannels 'Microsoft-Windows-FailoverClustering/Operational' -Files 'D:\App\logs\*.log'
  .\install-agent.ps1 -Server ... -Token ... -Package C:\temp\fluent-bit-5.1.3-win64.zip     # 망분리(오프라인)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$Token,
    [ValidateSet('vm', 'baremetal', '')][string]$Kind = '',
    [ValidatePattern('^[A-Za-z0-9_-]{0,30}$')][string]$Role = '',
    [string[]]$ExtraChannels = @(),
    [string[]]$Files = @(),
    [string]$CaFile = '',
    [switch]$Insecure,
    [string]$Package = '',
    [string]$Version = '5.1.3',
    [string]$InstallDir = "$env:ProgramFiles\fluent-bit",
    [string]$DataDir = "$env:ProgramData\fluent-bit",
    [string]$Buffer = '1G',
    [switch]$NoSecurityLog,
    [switch]$UseProxy          # 기본: AIOps 서버 접속은 시스템(IE) 프록시를 거치지 않음(내부 주소 가로채기 방지)
)
$ErrorActionPreference = 'Stop'
function Ok($m) { Write-Host "  ✔ $m" -ForegroundColor Green }
function Step($m) { Write-Host "`n▶ $m" -ForegroundColor Cyan }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "관리자 PowerShell 에서 실행하세요." }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- 환경
$uri = [Uri]$Server
$srvHost = $uri.Host; $srvPort = $uri.Port; $https = $uri.Scheme -eq 'https'
$cs = Get-CimInstance Win32_ComputerSystem
$hostName = if ($cs.Domain -and $cs.PartOfDomain) { "$($env:COMPUTERNAME).$($cs.Domain)".ToLower() } else { $env:COMPUTERNAME.ToLower() }
if (-not $Kind) { $Kind = if ($cs.Model -match 'VMware|Virtual') { 'vm' } else { 'baremetal' } }
$os = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "대상 서버 ${srvHost}:${srvPort} · 이 호스트 $hostName · 종류 $Kind$(if($Role){" · 역할 $Role"}) · $os"

# ---------------------------------------------------------------- 서버 접속·토큰 시험
Step "AIOps 서버 접속·토큰 시험"
if ($Insecure -and $https) {
    # 스크립트블록 콜백({ $true })은 .NET I/O 스레드에서 "no Runspace" 로 실패 → "unexpected error occurred on a send" 로 보임
    if ($PSVersionTable.PSEdition -eq 'Core') { $PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] = $true }
    elseif (-not ('AiopsTrust' -as [type])) {
        Add-Type 'using System.Net;using System.Security.Cryptography.X509Certificates;public class AiopsTrust:ICertificatePolicy{public bool CheckValidationResult(ServicePoint s,X509Certificate c,WebRequest r,int p){return true;}}'
    }
    if ('AiopsTrust' -as [type]) { [Net.ServicePointManager]::CertificatePolicy = New-Object AiopsTrust }
}
$sysProxy = [Net.WebRequest]::DefaultWebProxy
if (-not $UseProxy) { [Net.WebRequest]::DefaultWebProxy = $null }
function ErrChain($e) { $m = @(); while ($e) { $m += $e.Message; $e = $e.InnerException }; ($m | Select-Object -Unique) -join ' ← ' }
$probe = @(@{ aiops_heartbeat = 1; aiops_host = $hostName; aiops_kind = $Kind; aiops_os = 'windows'; aiops_agent = 'fluent-bit'; aiops_role = $Role }) | ConvertTo-Json -Compress
if (-not $probe.StartsWith('[')) { $probe = "[$probe]" }
try {
    $r = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Server/api/ingest" -Headers @{ 'X-AIOps-Token' = $Token } `
        -ContentType 'application/json' -Body $probe -TimeoutSec 10
    Ok "접속·토큰 정상 ($($r.Content))"
} catch {
    $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
    if ($code -eq 401) { throw "토큰 거부(401) — AIOps 화면에서 ingest 토큰을 다시 발급하세요." }
    $chain = ErrChain $_.Exception
    $hint = if ($chain -match 'Runspace') { '인증서 콜백 문제 — 최신 설치 명령으로 다시 실행' }
            elseif ($chain -match 'SSL/TLS|secure channel|algorithm|0x80090326|0x8009030') { 'TLS 협상 실패 — 그룹 정책의 TLS 1.2·암호군 제한 확인, 또는 curl.exe -vk ' + $Server + '/readyz' }
            elseif ($chain -match 'proxy|407') { '프록시 문제 — -UseProxy 없이 실행했는지, 방화벽에서 직접 접속 허용 여부 확인' }
            else { '방화벽·DNS·인증서(-CaFile 또는 -Insecure) 확인' }
    throw "서버 접속 실패(HTTP $code): $chain — $hint"
}
[Net.WebRequest]::DefaultWebProxy = $sysProxy      # 이후 인터넷(Fluent Bit 패키지) 다운로드는 시스템 프록시 사용

# ---------------------------------------------------------------- Fluent Bit 설치
$exe = Join-Path $InstallDir 'bin\fluent-bit.exe'
if (-not (Test-Path $exe)) {
    Step "Fluent Bit $Version 설치 → $InstallDir"
    $zip = $Package
    if (-not $zip) {
        $zip = Join-Path $env:TEMP "fluent-bit-$Version-win64.zip"
        Invoke-WebRequest -UseBasicParsing -Uri "https://packages.fluentbit.io/windows/fluent-bit-$Version-win64.zip" -OutFile $zip
    }
    if ($zip -like '*.exe') {
        Start-Process -FilePath $zip -ArgumentList '/S', "/D=$InstallDir" -Wait          # NSIS 설치 프로그램(무인)
    } else {
        $tmp = Join-Path $env:TEMP "fb-extract-$([guid]::NewGuid().ToString('N'))"
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $src = if (Test-Path (Join-Path $tmp 'bin\fluent-bit.exe')) { $tmp } else { (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName }
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        Copy-Item -Path (Join-Path $src '*') -Destination $InstallDir -Recurse -Force
        Remove-Item $tmp -Recurse -Force
    }
}
if (-not (Test-Path $exe)) { throw "fluent-bit.exe 를 찾을 수 없습니다: $exe" }
Ok (& $exe --version | Select-Object -First 1)

# ---------------------------------------------------------------- 구성
Step "구성 파일 작성: $DataDir\fluent-bit.conf"
New-Item -ItemType Directory -Force -Path $DataDir, "$DataDir\storage" | Out-Null
$fwd = { param($p) $p -replace '\\', '/' }
$tls = ''
if ($https) {
    $tls = "    tls               On`r`n    tls.vhost         $srvHost`r`n"
    if ($CaFile) {
        Copy-Item $CaFile "$DataDir\aiops-ca.pem" -Force
        $tls += "    tls.verify        On`r`n    tls.verify_hostname On`r`n    tls.ca_file       $(& $fwd "$DataDir\aiops-ca.pem")`r`n"
    } elseif ($Insecure) { $tls += "    tls.verify        Off`r`n" }
    else { $tls += "    tls.verify        On`r`n" }
}
$sysCh = @('System', 'Application') + $ExtraChannels
$extra = ''
$i = 0
foreach ($f in $Files) {
    $i++
    $extra += @"

[INPUT]
    Name              tail
    Tag               win.file.$i
    Path              $(& $fwd $f)
    Path_Key          file
    DB                $(& $fwd "$DataDir\tail-$i.db")
    Skip_Long_Lines   On
    storage.type      filesystem
"@
}
$sec = ''
if (-not $NoSecurityLog) {
    $sec = @"

# Security log: subscribe only to key events at the source (XPath) - logon failure, lockout, account/group change,
# audit policy change, audit log cleared. grep cannot filter numeric fields, so event_query is used (4624 etc. never read)
[INPUT]
    Name              winevtlog
    Tag               win.sec
    Channels          Security
    Event_Query       *[System[(EventID=4625 or EventID=4740 or EventID=4771 or EventID=4776 or EventID=4720 or EventID=4722 or EventID=4725 or EventID=4726 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4767 or EventID=4719 or EventID=1102)]]
    Interval_Sec      1
    DB                $(& $fwd "$DataDir\winevtlog-sec.sqlite")
    Read_Existing_Events false
    storage.type      filesystem
"@
}
$roleLine = if ($Role) { "    Record            aiops_role $Role`r`n" } else { '' }
$conf = @"
# VCF AIops agent - generated by install-agent.ps1 ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
# host: $hostName ($Kind$(if($Role){", $Role"}))  ->  $Server/api/ingest
[SERVICE]
    Flush                     1
    Log_Level                 warn
    storage.path              $(& $fwd "$DataDir\storage")
    storage.sync              normal
    storage.backlog.mem_limit 16M
    scheduler.cap             60

[INPUT]
    Name              winevtlog
    Tag               win.sys
    Channels          $($sysCh -join ',')
    Interval_Sec      1
    DB                $(& $fwd "$DataDir\winevtlog.sqlite")
    Read_Existing_Events false
    Ignore_Missing_Channels true
    storage.type      filesystem
$sec$extra

[INPUT]
    Name              dummy
    Tag               aiops.hb
    Dummy             {"aiops_heartbeat":1}
    Interval_Sec      60

[FILTER]
    Name              record_modifier
    Match             *
    Record            aiops_host $hostName
    Record            aiops_kind $Kind
    Record            aiops_os windows
    Record            aiops_agent fluent-bit
$roleLine
[OUTPUT]
    Name              http
    Match             *
    Host              $srvHost
    Port              $srvPort
    URI               /api/ingest
    Format            json
    json_date_key     date
    json_date_format  double
    Header            X-AIOps-Token $Token
    compress          gzip
$tls    Retry_Limit       no_limits
    storage.total_limit_size $Buffer
"@
$confPath = Join-Path $DataDir 'fluent-bit.conf'
Set-Content -Path $confPath -Value $conf -Encoding ASCII
# 토큰이 든 구성 파일: SYSTEM·Administrators 만
& icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
Ok "구성 작성 · 권한 제한(SYSTEM·Administrators)"

# ---------------------------------------------------------------- 서비스
Step "Windows 서비스 등록: fluent-bit"
$svc = Get-Service fluent-bit -ErrorAction SilentlyContinue
if ($svc) { if ($svc.Status -ne 'Stopped') { Stop-Service fluent-bit -Force }; & sc.exe delete fluent-bit | Out-Null; Start-Sleep 2 }
New-Service -Name fluent-bit -BinaryPathName "`"$exe`" -c `"$confPath`"" -StartupType Automatic `
    -DisplayName 'Fluent Bit (VCF AIops agent)' -Description 'VCF AIops — Windows 이벤트 로그 실시간 전송' | Out-Null
& sc.exe failure fluent-bit reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
Start-Service fluent-bit
Start-Sleep 3
if ((Get-Service fluent-bit).Status -ne 'Running') { throw "fluent-bit 서비스 기동 실패 — 이벤트 뷰어 > Application 확인" }
Ok "fluent-bit 서비스 동작 중(자동 시작 · 실패 시 5초/30초/60초 재시작)"
try { Write-EventLog -LogName Application -Source 'Application' -EventId 1000 -EntryType Information -Message "VCF AIops agent installed (kind=$Kind role=$Role)" } catch { }
Write-Host "`n  ✔ 완료 — AIOps 화면 › VM·서버 에이전트 에서 '$hostName' 가 1분 내 '정상'으로 표시되는지 확인하세요." -ForegroundColor Green
