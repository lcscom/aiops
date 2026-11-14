<#
.SYNOPSIS
  VCF AIops 수집 전용(쓰기 불가) vCenter 계정 생성 — readonly@vsphere.local + 읽기 전용 역할 + 권한 + 검증

.DESCRIPTION
  1) administrator 로 vCenter·SSO 에 로그인
  2) SSO 사용자 생성(이미 있으면 유지, -ResetPassword 면 비밀번호 재설정)
  3) 역할 생성/정정: 읽기 전용(System.Anonymous·View·Read) + Global.Diagnostics(ESXi 호스트 로그 읽기)만
     -NoDiagnostics 면 Global.Diagnostics 도 빼서 System.* 만(이 경우 ESXi 호스트 로그 수집은 syslog 전달로)
  4) vCenter 루트에 권한 부여(하위 전파)
  5) 검증(쓰기 동작 없이): 이 사용자의 유효 권한을 루트·데이터센터·클러스터·호스트·VM·데이터스토어에서 조회해
     허용 목록 밖 권한이 하나라도 있으면 실패, 대표 쓰기 권한 미보유 확인, 새 계정으로 로그인해 이벤트·로그 읽기 확인

  이 계정으로 되는 것   : 이벤트·알람·토폴로지·성능 카운터(성능 SLI)·ESXi 호스트 로그(hostd·vmkernel·vpxa) 조회
  이 계정으로 안 되는 것: 모든 변경(전원·마이그레이션·설정·알람 확인·유지보수 모드·ESXi syslog 대상 변경 등),
                          vCenter 어플라이언스 헬스 REST(/api/appliance/health — SystemConfiguration.Administrators 그룹이
                          필요해 넣지 않음 → 포털에서 해당 항목만 비활성)

.PARAMETER VCenter       vCenter FQDN/IP
.PARAMETER AdminUser     관리자 계정(기본 administrator@vsphere.local) — 실행 시 비밀번호 입력
.PARAMETER NewUser       만들 계정(기본 readonly@vsphere.local) — 도메인은 SSO 도메인과 같아야 함
.PARAMETER RoleName      역할 이름(기본 AIOps-ReadOnly-LogCollector)
.PARAMETER NewPassword   새 계정 비밀번호(SecureString). 생략하면 정책에 맞는 20자 무작위 생성 후 1회 표시
.PARAMETER NoDiagnostics Global.Diagnostics 제외(System.* 만)
.PARAMETER ResetPassword 계정이 이미 있으면 비밀번호 재설정
.PARAMETER SkipCertificateCheck  vCenter 인증서 검증 생략(자체 서명 랩)

.EXAMPLE
  .\New-AIOpsReadOnlyAccount.ps1 -VCenter vcsa.rangers.lab -SkipCertificateCheck
.EXAMPLE
  .\New-AIOpsReadOnlyAccount.ps1 -VCenter vcsa.rangers.lab -NoDiagnostics -ResetPassword

.NOTES
  필요 모듈: PowerCLI(VCF.PowerCLI 9.x 또는 VMware.PowerCLI 13.x) + VMware.vSphere.SsoAdmin
    Install-Module VCF.PowerCLI -Scope CurrentUser            # 또는 VMware.PowerCLI
    Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser
  망분리: 인터넷 PC 에서 Save-Module -Name VCF.PowerCLI,VMware.vSphere.SsoAdmin -Path .\mods 후 대상 PC 의
          $env:PSModulePath 경로(예: C:\Program Files\WindowsPowerShell\Modules)에 복사
  여러 번 실행해도 안전(멱등): 역할 권한이 달라졌으면 허용 목록으로 정정, 권한은 역할만 갱신
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$VCenter,
    [string]$AdminUser = 'administrator@vsphere.local',
    [string]$NewUser = 'readonly@vsphere.local',
    [string]$RoleName = 'AIOps-ReadOnly-LogCollector',
    [SecureString]$NewPassword,
    [switch]$NoDiagnostics,
    [switch]$ResetPassword,
    [switch]$SkipCertificateCheck
)
$ErrorActionPreference = 'Stop'

function Step($m) { Write-Host "`n▶ $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "  ✔ $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "  ✖ $m" -ForegroundColor Red; throw $m }

# ------------------------------------------------------------------ 0. 준비
Step '0. 모듈 확인'
$core = Get-Module -ListAvailable VMware.VimAutomation.Core | Sort-Object Version -Descending | Select-Object -First 1
if (-not $core) { Fail 'PowerCLI 없음 — Install-Module VCF.PowerCLI -Scope CurrentUser (또는 VMware.PowerCLI)' }
if (-not (Get-Module -ListAvailable VMware.vSphere.SsoAdmin)) { Fail 'SSO 모듈 없음 — Install-Module VMware.vSphere.SsoAdmin -Scope CurrentUser' }
Import-Module VMware.VimAutomation.Core -ErrorAction Stop | Out-Null
Import-Module VMware.vSphere.SsoAdmin -ErrorAction Stop | Out-Null
Ok "PowerCLI Core $($core.Version) · SsoAdmin $((Get-Module VMware.vSphere.SsoAdmin).Version)"

if ($NewUser -notmatch '^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+)$') { Fail "NewUser 형식 오류: $NewUser (예: readonly@vsphere.local)" }
$uName = $Matches[1]; $uDomain = $Matches[2].ToLower()
$principal = "$($uDomain.ToUpper())\$uName"

$allowed = @('System.Anonymous', 'System.View', 'System.Read')
if (-not $NoDiagnostics) { $allowed += 'Global.Diagnostics' }
# 대표 쓰기 권한 — 하나라도 있으면 실패(검증용 조회만, 실제 동작 없음)
$writeProbe = @('Folder.Create', 'Datacenter.Create', 'VirtualMachine.Interact.PowerOff', 'VirtualMachine.Inventory.Delete',
                'VirtualMachine.Config.Settings', 'Host.Config.Maintenance', 'Host.Config.AdvancedConfig', 'Host.Config.Network',
                'Datastore.DeleteFile', 'Datastore.FileManagement', 'Alarm.Acknowledge', 'Alarm.Create', 'Global.Settings',
                'Global.LogEvent', 'Resource.HotMigrate', 'Authorization.ModifyPermissions', 'Sessions.TerminateSession')

if ($SkipCertificateCheck) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false | Out-Null
}
try { Set-PowerCLIConfiguration -ParticipateInCEIP $false -Scope User -Confirm:$false | Out-Null } catch { }

$adminCred = Get-Credential -UserName $AdminUser -Message "vCenter $VCenter 관리자 비밀번호"

function New-StrongPassword {
    # vCenter SSO 기본 정책(8~20자, 대·소문자·숫자·특수문자, 같은 문자 3회 연속 금지) 충족 · 따옴표·공백·$·\ 제외
    $up = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray(); $lo = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $dg = '23456789'.ToCharArray(); $sp = '!@#%^*-_=+'.ToCharArray()
    $all = $up + $lo + $dg + $sp
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = { param($set) $b = [byte[]]::new(4); $rng.GetBytes($b); $set[[BitConverter]::ToUInt32($b, 0) % $set.Length] }
    do {
        $c = @((& $pick $up), (& $pick $lo), (& $pick $dg), (& $pick $sp)) + (1..16 | ForEach-Object { & $pick $all })
        $c = $c | Sort-Object { $b = [byte[]]::new(4); $rng.GetBytes($b); [BitConverter]::ToUInt32($b, 0) }
        $pw = -join $c
    } while ($pw -match '(.)\1\1')
    return $pw
}
function ConvertTo-Plain([SecureString]$s) {
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}

$vi = $null; $sso = $null; $shownPassword = $null
try {
    # ------------------------------------------------------------------ 1. 로그인
    Step "1. 관리자 로그인 — $VCenter"
    $vi = Connect-VIServer -Server $VCenter -Credential $adminCred
    $ssoArgs = @{ Server = $VCenter; Credential = $adminCred }
    if ($SkipCertificateCheck) { $ssoArgs.SkipCertificateCheck = $true }
    $sso = Connect-SsoAdminServer @ssoArgs
    Ok "vCenter $($vi.Version) build $($vi.Build) · SSO 연결"

    # ------------------------------------------------------------------ 2. SSO 사용자
    Step "2. SSO 사용자 $NewUser"
    $user = Get-SsoPersonUser -Name $uName -Domain $uDomain -Server $sso -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $uName } | Select-Object -First 1
    $plain = if ($NewPassword) { ConvertTo-Plain $NewPassword } else { $null }
    if (-not $user) {
        if (-not $plain) { $plain = New-StrongPassword; $shownPassword = $plain }
        $user = New-SsoPersonUser -UserName $uName -Password $plain -Description 'VCF AIops 수집 전용(읽기 전용) — 쓰기 권한 없음' `
                                  -FirstName 'AIOps' -LastName 'ReadOnly' -Server $sso
        Ok "생성: $principal"
    } elseif ($ResetPassword) {
        if (-not $plain) { $plain = New-StrongPassword; $shownPassword = $plain }
        Set-SsoPersonUser -User $user -NewPassword $plain | Out-Null
        Ok "이미 있음 → 비밀번호 재설정"
    } else {
        Ok "이미 있음 → 유지(비밀번호 재설정은 -ResetPassword)"
    }
    # 쓰기 가능한 SSO 그룹 소속이면 중단(Administrators·SystemConfiguration.Administrators 등)
    $risky = @('Administrators', 'SystemConfiguration.Administrators', 'SystemConfiguration.BashShellAdministrators',
               'LicenseService.Administrators', 'ComponentManager.Administrators', 'CAAdmins', 'SolutionUsers')
    foreach ($g in $risky) {
        $grp = Get-SsoGroup -Name $g -Domain $uDomain -Server $sso -ErrorAction SilentlyContinue
        if ($grp -and ($grp | Get-SsoPersonUser -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $uName })) {
            Fail "$principal 가 SSO 그룹 '$g' 에 속해 있습니다 — 쓰기 권한이 생기므로 그룹에서 제거한 뒤 다시 실행하세요"
        }
    }
    Ok 'SSO 관리 그룹 미소속'
    $pol = Get-SsoPasswordPolicy -Server $sso -ErrorAction SilentlyContinue
    $life = if ($pol -and $pol.PSObject.Properties['PasswordLifetimeDays']) { [int]$pol.PasswordLifetimeDays } else { 0 }
    if ($life -gt 0) {
        Warn "SSO 비밀번호 만료 정책 ${life}일 — 만료 전 -ResetPassword 로 재설정 후 AIOps 커넥터 비밀번호도 갱신하세요"
    }

    # ------------------------------------------------------------------ 3. 역할
    Step "3. 역할 $RoleName — $($allowed -join ', ')"
    $privs = Get-VIPrivilege -Id $allowed
    $role = Get-VIRole -Name $RoleName -ErrorAction SilentlyContinue
    if (-not $role) {
        $role = New-VIRole -Name $RoleName -Privilege $privs
        Ok '생성'
    } else {
        if ($role.IsSystem) { Fail "$RoleName 은 시스템 역할입니다 — 다른 이름을 쓰세요" }
        $extra = @($role.PrivilegeList | Where-Object { $_ -notin $allowed })
        $missing = @($allowed | Where-Object { $_ -notin $role.PrivilegeList })
        if ($extra.Count) { $role = Set-VIRole -Role $role -RemovePrivilege (Get-VIPrivilege -Id $extra); Warn "허용 밖 권한 제거: $($extra -join ', ')" }
        if ($missing.Count) { $role = Set-VIRole -Role $role -AddPrivilege (Get-VIPrivilege -Id $missing); Ok "누락 권한 추가: $($missing -join ', ')" }
        if (-not $extra.Count -and -not $missing.Count) { Ok '이미 허용 목록과 일치' }
    }
    $role = Get-VIRole -Name $RoleName
    $bad = @($role.PrivilegeList | Where-Object { $_ -notin $allowed })
    if ($bad.Count) { Fail "역할에 허용 밖 권한이 남아 있습니다: $($bad -join ', ')" }
    Ok "역할 권한: $(($role.PrivilegeList | Sort-Object) -join ', ')"

    # ------------------------------------------------------------------ 4. 권한(루트, 하위 전파)
    Step "4. 권한 — vCenter 루트에 $principal = $RoleName (하위 전파)"
    $root = Get-Folder -NoRecursion
    $perm = Get-VIPermission -Entity $root -Principal $principal -ErrorAction SilentlyContinue |
            Where-Object { $_.EntityId -eq $root.Id } | Select-Object -First 1
    if (-not $perm) {
        New-VIPermission -Entity $root -Principal $principal -Role $role -Propagate:$true | Out-Null
        Ok '부여'
    } elseif ($perm.Role -ne $RoleName -or -not $perm.Propagate) {
        Set-VIPermission -Permission $perm -Role $role -Propagate:$true | Out-Null
        Warn "기존 권한($($perm.Role)) → $RoleName 로 정정"
    } else { Ok '이미 부여됨' }
    # 하위 개체에 이 사용자를 직접 지정한 다른 권한이 있으면 쓰기 권한이 생길 수 있음 → 알림
    $others = @(Get-VIPermission -Principal $principal -ErrorAction SilentlyContinue | Where-Object { $_.EntityId -ne $root.Id })
    if ($others.Count) {
        $others | ForEach-Object { Warn "하위 개체 권한 존재: $($_.Entity.Name) = $($_.Role) — 검증 단계에서 확인" }
    }

    # ------------------------------------------------------------------ 5. 검증(쓰기 동작 없음)
    Step '5. 검증 — 유효 권한 조회(그룹·상속 포함)'
    $auth = Get-View AuthorizationManager
    $sample = @($root)
    $sample += @(Get-Datacenter | Select-Object -First 1) + @(Get-Cluster | Select-Object -First 1) +
               @(Get-VMHost | Select-Object -First 1) + @(Get-VM | Select-Object -First 1) + @(Get-Datastore | Select-Object -First 1)
    $sample = @($sample | Where-Object { $_ })
    $mors = $sample | ForEach-Object { $_.ExtensionData.MoRef }
    $eff = $auth.FetchUserPrivilegeOnEntities($mors, $principal)
    $violations = @()
    foreach ($r in $eff) {
        $name = ($sample | Where-Object { $_.ExtensionData.MoRef.Value -eq $r.Entity.Value } | Select-Object -First 1).Name
        $over = @($r.Privileges | Where-Object { $_ -notin $allowed })
        if ($over.Count) { $violations += "$name : $($over -join ', ')" }
    }
    if ($violations.Count) { $violations | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }; Fail '허용 목록 밖 유효 권한 발견 — 위 개체의 권한을 정리하세요' }
    Ok "유효 권한 = 허용 목록 이내 (개체 $($sample.Count)개: $(($sample | ForEach-Object { $_.GetType().Name -replace 'Impl$','' }) -join ', '))"
    $probe = $auth.HasUserPrivilegeOnEntities($mors, $principal, $writeProbe)
    $granted = @(foreach ($e in $probe) { $e.PrivAvailability | Where-Object { $_.IsGranted } | ForEach-Object { $_.PrivId } }) | Sort-Object -Unique
    if ($granted.Count) { Fail "쓰기 권한 보유: $($granted -join ', ')" }
    Ok "대표 쓰기 권한 $($writeProbe.Count)종 모두 없음"

    if ($shownPassword -or $plain) {
        Step '5-2. 새 계정으로 로그인해 읽기 확인'
        $sec = ConvertTo-SecureString ($(if ($shownPassword) { $shownPassword } else { $plain })) -AsPlainText -Force
        $ro = Connect-VIServer -Server $VCenter -Credential ([pscredential]::new($NewUser, $sec)) -NotDefault
        try {
            $ev = Get-VIEvent -Server $ro -MaxSamples 1
            Ok "이벤트 읽기 OK($(@($ev).Count)건 샘플)"
            $h = Get-VMHost -Server $ro | Where-Object { $_.ConnectionState -eq 'Connected' } | Select-Object -First 1
            if ($h -and -not $NoDiagnostics) {
                $dm = Get-View $ro.ExtensionData.Content.DiagnosticManager -Server $ro
                $log = $dm.BrowseDiagnosticLog($h.ExtensionData.MoRef, 'vmkernel', 999999999, 1)
                Ok "ESXi 호스트 로그 읽기 OK($($h.Name) vmkernel, 전체 $($log.LineEnd)줄)"
            }
            $pm = Get-View $ro.ExtensionData.Content.PerfManager -Server $ro
            Ok "성능 카운터 목록 읽기 OK($($pm.PerfCounter.Count)개)"
        } finally { Disconnect-VIServer -Server $ro -Confirm:$false | Out-Null }
    } else {
        Warn '기존 계정 유지 — 비밀번호를 몰라 로그인 확인은 건너뜀(-ResetPassword 로 다시 실행하면 확인)'
    }

    # ------------------------------------------------------------------ 결과
    Write-Host "`n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
    Write-Host "  계정      $NewUser"
    if ($shownPassword) { Write-Host "  비밀번호  $shownPassword   ← 지금만 표시됩니다. AIOps 커넥터에 입력 후 이 창을 닫으세요" -ForegroundColor Yellow }
    Write-Host "  역할      $RoleName  ($($allowed -join ', '))"
    Write-Host "  AIOps     운영 설정 › 커넥터 › vCenter: 계정 $NewUser"
    if (-not $NoDiagnostics) { Write-Host "            ESXi 호스트 로그 수집 칸: hostd / vmkernel / vpxa (줄마다 하나)" }
    else { Write-Host "            ESXi 호스트 로그는 syslog 전달로(이 계정은 Global.Diagnostics 없음)" }
    Write-Host "  비활성    알람 확인·유지보수·VM 조치·ESXi syslog 대상 변경·어플라이언스 헬스 REST(쓰기/관리 권한 필요)"
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
}
finally {
    if ($sso) { Disconnect-SsoAdminServer -Server $sso -ErrorAction SilentlyContinue }
    if ($vi) { Disconnect-VIServer -Server $vi -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
    $plain = $null; $shownPassword = $null
}
