<#
.SYNOPSIS
  HTTPS 인증서 준비 — Windows 인증서 저장소(LocalMachine\My)의 인증서를 PEM(certs\aiops.crt/.key)으로 내보낸다.
  config.yaml server.tls.enabled: auto(기본) 이면 파일이 생긴 뒤 서비스 재시작만으로 HTTPS 전환.

.EXAMPLE
  # 사내 CA가 발급한 인증서(개인키 내보내기 허용) 사용
  .\scripts\windows\export-cert.ps1 -Thumbprint 3A1F...C9
  # 자체 서명 인증서 생성(테스트·임시)
  .\scripts\windows\export-cert.ps1 -SelfSigned -DnsName aiops.corp.local,10.10.0.50
#>
[CmdletBinding(DefaultParameterSetName = 'Thumb')]
param(
    [Parameter(ParameterSetName = 'Thumb', Mandatory)][string]$Thumbprint,
    [Parameter(ParameterSetName = 'Self', Mandatory)][switch]$SelfSigned,
    [Parameter(ParameterSetName = 'Self')][string[]]$DnsName = @($env:COMPUTERNAME),
    [string]$EnvName = 'vcf-aiops',
    [string]$ServiceAccount = ''          # 서비스를 LocalService 등으로 돌릴 때 키 파일 읽기 권한 부여
)
. "$PSScriptRoot\common.ps1"
if (-not (Test-Admin)) { throw "관리자 PowerShell에서 실행하세요." }
$py = Get-EnvPython $EnvName
$certDir = Join-Path $Root 'certs'
New-Item -ItemType Directory -Force -Path $certDir | Out-Null

if ($SelfSigned) {
    $san = ($DnsName | ForEach-Object { if ($_ -match '^\d+\.\d+\.\d+\.\d+$') { "IPAddress=$_" } else { "DNS=$_" } }) -join '&'
    $cert = New-SelfSignedCertificate -Subject "CN=$($DnsName[0])" -CertStoreLocation 'Cert:\LocalMachine\My' `
        -TextExtension @("2.5.29.17={text}$san", "2.5.29.37={text}1.3.6.1.5.5.7.3.1") `
        -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) -FriendlyName 'VCF AIops'
    Write-Ok "자체 서명 인증서 생성: $($cert.Thumbprint) ($($DnsName -join ', '))"
    $Thumbprint = $cert.Thumbprint
}

$cert = Get-Item "Cert:\LocalMachine\My\$($Thumbprint -replace '\s', '')" -ErrorAction Stop
if (-not $cert.HasPrivateKey) { throw "개인키가 없는 인증서입니다." }
$pfx = Join-Path $env:TEMP "aiops-$([guid]::NewGuid().ToString('N')).pfx"
$pw = [guid]::NewGuid().ToString('N')
$sec = ConvertTo-SecureString $pw -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec -ChainOption BuildChain | Out-Null

$conv = @'
import os, sys
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
pfx, crt, key = sys.argv[1:4]
pw = os.environ["AIOPS_PFX_PW"]          # 비밀번호는 명령줄 대신 환경변수로 전달
k, c, chain = pkcs12.load_key_and_certificates(open(pfx, "rb").read(), pw.encode())
open(key, "wb").write(k.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
open(crt, "wb").write(c.public_bytes(Encoding.PEM) + b"".join(x.public_bytes(Encoding.PEM) for x in (chain or [])))
print(f"OK {c.subject.rfc4514_string()} ~ {c.not_valid_after_utc:%Y-%m-%d}")
'@
$tmpPy = Join-Path $env:TEMP 'aiops_pfx2pem.py'
Set-Content -Path $tmpPy -Value $conv -Encoding UTF8
try {
    $env:AIOPS_PFX_PW = $pw
    $res = & $py $tmpPy $pfx "$certDir\aiops.crt" "$certDir\aiops.key" | Select-Object -Last 1
} finally {
    Remove-Item Env:\AIOPS_PFX_PW -ErrorAction SilentlyContinue
    Remove-Item $pfx, $tmpPy -Force -ErrorAction SilentlyContinue
}
if ("$res" -notmatch '^OK') { throw "PEM 변환 실패: $res" }
Write-Ok "certs\aiops.crt (체인 포함) / certs\aiops.key 생성 — $($res.Substring(3))"

# 개인키 파일 ACL: 상속 제거, SYSTEM·Administrators(+서비스 계정)만
$grants = @('SYSTEM:F', 'Administrators:F')
if ($ServiceAccount) { $grants += "${ServiceAccount}:R" }
& icacls "$certDir\aiops.key" /inheritance:r /grant:r $grants /C /Q | Out-Null
Write-Ok "개인키 ACL 제한: $($grants -join ', ')"

if ($SelfSigned) {
    Write-Warn2 "자체 서명 인증서는 브라우저 경고가 뜹니다. 운영은 사내 CA 인증서를 -Thumbprint 로 사용하세요."
}
if (Get-Service -Name 'VCF-AIOps' -ErrorAction SilentlyContinue) {
    Write-Host "  적용: .\scripts\windows\service.ps1 restart" -ForegroundColor Cyan
}
