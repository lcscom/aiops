<#
.SYNOPSIS
  콘솔에서 포그라운드 실행(설치 직후 점검·데모용). Ctrl+C 로 종료. 운영은 service.ps1 install.
.EXAMPLE
  .\scripts\windows\run.ps1 -Demo      # 장비 없이 합성 로그로 화면·AI 판정 확인
  .\scripts\windows\run.ps1
#>
[CmdletBinding()]
param([string]$EnvName = 'vcf-aiops', [switch]$Demo)
. "$PSScriptRoot\common.ps1"
Set-Location $Root
if (Get-Service -Name 'VCF-AIOps' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running') {
    throw "VCF-AIOps 서비스가 실행 중입니다(포트 충돌). 먼저 .\scripts\windows\service.ps1 stop"
}
$py = Get-EnvPython $EnvName
$env:AIOPS_CONFIG = Join-Path $Root 'config.yaml'
$env:PYTHONUNBUFFERED = '1'
if ($Demo) { $env:AIOPS_DEMO = '1' } else { Remove-Item Env:\AIOPS_DEMO -ErrorAction SilentlyContinue }
& $py -X utf8 -m app.serve
