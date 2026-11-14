<#
  VCF AIops — 서버 사양 수집(가정 분석용, Windows). 추가하려는 서버에서 한 번 실행하고, 나온 JSON 을 포털에 올린다.
    포털: 성능·용량 › 용량·적정화 › 가정 분석 › 서버 사양 › 'JSON 올리기'
  사용:  powershell -ExecutionPolicy Bypass -File .\collect-server-spec.ps1 > spec.json     (읽기만, 아무것도 바꾸지 않음)
  보내지 않음: 컴퓨터 이름·IP·MAC·시리얼 번호
#>
$ErrorActionPreference = 'SilentlyContinue'
$cs  = Get-CimInstance Win32_ComputerSystem
$cpu = @(Get-CimInstance Win32_Processor)
$mem = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
$disks = @(Get-PhysicalDisk | Where-Object { $_.BusType -ne 'USB' } | ForEach-Object {
    $t = if ($_.BusType -eq 'NVMe') { 'nvme' } elseif ($_.MediaType -eq 'SSD') { 'ssd' } else { 'hdd' }
    [ordered]@{ gb = [math]::Round($_.Size / 1e9); type = $t } })
$nics = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and $_.Speed -gt 0 } | ForEach-Object { [ordered]@{ gbps = [math]::Round($_.Speed / 1e9) } })
$model = ($cpu[0].Name -replace '\s+', ' ').Trim()
$ghz = if ($model -match '@\s*([0-9.]+)\s*GHz') { [double]$Matches[1] } else { [math]::Round($cpu[0].MaxClockSpeed / 1000, 2) }
[ordered]@{
    schema = 'vcf-aiops-server-spec/1'; os = "windows $((Get-CimInstance Win32_OperatingSystem).Version)"
    vendor = "$($cs.Manufacturer)"; model = "$($cs.Model)"; cpu_model = $model
    sockets = $cpu.Count; cores = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
    threads = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
    core_ghz = $ghz; mem_gb = [math]::Round($mem / 1GB); disks = $disks; nics = $nics
} | ConvertTo-Json -Depth 4 -Compress
