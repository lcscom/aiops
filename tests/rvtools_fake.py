"""합성 RVTools 내보내기(.xlsx) — 시험용. 실제 고객 데이터 없음(이름·주소·시리얼 모두 지어낸 값)

RVTools 4.x 'Export all to xlsx' 의 시트·열 이름을 따른다. 일부러 넣은 문제:
  · esx01: 경로 없는 offline FC 포트(vmhba3), 단일 경로 SAN LUN(ds-san-02), 인증서 30일 내 만료
  · esx02: ESXi 7.0.3 + Broadwell(E5-2680 v4, VCF 9 미지원), dead 경로 1개(ds-san-01), 업링크 다운 vmnic1
  · VM: Tools 미설치(app02), Win2008(legacy01), CD 연결(app01), 스냅숏 30일, 파티션 3%, CPU ready 25%, 메모리 Limit, 좀비 VMDK, 템플릿 1개
  · 라이선스 60일 내 만료
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.readiness.export import xlsx

VC = "vc01.example.test"
KEY_TERM = "A1A1A-B2B2B-C3C3C-D4D4D-TERM1"      # 지어낸 키(형식만 5x5)
KEY_PERP = "A1A1A-B2B2B-C3C3C-D4D4D-PERP1"
NOW = datetime(2026, 9, 1, 9, 0, 0)


def _d(days: float) -> str:
    return (NOW + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def _sheet(cols: list[str], rows: list[dict]) -> list[list]:
    return [cols] + [[r.get(c, "") for c in cols] for r in rows]


def build() -> bytes:
    hosts = [
        {"Host": "esx01.example.test", "Datacenter": "DC1", "Cluster": "CL1", "Config status": "green", "in Maintenance Mode": "False", "CPU Model": "Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz",
         "Speed": 2000, "HT Available": "True", "HT Active": "True", "# CPU": 2, "Cores per CPU": 32, "# Cores": 64, "CPU usage %": 35, "# Memory": 1048576, "Memory usage %": 55,
         "# VMs": 4, "# vCPUs": 40, "vCPUs per Core": 0.6, "ESX Version": "VMware ESXi 8.0.3 build-24022510", "NTP Server(s)": "ntp1.example.test", "NTPD running": "True",
         "Vendor": "Dell Inc.", "Model": "PowerEdge R750", "Serial number": "FAKE001", "BIOS Version": "1.10.2", "BIOS Date": "2025-01-10",
         "Certificate Expiry Date": _d(20), "Certificate Issuer": "O=VMware, CN=CA", "Assigned License(s)": KEY_TERM, "Host Power Policy": "Balanced", "Current EVC": "", "Max EVC": "intel-icelake", "VI SDK Server": VC},
        {"Host": "esx02.example.test", "Datacenter": "DC1", "Cluster": "CL1", "Config status": "yellow", "in Maintenance Mode": "False", "CPU Model": "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz",
         "Speed": 2400, "HT Available": "True", "HT Active": "True", "# CPU": 2, "Cores per CPU": 14, "# Cores": 28, "CPU usage %": 70, "# Memory": 524288, "Memory usage %": 80,
         "# VMs": 3, "# vCPUs": 60, "vCPUs per Core": 2.1, "ESX Version": "VMware ESXi 7.0.3 build-21424296", "NTP Server(s)": "", "NTPD running": "False",
         "Vendor": "HPE", "Model": "ProLiant DL380 Gen9", "Serial number": "FAKE002", "BIOS Version": "P89", "BIOS Date": "2019-05-01",
         "Certificate Expiry Date": _d(700), "Host Power Policy": "High performance", "Assigned License(s)": KEY_PERP, "VI SDK Server": VC},
    ]
    vinfo, vtools, vcpu, vmem = [], [], [], []

    def vm(name, host, power="poweredOn", cpus=4, mem=8192, prov=102400, used=51200, os_="Red Hat Enterprise Linux 9 (64-bit)", hw="vmx-19", tools="toolsOk",
           ready=0.5, template="False", nets=("pg-app",), cpu_limit=-1, mem_limit=-1, ip="10.0.0.10", ballooned=0):
        vinfo.append({"VM": name, "Powerstate": power, "Template": template, "Config status": "green", "CPUs": cpus, "Memory": mem, "Provisioned MiB": prov, "In Use MiB": used,
                      "Host": host, "Cluster": "CL1", "Datacenter": "DC1", "OS according to the VMware Tools": os_ if tools != "toolsNotInstalled" else "",
                      "OS according to the configuration file": os_, "HW version": hw, "Overall Cpu Readiness": ready, "Primary IP Address": ip,
                      **{f"Network #{i + 1}": n for i, n in enumerate(nets)}, "VI SDK Server": VC, "Consolidation Needed": "False"})
        vtools.append({"VM": name, "Tools": tools, "Upgradeable": "False", "VI SDK Server": VC})
        vcpu.append({"VM": name, "Limit": cpu_limit, "Hot Add": "False", "VI SDK Server": VC})
        vmem.append({"VM": name, "Limit": mem_limit, "Ballooned": ballooned, "Swapped": 0, "VI SDK Server": VC})
    vm("app01", "esx01.example.test")
    vm("app02", "esx01.example.test", tools="toolsNotInstalled", ip="")
    vm("db01", "esx02.example.test", cpus=16, mem=65536, ready=25, mem_limit=32768, ballooned=1024)
    vm("legacy01", "esx02.example.test", os_="Microsoft Windows Server 2008 R2 (64-bit)", hw="vmx-08")
    vm("old01", "esx01.example.test", power="poweredOff", prov=512000)
    vm("tpl-rhel9", "esx01.example.test", power="poweredOff", template="True")
    ds = [{"Name": "ds-san-01", "Type": "VMFS", "Accessible": "True", "Capacity MiB": 4194304, "Provisioned MiB": 3000000, "In Use MiB": 3800000, "Free MiB": 394304, "Free %": 9,
           "# VMs": 4, "Hosts": "esx01.example.test, esx02.example.test", "VI SDK Server": VC},
          {"Name": "ds-san-02", "Type": "VMFS", "Accessible": "True", "Capacity MiB": 2097152, "Provisioned MiB": 500000, "In Use MiB": 400000, "Free MiB": 1697152, "Free %": 81,
           "# VMs": 2, "Hosts": "esx01.example.test, esx02.example.test", "VI SDK Server": VC},
          {"Name": "ds-nfs-01", "Type": "NFS41", "Accessible": "True", "Capacity MiB": 1048576, "Provisioned MiB": 100000, "In Use MiB": 100000, "Free MiB": 948576, "Free %": 90,
           "# VMs": 0, "Hosts": "esx01.example.test, esx02.example.test", "VI SDK Server": VC}]
    sheets = [
        ("vInfo", _sheet(sorted({k for r in vinfo for k in r}), vinfo)),
        ("vCPU", _sheet(["VM", "Limit", "Hot Add", "VI SDK Server"], vcpu)),
        ("vMemory", _sheet(["VM", "Limit", "Ballooned", "Swapped", "VI SDK Server"], vmem)),
        ("vTools", _sheet(["VM", "Tools", "Upgradeable", "VI SDK Server"], vtools)),
        ("vDisk", _sheet(["VM", "Disk", "Capacity MiB", "Path", "VI SDK Server"], [
            {"VM": "app01", "Disk": "Hard disk 1", "Capacity MiB": 102400, "Path": "[ds-san-01] app01/app01.vmdk"},
            {"VM": "db01", "Disk": "Hard disk 1", "Capacity MiB": 204800, "Path": "[ds-san-02] db01/db01.vmdk"}])),
        ("vPartition", _sheet(["VM", "Disk", "Capacity MiB", "Free MiB", "Free %", "VI SDK Server"], [
            {"VM": "db01", "Disk": "/data", "Capacity MiB": 204800, "Free MiB": 6144, "Free %": 3}, {"VM": "app01", "Disk": "/", "Capacity MiB": 51200, "Free MiB": 30000, "Free %": 58}])),
        ("vCD", _sheet(["VM", "Powerstate", "Connected", "Starts Connected", "Device Type", "VI SDK Server"], [
            {"VM": "app01", "Powerstate": "poweredOn", "Connected": "True", "Starts Connected": "False", "Device Type": "ISO [ds-san-01] iso/os.iso"}])),
        ("vSnapshot", _sheet(["VM", "Name", "Date / time", "Size MiB (total)", "Quiesced", "VI SDK Server"], [
            {"VM": "db01", "Name": "before-patch", "Date / time": _d(-30), "Size MiB (total)": 40960, "Quiesced": "False"}])),
        ("vSource", _sheet(["Name", "Fullname", "Version", "Build", "API version", "VI SDK Server"], [
            {"Name": VC, "Fullname": "VMware vCenter Server 8.0.3 build-24022515", "Version": "8.0.3", "Build": "24022515", "API version": "8.0.3.0", "VI SDK Server": VC}])),
        ("vCluster", _sheet(["Name", "OverallStatus", "NumHosts", "NumCpuCores", "TotalMemory", "HA enabled", "AdmissionControlEnabled", "DRS enabled", "DRS default VM behavior", "VI SDK Server"], [
            {"Name": "CL1", "OverallStatus": "yellow", "NumHosts": 2, "NumCpuCores": 92, "TotalMemory": 1610612736, "HA enabled": "True", "AdmissionControlEnabled": "False",
             "DRS enabled": "True", "DRS default VM behavior": "fullyAutomated", "VI SDK Server": VC}])),
        ("vHost", _sheet(sorted({k for r in hosts for k in r}), hosts)),
        ("vHBA", _sheet(["Host", "Device", "Type", "Status", "Driver", "Model", "VI SDK Server"], [
            {"Host": "esx01.example.test", "Device": "vmhba2", "Type": "Fibre Channel", "Status": "online", "Driver": "lpfc", "Model": "FakeFC 32G"},
            {"Host": "esx01.example.test", "Device": "vmhba3", "Type": "Fibre Channel", "Status": "offline", "Driver": "lpfc", "Model": "FakeFC 32G"},
            {"Host": "esx02.example.test", "Device": "vmhba2", "Type": "Fibre Channel", "Status": "online", "Driver": "qlnativefc", "Model": "FakeQL 16G"},
            {"Host": "esx02.example.test", "Device": "vmhba3", "Type": "Fibre Channel", "Status": "online", "Driver": "qlnativefc", "Model": "FakeQL 16G"},
            {"Host": "esx01.example.test", "Device": "vmhba0", "Type": "Block SCSI", "Status": "unknown", "Driver": "lsi_mr3", "Model": "PERC"}])),
        ("vNIC", _sheet(["Host", "Network Device", "Driver", "Speed", "Duplex", "MAC", "Switch", "Uplink port", "VI SDK Server"], [
            {"Host": "esx01.example.test", "Network Device": "vmnic0", "Driver": "i40en", "Speed": 25000, "Duplex": "Full Duplex", "MAC": "00:50:56:00:00:01", "Switch": "vds-01"},
            {"Host": "esx01.example.test", "Network Device": "vmnic1", "Driver": "i40en", "Speed": 25000, "Duplex": "Full Duplex", "MAC": "00:50:56:00:00:02", "Switch": "vds-01"},
            {"Host": "esx02.example.test", "Network Device": "vmnic0", "Driver": "ixgben", "Speed": 10000, "Duplex": "Full Duplex", "MAC": "00:50:56:00:00:03", "Switch": "vds-01"},
            {"Host": "esx02.example.test", "Network Device": "vmnic1", "Driver": "ixgben", "Speed": 0, "Duplex": "", "MAC": "00:50:56:00:00:04", "Switch": "vds-01"},
            {"Host": "esx02.example.test", "Network Device": "vmnic5", "Driver": "ixgben", "Speed": 0, "Duplex": "", "MAC": "00:50:56:00:00:05", "Switch": ""}])),
        ("vSwitch", _sheet(["Host", "Switch", "MTU", "# Ports", "Promiscuous Mode", "Mac Changes", "Forged Transmits", "VI SDK Server"], [
            {"Host": "esx01.example.test", "Switch": "vSwitch0", "MTU": 1500, "# Ports": 128, "Promiscuous Mode": "False", "Mac Changes": "True", "Forged Transmits": "True"}])),
        ("vPort", _sheet(["Host", "Port Group", "Switch", "VLAN", "VI SDK Server"], [{"Host": "esx01.example.test", "Port Group": "VM Network", "Switch": "vSwitch0", "VLAN": "0"}])),
        ("dvSwitch", _sheet(["Switch", "Datacenter", "Version", "Max MTU", "# Ports", "# VMs", "Host members", "CDP Type", "CDP Operation", "VI SDK Server"], [
            {"Switch": "vds-01", "Datacenter": "DC1", "Version": "8.0.0", "Max MTU": 1500, "# Ports": 256, "# VMs": 4, "Host members": "esx01.example.test, esx02.example.test",
             "CDP Type": "", "CDP Operation": ""}])),
        ("dvPort", _sheet(["Port", "Switch", "Type", "VLAN", "# Ports", "Allow Promiscuous", "Mac Changes", "Forged Transmits", "Active Uplink", "Policy", "VI SDK Server"], [
            {"Port": "pg-app", "Switch": "vds-01", "Type": "earlyBinding", "VLAN": "100", "# Ports": 64, "Allow Promiscuous": "False", "Mac Changes": "False", "Forged Transmits": "False",
             "Active Uplink": "Uplink 1, Uplink 2", "Policy": "loadbalance_srcid"},
            {"Port": "pg-vmotion", "Switch": "vds-01", "Type": "earlyBinding", "VLAN": "200", "# Ports": 8},
            {"Port": "vds-01-DVUplinks", "Switch": "vds-01", "Type": "earlyBinding", "VLAN": "0-4094", "# Ports": 4}])),
        ("vSC_VMK", _sheet(["Host", "Device", "Port Group", "IP Address", "Subnet mask", "MTU", "VI SDK Server"], [
            {"Host": "esx01.example.test", "Device": "vmk1", "Port Group": "pg-vmotion", "IP Address": "10.0.2.11", "Subnet mask": "255.255.255.0", "MTU": 9000}])),
        ("vDatastore", _sheet(sorted({k for r in ds for k in r}), ds)),
        ("vMultiPath", _sheet(["Host", "Datastore", "Disk", "Policy", "Oper. State", "Path 1", "Path 1 state", "Path 2", "Path 2 state", "Vendor", "Model", "VI SDK Server"], [
            {"Host": "esx01.example.test", "Datastore": "ds-san-01", "Disk": "naa.600a0001", "Policy": "VMW_PSP_RR", "Oper. State": "ok", "Path 1": "vmhba2", "Path 1 state": "Active",
             "Path 2": "vmhba2", "Path 2 state": "Active", "Vendor": "FAKE", "Model": "Array"},
            {"Host": "esx01.example.test", "Datastore": "ds-san-02", "Disk": "naa.600a0002", "Policy": "VMW_PSP_FIXED", "Oper. State": "ok", "Path 1": "vmhba2", "Path 1 state": "Active",
             "Vendor": "FAKE", "Model": "Array"},
            {"Host": "esx02.example.test", "Datastore": "ds-san-01", "Disk": "naa.600a0001", "Policy": "VMW_PSP_RR", "Oper. State": "ok", "Path 1": "vmhba2", "Path 1 state": "Active",
             "Path 2": "vmhba3", "Path 2 state": "Dead", "Vendor": "FAKE", "Model": "Array"},
            {"Host": "esx01.example.test", "Datastore": "local-esx01", "Disk": "naa.local", "Policy": "VMW_PSP_FIXED", "Oper. State": "ok", "Path 1": "vmhba0", "Path 1 state": "Active",
             "Vendor": "DELL", "Model": "PERC"}])),
        ("vLicense", _sheet(["Name", "Key", "Total", "Used", "Cost Unit", "Expiration Date", "VI SDK Server"], [
            {"Name": "vSphere 8 Enterprise Plus", "Key": KEY_PERP, "Total": 8, "Used": 2, "Cost Unit": "cpuPackage:32core", "Expiration Date": _d(60)},
            {"Name": "vSphere 8 Enterprise Plus for VCF", "Key": KEY_TERM, "Total": 256, "Used": 64, "Cost Unit": "cpuCore:16core", "Expiration Date": _d(400)}])),
        ("vHealth", _sheet(["Name", "Message", "Message type", "VI SDK Server"], [
            {"Name": "[ds-san-01] gone/gone.vmdk", "Message": "Possibly a Zombie vmdk file! Please check.", "Message type": "Zombie"},
            {"Name": "esx02.example.test", "Message": "NTP service not running", "Message type": "NTP"}])),
        ("vMetaData", _sheet(["RVTools major version", "RVTools version", "xlsx creation datetime", "Server"], [
            {"RVTools major version": 4, "RVTools version": "4.7.1.4", "xlsx creation datetime": NOW.strftime("%Y-%m-%d %H:%M:%S"), "Server": VC}])),
    ]
    return xlsx(sheets)
