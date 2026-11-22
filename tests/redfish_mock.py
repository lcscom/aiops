"""모의 Redfish BMC(테스트·개발용) — Dell iDRAC9 형태 R760(정상)·HPE iLO5 형태 DL380 Gen10(구형 CPU·RAID·1GbE)·일반

build_tree(kind) → {경로: JSON}. MockBmc 는 httpx 전송(MockTransport)과 ASGI 앱(개발 서버) 두 가지로 쓸 수 있고,
받은 요청을 모두 기록해(메서드·경로) 읽기 전용 정책을 시험에서 확인한다.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx


def _col(path: str, ids: list[str]) -> dict:
    return {"@odata.id": path, "Members@odata.count": len(ids), "Members": [{"@odata.id": f"{path}/{i}"} for i in ids]}


def build_tree(kind: str = "dell") -> dict[str, Any]:
    t: dict[str, Any] = {}
    if kind == "dell":
        S, C, M = "/redfish/v1/Systems/System.Embedded.1", "/redfish/v1/Chassis/System.Embedded.1", "/redfish/v1/Managers/iDRAC.Embedded.1"
        cpu_model, cores, sockets = "Intel(R) Xeon(R) Gold 6430", 32, 2
        dimm_speed, rated, dtype, dimm_gib = 4400, 4800, "DDR5", 64
        dimm_slots = [f"A{i}" for i in range(1, 9)] + [f"B{i}" for i in range(1, 9)]
        populated = set(dimm_slots)
        vendor_root = {"Vendor": "Dell", "Oem": {"Dell": {}}}
        model, serial, bios = "PowerEdge R760", "7XK1R63", "2.1.5"
    elif kind == "hpe":
        S, C, M = "/redfish/v1/Systems/1", "/redfish/v1/Chassis/1", "/redfish/v1/Managers/1"
        cpu_model, cores, sockets = "Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz", 16, 2
        dimm_speed, rated, dtype, dimm_gib = 2400, 2666, "DDR4", 32
        dimm_slots = [f"PROC {p} DIMM {d}" for p in (1, 2) for d in range(1, 13)]
        populated = {f"PROC {p} DIMM {d}" for p in (1, 2) for d in (1, 3, 5, 8, 10)}          # 채널 불균형
        vendor_root = {"Vendor": "HPE", "Oem": {"Hpe": {}}}
        model, serial, bios = "ProLiant DL380 Gen10", "MXQ81204ZZ", "U30 v2.16 (03/01/2019)"
    else:
        S, C, M = "/redfish/v1/Systems/1", "/redfish/v1/Chassis/1", "/redfish/v1/Managers/1"
        cpu_model, cores, sockets = "AMD EPYC 9354 32-Core Processor", 32, 1
        dimm_speed, rated, dtype, dimm_gib = 4800, 4800, "DDR5", 32
        dimm_slots = [f"DIMM_{c}1" for c in "ABCDEFGHIJKL"]
        populated = set(dimm_slots)
        vendor_root = {"Vendor": "Supermicro"}
        model, serial, bios = "AS -1125HS-TNR", "S5123456", "1.4"
    t["/redfish/v1"] = {"@odata.id": "/redfish/v1", "RedfishVersion": "1.17.0", "Systems": {"@odata.id": "/redfish/v1/Systems"},
                        "Chassis": {"@odata.id": "/redfish/v1/Chassis"}, "Managers": {"@odata.id": "/redfish/v1/Managers"},
                        "AccountService": {"@odata.id": "/redfish/v1/AccountService"}, "SessionService": {"@odata.id": "/redfish/v1/SessionService"},
                        "UpdateService": {"@odata.id": "/redfish/v1/UpdateService"}, "CertificateService": {"@odata.id": "/redfish/v1/CertificateService"},
                        **vendor_root}
    t["/redfish/v1/Systems"] = _col("/redfish/v1/Systems", [S.rsplit("/", 1)[1]])
    t["/redfish/v1/Chassis"] = _col("/redfish/v1/Chassis", [C.rsplit("/", 1)[1]])
    t["/redfish/v1/Managers"] = _col("/redfish/v1/Managers", [M.rsplit("/", 1)[1]])
    t[S] = {"@odata.id": S, "Id": S.rsplit("/", 1)[1], "SystemType": "Physical", "Manufacturer": vendor_root["Vendor"] if kind != "hpe" else "HPE",
            "Model": model, "SerialNumber": serial, "SKU": serial, "UUID": "4C4C4544-0058-4B10-8031-B7C04F523633" if kind == "dell" else "30373237-3132-584D-5138-313230345A5A",
            "BiosVersion": bios, "PowerState": "On", "HostName": f"esx-{kind}01.lab", "Status": {"State": "Enabled", "Health": "OK", "HealthRollup": "OK"},
            "Boot": {"BootSourceOverrideMode": "UEFI" if kind != "hpe" else "Legacy"},
            "ProcessorSummary": {"Count": sockets, "Model": cpu_model}, "MemorySummary": {"TotalSystemMemoryGiB": len(populated) * dimm_gib},
            "TrustedModules": [{"InterfaceType": "TPM2_0", "FirmwareVersion": "7.2.2.0", "Status": {"State": "Enabled"}}] if kind != "hpe" else [],
            "Processors": {"@odata.id": f"{S}/Processors"}, "Memory": {"@odata.id": f"{S}/Memory"}, "Storage": {"@odata.id": f"{S}/Storage"},
            "Bios": {"@odata.id": f"{S}/Bios"}, "SecureBoot": {"@odata.id": f"{S}/SecureBoot"}, "LogServices": {"@odata.id": f"{S}/LogServices"},
            "EthernetInterfaces": {"@odata.id": f"{S}/EthernetInterfaces"},
            "PCIeDevices": [{"@odata.id": f"{C}/PCIeDevices/{d}"} for d in ("59-0", "202-0", "3-0")]}
    t[f"{S}/Processors"] = _col(f"{S}/Processors", [f"CPU.Socket.{i}" for i in range(1, sockets + 1)])
    for i in range(1, sockets + 1):
        t[f"{S}/Processors/CPU.Socket.{i}"] = {"Id": f"CPU.Socket.{i}", "Socket": f"CPU.Socket.{i}", "ProcessorType": "CPU", "Model": cpu_model,
                                               "Manufacturer": "AMD" if "EPYC" in cpu_model else "Intel", "TotalCores": cores, "TotalThreads": cores * 2,
                                               "MaxSpeedMHz": 4000, "Status": {"State": "Enabled", "Health": "OK"}}
    t[f"{S}/Memory"] = _col(f"{S}/Memory", [s.replace(" ", "_") for s in dimm_slots])
    for i, sl in enumerate(dimm_slots):
        on = sl in populated
        sock = 2 if (" 2 " in sl or sl.startswith("B")) else 1
        t[f"{S}/Memory/{sl.replace(' ', '_')}"] = {"Id": sl.replace(" ", "_"), "Name": sl, "DeviceLocator": sl if kind != "dell" else f"DIMM.Socket.{sl}",
                                                   "CapacityMiB": dimm_gib * 1024 if on else 0, "OperatingSpeedMhz": dimm_speed if on else None,
                                                   "AllowedSpeedsMHz": [rated] if on else [], "MemoryDeviceType": dtype, "RankCount": 2,
                                                   "Manufacturer": "Samsung" if on else "", "PartNumber": "M321R8GA0BB0-CQKZJ" if on else "",
                                                   "ErrorCorrection": "MultiBitECC",
                                                   "MemoryLocation": {"Socket": sock, "Channel": i % 8 if kind != "hpe" else None, "Slot": i} if kind == "dell" else {},
                                                   "Status": {"State": "Enabled" if on else "Absent", "Health": "OK" if on else None}}
    # 스토리지
    if kind == "dell":
        t[f"{S}/Storage"] = _col(f"{S}/Storage", ["CPU.1", "AHCI.Embedded.1-1"])
        t[f"{S}/Storage/CPU.1"] = {"Id": "CPU.1", "Name": "CPU.1", "StorageControllers": [{"Name": "CPU.1", "Model": "Direct-attached NVMe", "SupportedDeviceProtocols": ["NVMe"]}],
                                   "Drives": [{"@odata.id": f"{S}/Storage/CPU.1/Drives/Disk.Bay.{i}"} for i in range(4)]}
        for i in range(4):
            t[f"{S}/Storage/CPU.1/Drives/Disk.Bay.{i}"] = {"Id": f"Disk.Bay.{i}", "Name": f"PCIe SSD in Slot {i}", "Model": "Dell Ent NVMe PM1733a RI 3.84TB",
                                                           "Manufacturer": "Samsung", "SerialNumber": f"S6CJNA0T9{i}", "Revision": "2.0.0", "Protocol": "NVMe",
                                                           "MediaType": "SSD", "CapacityBytes": 3840755982336, "PredictedMediaLifeLeftPercent": 99 - i,
                                                           "Status": {"State": "Enabled", "Health": "OK"},
                                                           "Links": {"PCIeFunctions": [{"@odata.id": f"{C}/PCIeDevices/59-{i}/PCIeFunctions/59-{i}-0"}]}}
            t[f"{C}/PCIeDevices/59-{i}/PCIeFunctions/59-{i}-0"] = {"Id": f"59-{i}-0", "VendorId": "0x144d", "DeviceId": "0xa824", "SubsystemVendorId": "0x1028",
                                                                    "SubsystemId": "0x2112", "DeviceClass": "MassStorageController"}
        t[f"{S}/Storage/AHCI.Embedded.1-1"] = {"Id": "AHCI.Embedded.1-1", "Name": "BOSS-N1", "StorageControllers": [{"Name": "BOSS-N1", "Model": "BOSS-N1 Monolithic"}],
                                               "Drives": [{"@odata.id": f"{S}/Storage/AHCI.Embedded.1-1/Drives/Disk.M.2.0"}]}
        t[f"{S}/Storage/AHCI.Embedded.1-1/Drives/Disk.M.2.0"] = {"Id": "Disk.M.2.0", "Name": "M.2 SSD 0", "Model": "MTFDKBG480TFR", "Protocol": "NVMe", "MediaType": "SSD",
                                                                 "CapacityBytes": 480103981056, "Revision": "E2MU200", "PredictedMediaLifeLeftPercent": 100,
                                                                 "Status": {"State": "Enabled", "Health": "OK"}}
    elif kind == "hpe":
        t[f"{S}/Storage"] = _col(f"{S}/Storage", ["DE00A000"])
        t[f"{S}/Storage/DE00A000"] = {"Id": "DE00A000", "Name": "HPE Smart Array P816i-a SR Gen10", "StorageControllers": [
            {"Name": "HPE Smart Array P816i-a SR Gen10", "Model": "HPE Smart Array P816i-a SR Gen10", "FirmwareVersion": "1.98", "SupportedDeviceProtocols": ["SAS", "SATA"]}],
            "Drives": [{"@odata.id": f"{S}/Storage/DE00A000/Drives/{i}"} for i in range(6)]}
        for i in range(6):
            t[f"{S}/Storage/DE00A000/Drives/{i}"] = {"Id": str(i), "Name": f"Drive {i}", "Model": "MZ7LH960HAJR" if i < 2 else "EG001200JWJNQ",
                                                     "Protocol": "SATA" if i < 2 else "SAS", "MediaType": "SSD" if i < 2 else "HDD",
                                                     "CapacityBytes": 960197124096 if i < 2 else 1200243695616, "Revision": "HPG3",
                                                     "PredictedMediaLifeLeftPercent": 12 if i == 0 else (95 if i < 2 else None),
                                                     "Status": {"State": "Enabled", "Health": "Warning" if i == 0 else "OK"}}
    else:
        t[f"{S}/Storage"] = _col(f"{S}/Storage", [])
    # PCIe
    pcie = {"59-0": ("NVMe SSD", "0x144d", "0xa824", "0x1028", "0x2112", "MassStorageController"),
            "202-0": ("Broadcom BCM57508 NetXtreme-E 10Gb/25Gb/40Gb/50Gb/100Gb/200Gb", "0x14e4", "0x1750", "0x14e4", "0x2100", "NetworkController")
            if kind != "hpe" else ("HPE Ethernet 1Gb 4-port 331i Adapter", "0x14e4", "0x1657", "0x103c", "0x22be", "NetworkController"),
            "3-0": ("Matrox G200eW3", "0x102b", "0x0536", "0x1028", "0x0b1c", "DisplayController")}
    for d, (nm, v, di, sv, ss, cls) in pcie.items():
        t[f"{C}/PCIeDevices/{d}"] = {"Id": d, "Name": nm, "Manufacturer": nm.split()[0], "FirmwareVersion": "22.31.13.70",
                                     "PCIeInterface": {"PCIeType": "Gen4", "LanesInUse": 16, "MaxLanes": 16},
                                     "PCIeFunctions": {"@odata.id": f"{C}/PCIeDevices/{d}/PCIeFunctions"}, "Status": {"State": "Enabled", "Health": "OK"}}
        t[f"{C}/PCIeDevices/{d}/PCIeFunctions"] = _col(f"{C}/PCIeDevices/{d}/PCIeFunctions", [f"{d}-0"])
        t[f"{C}/PCIeDevices/{d}/PCIeFunctions/{d}-0"] = {"Id": f"{d}-0", "VendorId": v, "DeviceId": di, "SubsystemVendorId": sv, "SubsystemId": ss, "DeviceClass": cls}
    # 섀시·NIC·전원·온도
    t[C] = {"Id": C.rsplit("/", 1)[1], "ChassisType": "RackMount", "Model": model, "SerialNumber": serial, "NetworkAdapters": {"@odata.id": f"{C}/NetworkAdapters"},
            "Power": {"@odata.id": f"{C}/Power"}, "Thermal": {"@odata.id": f"{C}/Thermal"}, "PCIeDevices": {"@odata.id": f"{C}/PCIeDevices"}}
    t[f"{C}/NetworkAdapters"] = _col(f"{C}/NetworkAdapters", ["NIC.Slot.2"])
    t[f"{C}/NetworkAdapters/NIC.Slot.2"] = {"Id": "NIC.Slot.2", "Model": pcie["202-0"][0], "Manufacturer": "Broadcom", "Controllers": [{"FirmwarePackageVersion": "22.31.13.70"}],
                                           "Ports": {"@odata.id": f"{C}/NetworkAdapters/NIC.Slot.2/Ports"}}
    nports = 2 if kind != "hpe" else 4
    t[f"{C}/NetworkAdapters/NIC.Slot.2/Ports"] = _col(f"{C}/NetworkAdapters/NIC.Slot.2/Ports", [str(i) for i in range(1, nports + 1)])
    for i in range(1, nports + 1):
        lldp = {}
        if kind == "dell":
            lldp = {"ChassisId": f"00:3a:9c:aa:0{i}:00", "PortId": f"Ethernet1/{11}", "SystemName": f"leaf-0{i}.dc1", "ManagementAddressIPv4": f"10.0.0.{i}"}
        elif kind == "hpe" and i <= 2:
            lldp = {"ChassisId": "00:3a:9c:aa:01:00", "PortId": f"Ethernet1/{20 + i}", "SystemName": "leaf-01.dc1"}      # 같은 스위치에만 연결(단일 홈)
        t[f"{C}/NetworkAdapters/NIC.Slot.2/Ports/{i}"] = {"Id": str(i), "LinkStatus": "Up" if i <= 2 else "Down",
                                                          "CurrentSpeedGbps": (25 if kind != "hpe" else 1) if i <= 2 else 0, "MaxSpeedGbps": 100 if kind != "hpe" else 1,
                                                          "PortMedium": "Optical" if kind != "hpe" else "Electrical",
                                                          "Ethernet": {"AssociatedMACAddresses": [f"b0:26:28:00:00:0{i}"], "LLDPReceive": lldp}}
    t[f"{C}/Power"] = {"PowerSupplies": [{"Name": f"PS{i}", "PowerCapacityWatts": 1400 if kind != "hpe" else 800, "Model": "PWR SPLY", "FirmwareVersion": "00.1D.7D",
                                          "LineInputVoltage": 230, "Status": {"State": "Enabled", "Health": "OK"}} for i in (1, 2)] if kind != "hpe" else
                       [{"Name": "PS1", "PowerCapacityWatts": 800, "Status": {"State": "Enabled", "Health": "OK"}}],
                       "PowerControl": [{"PowerConsumedWatts": 412 if kind != "hpe" else 290, "PowerLimit": {"LimitInWatts": None}}],
                       "Redundancy": [{"Mode": "N+m", "Status": {"Health": "OK" if kind != "hpe" else "Critical"}}]}
    t[f"{C}/Thermal"] = {"Temperatures": [{"Name": "CPU1 Temp", "ReadingCelsius": 54, "UpperThresholdCritical": 100, "Status": {"State": "Enabled", "Health": "OK"}},
                                          {"Name": "System Board Inlet Temp", "ReadingCelsius": 23, "UpperThresholdNonCritical": 42, "Status": {"State": "Enabled", "Health": "OK"}}],
                         "Fans": [{"Name": f"Fan{i}", "Reading": 6000, "Status": {"State": "Enabled", "Health": "OK"}} for i in range(1, 7)]}
    # BIOS·Secure Boot
    if kind == "dell":
        attrs = {"BootMode": "Uefi", "SysProfile": "PerfOptimized", "ProcVirtualization": "Enabled", "ProcX2Apic": "Enabled", "SriovGlobalEnable": "Enabled",
                 "LogicalProc": "Enabled", "ProcCStates": "Disabled", "ProcC1E": "Disabled", "NodeInterleave": "Disabled", "MemOpMode": "OptimizerMode",
                 "TpmSecurity": "On", "Tpm2Hierarchy": "Enabled", "IntelTxt": "Off", "SecureBoot": "Enabled", "SetupPassword": "secret", "MmioAbove4Gb": "Enabled"}
    elif kind == "hpe":
        attrs = {"BootMode": "LegacyBios", "WorkloadProfile": "GeneralPowerEfficientCompute", "ProcVirtualization": "Enabled", "Sriov": "Disabled",
                 "ProcHyperthreading": "Enabled", "MinProcIdlePower": "C6", "PowerRegulator": "DynamicPowerSavings", "TpmState": "NotPresent",
                 "IntelligentProvisioning": "Enabled", "ProcX2Apic": "Enabled"}
    else:
        attrs = {"BootMode": "UEFI", "SVMMode": "Enabled", "SMTControl": "Auto", "IOMMU": "Enabled", "SRIOVSupport": "Enabled", "DeterminismControl": "Manual"}
    t[f"{S}/Bios"] = {"AttributeRegistry": "BiosAttributeRegistry.v1_0_0", "Attributes": attrs}
    t[f"{S}/SecureBoot"] = {"SecureBootEnable": kind != "hpe", "SecureBootCurrentBoot": "Enabled" if kind != "hpe" else "Disabled", "SecureBootMode": "DeployedMode"}
    t[f"{S}/EthernetInterfaces"] = _col(f"{S}/EthernetInterfaces", [])
    # BMC
    t[M] = {"@odata.id": M, "Id": M.rsplit("/", 1)[1], "ManagerType": "BMC", "Model": "16G Monolithic" if kind == "dell" else ("iLO 5" if kind == "hpe" else "BMC"),
            "FirmwareVersion": "7.00.60.00" if kind == "dell" else ("2.10" if kind == "hpe" else "01.01.10"), "Status": {"State": "Enabled", "Health": "OK"},
            "NetworkProtocol": {"@odata.id": f"{M}/NetworkProtocol"}, "LogServices": {"@odata.id": f"{M}/LogServices"},
            "EthernetInterfaces": {"@odata.id": f"{M}/EthernetInterfaces"}, "DateTime": "2026-10-23T06:00:00+00:00"}
    secure = kind == "dell"
    t[f"{M}/NetworkProtocol"] = {"HTTP": {"ProtocolEnabled": not secure, "Port": 80}, "HTTPS": {"ProtocolEnabled": True, "Port": 443},
                                 "IPMI": {"ProtocolEnabled": not secure, "Port": 623}, "SSH": {"ProtocolEnabled": not secure, "Port": 22},
                                 "Telnet": {"ProtocolEnabled": False}, "SSDP": {"ProtocolEnabled": not secure},
                                 "SNMP": {"ProtocolEnabled": True, "Port": 161, "EnableSNMPv1": not secure, "EnableSNMPv2c": not secure, "EnableSNMPv3": True},
                                 "NTP": {"ProtocolEnabled": True, "NTPServers": ["10.0.0.10", "10.0.0.11"] if secure else []}}
    t[f"{M}/EthernetInterfaces"] = _col(f"{M}/EthernetInterfaces", ["NIC.1"])
    t[f"{M}/EthernetInterfaces/NIC.1"] = {"MACAddress": "d0:8e:79:00:00:01", "DHCPv4": {"DHCPEnabled": not secure}, "IPv4Addresses": [{"Address": "10.10.0.21"}],
                                          "VLAN": {"VLANEnable": False}, "SpeedMbps": 1000}
    t[f"{M}/LogServices"] = _col(f"{M}/LogServices", ["Sel" if kind != "hpe" else "IEL"])
    lid = "Sel" if kind != "hpe" else "IEL"
    t[f"{M}/LogServices/{lid}"] = {"Id": lid, "Name": "System Event Log" if kind != "hpe" else "iLO Event Log", "Entries": {"@odata.id": f"{M}/LogServices/{lid}/Entries"}}
    ago = lambda h: (datetime.now(timezone.utc) - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%S+00:00")   # noqa: E731  날짜가 지나도 '최근 30일' 안
    ents = [{"Id": "1", "Created": ago(72), "Severity": "OK", "Message": "The system inlet temperature is within range.", "MessageId": "TMP0121"},
            {"Id": "2", "Created": ago(25), "Severity": "Warning" if kind != "dell" else "OK",
             "Message": "Correctable memory error rate exceeded for DIMM PROC 1 DIMM 3." if kind != "dell" else "Log cleared.", "MessageId": "MEM0701"},
            {"Id": "3", "Created": ago(24), "Severity": "Critical" if kind == "hpe" else "OK",
             "Message": "Power supply redundancy is lost." if kind == "hpe" else "Drive 0 inserted.", "MessageId": "PSU0003"}]
    t[f"{M}/LogServices/{lid}/Entries"] = {"Members": ents}
    t[f"{S}/LogServices"] = _col(f"{S}/LogServices", [])
    # 계정·세션·인증서·펌웨어
    t["/redfish/v1/AccountService"] = {"MinPasswordLength": 12 if secure else 8, "MaxPasswordLength": 40, "AccountLockoutThreshold": 5 if secure else 0,
                                       "AccountLockoutDuration": 300 if secure else 0, "LDAP": {"ServiceEnabled": secure}, "ActiveDirectory": {"ServiceEnabled": False},
                                       "Accounts": {"@odata.id": "/redfish/v1/AccountService/Accounts"}}
    t["/redfish/v1/AccountService/Accounts"] = _col("/redfish/v1/AccountService/Accounts", ["1", "2", "3"])
    t["/redfish/v1/AccountService/Accounts/1"] = {"UserName": "", "Enabled": False, "RoleId": "None"}
    t["/redfish/v1/AccountService/Accounts/2"] = {"UserName": "root" if kind == "dell" else ("Administrator" if kind == "hpe" else "ADMIN"), "Enabled": True,
                                                  "RoleId": "Administrator", "Locked": False}
    t["/redfish/v1/AccountService/Accounts/3"] = {"UserName": "aiops-ro", "Enabled": True, "RoleId": "ReadOnly", "Locked": False}
    t["/redfish/v1/SessionService"] = {"SessionTimeout": 600 if secure else 3600, "Sessions": {"@odata.id": "/redfish/v1/SessionService/Sessions"}}
    t["/redfish/v1/CertificateService"] = {"CertificateLocations": {"@odata.id": "/redfish/v1/CertificateService/CertificateLocations"}}
    t["/redfish/v1/CertificateService/CertificateLocations"] = {"Links": {"Certificates": [{"@odata.id": f"{M}/NetworkProtocol/HTTPS/Certificates/1"}]}}
    issuer = {"CommonName": "Corp Issuing CA 01"} if secure else {"CommonName": "idrac-default"}
    t[f"{M}/NetworkProtocol/HTTPS/Certificates/1"] = {"Subject": {"CommonName": f"bmc-{kind}01.lab"} if secure else {"CommonName": "idrac-default"}, "Issuer": issuer,
                                                       "ValidNotAfter": "2027-06-30T00:00:00Z" if secure else "2025-01-01T00:00:00Z"}
    t["/redfish/v1/UpdateService"] = {"FirmwareInventory": {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory"}}
    t["/redfish/v1/UpdateService/FirmwareInventory"] = {"Members": [{"Id": "Installed-BIOS", "Name": "BIOS", "Version": bios, "Updateable": True},
                                                                    {"Id": "Installed-iDRAC", "Name": "BMC", "Version": t[M]["FirmwareVersion"], "Updateable": True},
                                                                    {"Id": "Installed-NIC", "Name": pcie["202-0"][0], "Version": "22.31.13.70", "Updateable": True}]}
    if kind == "dell":
        t[f"{S}/NetworkPorts/Oem/Dell/DellSwitchConnections"] = {"Members": []}
        t[f"{M}/Attributes"] = {"Attributes": {"IPMILan.1.Enable": "Disabled", "SSH.1.Enable": "Disabled", "WebServer.1.TLSProtocol": "TLS 1.2 and Higher",
                                               "Lockdown.1.SystemLockdown": "Disabled", "IPBlocking.1.BlockEnable": "Enabled", "Telnet.1.Enable": "Disabled",
                                               "IPMILan.1.EncryptionKey": "0000000000000000000000000000000000000000"}}
        t["/redfish/v1/LicenseService/Licenses"] = {"Members": [{"Description": "iDRAC9 Enterprise License"}]}
    return t


class MockBmc:
    def __init__(self, kind: str = "dell", username: str = "aiops-ro", password: str = "Pw!", sessions: bool = True):
        self.tree = build_tree(kind)
        self.username, self.password, self.sessions = username, password, sessions
        self.calls: list[tuple[str, str]] = []
        self.tokens: set[str] = set()

    def handle(self, method: str, path: str, headers: dict, body: bytes) -> tuple[int, dict, dict]:
        p = path.rstrip("/") or "/redfish/v1"
        self.calls.append((method, p))
        if method == "POST" and p == "/redfish/v1/SessionService/Sessions":
            if not self.sessions:
                return 405, {}, {}
            b = json.loads(body or b"{}")
            if b.get("UserName") != self.username or b.get("Password") != self.password:
                return 401, {}, {}
            tok = f"tok{len(self.tokens) + 1}"
            self.tokens.add(tok)
            return 201, {"X-Auth-Token": tok, "Location": f"/redfish/v1/SessionService/Sessions/{tok}"}, {"Id": tok}
        if p == "/redfish/v1":
            return 200, {}, self.tree[p]
        auth_ok = headers.get("x-auth-token") in self.tokens
        if not auth_ok and headers.get("authorization"):
            import base64
            try:
                u, _, pw = base64.b64decode(headers["authorization"].split()[1]).decode().partition(":")
                auth_ok = u == self.username and pw == self.password
            except Exception:  # noqa: BLE001
                auth_ok = False
        if not auth_ok:
            return 401, {}, {}
        if method == "DELETE" and p.startswith("/redfish/v1/SessionService/Sessions/"):
            self.tokens.discard(p.rsplit("/", 1)[1])
            return 204, {}, {}
        if method != "GET":
            return 405, {}, {"error": "mock is read-only"}
        if p in self.tree:
            return 200, {}, self.tree[p]
        return 404, {}, {}

    def transport(self) -> httpx.MockTransport:
        def h(req: httpx.Request) -> httpx.Response:
            st, hd, js = self.handle(req.method, req.url.path, {k.lower(): v for k, v in req.headers.items()}, req.content)
            return httpx.Response(st, headers=hd, json=js) if js or st < 300 else httpx.Response(st, headers=hd)
        return httpx.MockTransport(h)

    async def asgi(self, scope, receive, send):
        if scope["type"] != "http":
            return
        body = b""
        while True:
            m = await receive()
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        hd = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        import datetime as _dt                             # 개발 서버: BMC 시계를 현재 시각으로
        for k, v in self.tree.items():
            if isinstance(v, dict) and "DateTime" in v:
                v["DateTime"] = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        st, rh, js = self.handle(scope["method"], scope["path"], hd, body)
        out = json.dumps(js).encode() if js else b""
        await send({"type": "http.response.start", "status": st,
                    "headers": [(b"content-type", b"application/json")] + [(k.encode(), v.encode()) for k, v in rh.items()]})
        await send({"type": "http.response.body", "body": out})
