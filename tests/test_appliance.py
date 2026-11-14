"""OVA 어플라이언스 — OVF 생성·OVF 환경 해석·네트워크 설정 생성 검증(빌드 없이 실행)."""
import hashlib
import importlib.util
import sys
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "appliance"
sys.path.insert(0, str(APP))

import spec  # noqa: E402
import provision as P  # noqa: E402

_mo = importlib.util.spec_from_file_location("make_ovf", APP / "make-ovf.py")
make_ovf = importlib.util.module_from_spec(_mo)
_mo.loader.exec_module(make_ovf)

OVF = "{http://schemas.dmtf.org/ovf/envelope/1}"
RASD = "{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData}"
VMW = "{http://www.vmware.com/schema/ovf}"

ENV = """<?xml version="1.0" encoding="UTF-8"?>
<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:oe="http://schemas.dmtf.org/ovf/environment/1"
  xmlns:ve="http://www.vmware.com/schema/ovfenv" oe:id="" ve:vCenterId="vm-42">
 <PlatformSection><Kind>VMware ESXi</Kind></PlatformSection>
 <PropertySection>
  <Property oe:key="net.hostname" oe:value="AIOps.Corp.Example."/>
  <Property oe:key="net.ip" oe:value="10.10.20.50"/>
  <Property oe:key="net.prefix" oe:value="24"/>
  <Property oe:key="net.gateway" oe:value="10.10.20.1"/>
  <Property oe:key="net.dns" oe:value="10.10.0.11, 10.10.0.12;bogus"/>
  <Property oe:key="net.search" oe:value="corp.example"/>
  <Property oe:key="net.ntp" oe:value="10.10.0.1,ntp.corp.example,bad_host!"/>
  <Property oe:key="sys.password" oe:value="S3cret&amp;Pw!!long"/>
  <Property oe:key="sys.ssh" oe:value="False"/>
  <Property oe:key="app.port" oe:value="99999"/>
 </PropertySection>
</Environment>"""


@pytest.fixture()
def built(tmp_path):
    vmdk = tmp_path / "vcf-aiops-9.9.9-disk1.vmdk"
    vmdk.write_bytes(b"KDMV" + b"\0" * 4092)
    sys.argv = ["make-ovf.py", "--vmdk", str(vmdk), "--version", "9.9.9", "--out", str(tmp_path), "--populated", "123"]
    assert make_ovf.main() == 0
    return tmp_path


def test_ovf_structure(built):
    root = ET.parse(built / "vcf-aiops-9.9.9.ovf").getroot()
    vs = root.find(f"{OVF}VirtualSystem")
    hw = vs.find(f"{OVF}VirtualHardwareSection")
    assert hw.get(f"{OVF}transport") == "com.vmware.guestInfo"
    assert hw.find(f"{OVF}System/").tag  # System 존재
    # 배포 크기: 기본 1개, 각 크기별 CPU·메모리·데이터 디스크 Item
    cfgs = root.findall(f"{OVF}DeploymentOptionSection/{OVF}Configuration")
    assert [c.get(f"{OVF}id") for c in cfgs] == list(spec.SIZES)
    assert sum(1 for c in cfgs if c.get(f"{OVF}default") == "true") == 1
    items = hw.findall(f"{OVF}Item")
    for cid, s in spec.SIZES.items():
        mine = [i for i in items if i.get(f"{OVF}configuration") == cid]
        by = {i.find(f"{RASD}ResourceType").text: i for i in mine}
        assert by["3"].find(f"{RASD}VirtualQuantity").text == str(s["cpu"])
        assert by["4"].find(f"{RASD}VirtualQuantity").text == str(s["mem_gb"] * 1024)
        assert by["17"].find(f"{RASD}HostResource").text == f"ovf:/disk/data-{cid}"
    subtypes = {i.find(f"{RASD}ResourceSubType").text for i in items if i.find(f"{RASD}ResourceSubType") is not None}
    assert {"VirtualSCSI", "VmxNet3"} <= subtypes
    # 빈 데이터 디스크(fileRef 없음) + OS 디스크(fileRef)
    disks = {d.get(f"{OVF}diskId"): d for d in root.findall(f"{OVF}DiskSection/{OVF}Disk")}
    assert disks["vmdisk1"].get(f"{OVF}fileRef") == "file1"
    assert all(disks[f"data-{c}"].get(f"{OVF}fileRef") is None for c in spec.SIZES)
    assert disks["data-large"].get(f"{OVF}capacity") == "700"
    cfg = {c.get(f"{VMW}key"): c.get(f"{VMW}value") for c in hw.findall(f"{VMW}Config")}
    assert cfg["firmware"] == "efi" and cfg["bootOptions.efiSecureBootEnabled"] == "true"
    assert cfg["tools.syncTimeWithHost"] == "false"


def test_ovf_properties_match_spec(built):
    root = ET.parse(built / "vcf-aiops-9.9.9.ovf").getroot()
    props = root.findall(f"{OVF}VirtualSystem/{OVF}ProductSection/{OVF}Property")
    assert [p.get(f"{OVF}key") for p in props] == [p["key"] for p in spec.PROPS]
    pw = {p.get(f"{OVF}key") for p in props if p.get(f"{OVF}password") == "true"}
    assert pw == spec.PASSWORD_KEYS == {"sys.password", "app.admin_password", "app.pais_key", "app.key_pem"}
    q = {p.get(f"{OVF}key"): p.get(f"{OVF}qualifiers") for p in props}
    assert q["sys.password"].startswith("MinLen(12)") and q["app.admin_password"].startswith("MinLen(12)")
    assert all(p.find(f"{OVF}Label").text for p in props)


def test_manifest_and_ova_order(built):
    mf = (built / "vcf-aiops-9.9.9.mf").read_text().splitlines()
    for ln in mf:
        name = ln.split("(")[1].split(")")[0]
        assert ln.endswith(hashlib.sha256((built / name).read_bytes()).hexdigest())
    with tarfile.open(built / "vcf-aiops-9.9.9.ova") as t:
        assert [m.name for m in t.getmembers()] == ["vcf-aiops-9.9.9.ovf", "vcf-aiops-9.9.9.mf", "vcf-aiops-9.9.9-disk1.vmdk"]


def test_env_parse_and_validation():
    p = P.Props(P.parse_env(ENV), "test")
    assert p.s("sys.password") == "S3cret&Pw!!long"
    assert p.redacted()["sys.password"] == "********"
    assert p.b("sys.ssh") is False and p.b("sys.firewall") is True          # 기본값 true
    assert p.i("app.port", 1024, 65535) == 65535                            # 범위 밖 → 상한
    assert p.s("sys.timezone") == "Asia/Seoul"
    n = P.net_settings(p)
    assert n["fqdn"] == "aiops.corp.example" and n["short"] == "aiops"
    assert n["dhcp"] is False and n["ip"] == "10.10.20.50" and n["gateway"] == "10.10.20.1"
    assert n["dns"] == ["10.10.0.11", "10.10.0.12"]
    assert n["ntp"] == ["10.10.0.1", "ntp.corp.example"]


def test_defaults_without_env():
    n = P.net_settings(P.Props({}, "없음"))
    assert n["dhcp"] is True and n["fqdn"] == "aiops"


def test_netplan_yaml(tmp_path, monkeypatch):
    out = {}
    monkeypatch.setattr(P, "NETPLAN", tmp_path / "netplan" / "50-vcf-aiops.yaml")
    monkeypatch.setattr(P, "write", lambda path, text, *a, **k: out.__setitem__(str(path), text) or True)
    monkeypatch.setattr(P, "run", lambda *a, **k: None)
    monkeypatch.setattr(P, "Path", lambda *a: tmp_path / "none" if a == ("/etc/netplan",) else Path(*a))
    n = P.net_settings(P.Props(P.parse_env(ENV.replace("10.10.20.1", "10.10.99.1")), "t"))
    P.apply_netplan(n)
    doc = yaml.safe_load(next(iter(out.values())))
    nic = doc["network"]["ethernets"]["nic0"]
    assert nic["addresses"] == ["10.10.20.50/24"] and nic["dhcp4"] is False
    assert nic["routes"] == [{"to": "default", "via": "10.10.99.1", "on-link": True}]   # 서브넷 밖 게이트웨이
    assert nic["nameservers"]["search"] == ["corp.example"]


def test_install_stage_flags():
    s = (ROOT / "scripts/linux/install.sh").read_text(encoding="utf-8")
    assert "--stage" in s and 'STAGE" != configure' in s and 'STAGE" != image' in s
    assert "appliance" in s.split("for d in app scripts deploy ragpacks docs tests")[1].split(";")[0]
