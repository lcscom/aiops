#!/usr/bin/env python3
"""OVF 디스크립터 · 매니페스트 · OVA 생성.

  python3 make-ovf.py --vmdk out/vcf-aiops-1.0.0-disk1.vmdk --version 1.0.0 --out out/
    → out/vcf-aiops-1.0.0.ovf · .mf · .ova (OVF 1.0, SHA256 매니페스트, tar 순서 ovf→mf→vmdk)

하드웨어: vmx-17(ESXi 7.0+) · EFI + 보안 부팅 · PVSCSI · VMXNET3 · 배포 크기(소/중/대)별 vCPU·메모리·빈 데이터 디스크.
vApp 속성은 spec.py, 전송은 VMware Tools(guestinfo.ovfEnv).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tarfile
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec import OS_DISK_GB, OS_USER, PRODUCT, PROPS, SIZES, VENDOR  # noqa: E402

VMDK_FMT = "http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"


def a(v: object) -> str:
    return quoteattr(str(v))


def build_ovf(name: str, version: str, vmdk: Path, populated: int | None, hw: str) -> str:
    size = vmdk.stat().st_size
    L: list[str] = []
    w = L.append
    w('<?xml version="1.0" encoding="UTF-8"?>')
    w('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"'
      ' xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common"'
      ' xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"'
      ' xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"'
      ' xmlns:vmw="http://www.vmware.com/schema/ovf"'
      ' xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"'
      ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">')
    w('  <References>')
    w(f'    <File ovf:href={a(vmdk.name)} ovf:id="file1" ovf:size={a(size)}/>')
    w('  </References>')
    # ------------------------------------------------------------------ 디스크
    w('  <DiskSection>')
    w('    <Info>Virtual disk information</Info>')
    pop = f' ovf:populatedSize={a(populated)}' if populated else ''
    w(f'    <Disk ovf:capacity={a(OS_DISK_GB)} ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1"'
      f' ovf:fileRef="file1" ovf:format={a(VMDK_FMT)}{pop}/>')
    for cid, s in SIZES.items():
        # fileRef 없는 디스크 = 배포 시 빈 디스크 생성(첫 부팅에 XFS 포맷·/var/lib/vcf-aiops 마운트)
        w(f'    <Disk ovf:capacity={a(s["data_gb"])} ovf:capacityAllocationUnits="byte * 2^30"'
          f' ovf:diskId={a("data-" + cid)} ovf:format={a(VMDK_FMT)}/>')
    w('  </DiskSection>')
    # ------------------------------------------------------------------ 네트워크
    w('  <NetworkSection>')
    w('    <Info>The list of logical networks</Info>')
    w('    <Network ovf:name="Management">')
    w('      <Description>관리망 — 장비 syslog·SNMP 수신, vCenter·NSX·BMC API, 운영자 브라우저와 통신 가능한 포트그룹</Description>')
    w('    </Network>')
    w('  </NetworkSection>')
    # ------------------------------------------------------------------ 배포 크기
    w('  <DeploymentOptionSection>')
    w('    <Info>Deployment size</Info>')
    for cid, s in SIZES.items():
        dflt = ' ovf:default="true"' if s.get("default") else ''
        w(f'    <Configuration ovf:id={a(cid)}{dflt}>')
        w(f'      <Label>{escape(s["label"])}</Label>')
        w(f'      <Description>{escape(s["desc"])}</Description>')
        w('    </Configuration>')
    w('  </DeploymentOptionSection>')
    # ------------------------------------------------------------------ VM
    w(f'  <VirtualSystem ovf:id={a(name)}>')
    w('    <Info>A virtual machine</Info>')
    w(f'    <Name>{escape(name)}</Name>')
    w('    <AnnotationSection>')
    w('      <Info>A human-readable annotation</Info>')
    w(f'      <Annotation>{escape(PRODUCT)} {escape(version)} 어플라이언스 — Ubuntu 24.04 LTS. 배포 시 입력한 vApp 속성으로 '
      f'첫 부팅에 네트워크·계정·인증서·서비스가 자동 구성됩니다. 콘솔 로그인 {OS_USER}. 문서: /opt/vcf-aiops/docs/OVA.md</Annotation>')
    w('    </AnnotationSection>')
    w('    <ProductSection ovf:required="false">')
    w('      <Info>Information about the installed software</Info>')
    w(f'      <Product>{escape(PRODUCT)}</Product>')
    w(f'      <Vendor>{escape(VENDOR)}</Vendor>')
    w(f'      <Version>{escape(version)}</Version>')
    w(f'      <FullVersion>{escape(version)}</FullVersion>')
    cat = None
    for p in PROPS:
        if p["cat"] != cat:
            cat = p["cat"]
            w(f'      <Category>{escape(cat)}</Category>')
        attrs = [f'ovf:key={a(p["key"])}', f'ovf:type={a(p["type"])}', 'ovf:userConfigurable="true"',
                 f'ovf:value={a(p["default"])}']
        if p.get("qualifiers"):
            attrs.append(f'ovf:qualifiers={a(p["qualifiers"])}')
        if p.get("password"):
            attrs.append('ovf:password="true"')
        w(f'      <Property {" ".join(attrs)}>')
        w(f'        <Label>{escape(p["label"])}</Label>')
        w(f'        <Description>{escape(p["desc"])}</Description>')
        w('      </Property>')
    w('    </ProductSection>')
    w('    <OperatingSystemSection ovf:id="94" vmw:osType="ubuntu64Guest">')
    w('      <Info>The kind of installed guest operating system</Info>')
    w('      <Description>Ubuntu Linux (64-bit)</Description>')
    w('    </OperatingSystemSection>')
    w('    <VirtualHardwareSection ovf:transport="com.vmware.guestInfo">')
    w('      <Info>Virtual hardware requirements</Info>')
    w('      <System>')
    w('        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>')
    w('        <vssd:InstanceID>0</vssd:InstanceID>')
    w(f'        <vssd:VirtualSystemIdentifier>{escape(name)}</vssd:VirtualSystemIdentifier>')
    w(f'        <vssd:VirtualSystemType>{escape(hw)}</vssd:VirtualSystemType>')
    w('      </System>')
    for cid, s in SIZES.items():
        w(f'      <Item ovf:configuration={a(cid)}>')
        w('        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>')
        w('        <rasd:Description>Number of Virtual CPUs</rasd:Description>')
        w(f'        <rasd:ElementName>{s["cpu"]} virtual CPU(s)</rasd:ElementName>')
        w('        <rasd:InstanceID>1</rasd:InstanceID>')
        w('        <rasd:ResourceType>3</rasd:ResourceType>')
        w(f'        <rasd:VirtualQuantity>{s["cpu"]}</rasd:VirtualQuantity>')
        w('      </Item>')
    for cid, s in SIZES.items():
        w(f'      <Item ovf:configuration={a(cid)}>')
        w('        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>')
        w('        <rasd:Description>Memory Size</rasd:Description>')
        w(f'        <rasd:ElementName>{s["mem_gb"] * 1024}MB of memory</rasd:ElementName>')
        w('        <rasd:InstanceID>2</rasd:InstanceID>')
        w('        <rasd:ResourceType>4</rasd:ResourceType>')
        w(f'        <rasd:VirtualQuantity>{s["mem_gb"] * 1024}</rasd:VirtualQuantity>')
        w('      </Item>')
    w('      <Item>')
    w('        <rasd:Address>0</rasd:Address>')
    w('        <rasd:Description>SCSI Controller</rasd:Description>')
    w('        <rasd:ElementName>SCSI controller 0</rasd:ElementName>')
    w('        <rasd:InstanceID>3</rasd:InstanceID>')
    w('        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType>')
    w('        <rasd:ResourceType>6</rasd:ResourceType>')
    w('      </Item>')
    w('      <Item>')
    w('        <rasd:AddressOnParent>0</rasd:AddressOnParent>')
    w('        <rasd:ElementName>Hard disk 1</rasd:ElementName>')
    w('        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>')
    w('        <rasd:InstanceID>4</rasd:InstanceID>')
    w('        <rasd:Parent>3</rasd:Parent>')
    w('        <rasd:ResourceType>17</rasd:ResourceType>')
    w('      </Item>')
    for cid in SIZES:
        w(f'      <Item ovf:configuration={a(cid)}>')
        w('        <rasd:AddressOnParent>1</rasd:AddressOnParent>')
        w('        <rasd:ElementName>Hard disk 2</rasd:ElementName>')
        w(f'        <rasd:HostResource>ovf:/disk/data-{cid}</rasd:HostResource>')
        w('        <rasd:InstanceID>5</rasd:InstanceID>')
        w('        <rasd:Parent>3</rasd:Parent>')
        w('        <rasd:ResourceType>17</rasd:ResourceType>')
        w('      </Item>')
    w('      <Item>')
    w('        <rasd:AddressOnParent>7</rasd:AddressOnParent>')
    w('        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>')
    w('        <rasd:Connection>Management</rasd:Connection>')
    w('        <rasd:Description>VmxNet3 ethernet adapter on "Management"</rasd:Description>')
    w('        <rasd:ElementName>Network adapter 1</rasd:ElementName>')
    w('        <rasd:InstanceID>6</rasd:InstanceID>')
    w('        <rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType>')
    w('        <rasd:ResourceType>10</rasd:ResourceType>')
    w('      </Item>')
    w('      <Item ovf:required="false">')
    w('        <rasd:AutomaticAllocation>false</rasd:AutomaticAllocation>')
    w('        <rasd:ElementName>Video card</rasd:ElementName>')
    w('        <rasd:InstanceID>7</rasd:InstanceID>')
    w('        <rasd:ResourceType>24</rasd:ResourceType>')
    w('      </Item>')
    w('      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="efi"/>')
    w('      <vmw:Config ovf:required="false" vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="true"/>')
    w('      <vmw:Config ovf:required="false" vmw:key="tools.syncTimeWithHost" vmw:value="false"/>')
    w('      <vmw:Config ovf:required="false" vmw:key="tools.toolsUpgradePolicy" vmw:value="manual"/>')
    w('      <vmw:ExtraConfig ovf:required="false" vmw:key="disk.EnableUUID" vmw:value="TRUE"/>')
    w('    </VirtualHardwareSection>')
    w('  </VirtualSystem>')
    w('</Envelope>')
    return "\n".join(L) + "\n"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vmdk", required=True, type=Path)
    ap.add_argument("--version", required=True)
    ap.add_argument("--name", default="vcf-aiops")
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--populated", type=int, default=0, help="OS 디스크 실사용 바이트(선택)")
    ap.add_argument("--hw", default="vmx-17", help="가상 하드웨어 버전(기본 vmx-17 = ESXi 7.0 이상)")
    ap.add_argument("--no-ova", action="store_true")
    o = ap.parse_args()
    o.out.mkdir(parents=True, exist_ok=True)
    base = f"{o.name}-{o.version}"
    ovf = o.out / f"{base}.ovf"
    mf = o.out / f"{base}.mf"
    vmdk = o.vmdk.resolve()
    if vmdk.parent != o.out.resolve():
        raise SystemExit("--vmdk 는 --out 폴더 안에 있어야 합니다(OVF 상대 경로)")
    ovf.write_text(build_ovf(o.name, o.version, vmdk, o.populated or None, o.hw), encoding="utf-8")
    mf.write_text(f"SHA256({ovf.name})= {sha256(ovf)}\nSHA256({vmdk.name})= {sha256(vmdk)}\n", encoding="utf-8")
    print(f"OVF {ovf} · MF {mf}")
    if not o.no_ova:
        ova = o.out / f"{base}.ova"
        with tarfile.open(ova, "w", format=tarfile.USTAR_FORMAT) as t:   # OVF 1.0: ovf 가 첫 항목
            for f in (ovf, mf, vmdk):
                ti = t.gettarinfo(str(f), arcname=f.name)
                ti.uid = ti.gid = 64
                ti.uname = ti.gname = "someone"
                ti.mode = 0o644
                with f.open("rb") as fh:
                    t.addfile(ti, fh)
        print(f"OVA {ova} ({os.path.getsize(ova) / 2**20:.0f} MiB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
