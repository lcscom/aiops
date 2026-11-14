"""vCenter 인프라 상세 점검 — Compute · Storage · Network · Hardware(드라이버·펌웨어) 규칙.

입력은 vCenter 커넥터가 PropertyCollector 로 모은 순수 dict 스냅숏(vim 객체 없음)이라 단위 시험이 쉽다.
수집 항목(모두 읽기 전용 권한 System.Read 로 조회 가능):
  HostSystem  hardware.systemInfo · hardware.biosInfo · hardware.pciDevice · summary.hardware · config.product
              config.network(pnic·vswitch·proxySwitch·vnic·portgroup) · config.virtualNicManagerInfo.netConfig
              config.storageDevice(hostBusAdapter·scsiLun·multipathInfo) · config.dateTimeInfo · config.service
              config.lockdownMode · runtime.healthSystemRuntime · configIssue · runtime.bootTime
              PhysicalNic.driverVersion/firmwareVersion(vSphere 8.0U1+) · HostBusAdapter.driverVersion/firmwareVersion(9.1+)
              그 이전 버전은 HostImageConfigManager.FetchSoftwarePackages(VIB 이름·버전)로 드라이버 버전을 보완
  Cluster     configurationEx(das·drs·vsan) · summary.currentEVCModeKey
  Datastore   summary(capacity·freeSpace·uncommitted·accessible·maintenanceMode) · host
  VM          snapshot · runtime.consolidationNeeded · config.hardware.numCPU · runtime.powerState
  BMC(선택)   같은 서버의 Redfish/CIMC 커넥터 펌웨어 인벤토리(esxi_host 로 연결)
HCL(호환성 목록) 대조는 하지 않는다 — vLCM 하드웨어 호환성 보고서가 있으면 그 결과를 함께 보여 준다.
"""
from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from typing import Any

SEV_ORDER = ["info", "warning", "error", "critical"]
AREAS = {"compute": "Compute", "storage": "Storage", "network": "Network", "hardware": "Hardware", "security": "보안·구성"}

DEFAULTS = {
    "ds_warn": 80, "ds_error": 90, "ds_critical": 95,          # 데이터스토어 사용률(%)
    "overprov_warn": 150,                                       # (사용+미할당 씬)/용량 %
    "snap_age_days": 3, "snap_count": 3,                        # 스냅숏 보관 기간·개수
    "vcpu_ratio_warn": 4.0, "vcpu_ratio_error": 8.0,            # 클러스터 vCPU : 물리 코어
    "mem_warn": 85, "mem_error": 95,                            # 호스트 메모리 사용률(%)
    "uptime_days": 365,                                         # 재부팅(패치) 없이 가동 일수
    "ssh_is_finding": True, "lockdown_is_finding": True,
}


def _norm_drv(s: str) -> str:
    return re.sub(r"[-_]", "", str(s or "").lower())


def driver_version(drv: str, explicit: str, vibs: dict[str, str]) -> str:
    """vSphere 8.0U1+ 는 PhysicalNic.driverVersion, 이전은 VIB 버전(드라이버 모듈 nmlx5_core ↔ VIB nmlx5-core)."""
    if explicit:
        return str(explicit)
    if not drv or not vibs:
        return ""
    n = _norm_drv(drv)
    for name, ver in vibs.items():
        if _norm_drv(name) == n:
            return ver
    for name, ver in vibs.items():                               # nmlx5_core → nmlx5-core / qedentv → qedentv-ens 등
        nn = _norm_drv(name)
        if (nn.startswith(n) or n.startswith(nn)) and min(len(n), len(nn)) >= 4:
            return ver
    return ""


class _F:
    def __init__(self):
        self.items: list[dict[str, Any]] = []

    def add(self, cid: str, area: str, sev: str, entity: str, title: str, detail: str = "", fix: str = "", **kw):
        self.items.append({"id": cid, "area": area, "severity": sev, "entity": entity, "title": title,
                           "detail": detail, "fix": fix, **kw})


def _drift(f: _F, cid: str, area: str, scope: str, values: dict[str, str], what: str, fix: str, sev: str = "warning"):
    """같은 범위(클러스터·동일 모델) 안에서 값이 여러 개면 드리프트. values: 호스트 → 값"""
    vals = {h: v for h, v in values.items() if v}
    c = Counter(vals.values())
    if len(c) <= 1:
        return
    major = c.most_common(1)[0][0]
    odd = sorted(h for h, v in vals.items() if v != major)
    f.add(cid, area, sev, scope, f"{what} 불일치 ({len(c)}종)",
          " · ".join(f"{v} × {n}" for v, n in c.most_common()) + f" — 다수와 다른 호스트: {', '.join(odd[:8])}{' …' if len(odd) > 8 else ''}",
          fix, versions=dict(c), outliers=odd)


def evaluate(snap: dict[str, Any], th: dict[str, Any] | None = None, now: float | None = None) -> dict[str, Any]:
    th = {**DEFAULTS, **(th or {})}
    now = now or time.time()
    f = _F()
    hosts: dict[str, dict] = snap.get("hosts", {})
    clusters: dict[str, dict] = snap.get("clusters", {})
    bmc: dict[str, dict] = snap.get("bmc", {})

    # ------------------------------------------------------------ Compute (호스트)
    for hn, h in hosts.items():
        if h.get("conn") and h["conn"] != "connected":
            f.add("C01", "compute", "critical", hn, f"호스트 연결 상태 {h['conn']}", f"클러스터 {h.get('cluster') or '-'}",
                  "관리망·hostd/vpxa 상태 확인, 필요 시 vCenter 에서 다시 연결")
            continue
        if h.get("maintenance"):
            f.add("C02", "compute", "info", hn, "유지보수 모드", "HA·DRS 대상에서 제외된 상태", "작업 종료 후 유지보수 모드 해제")
        mem, used = h.get("mem_mb") or 0, h.get("mem_used_mb") or 0
        if mem:
            p = used / mem * 100
            if p >= th["mem_error"]:
                f.add("C08", "compute", "error", hn, f"메모리 사용률 {p:.0f}%", f"{used / 1024:.0f} / {mem / 1024:.0f} GB", "VM 재배치·증설 검토")
            elif p >= th["mem_warn"]:
                f.add("C08", "compute", "warning", hn, f"메모리 사용률 {p:.0f}%", f"{used / 1024:.0f} / {mem / 1024:.0f} GB", "DRS 균형·증설 검토")
        bt = h.get("boot_time") or 0
        if bt and (now - bt) / 86400 > th["uptime_days"]:
            f.add("C12", "compute", "info", hn, f"{(now - bt) / 86400:.0f}일 동안 재부팅 없음", f"ESXi {h.get('version', '')} build {h.get('build', '')}",
                  "보안 패치 적용 주기 확인(재부팅 필요 패치 누락 가능)")
        if h.get("ht_available") and h.get("ht_active") is False:
            f.add("C13", "compute", "info", hn, "하이퍼스레딩 비활성", "", "보안 정책(L1TF 등)으로 끈 것이 아니면 활성화 검토")
        for msg in h.get("config_issues", [])[:5]:
            f.add("C15", "compute", "warning", hn, "호스트 구성 경고", msg, "vCenter › 호스트 › 요약의 구성 문제 확인")
        if not h.get("ntp_servers"):
            f.add("C09", "compute", "warning", hn, "NTP 서버 미설정", "", "호스트 › 구성 › 시간 구성에서 NTP 지정(로그 상관분석·인증에 필수)")
        elif h.get("services", {}).get("ntpd") is False:
            f.add("C09", "compute", "warning", hn, "NTP 서비스 중지", ", ".join(h["ntp_servers"][:3]), "ntpd 서비스 시작·정책 '호스트와 함께 시작'")
        sv = h.get("services", {})
        if th["ssh_is_finding"] and (sv.get("TSM-SSH") or sv.get("TSM")):
            on = [n for n in ("TSM-SSH", "TSM") if sv.get(n)]
            f.add("C10", "security", "warning", hn, f"{' · '.join('SSH' if n == 'TSM-SSH' else 'ESXi Shell' for n in on)} 실행 중", "",
                  "작업 후 중지 — 보안 가이드(SCG)는 기본 중지 권고")
        if th["lockdown_is_finding"] and h.get("lockdown") in ("lockdownDisabled",):
            f.add("C11", "security", "info", hn, "잠금 모드(Lockdown) 해제", "", "금융권 보안 기준에 따라 Normal 잠금 모드 검토")

    # ------------------------------------------------------------ Compute (클러스터)
    by_cluster: dict[str, list[str]] = defaultdict(list)
    for hn, h in hosts.items():
        by_cluster[h.get("cluster") or "(standalone)"].append(hn)
    for cn, hl in by_cluster.items():
        if cn == "(standalone)":
            continue
        c = clusters.get(cn, {})
        live = [h for h in hl if hosts[h].get("conn") == "connected" and not hosts[h].get("maintenance")]
        if len(hl) >= 2 and c and not c.get("ha"):
            f.add("C03", "compute", "error", cn, "vSphere HA 비활성", f"호스트 {len(hl)}대", "HA 활성화(호스트 장애 시 VM 자동 재시작)")
        elif c.get("ha") and not c.get("ha_admission"):
            f.add("C03", "compute", "warning", cn, "HA 승인 제어(Admission Control) 꺼짐", "장애 시 재시작 자원 미보장", "승인 제어 활성화(호스트 장애 허용 1 이상)")
        if c and len(hl) >= 2 and not c.get("drs"):
            f.add("C04", "compute", "warning", cn, "DRS 비활성", "", "DRS 활성화(완전 자동화 권장)")
        elif c.get("drs") and c.get("drs_behavior") and c["drs_behavior"] != "fullyAutomated":
            f.add("C04", "compute", "info", cn, f"DRS 자동화 수준 {c['drs_behavior']}", "", "완전 자동화 검토")
        _drift(f, "C05", "compute", cn, {h: f"{hosts[h].get('version', '')} ({hosts[h].get('build', '')})" for h in hl if hosts[h].get("build")},
               "ESXi 버전·빌드", "vLCM 이미지로 클러스터 단일 빌드 유지")
        cpus = {h: hosts[h].get("cpu_model", "") for h in hl}
        if len({v for v in cpus.values() if v}) > 1 and not c.get("evc"):
            _drift(f, "C06", "compute", cn, cpus, "CPU 모델(EVC 미설정)", "EVC 모드 설정 — 미설정 시 vMotion 실패 가능", sev="error")
        cores = sum(hosts[h].get("cores") or 0 for h in live)
        vcpu = sum(hosts[h].get("vcpus") or 0 for h in live)
        if cores and vcpu:
            r = vcpu / cores
            if r >= th["vcpu_ratio_error"]:
                f.add("C07", "compute", "error", cn, f"vCPU 과할당 {r:.1f}:1", f"vCPU {vcpu} / 물리 코어 {cores}", "CPU ready 확인 후 VM 크기 조정·증설", ratio=round(r, 2))
            elif r >= th["vcpu_ratio_warn"]:
                f.add("C07", "compute", "warning", cn, f"vCPU 과할당 {r:.1f}:1", f"vCPU {vcpu} / 물리 코어 {cores}", "성능 SLI(CPU ready)와 함께 확인", ratio=round(r, 2))
        mems = [(hosts[h].get("mem_mb") or 0, hosts[h].get("mem_used_mb") or 0) for h in live]
        if len(mems) >= 2:
            tot, used, big = sum(m for m, _ in mems), sum(u for _, u in mems), max(m for m, _ in mems)
            if tot - big and used > (tot - big) * 0.95:
                f.add("C08", "compute", "error", cn, "호스트 1대 장애 시 메모리 부족",
                      f"사용 {used / 1024:.0f} GB > 1대 제외 용량 {(tot - big) / 1024:.0f} GB의 95%", "증설 또는 VM 정리(N+1 여유 확보)")

    # ------------------------------------------------------------ Storage
    for dn, d in snap.get("datastores", {}).items():
        cap, free = d.get("capacity") or 0, d.get("free") or 0
        if d.get("accessible") is False:
            f.add("S03", "storage", "critical", dn, "데이터스토어 접근 불가", f"유형 {d.get('type', '')}", "스토리지 경로·LUN 마스킹·NFS 서버 확인")
            continue
        if cap:
            used = (cap - free) / cap * 100
            sev = "critical" if used >= th["ds_critical"] else "error" if used >= th["ds_error"] else "warning" if used >= th["ds_warn"] else ""
            if sev:
                f.add("S01", "storage", sev, dn, f"사용률 {used:.0f}%", f"여유 {free / 2**30:.0f} GB / {cap / 2**30:.0f} GB", "스냅숏·미사용 VM 정리 또는 확장", pct=round(used, 1))
            unc = d.get("uncommitted") or 0
            prov = (cap - free + unc) / cap * 100
            if unc and prov >= th["overprov_warn"]:
                f.add("S02", "storage", "warning", dn, f"씬 프로비저닝 과할당 {prov:.0f}%", f"미할당 {unc / 2**30:.0f} GB", "씬 디스크가 모두 차면 공간 고갈 — 용량 계획 필요", pct=round(prov, 1))
        if d.get("maintenance") and d["maintenance"] != "normal":
            f.add("S03", "storage", "info", dn, f"데이터스토어 유지보수 {d['maintenance']}", "", "")
    # 클러스터 공유 데이터스토어가 일부 호스트에만 마운트
    for cn, hl in by_cluster.items():
        if cn == "(standalone)" or len(hl) < 2:
            continue
        hs = set(hl)
        for dn, d in snap.get("datastores", {}).items():
            if d.get("local"):
                continue
            on = hs & set(d.get("hosts", []))
            if 1 < len(on) < len(hs) or (len(on) == 1 and len(hs) > 2 and d.get("type") in ("VMFS", "NFS", "NFS41", "vsan", "VVOL")):
                if len(on) >= len(hs) / 2:
                    miss = sorted(hs - on)
                    f.add("S07", "storage", "warning", f"{cn}/{dn}", "일부 호스트에 미마운트", f"없음: {', '.join(miss[:6])}",
                          "HA 재시작·vMotion 대상 제한 — 모든 호스트에 마운트")
    for hn, h in hosts.items():
        p = h.get("paths") or {}
        if p.get("dead"):
            f.add("S04", "storage", "error", hn, f"스토리지 경로 dead {p['dead']}개", ", ".join(p.get("dead_luns", [])[:5]), "HBA·스위치 포트·케이블·어레이 포트 확인")
        if p.get("single"):
            f.add("S04", "storage", "warning", hn, f"단일 경로 LUN {len(p['single'])}개", ", ".join(p["single"][:5]), "멀티패스(2개 이상 경로) 구성")
        for a in h.get("hbas", []):
            if a.get("status") and a["status"].lower() not in ("online", "unknown", "unbound"):
                f.add("S08", "storage", "error", f"{hn}/{a.get('device')}", f"HBA 상태 {a['status']}", f"{a.get('model', '')} · {a.get('driver', '')}", "HBA 링크·드라이버 확인")
    for v in snap.get("vms", []):
        snaps = v.get("snapshots") or []
        if snaps:
            oldest = min(s.get("created") or now for s in snaps)
            age = (now - oldest) / 86400
            if age >= th["snap_age_days"] or len(snaps) >= th["snap_count"]:
                f.add("S05", "storage", "warning" if age < 14 else "error", v["name"], f"스냅숏 {len(snaps)}개 · 가장 오래된 것 {age:.0f}일",
                      ", ".join(s.get("name", "") for s in snaps[:3]), "백업 후 삭제(장기 스냅숏은 성능 저하·공간 증가)", age_days=round(age, 1))
        if v.get("consolidation"):
            f.add("S06", "storage", "warning", v["name"], "디스크 통합 필요", "", "VM › 스냅숏 › 통합 실행")

    # ------------------------------------------------------------ Network
    for hn, h in hosts.items():
        nics = {n["device"]: n for n in h.get("nics", [])}
        for sw in h.get("vswitches", []):
            ups = [nics[u] for u in sw.get("uplinks", []) if u in nics]
            up_live = [n for n in ups if n.get("speed")]
            for n in ups:
                if not n.get("speed"):
                    f.add("N01", "network", "error", f"{hn}/{n['device']}", f"업링크 링크 다운 ({sw['name']})", f"{n.get('driver', '')} {n.get('mac', '')}", "케이블·스위치 포트·SFP 확인")
                elif n.get("duplex") is False:
                    f.add("N05", "network", "warning", f"{hn}/{n['device']}", "Half duplex", f"{n['speed']} Mb/s", "스위치 포트 속도·duplex 설정 확인")
            if ups and len(up_live) < 2:
                f.add("N02", "network", "warning" if up_live else "critical", f"{hn}/{sw['name']}",
                      f"업링크 이중화 없음 (정상 {len(up_live)}/{len(ups)})", ", ".join(n["device"] for n in ups), "업링크 2개 이상(서로 다른 스위치) 구성")
            speeds = {n["speed"] for n in up_live}
            if len(speeds) > 1:
                f.add("N04", "network", "warning", f"{hn}/{sw['name']}", "업링크 속도 불일치", ", ".join(f"{n['device']} {n['speed']}" for n in up_live), "같은 팀의 업링크는 같은 속도로")
            for vmk in [k for k in h.get("vmks", []) if k.get("switch") == sw["name"]]:
                if sw.get("mtu") and vmk.get("mtu") and vmk["mtu"] > sw["mtu"]:
                    f.add("N03", "network", "error", f"{hn}/{vmk['device']}", f"MTU 불일치 vmk {vmk['mtu']} > 스위치 {sw['mtu']}", ", ".join(vmk.get("services", [])),
                          "스위치 MTU 를 vmk 이상으로(물리 스위치 포함 종단 간 일치)")
    # 같은 서비스 vmk 의 MTU 가 클러스터 안에서 다름(vMotion·vSAN·NFS 등)
    for cn, hl in by_cluster.items():
        svc_mtu: dict[str, dict[str, str]] = defaultdict(dict)
        for hn in hl:
            for k in hosts[hn].get("vmks", []):
                for s in k.get("services", []):
                    if s in ("vmotion", "vsan", "vSphereReplication", "nvmeTcp", "vsanWitness") and k.get("mtu"):
                        svc_mtu[s][hn] = str(k["mtu"])
        for s, vals in svc_mtu.items():
            _drift(f, "N03", "network", f"{cn}/{s}", vals, f"{s} vmk MTU", "같은 용도 vmk 는 클러스터 전체 동일 MTU")

    # ------------------------------------------------------------ Hardware
    for hn, h in hosts.items():
        for s in h.get("sensors", []):
            st = str(s.get("state", "")).lower()
            if st in ("red", "yellow"):
                f.add("H01", "hardware", "critical" if st == "red" else "warning", hn, f"센서 {s.get('name', '')} = {st}",
                      f"{s.get('type', '')} {s.get('reading', '')}".strip(), "BMC(iLO·iDRAC·XCC·CIMC) 이벤트·부품 상태 확인")
        for s in h.get("hw_status", []):
            st = str(s.get("state", "")).lower()
            if st in ("red", "yellow"):
                f.add("H01", "hardware", "critical" if st == "red" else "warning", hn, f"{s.get('kind', '')} {s.get('name', '')} = {st}", "", "부품 교체·BMC 로그 확인")
    # 같은 클러스터·같은 모델 서버끼리 BIOS·드라이버·펌웨어 드리프트
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for hn, h in hosts.items():
        groups[(h.get("cluster") or "(standalone)", f"{h.get('vendor', '')} {h.get('model', '')}".strip())].append(hn)
    for (cn, model), hl in groups.items():
        if len(hl) < 2:
            continue
        scope = f"{cn} · {model}"
        _drift(f, "H02", "hardware", scope, {x: hosts[x].get("bios", "") for x in hl}, "BIOS 버전", "벤더 펌웨어 번들(HSM/vLCM)로 일괄 맞춤")
        _drift(f, "H05", "hardware", scope, {x: (bmc.get(x) or {}).get("bmc_fw", "") for x in hl}, "BMC 펌웨어", "BMC 펌웨어 일괄 업데이트")
        drv: dict[str, dict[str, str]] = defaultdict(dict)
        fw: dict[str, dict[str, str]] = defaultdict(dict)
        for x in hl:
            for n in hosts[x].get("nics", []) + hosts[x].get("hbas", []):
                key = n.get("driver") or ""
                if not key:
                    continue
                if n.get("driver_version"):
                    drv[key][x] = n["driver_version"]
                if n.get("firmware"):
                    fw[f"{key} ({n.get('model') or n.get('pci_name') or ''})".replace(" ()", "")][x] = n["firmware"]
            for c in (bmc.get(x) or {}).get("firmware", []):
                nm = re.sub(r"\s*\d+$", "", str(c.get("name", "")))            # 'PCIe Slot 1' 류 번호 제거 → 같은 부품군
                if nm and c.get("version"):
                    fw[f"BMC:{nm}"].setdefault(x, c["version"])
        for k, vals in drv.items():
            _drift(f, "H03", "hardware", scope, vals, f"드라이버 {k}", "vLCM 이미지(벤더 애드온·드라이버 컴포넌트)로 통일")
        for k, vals in fw.items():
            _drift(f, "H04", "hardware", scope, vals, f"펌웨어 {k}", "드라이버-펌웨어 조합은 VCG(호환성 가이드)로 확인 후 일괄 적용")
    for cn, rep in (snap.get("hcl") or {}).items():
        st = str(rep.get("status", "")).upper()
        if st in ("INCOMPATIBLE", "HCL_DATA_UNAVAILABLE", "UNAVAILABLE", "NON_COMPLIANT"):
            f.add("H06", "hardware", "error" if st in ("INCOMPATIBLE", "NON_COMPLIANT") else "info", cn, f"vLCM 호환성/규정 준수 {st}",
                  rep.get("detail", ""), "vSphere Client › 클러스터 › 업데이트 › 하드웨어 호환성 확인")

    items = sorted(f.items, key=lambda x: (-SEV_ORDER.index(x["severity"]), x["area"], x["id"], x["entity"]))
    summ: dict[str, dict[str, int]] = {a: {s: 0 for s in SEV_ORDER} for a in AREAS}
    for x in items:
        summ[x["area"]][x["severity"]] += 1
    return {"findings": items, "summary": summ, "hosts": len(hosts), "clusters": len([c for c in by_cluster if c != "(standalone)"]),
            "datastores": len(snap.get("datastores", {})), "evaluated": now}


def hw_table(snap: dict[str, Any]) -> list[dict[str, Any]]:
    """호스트별 하드웨어·드라이버·펌웨어 표(화면·CSV)"""
    out = []
    bmc = snap.get("bmc", {})
    for hn, h in sorted(snap.get("hosts", {}).items()):
        b = bmc.get(hn) or {}
        out.append({"host": hn, "cluster": h.get("cluster", ""), "vendor": h.get("vendor", ""), "model": h.get("model", ""),
                    "serial": h.get("serial", ""), "cpu": h.get("cpu_model", ""), "cores": h.get("cores"),
                    "mem_gb": round((h.get("mem_mb") or 0) / 1024), "esxi": f"{h.get('version', '')} ({h.get('build', '')})",
                    "bios": h.get("bios", ""), "bios_date": h.get("bios_date", ""), "bmc": b.get("connector", ""),
                    "bmc_fw": b.get("bmc_fw", ""), "bmc_health": b.get("health", ""),
                    "nics": [{k: n.get(k) for k in ("device", "driver", "driver_version", "firmware", "speed", "pci_name")} for n in h.get("nics", [])],
                    "hbas": [{k: a.get(k) for k in ("device", "model", "driver", "driver_version", "firmware", "status")} for a in h.get("hbas", [])],
                    "sensors_bad": sum(1 for s in h.get("sensors", []) if str(s.get("state", "")).lower() in ("red", "yellow"))})
    return out
