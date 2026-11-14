"""RVTools 분석 — 요약 통계·용량·RVTools 전용 점검·VCF 9 준비도·물리/논리/스토리지 구성도

전체 컴플라이언스 = ① 인프라 상세 점검(vcheck, 기존 규칙) ② KISA 하이퍼바이저 보안(assess.hardening, 기존 규칙 — RVTools 로 안 보이는 항목은 '현장 확인')
                  ③ VMSA 빌드 판정(보안 판독의 권고 DB 가 있을 때) ④ RVTools 전용 점검(RV-*) ⑤ VCF 9 준비도(VCF-*) ⑥ RVTools vHealth 메시지
근거(1차 출처): CPU — Broadcom KB 428874 + BCG CPU Series(하드웨어 준비도와 같은 규칙), legacy BIOS — KB 313152(게스트 펌웨어 아님, 참고),
업그레이드 경로 — KB 418259(상호운용성 매트릭스), 빌드 출시일 역행 금지 — KB 457561.
"""
from __future__ import annotations

import re
import time
from collections import Counter, defaultdict

from .. import stack, vcheck
from ..readiness import rules as R
from . import model as Mdl

SEV_ORDER = ["critical", "error", "warning", "info"]
SEV_KO = {"critical": "위험", "error": "오류", "warning": "경고", "info": "정보"}
KB = {"cpu": "https://knowledge.broadcom.com/external/article/428874", "upgrade": "https://knowledge.broadcom.com/external/article/418259",
      "backdate": "https://knowledge.broadcom.com/external/article/457561"}
# 게스트 OS 지원 종료(제조사 공지 기준 — 연장 지원 계약 여부는 고객 확인)
OS_EOL = [(r"windows server 2003|windows xp|windows 2000", "2015-07-14"), (r"windows server 2008", "2020-01-14"),
          (r"windows server 2012", "2023-10-10"), (r"windows 7\b", "2020-01-14"), (r"centos 6", "2020-11-30"), (r"centos 7", "2024-06-30"),
          (r"centos 8|centos linux 8", "2021-12-31"), (r"red hat enterprise linux 6", "2020-11-30"), (r"red hat enterprise linux 7", "2024-06-30"),
          (r"suse linux enterprise 11", "2019-03-31"), (r"ubuntu.*(14\.04|16\.04)", "2021-04-30"), (r"ubuntu.*18\.04", "2023-05-31"),
          (r"windows server 2016", "2027-01-12")]


class F:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, cid, area, sev, entity, title, detail="", fix="", ref="", **kw):
        self.items.append({"id": cid, "area": area, "severity": sev, "entity": entity, "title": title, "detail": detail, "fix": fix, "ref": ref, **kw})


def _gb(mib) -> float:
    return round((mib or 0) / 1024, 1)


def _list(xs: list[str], k: int = 12) -> str:
    return ", ".join(xs[:k]) + (f" 외 {len(xs) - k}" if len(xs) > k else "")


# ------------------------------------------------------------------------------------------------ RVTools 전용 점검
def rv_checks(inv: dict, now: float) -> list[dict]:
    f = F()
    vms = [v for v in inv["vms"].values() if not v["template"]]
    on = [v for v in vms if v["power"] == "poweredOn"]
    # Tools
    nt = [v["name"] for v in on if v["tools"] == "toolsNotInstalled"]
    nr = [v["name"] for v in on if v["tools"] == "toolsNotRunning"]
    old = [v["name"] for v in on if v["tools"] == "toolsOld" or v["tools_upgradeable"]]
    if nt:
        f.add("RV-01", "vm", "warning", f"VM {len(nt)}대", "켜진 VM 에 VMware Tools 미설치", _list(nt), "open-vm-tools/VMware Tools 설치 — 정상 종료·IP 표시·백업 정지점·시간 동기화에 필요")
    if nr:
        f.add("RV-02", "vm", "warning", f"VM {len(nr)}대", "VMware Tools 실행 안 됨", _list(nr), "게스트에서 vmtoolsd 서비스 확인")
    if old:
        f.add("RV-03", "vm", "info", f"VM {len(old)}대", "VMware Tools 업그레이드 가능", _list(old), "유지보수 창에 Tools 업그레이드(vLCM/게스트 패키지)")
    # 가상 하드웨어
    hw = Counter(v["hw"] for v in vms if v["hw"])
    low = [v["name"] for v in vms if (n := re.search(r"(\d+)", v["hw"] or "")) and int(n.group(1)) < 14]
    if low:
        f.add("RV-04", "vm", "info", f"VM {len(low)}대", "가상 하드웨어 버전 14 미만", _list(low) + " · 분포 " + ", ".join(f"{k}×{c}" for k, c in sorted(hw.items())),
              "호환성 확인 후 HW 버전 업그레이드(가상 TPM·최신 CPU 기능 등은 높은 버전 필요)")
    # CD-ROM 연결
    cd = sorted({c["vm"] for c in inv["cds"] if c["connected"]})
    if cd:
        f.add("RV-05", "vm", "warning", f"VM {len(cd)}대", "CD/DVD 연결됨", _list(cd), "사용 후 연결 해제 — 연결된 ISO/호스트 장치는 vMotion·DRS 를 막을 수 있음")
    # 스냅숏 나이·개수는 인프라 점검 S05(기존 규칙)가 판단 — 중복 없음
    # 게스트 파티션
    for p in inv["partitions"]:
        if p["free_pct"] is not None and p["cap_mib"] and p["cap_mib"] > 1024 and p["free_pct"] < 10:
            f.add("RV-07", "vm", "error" if p["free_pct"] < 5 else "warning", f"{p['vm']} {p['disk']}", f"게스트 디스크 여유 {p['free_pct']}%",
                  f"{_gb(p['free_mib'])} / {_gb(p['cap_mib'])} GB", "게스트 정리 또는 디스크 확장")
    # CPU ready·메모리 경합·제한
    for v in on:
        if (v["cpu_ready"] or 0) >= 10:
            f.add("RV-08", "vm", "error" if v["cpu_ready"] >= 20 else "warning", v["name"], f"CPU 준비 대기 {v['cpu_ready']}%", f"vCPU {v['vcpu']} · 호스트 {v['host']}",
                  "vCPU 수 축소·호스트 과할당 완화(RVTools 'Overall Cpu Readiness')")
        if (v["ballooned"] or 0) > 0 or (v["swapped"] or 0) > 0:
            f.add("RV-09", "vm", "warning", v["name"], "메모리 회수(벌룬·스왑) 발생", f"벌룬 {v['ballooned']} MB · 스왑 {v['swapped']} MB", "호스트 메모리 여유·VM 제한(Limit) 확인")
        lim = [x for x, val in (("CPU", v["cpu_limit"]), ("메모리", v["mem_limit"])) if val not in (None, -1, 0)]
        if lim:
            f.add("RV-10", "vm", "warning", v["name"], f"{'·'.join(lim)} 제한(Limit) 설정", f"CPU {v['cpu_limit']} MHz · 메모리 {v['mem_limit']} MB",
                  "의도하지 않은 제한은 성능 저하 — 해제 검토")
    hot = [v["name"] for v in on if v["cpu_hotadd"] and (v["vcpu"] or 0) > 8]
    if hot:
        f.add("RV-11", "vm", "info", f"VM {len(hot)}대", "CPU 핫애드 켜짐(vCPU 9개 이상)", _list(hot), "CPU 핫애드는 vNUMA 를 끔 — 대형 VM 은 해제 검토")
    if any(v["consolidation"] for v in vms):
        cs = [v["name"] for v in vms if v["consolidation"]]
        f.add("RV-12", "storage", "warning", f"VM {len(cs)}대", "디스크 통합 필요", _list(cs), "VM › 스냅숏 › 통합")
    # 게스트 OS 지원 종료
    eol: dict[str, list[str]] = defaultdict(list)
    for v in vms:
        os_ = (v["os_tools"] or v["os_cfg"]).lower()
        for rx, d in OS_EOL:
            if re.search(rx, os_):
                eol[f"{v['os_tools'] or v['os_cfg']}|{d}"].append(v["name"])
                break
    for k, names in eol.items():
        osn, d = k.split("|")
        past = time.strftime("%Y-%m-%d", time.localtime(now)) >= d
        f.add("RV-13", "vm", "warning" if past else "info", f"VM {len(names)}대", f"게스트 OS {'지원 종료' if past else '지원 종료 예정'}: {osn}", f"종료일 {d} · {_list(names, 8)}",
              "OS 업그레이드·연장 지원(ESU/ELS) 계약 확인")
    # 꺼진 VM·템플릿·좀비 파일
    off = [v for v in vms if v["power"] != "poweredOn"]
    if off:
        f.add("RV-14", "capacity", "info", f"VM {len(off)}대", "꺼진 VM", f"할당 디스크 {sum(_gb(v['prov_mib']) for v in off):,.0f} GB · " + _list([v["name"] for v in off], 8),
              "소유자 확인 후 정리(용량 회수)")
    zombie = [h for h in inv["health"] if h["type"].lower() == "zombie"]
    if zombie:
        f.add("RV-15", "storage", "warning", f"파일 {len(zombie)}개", "좀비 VMDK 의심(어느 VM 에도 연결 안 된 디스크 파일)", _list([z["name"] for z in zombie], 6),
              "백업·SRM·복제 대상인지 확인 후 정리 — RVTools vHealth 기준이며 실제 삭제 전 검증 필수")
    # 호스트·클러스터
    for hn, h in inv["hosts"].items():
        if h["cert_expiry"] and h["cert_expiry"] - now < 90 * 86400:
            d = (h["cert_expiry"] - now) / 86400
            f.add("RV-20", "security", "error" if d < 30 else "warning", hn, f"ESXi 인증서 {'만료' if d < 0 else f'{d:.0f}일 후 만료'}", h["cert_issuer"], "인증서 갱신(vCenter › 호스트 › 인증서)")
        if h["power_policy"] and not re.search(r"high|static", h["power_policy"], re.IGNORECASE):
            f.add("RV-21", "compute", "info", hn, f"호스트 전원 정책 '{h['power_policy']}'", "", "지연 민감 업무는 '고성능' 검토(BIOS 는 OS 제어)")
        if h["evc"] and h["max_evc"] and h["evc"] != h["max_evc"]:
            f.add("RV-22", "compute", "info", hn, f"EVC {h['evc']} < 지원 최대 {h['max_evc']}", h["cluster"], "모든 호스트가 지원하면 EVC 상향 검토")
        if h["vcpu_per_core"] and h["vcpu_per_core"] >= 6:
            f.add("RV-23", "compute", "warning", hn, f"코어당 vCPU {h['vcpu_per_core']}", f"vCPU {h['vcpus']} / 코어 {h['cores']}", "CPU 준비 대기와 함께 확인")
    for p in inv["paths"]:
        if p["policy"] and p["policy"] not in ("VMW_PSP_RR",) and p["paths"] > 1:
            f.add("RV-24", "storage", "info", f"{p['host']}/{p['datastore'] or p['disk']}", f"경로 정책 {p['policy']}", f"경로 {p['paths']}개", "어레이 권장 정책(대개 Round Robin) 확인")
    used = {(p["host"], hb) for p in inv["paths"] for hb in p["hbas"]}
    idle = [f"{Mdl._short(a['host'])}/{a['device']}" for a in inv["hbas"] if a["type"].lower().startswith("fibre") and a["status"].lower() != "online"
            and (a["host"], a["device"]) not in used]
    if idle:                                              # 경로가 걸린 offline HBA 는 vcheck S08(오류)이 판단
        f.add("RV-19", "storage", "info", f"HBA 포트 {len(idle)}개", "경로 없는 offline FC 포트(미결선 추정)", _list(idle, 10),
              "의도된 예비 포트인지 확인 — 이중화 설계상 사용해야 하는 포트라면 결선·존 구성 점검")
    # vmk MTU > 스위치 MTU 는 인프라 점검 N03(기존 규칙)이 판단
    for d in inv["dvswitches"].values():
        if d["discovery"] and str(d["discovery_op"]).lower() in ("none", "") or not d["discovery"]:
            f.add("RV-26", "network", "info", d["name"], "VDS 이웃 탐색(LLDP/CDP) 미사용", f"{d['discovery'] or '-'} {d['discovery_op'] or ''}".strip(),
                  "LLDP 송·수신(both) — 물리 스위치 포트 추적·장애 분석에 필요")
    # 라이선스
    for l in inv["licenses"]:
        if l["expires"] and l["expires"] - now < 120 * 86400:
            d = (l["expires"] - now) / 86400
            f.add("RV-27", "license", "error" if d < 30 else "warning", l["name"], f"라이선스 {'만료' if d < 0 else f'{d:.0f}일 후 만료'}", f"사용 {l['used']} / {l['total']} {l['unit']}",
                  "갱신·VCF 9 라이선스 전환 일정 확인")
        if l["expires_raw"].lower() == "never" and "eval" in l["name"].lower():
            f.add("RV-27", "license", "warning", l["name"], "평가판 라이선스", "", "정식 라이선스 지정")
    # vHealth 기타(RVTools 판단 그대로 — 정보)
    other = Counter(h["type"] for h in inv["health"] if h["type"].lower() != "zombie")
    for t, c in other.items():
        sample = [h["message"] for h in inv["health"] if h["type"] == t][:3]
        f.add("RV-30", "rvtools", "info", f"{t} {c}건", f"RVTools vHealth: {t}", " | ".join(sample)[:400], "RVTools 임계값 기준 참고 메시지")
    return f.items


# ------------------------------------------------------------------------------------------------ VCF 9 준비도(호스트·VM 관점)
def vcf9(inv: dict) -> dict:
    f = F()
    hosts = []
    for hn, h in inv["hosts"].items():
        cl = R.classify_cpu(h["cpu_model"])
        speeds = [p["speed"] for p in inv["pnics"] if p["host"] == hn and p["speed"]]
        mx = max(speeds) / 1000 if speeds else None
        ver = h["version"]
        major = int(ver.split(".")[0]) if ver[:1].isdigit() else 0
        lic = (max(16, h["cores_per_cpu"] or 0) * (h["sockets"] or 0)) if h["sockets"] else max(16, h["cores"] or 0)
        rows = {"cpu": cl["status"], "nic": "pass" if (mx or 0) >= 25 else ("warn" if (mx or 0) >= 10 else ("fail" if mx else "unknown")),
                "esx": "pass" if major >= 8 else ("warn" if major == 7 else "fail")}
        verdict = "not_ready" if "fail" in (rows["cpu"], rows["esx"]) and cl["tier"] in ("eol", "not_eligible") else \
            ("actions" if any(v in ("warn", "fail") for v in rows.values()) else ("unknown" if "unknown" in rows.values() else "ready"))
        hosts.append({"host": hn, "cluster": h["cluster"], "cpu": h["cpu_model"], "cpu_family": cl["family"], "cpu_tier": cl["label"], "cpu_status": cl["status"],
                      "esx": f"{h['version']} ({h['build']})", "esx_status": rows["esx"], "nic_gbps": mx, "nic_status": rows["nic"], "cores": h["cores"],
                      "sockets": h["sockets"], "licensed_cores": lic, "vendor": h["vendor"], "model": h["model"], "verdict": verdict})
        if cl["tier"] in ("deprecated", "deprecated_override", "eol", "not_eligible", "verify"):
            f.add("VCF-01", "vcf9", {"fail": "error", "warn": "warning"}.get(cl["status"], "info"), hn, f"CPU {cl['label']}", f"{h['cpu_model']} → {cl['family']}",
                  {"deprecated": "VCF 9 에서 Deprecated Mode 로 지원 — 교체 계획 수립", "deprecated_override": "ESX 9 설치·업그레이드 시 CPU override 절차 필요(KB 428874)",
                   "eol": "ESX 9 미지원 — 서버 교체", "not_eligible": "서버 플랫폼으로 교체", "verify": "BCG 에서 확인"}.get(cl["tier"], ""), KB["cpu"])
        if major and major < 8:
            f.add("VCF-02", "vcf9", "warning", hn, f"ESXi {ver} — 9.x 로 가기 전 업그레이드 경로 확인", h["esx"],
                  "상호운용성 매트릭스의 업그레이드 경로(KB 418259)로 단계 계획, 대상 빌드가 현재 빌드보다 나중 출시인지 확인(KB 457561)", KB["upgrade"])
        if rows["nic"] in ("warn", "fail"):
            f.add("VCF-03", "vcf9", "warning" if rows["nic"] == "warn" else "error", hn, f"최대 연결 NIC {mx or '?'}Gb", f"{len(speeds)}개 연결",
                  "VCF·vSAN ESA 는 10GbE 이상, 신규는 25GbE 이상 권장")
    # 클러스터 노드 수
    for cn, c in inv["clusters"].items():
        if c["hosts"] and c["hosts"] < 3:
            f.add("VCF-04", "vcf9", "info", cn, f"호스트 {c['hosts']}대", "", "VCF 9.1 Simple 은 vSAN 3대(외부 스토리지 2대), HA 는 4대 이상")
    vc_old = [vc for vc, x in inv["vcenters"].items() if x.get("version") and int(x["version"].split(".")[0] or 0) < 8]
    for vc in vc_old:
        f.add("VCF-05", "vcf9", "warning", vc, f"vCenter {inv['vcenters'][vc]['version']}", "", "vCenter 를 먼저 지원 경로로 업그레이드(KB 418259)", KB["upgrade"])
    return {"hosts": hosts, "findings": f.items, "licensed_cores": sum(x["licensed_cores"] for x in hosts),
            "verdicts": dict(Counter(x["verdict"] for x in hosts)), "cpu_tiers": dict(Counter(x["cpu_tier"] for x in hosts))}


# ------------------------------------------------------------------------------------------------ 요약 통계·용량
def summary(inv: dict) -> dict:
    vms = [v for v in inv["vms"].values() if not v["template"]]
    on = [v for v in vms if v["power"] == "poweredOn"]
    tot_cores = sum(h["cores"] or 0 for h in inv["hosts"].values())
    tot_mem = sum(h["mem_mb"] or 0 for h in inv["hosts"].values())
    vcpu_on = sum(v["vcpu"] or 0 for v in on)
    clusters = []
    for cn, c in inv["clusters"].items():
        hs = [h for h in inv["hosts"].values() if h["cluster"] == cn]
        cv = [v for v in on if v["cluster"] == cn]
        cores = sum(h["cores"] or 0 for h in hs)
        mem = sum(h["mem_mb"] or 0 for h in hs)
        used = sum((h["mem_pct"] or 0) / 100 * (h["mem_mb"] or 0) for h in hs)
        big = max([h["mem_mb"] or 0 for h in hs] + [0])
        clusters.append({"name": cn, "hosts": len(hs), "cores": cores, "vms_on": len(cv), "vcpu": sum(v["vcpu"] or 0 for v in cv),
                         "ratio": round(sum(v["vcpu"] or 0 for v in cv) / cores, 2) if cores else None, "mem_gb": round(mem / 1024),
                         "vram_gb": round(sum(v["mem_mb"] or 0 for v in cv) / 1024), "mem_used_pct": round(used / mem * 100, 1) if mem else None,
                         "n1_mem_pct": round(used / (mem - big) * 100, 1) if mem - big > 0 else None, "ha": c["ha"], "drs": c["drs"], "drs_behavior": c["drs_behavior"],
                         "cpu_avg": round(sum(h["cpu_pct"] or 0 for h in hs) / len(hs), 1) if hs else None})
    ds_cap = sum(d["cap_mib"] for d in inv["datastores"].values())
    ds_free = sum(d["free_mib"] for d in inv["datastores"].values())
    ds_prov = sum(d["prov_mib"] for d in inv["datastores"].values())
    top = lambda key, k=10: [{"name": v["name"], "value": v[key], "power": v["power"], "host": v["host"]} for v in sorted(vms, key=lambda x: -(x[key] or 0))[:k]]
    osd = Counter(v["os_tools"] or v["os_cfg"] or "(미상)" for v in vms)
    return {"vcenters": list(inv["vcenters"].values()), "rvtools": inv["meta"], "datacenters": sorted({h["datacenter"] for h in inv["hosts"].values() if h["datacenter"]}),
            "counts": {"clusters": len(inv["clusters"]), "hosts": len(inv["hosts"]), "vms": len(vms), "vms_on": len(on), "vms_off": len(vms) - len(on),
                       "templates": sum(1 for v in inv["vms"].values() if v["template"]), "datastores": len(inv["datastores"]), "dvswitches": len(inv["dvswitches"]),
                       "portgroups": sum(1 for x in inv["networks"].values() if x.get("kind") in ("dvportgroup", "portgroup") and not x.get("uplink_pg")),
                       "snapshots": len(inv["snapshots"]), "vmks": len(inv["vmks"])},
            "compute": {"sockets": sum(h["sockets"] or 0 for h in inv["hosts"].values()), "cores": tot_cores, "mem_gb": round(tot_mem / 1024),
                        "vcpu_on": vcpu_on, "vcpu_all": sum(v["vcpu"] or 0 for v in vms), "ratio": round(vcpu_on / tot_cores, 2) if tot_cores else None,
                        "vram_on_gb": round(sum(v["mem_mb"] or 0 for v in on) / 1024), "mem_overcommit": round(sum(v["mem_mb"] or 0 for v in on) / tot_mem, 2) if tot_mem else None},
            "storage": {"cap_tb": round(ds_cap / 1024 / 1024, 2), "free_tb": round(ds_free / 1024 / 1024, 2), "prov_tb": round(ds_prov / 1024 / 1024, 2),
                        "used_pct": round((1 - ds_free / ds_cap) * 100, 1) if ds_cap else None, "vm_prov_tb": round(sum(v["prov_mib"] for v in vms) / 1024 / 1024, 2),
                        "vm_used_tb": round(sum(v["used_mib"] for v in vms) / 1024 / 1024, 2),
                        "off_prov_tb": round(sum(v["prov_mib"] for v in vms if v["power"] != "poweredOn") / 1024 / 1024, 2),
                        "snap_gb": round(sum(x["size_mib"] or 0 for x in inv["snapshots"]) / 1024, 1),
                        "types": dict(Counter(d["type"] for d in inv["datastores"].values()))},
            "clusters": clusters, "os": [{"os": k, "count": c} for k, c in osd.most_common()],
            "hw_versions": dict(sorted(Counter(v["hw"] for v in vms if v["hw"]).items())), "tools": dict(Counter(v["tools"] or "(미상)" for v in on)),
            "power": dict(Counter(v["power"] for v in vms)),
            "top": {"vcpu": top("vcpu"), "mem_mb": top("mem_mb"), "prov_mib": top("prov_mib")},
            "licenses": [{k: v for k, v in x.items() if k != "key"} for x in inv["licenses"]]}


# ------------------------------------------------------------------------------------------------ 구성도
PHYS_LAYERS = ["vCenter", "데이터센터", "클러스터", "ESXi 호스트", "물리 NIC · HBA", "가상 스위치 · 스토리지 경로", "데이터스토어 · 포트그룹"]
STOR_LAYERS = ["클러스터", "ESXi 호스트", "HBA · vmk", "데이터스토어", "VM"]


def graph_physical(inv: dict) -> dict:
    nodes: dict[str, dict] = {}
    links: list[tuple] = []

    def node(nid, layer, label, kind, state="ok", sub="", group="", **kw):
        nodes.setdefault(nid, {"id": nid, "layer": layer, "label": label, "kind": kind, "state": state, "sub": sub, "group": group, **kw})

    def link(a, b_, k=""):
        if a in nodes and b_ in nodes and a != b_:
            links.append((a, b_, k))
    for vc, x in inv["vcenters"].items():
        node(f"vc:{vc}", 0, vc, "vcenter", "ok", x.get("fullname") or f"vCenter {x.get('version', '')}")
    for hn, h in inv["hosts"].items():
        dc, cl = h["datacenter"] or "(데이터센터)", h["cluster"] or "(독립 호스트)"
        node(f"dc:{h['vcenter']}:{dc}", 1, dc, "datacenter", "ok", "데이터센터")
        link(f"vc:{h['vcenter']}", f"dc:{h['vcenter']}:{dc}")
        c = inv["clusters"].get(cl) or {}
        node(f"cl:{cl}", 2, cl, "cluster", {"red": "down", "yellow": "warn"}.get(c.get("status"), "ok"),
             f"HA {'켬' if c.get('ha') else '끔'} · DRS {'켬' if c.get('drs') else '끔'}" if c else "", group=cl)
        link(f"dc:{h['vcenter']}:{dc}", f"cl:{cl}")
        st = "maint" if h["maintenance"] else {"red": "down", "yellow": "warn"}.get(h["status"], "ok")
        node(f"host:{hn}", 3, hn, "esxi", st, f"{h['vendor']} {h['model']} · {h['sockets']}×{h['cores_per_cpu']}C · {round((h['mem_mb'] or 0) / 1024)}GB · ESXi {h['version']}",
             group=cl, cpu=h["cpu_pct"], mem=h["mem_pct"], vms=h["vms"], serial=h["serial"], bios=h["bios"], cpu_model=h["cpu_model"], esx=h["esx"])
        link(f"cl:{cl}", f"host:{hn}")
    for p in inv["pnics"]:
        nid = f"nic:{p['host']}:{p['device']}"
        if not p["switch"] and not p["speed"]:              # 결선·할당 안 된 예비 포트는 물리 구성도에서 생략(표·NIC 탭에서 확인)
            continue
        node(nid, 4, f"{Mdl._short(p['host'])} {p['device']}", "pnic", "ok" if p["speed"] else "down",
             f"{p['speed'] // 1000 if p['speed'] else 0}Gb · {p['driver']}" + (f" → {p['switch']}" if p["switch"] else " · 미사용"), group=inv["hosts"].get(p["host"], {}).get("cluster", ""))
        link(f"host:{p['host']}", nid, "pNIC")
        if p["switch"]:
            sid = f"sw:{p['switch']}" if p["switch"] in inv["dvswitches"] else f"vss:{p['host']}:{p['switch']}"
            d = inv["dvswitches"].get(p["switch"]) or {}
            node(sid, 5, p["switch"] if d else f"{Mdl._short(p['host'])} {p['switch']}", "vds" if d else "vss", "ok",
                 f"VDS {d.get('version', '')} · MTU {d.get('mtu', '')} · 호스트 {len(d.get('hosts') or [])}" if d else "표준 vSwitch")
            link(nid, sid, f"{p['speed'] // 1000 if p['speed'] else 0}G")
    used = {(p["host"], hb) for p in inv["paths"] for hb in p["hbas"]}
    for a in inv["hbas"]:
        if not a["type"].lower().startswith(("fibre", "fc", "iscsi", "nvme")):
            continue
        if a["status"].lower() != "online" and (a["host"], a["device"]) not in used:     # 경로 없는 offline 예비 포트(RV-19)는 생략
            continue
        nid = f"hba:{a['host']}:{a['device']}"
        node(nid, 4, f"{Mdl._short(a['host'])} {a['device']}", "hba", "ok" if a["status"].lower() == "online" else "down", f"{a['type']} · {a['status']} · {a['model'][:40]}",
             group=inv["hosts"].get(a["host"], {}).get("cluster", ""))
        link(f"host:{a['host']}", nid, "HBA")
    for p in inv["paths"]:
        ds = p["datastore"] or p["disk"]
        dsid = f"ds:{ds}"
        d = inv["datastores"].get(p["datastore"]) or {}
        node(dsid, 6, ds, "datastore", "ok" if d.get("accessible") is not False else "down",
             f"{d.get('type', '')} {_gb(d.get('cap_mib'))}GB · 사용 {100 - (d.get('free_pct') or 0) if d.get('free_pct') is not None else '?'}%")
        pid = f"path:{p['host']}:{ds}"
        node(pid, 5, f"{Mdl._short(p['host'])} → {ds}"[:60], "mpath", "down" if p["dead"] else ("warn" if p["paths"] < 2 else "ok"),
             f"{p['policy']} · 경로 {p['active']}/{p['paths']} · {p['vendor'].strip()} {p['model'].strip()}")
        for hb in p["hbas"]:
            link(f"hba:{p['host']}:{hb}", pid, "경로")
        link(pid, dsid)
    for dn, d in inv["datastores"].items():                 # NFS·vSAN 등 경로 정보 없는 데이터스토어
        if f"ds:{dn}" not in nodes:
            node(f"ds:{dn}", 6, dn, "datastore", "ok" if d["accessible"] is not False else "down", f"{d['type']} {_gb(d['cap_mib'])}GB · 사용 {100 - (d['free_pct'] or 0) if d['free_pct'] is not None else '?'}%")
            for hn in d["hosts"][:64]:
                link(f"host:{hn}", f"ds:{dn}", d["type"])
    pg_by: dict[str, list] = defaultdict(list)             # 포트그룹은 VDS 별 묶음 1개(개별 포트그룹은 논리 구성도)
    for nm, x in inv["networks"].items():
        if x.get("kind") == "dvportgroup" and not x.get("uplink_pg"):
            pg_by[x.get("dvs", "")].append(x)
    for dvs, xs in pg_by.items():
        if f"sw:{dvs}" in nodes:
            vl = sorted({str(x.get("vlan")) for x in xs if x.get("vlan") not in (None, "", "0")}, key=lambda v: (len(v), v))
            node(f"pgs:{dvs}", 6, f"{dvs} 포트그룹 {len(xs)}", "portgroup", "ok", f"VLAN {', '.join(vl[:12])}{' …' if len(vl) > 12 else ''} · VM 연결 {sum(x.get('vm_count', 0) for x in xs)}")
            link(f"sw:{dvs}", f"pgs:{dvs}", "")
    return _pack(nodes, links, PHYS_LAYERS)


def graph_storage(inv: dict, vm_limit: int = 200) -> dict:
    nodes: dict[str, dict] = {}
    links: list[tuple] = []

    def node(nid, layer, label, kind, state="ok", sub="", group="", **kw):
        nodes.setdefault(nid, {"id": nid, "layer": layer, "label": label, "kind": kind, "state": state, "sub": sub, "group": group, **kw})

    def link(a, b_, k=""):
        if a in nodes and b_ in nodes and a != b_:
            links.append((a, b_, k))
    for hn, h in inv["hosts"].items():
        cl = h["cluster"] or "(독립 호스트)"
        node(f"cl:{cl}", 0, cl, "cluster", "ok", "", group=cl)
        node(f"host:{hn}", 1, hn, "esxi", "ok", f"{h['vendor']} {h['model']}", group=cl)
        link(f"cl:{cl}", f"host:{hn}")
    used = {(p["host"], hb) for p in inv["paths"] for hb in p["hbas"]}
    for a in inv["hbas"]:
        if a["type"].lower().startswith(("fibre", "iscsi", "nvme")) and (a["status"].lower() == "online" or (a["host"], a["device"]) in used):
            node(f"hba:{a['host']}:{a['device']}", 2, f"{Mdl._short(a['host'])} {a['device']}", "hba", "ok" if a["status"].lower() == "online" else "down", f"{a['type']} {a['status']}")
            link(f"host:{a['host']}", f"hba:{a['host']}:{a['device']}")
    for k in inv["vmks"]:
        if any(s_ in k["services"] for s_ in ("nfs", "vsan")):
            node(f"vmk:{k['host']}:{k['device']}", 2, f"{Mdl._short(k['host'])} {k['device']}", "vmk", "ok", f"{k['portgroup']} · MTU {k['mtu']} · {k['ip']}")
            link(f"host:{k['host']}", f"vmk:{k['host']}:{k['device']}")
    for dn, d in inv["datastores"].items():
        used = 100 - d["free_pct"] if d["free_pct"] is not None else None
        node(f"ds:{dn}", 3, dn, "datastore", "down" if d["accessible"] is False else ("down" if (used or 0) >= 95 else "warn" if (used or 0) >= 85 else "ok"),
             f"{d['type']} · {_gb(d['cap_mib']):,.0f}GB · 사용 {used if used is not None else '?'}% · VM {d['vms']}", used=used)
        hb = [p for p in inv["paths"] if p["datastore"] == dn]
        if hb:
            for p in hb:
                for x in p["hbas"]:
                    link(f"hba:{p['host']}:{x}", f"ds:{dn}", p["policy"])
        else:
            vk = [k for k in inv["vmks"] if k["host"] in d["hosts"] and "nfs" in k["services"]]
            if vk and d["type"].upper().startswith("NFS"):
                for k in vk:
                    link(f"vmk:{k['host']}:{k['device']}", f"ds:{dn}", "NFS")
            else:
                for hn in d["hosts"]:
                    link(f"host:{hn}", f"ds:{dn}", d["type"])
    by_ds: dict[str, list] = defaultdict(list)
    for dk in inv["disks"]:
        m = re.match(r"\[([^\]]+)\]", dk["path"] or "")
        if m:
            by_ds[m.group(1)].append(dk["vm"])
    shown = 0
    for ds, vms in by_ds.items():
        for vm in sorted(set(vms)):
            if shown >= vm_limit:
                break
            v = inv["vms"].get(vm) or {}
            node(f"vm:{vm}", 4, vm, "vm", "ok" if v.get("power") == "poweredOn" else "maint", f"{v.get('os_tools') or v.get('os_cfg') or ''}"[:40])
            link(f"ds:{ds}", f"vm:{vm}", "VMDK")
            shown += 1
    return _pack(nodes, links, STOR_LAYERS)


def _pack(nodes: dict, links: list, layers: list[str]) -> dict:
    return {"layers": layers, "used_layers": sorted({n["layer"] for n in nodes.values()}), "nodes": list(nodes.values()),
            "links": [{"s": a, "t": b_, "k": k} for a, b_, k in links], "clusters": sorted({n["group"] for n in nodes.values() if n.get("group")})}


class _FakeVC:
    type = "vcenter"
    enabled = True

    def __init__(self, name: str, topo: dict):
        self.name, self.host, self.topology = name, name, topo

    def state(self):
        return {"state": "ok"}


def graph_logical(inv: dict, vm_limit: int = 0) -> dict:
    """기존 '물리 → 논리' 스택 구성도 로직(stack.build)을 그대로 — RVTools 로 만든 가상 vCenter 커넥터를 넣어 실행"""
    from types import SimpleNamespace
    eng = SimpleNamespace(connectors=[_FakeVC(vc, Mdl.vc_topology(inv, vc)) for vc in inv["vcenters"]], anomalies={})
    g = stack.build(eng, vm_limit=vm_limit, pod_limit=0, vms=True, pods=False)
    return {k: g[k] for k in ("layers", "used_layers", "nodes", "links", "clusters", "counts")}


# ------------------------------------------------------------------------------------------------ 전체
def analyze(inv: dict, advisories: list[dict] | None = None, now: float | None = None) -> dict:
    from .. import assess as AS
    now = now or inv["meta"].get("exported") or time.time()
    vch = vcheck.evaluate(Mdl.vcheck_snap(inv), now=now)
    vch_items = vch["findings"]                           # now = RVTools 내보낸 시각 → 가동 일수·인증서 등은 그 시점 기준
    hard_rows, targets = [], []
    for vc in inv["vcenters"]:
        hi = Mdl.hardening_inv(inv, vc)
        vcd = hi["vcenter"]
        if vcd.get("version"):
            targets.append({"product": "vcenter", "name": vc, "version": vcd["version"], "build": vcd["build"]})
        for h in hi["hosts"]:
            if h["version"]:
                targets.append({"product": "esxi", "name": h["name"], "version": h["version"], "build": h["build"]})
    cve_rows, hits = AS.evaluate(advisories or [], targets)
    for vc in inv["vcenters"]:
        hard_rows += [dict(r, vcenter=vc) for r in AS.hardening(Mdl.hardening_inv(inv, vc), hits, bool(advisories))]
    rv = rv_checks(inv, now)
    v9 = vcf9(inv)
    findings = [dict(x, source="인프라 점검") for x in vch_items] + [dict(x, source="RVTools 점검") for x in rv] + [dict(x, source="VCF 9 준비도") for x in v9["findings"]]
    findings.sort(key=lambda x: (SEV_ORDER.index(x["severity"]) if x["severity"] in SEV_ORDER else 9, x["area"], x["id"]))
    cnt = Counter(x["severity"] for x in findings)
    hc = Counter(r["status"] for r in hard_rows)
    scored = hc["PASS"] + hc["FAIL"] + hc["WARN"]
    w = {"critical": 15, "error": 6, "warning": 2, "info": 0.3}
    pen: dict[tuple, float] = defaultdict(float)
    for x in findings:                                    # 같은 점검이 여러 대상에 반복되면 감점은 점감(최대 3배)
        k = (x["id"], x["severity"])
        pen[k] = min(pen[k] + w.get(x["severity"], 0) * (1 if pen[k] == 0 else 0.25), w.get(x["severity"], 0) * 3)
    score = 100 - min(100, sum(pen.values()))
    return {"summary": summary(inv), "findings": findings, "counts": dict(cnt), "areas": {a: dict(Counter(x["severity"] for x in findings if x["area"] == a))
                                                                                         for a in sorted({x["area"] for x in findings})},
            "hardening": {"rows": hard_rows, "kisa": AS.kisa_summary(hard_rows), "counts": dict(hc), "score": round(hc["PASS"] / scored * 100, 1) if scored else None,
                          "note": "RVTools 에는 ESXi 고급 설정·서비스·방화벽·잠금 모드 정보가 없어 해당 KISA 항목은 '현장 확인(MANUAL)'으로 남습니다"},
            "vmsa": {"rows": cve_rows[:2000], "db": len(advisories or []), "vulnerable": sum(1 for r in cve_rows if r["verdict"] == "취약"),
                     "possible": sum(1 for r in cve_rows if r["verdict"] == "가능")},
            "vcf9": v9, "score": round(max(0, score), 1), "evaluated": now}


def ai_digest(inv: dict, res: dict, limit: int = 14000) -> str:
    """PAIS 에 보낼 분석 요약(JSON 문자열) — 원본 행 대신 집계와 상위 이슈만"""
    import json
    sm = res["summary"]
    d = {"환경": {"vCenter": [{"이름": x["name"], "버전": x.get("fullname") or x.get("version")} for x in sm["vcenters"]], "RVTools": sm["rvtools"].get("rvtools"),
                 "수량": sm["counts"], "컴퓨트": sm["compute"], "스토리지": sm["storage"], "클러스터": sm["clusters"]},
         "호스트": [{k: x[k] for k in ("host", "cluster", "vendor", "model", "cpu", "cpu_tier", "esx", "nic_gbps", "cores")} for x in res["vcf9"]["hosts"]][:40],
         "게스트OS": sm["os"][:15], "VM HW 버전": sm["hw_versions"], "Tools": sm["tools"],
         "점검 결과 건수": res["counts"], "KISA": {"점수": res["hardening"]["score"], "건수": res["hardening"]["counts"],
                                                    "실패 항목": sorted({r["title"] for r in res["hardening"]["rows"] if r["status"] == "FAIL"})[:20]},
         "VMSA": {"취약": res["vmsa"]["vulnerable"], "가능": res["vmsa"]["possible"], "권고 DB": res["vmsa"]["db"]},
         "VCF9 준비도": {"판정": res["vcf9"]["verdicts"], "CPU 등급": res["vcf9"]["cpu_tiers"], "라이선스 코어(16코어 최소)": res["vcf9"]["licensed_cores"]},
         "주요 이슈": [{"등급": SEV_KO.get(x["severity"]), "영역": x["area"], "대상": x["entity"], "내용": x["title"], "상세": str(x["detail"])[:160]}
                    for x in res["findings"] if x["severity"] in ("critical", "error", "warning")][:60],
         "라이선스": [{"이름": l["name"], "총": l["total"], "사용": l["used"], "만료": l["expires_raw"]} for l in sm["licenses"]][:12],
         "상위 VM(vCPU)": sm["top"]["vcpu"][:8], "상위 VM(메모리 MB)": sm["top"]["mem_mb"][:8]}
    s_ = json.dumps(d, ensure_ascii=False, default=str)
    return s_[:limit]


def names_of(inv: dict) -> list[str]:
    """가명화 대상 이름(외부 LLM 일 때 Masker 가 사용)"""
    out = set(inv["hosts"]) | set(inv["clusters"]) | set(inv["datastores"]) | set(inv["vcenters"]) | {v["name"] for v in inv["vms"].values()}
    out |= {h["datacenter"] for h in inv["hosts"].values() if h["datacenter"]}
    return sorted(x for x in out if x and len(x) >= 3)[:3000]


def search_rows(inv: dict, q: str, limit: int = 30) -> list[str]:
    """질문에 나온 이름·키워드로 관련 원본 요약 줄 찾기(Q&A 컨텍스트)"""
    toks = [t for t in re.split(r"[\s,?!.()]+", q.lower()) if len(t) >= 3]
    out = []
    for v in inv["vms"].values():
        name = v["name"].lower()
        if any(t in name for t in toks) or (v["ip"] and v["ip"] in q):
            out.append(f"VM {v['name']}: {v['power']} vCPU {v['vcpu']} 메모리 {round((v['mem_mb'] or 0) / 1024, 1)}GB 디스크 {_gb(v['prov_mib'])}GB OS {v['os_tools'] or v['os_cfg']} "
                       f"HW {v['hw']} Tools {v['tools']} 호스트 {v['host']} 클러스터 {v['cluster']} 네트워크 {','.join(v['networks'][:4])} IP {v['ip']} CPU준비 {v['cpu_ready']}%")
    for hn, h in inv["hosts"].items():
        if any(t in hn.lower() for t in toks):
            out.append(f"호스트 {hn}: {h['vendor']} {h['model']} CPU {h['cpu_model']} {h['sockets']}x{h['cores_per_cpu']} 메모리 {round((h['mem_mb'] or 0) / 1024)}GB "
                       f"CPU {h['cpu_pct']}% 메모리 {h['mem_pct']}% VM {h['vms']} vCPU {h['vcpus']} ESXi {h['esx']} BIOS {h['bios']} NTP {','.join(h['ntp'])}")
    for dn, d in inv["datastores"].items():
        if any(t in dn.lower() for t in toks):
            out.append(f"데이터스토어 {dn}: {d['type']} {_gb(d['cap_mib'])}GB 여유 {d['free_pct']}% 프로비전 {_gb(d['prov_mib'])}GB VM {d['vms']} 호스트 {len(d['hosts'])}")
    for nm, x in inv["networks"].items():
        if any(t in nm.lower() for t in toks):
            out.append(f"네트워크 {nm}: {x.get('kind')} VLAN {x.get('vlan', '')} VDS {x.get('dvs', '')} VM {x.get('vm_count', 0)}")
    return out[:limit]
