"""VMware 권장 구성 판독(2.28.0) — 인프라 점검 스냅숏(vCenter, 읽기 전용)을 Broadcom 공식 권장 사항과 대조해
클러스터마다 '권장 구성 / 부분 권장 / 권장 아님'을 판정한다.

규칙마다 수준(필수·권장·참고)과 근거 문서(제목·URL)를 붙인다. 문서 원문은 옮기지 않고 요지만 우리말로 적는다.
  · 필수 항목이 하나라도 어긋나면 '권장 아님'
  · 아니면 가중 점수(필수 3 · 권장 2 · 참고 1, 판단 불가 제외) 90 이상 '권장 구성', 그 밖 '부분 권장'
VM 규칙은 클러스터 안 VM 의 준수 비율로 판정(95% 이상 통과, 80% 이상 부분 — 부분은 점수 절반).
"""
from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Any

PERF = ("Performance Best Practices for VMware vSphere 8.0", "https://www.vmware.com/docs/vsphere-esxi-vcenter-server-80-performance-best-practices")
VCF_CLS = ("VCF 5.2 Design — vSphere Cluster Design Requirements and Recommendations",
           "https://docs.vmware.com/en/VMware-Cloud-Foundation/5.2/vcf-design/GUID-7842E8F5-DD13-4B85-8A7B-F90CEC04B5DC.html")
VCF_WLD = ("VCF 4.5 VI Workload Domain Design — vCenter Server Design Decisions",
           "https://docs.vmware.com/en/VMware-Cloud-Foundation/4.5/vcf-vi-workload-domain-design/GUID-4F0A15E4-402A-44E9-98E1-AD556EA96714.html")
VCF_HA_VSAN = ("VCF 4.5 VI Workload Domain Design — vSphere HA(호스트 격리 대응)",
               "https://docs.vmware.com/en/VMware-Cloud-Foundation/4.5/vcf-vi-workload-domain-design/GUID-8907DABF-5FA2-4BF6-BD6E-CD93435C0CB2.html")
VSAN_NET = ("vSAN Planning and Deployment — Designing the vSAN Network", "https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-031F9637-EE29-4684-8644-7A93B9FD8D7B.html")
VSAN_NETREQ = ("vSAN Planning and Deployment — Networking Requirements for vSAN",
               "https://docs.vmware.com/en/VMware-vSphere/8.0/vsan-planning/GUID-AFF133BC-F4B6-4753-815F-20D3D752D898.html")
VSAN_MTU = ("Broadcom KB 391883 — vSAN cluster partition due to MTU mismatch",
            "https://knowledge.broadcom.com/external/article/391883/vsan-cluster-partition-due-to-mtu-mismat.html")
SNAP = ("Broadcom KB 318825 — Best practices for using VMware snapshots", "https://knowledge.broadcom.com/external/article/318825")

LEVELS = {"must": ("필수", 3), "should": ("권장", 2), "may": ("참고", 1)}

# id, 범위, 영역, 수준, 제목, 권장 내용(요지), 근거
RULES: list[dict[str, Any]] = [
    {"id": "BP-C01", "scope": "cluster", "area": "가용성", "level": "must", "title": "vSphere HA 사용",
     "rec": "모든 클러스터에서 vSphere HA 로 VM 을 보호", "src": VCF_CLS},
    {"id": "BP-C02", "scope": "cluster", "area": "가용성", "level": "must", "title": "HA 호스트 모니터링 켜짐",
     "rec": "호스트 모니터링을 켜 두어야 장애 호스트의 VM 이 다른 호스트에서 재시작됨", "src": VCF_CLS},
    {"id": "BP-C03", "scope": "cluster", "area": "가용성", "level": "should", "title": "승인 제어: 호스트 1대 장애 · 비율 기반",
     "rec": "승인 제어를 켜고 '클러스터 자원 비율' 방식으로 호스트 1대 장애분을 예약", "src": VCF_CLS},
    {"id": "BP-C04", "scope": "cluster", "area": "가용성", "level": "should", "title": "VM 모니터링 사용",
     "rec": "VM 모니터링(VMware Tools 하트비트)을 켜서 게스트 멈춤 시 자동 재시작", "src": VCF_WLD},
    {"id": "BP-C05", "scope": "cluster", "area": "가용성", "level": "must", "title": "vSAN: 호스트 격리 대응 = 전원 끄고 재시작",
     "rec": "vSAN 클러스터는 격리된 호스트의 VM 을 전원 끄고 다른 호스트에서 재시작하도록 설정", "src": VCF_HA_VSAN, "when": "vsan"},
    {"id": "BP-C06", "scope": "cluster", "area": "자원", "level": "should", "title": "DRS 완전 자동 · 중간 임계값",
     "rec": "DRS 를 켜고 완전 자동, 마이그레이션 임계값 기본(중간, 3)으로", "src": VCF_CLS},
    {"id": "BP-C07", "scope": "cluster", "area": "가용성", "level": "should", "title": "vSAN 클러스터 호스트 4대 이상",
     "rec": "vSAN 을 주 스토리지로 쓰는 클러스터는 최소 4대(유지보수 중에도 FTT=1 재구성 여유)", "src": VCF_WLD, "when": "vsan"},
    {"id": "BP-H01", "scope": "host", "area": "네트워크", "level": "must", "title": "업링크 이중화(2개 이상)",
     "rec": "가상 스위치마다 정상 업링크 2개 이상 — 장애 조치용 물리 NIC 추가", "src": VSAN_NET},
    {"id": "BP-H02", "scope": "host", "area": "네트워크", "level": "should", "title": "팀 업링크 속도 동일",
     "rec": "부하 분산 팀의 NIC 는 모두 같은 회선 속도", "src": PERF},
    {"id": "BP-H03", "scope": "host", "area": "vSAN", "level": "must", "title": "vSAN 대역폭(OSA 10GbE · ESA 25GbE 이상)",
     "rec": "vSAN 트래픽 업링크 속도 — OSA 올플래시 10GbE 이상, ESA 25GbE 이상", "src": VSAN_NETREQ, "when": "vsan"},
    {"id": "BP-H04", "scope": "host", "area": "vSAN", "level": "must", "title": "vSAN·vMotion VMkernel MTU 클러스터 내 일치",
     "rec": "같은 용도 VMkernel 의 MTU 를 클러스터 전체(물리 경로 포함)에서 일치 — 어긋나면 vSAN 파티션 위험", "src": VSAN_MTU},
    {"id": "BP-H05", "scope": "host", "area": "컴퓨트", "level": "should", "title": "하이퍼스레딩 사용",
     "rec": "BIOS 에서 하이퍼스레딩을 켜 두기 — ESXi 가 자동 활용", "src": PERF},
    {"id": "BP-H06", "scope": "host", "area": "컴퓨트", "level": "should", "title": "전원 정책: 저전력(Low Power) 아님",
     "rec": "기본 '균형'은 성능 영향이 거의 없음, 지연 민감 업무는 '고성능' — 저전력은 성능 저하", "src": PERF},
    {"id": "BP-V01", "scope": "vm", "area": "VM", "level": "should", "title": "VMware Tools 실행 중",
     "rec": "전원 켠 VM 에 VMware Tools 설치·실행(메모리 풍선·시간 동기·정상 종료·VM 모니터링에 필요)", "src": PERF},
    {"id": "BP-V02", "scope": "vm", "area": "VM", "level": "should", "title": "가상 NIC = VMXNET3",
     "rec": "반가상화 VMXNET3 사용 — E1000/E1000e 는 에뮬레이션이라 CPU 부담이 큼", "src": PERF},
    {"id": "BP-V03", "scope": "vm", "area": "VM", "level": "must", "title": "스냅숏 72시간 이내 · 체인 3개 이하",
     "rec": "스냅숏은 백업이 아님 — 한 스냅숏을 72시간 넘게 두지 말고 체인은 2~3개로", "src": SNAP},
    {"id": "BP-V04", "scope": "vm", "area": "VM", "level": "may", "title": "쓰지 않는 CD/DVD 연결 해제",
     "rec": "사용하지 않는 광학 드라이브 등 가상 장치는 끄거나 제거(게스트 폴링 부담·vMotion 제약)", "src": PERF},
    {"id": "BP-V05", "scope": "vm", "area": "VM", "level": "may", "title": "vCPU ≤ NUMA 노드 코어 수",
     "rec": "vCPU 가 한 NUMA 노드의 코어 수 이하이면 로컬 메모리만 써 지연이 가장 낮음 — 넘으면 vNUMA 확인", "src": PERF},
]
RULE = {r["id"]: r for r in RULES}


def _vm_rule(vms: list[dict], test) -> tuple[str, str, list[str]]:
    """VM 규칙 판정: 대상 VM 중 통과 비율 → pass(≥95%) / partial(≥80%) / fail"""
    tgt = [v for v in vms if test(v) is not None]
    if not tgt:
        return "na", "대상 VM 없음", []
    bad = [v["name"] for v in tgt if test(v) is False]
    pct = (len(tgt) - len(bad)) / len(tgt) * 100
    st = "pass" if pct >= 95 else "partial" if pct >= 80 else "fail"
    return st, f"{len(tgt) - len(bad)}/{len(tgt)} VM 준수({pct:.0f}%)", bad


def evaluate(snap: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    hosts: dict[str, dict] = snap.get("hosts", {}) or {}
    clusters: dict[str, dict] = snap.get("clusters", {}) or {}
    bpv = snap.get("bp_vms") or {}
    vm_err = bpv.get("error") or ("" if bpv.get("vms") is not None and bpv else "VM 장치 정보 미수집(다음 점검 때 수집)")
    by_cluster: dict[str, list[str]] = defaultdict(list)
    for hn, h in hosts.items():
        if h.get("cluster"):
            by_cluster[h["cluster"]].append(hn)
    host_cl = {hn: h.get("cluster", "") for hn, h in hosts.items()}
    vms_by_cl: dict[str, list[dict]] = defaultdict(list)
    for v in bpv.get("vms") or []:
        cn = host_cl.get(v.get("host", ""), "")
        if cn:
            vms_by_cl[cn].append(v)
    out = []
    for cn in sorted(set(clusters) | set(by_cluster)):
        c = clusters.get(cn, {})
        hl = by_cluster.get(cn, [])
        live = [h for h in hl if hosts[h].get("conn", "connected") == "connected"]
        vsan = bool(c.get("vsan"))
        res: list[dict] = []

        def put(rid: str, status: str, detail: str = "", entities: list[str] | None = None):
            r = RULE[rid]
            if r.get("when") == "vsan" and not vsan:
                status, detail = "na", "vSAN 클러스터 아님"
            res.append({"id": rid, "status": status, "detail": detail, "entities": (entities or [])[:20], "n_entities": len(entities or [])})

        # ---- 클러스터
        put("BP-C01", "pass" if c.get("ha") else "fail", "HA 켜짐" if c.get("ha") else "HA 꺼짐")
        if c.get("ha"):
            hm = c.get("ha_host_monitoring", "")
            put("BP-C02", "na" if not hm else "pass" if hm == "enabled" else "fail", f"hostMonitoring={hm or '?'}")
            pol, ac = c.get("ha_policy", ""), c.get("ha_admission")
            if not ac:
                put("BP-C03", "fail", "승인 제어 꺼짐")
            elif "FailoverResources" in pol:
                put("BP-C03", "pass", f"비율 기반 CPU {c.get('ha_cpu_pct', 0)}% · 메모리 {c.get('ha_mem_pct', 0)}%"
                    + (f" · 장애 허용 {c['ha_failover_level']}대" if c.get("ha_failover_level") else ""))
            elif pol:
                put("BP-C03", "partial", f"{'슬롯' if 'FailoverLevel' in pol else '전용 장애 조치 호스트' if 'FailoverHosts' in pol else pol} 방식 — 비율 기반 권장")
            else:
                put("BP-C03", "na", "정책 정보 없음")
            vmm = c.get("ha_vm_monitoring", "")
            put("BP-C04", "na" if not vmm else "pass" if vmm in ("vmMonitoringOnly", "vmAndAppMonitoring") else "fail", f"vmMonitoring={vmm or '?'}")
            iso = c.get("ha_isolation", "")
            put("BP-C05", "na" if not iso else "pass" if iso == "powerOff" else "fail", f"isolationResponse={iso or '?'}")
        else:
            for rid in ("BP-C02", "BP-C03", "BP-C04", "BP-C05"):
                put(rid, "na", "HA 꺼짐 — BP-C01 에서 한 번만 감점")
        if not c.get("drs"):
            put("BP-C06", "fail", "DRS 꺼짐")
        else:
            beh, rate = c.get("drs_behavior", ""), int(c.get("drs_rate") or 0)
            ok_b, ok_r = beh == "fullyAutomated", rate in (0, 3)
            put("BP-C06", "pass" if ok_b and ok_r else "partial", f"{beh or '자동화 수준 미확인'} · 임계값 {rate or '기본'}")
        put("BP-C07", "pass" if len(hl) >= 4 else "fail", f"호스트 {len(hl)}대")

        # ---- 호스트
        no_red, mixed, slow, no_ht, low = [], [], [], [], []
        mtu: dict[str, dict[str, int]] = defaultdict(dict)
        need = 25000 if c.get("vsan_esa") else 10000
        for hn in live:
            h = hosts[hn]
            nics = {n["device"]: n for n in h.get("nics", [])}
            for sw in h.get("vswitches", []):
                ups = [nics[u] for u in sw.get("uplinks", []) if u in nics]
                upl = [n for n in ups if n.get("speed")]
                if ups and len(upl) < 2:
                    no_red.append(f"{hn}/{sw['name']}")
                if len({n["speed"] for n in upl}) > 1:
                    mixed.append(f"{hn}/{sw['name']}")
            for k in h.get("vmks", []):
                for s in k.get("services", []):
                    if s in ("vsan", "vmotion") and k.get("mtu"):
                        mtu[s][hn] = int(k["mtu"])
                if "vsan" in k.get("services", []):
                    sw = next((x for x in h.get("vswitches", []) if x["name"] == k.get("switch")), None)
                    sp = max([nics[u].get("speed") or 0 for u in (sw or {}).get("uplinks", []) if u in nics] or [0])
                    if sp and sp < need:
                        slow.append(f"{hn}/{k['device']} {sp // 1000}GbE")
            if h.get("ht_available") and h.get("ht_active") is False:
                no_ht.append(hn)
            if str(h.get("power_policy", "")).lower() in ("low", "lowpower"):
                low.append(hn)
        put("BP-H01", "pass" if not no_red else "fail", f"이중화 없는 스위치 {len(no_red)}개" if no_red else f"호스트 {len(live)}대 모두 2개 이상", no_red)
        put("BP-H02", "pass" if not mixed else "partial", f"속도 섞인 팀 {len(mixed)}개" if mixed else "모두 동일", mixed)
        if vsan and not any("vsan" in k.get("services", []) for hn in live for k in hosts[hn].get("vmks", [])):
            put("BP-H03", "na", "vSAN VMkernel 을 찾지 못함")
        else:
            put("BP-H03", "pass" if not slow else "fail", (f"{'ESA' if c.get('vsan_esa') else 'OSA'} 기준 {need // 1000}GbE 미만 {len(slow)}개" if slow
                                                            else f"{'ESA' if c.get('vsan_esa') else 'OSA'} 기준 충족"), slow)
        odd = []
        for s, vals in mtu.items():
            if len(set(vals.values())) > 1:
                cnt = defaultdict(int)
                for v in vals.values():
                    cnt[v] += 1
                major = max(cnt, key=cnt.get)
                odd += [f"{h}({s} {v})" for h, v in vals.items() if v != major]
        put("BP-H04", "na" if not mtu else "pass" if not odd else "fail",
            "일치" if mtu and not odd else f"다른 MTU {len(odd)}개" if odd else "대상 VMkernel 없음", odd)
        put("BP-H05", "pass" if not no_ht else "partial", f"HT 꺼진 호스트 {len(no_ht)}대" if no_ht else "켜짐", no_ht)
        pp = [hosts[h].get("power_policy") for h in live if hosts[h].get("power_policy")]
        put("BP-H06", "na" if not pp else "pass" if not low else "fail", f"저전력 {len(low)}대" if low else ("정책: " + ", ".join(sorted(set(pp)))) if pp else "정보 없음", low)

        # ---- VM
        vms = vms_by_cl.get(cn, [])
        on = [v for v in vms if v.get("power") == "poweredOn"]
        if vm_err and not vms:
            for rid in ("BP-V01", "BP-V02", "BP-V03", "BP-V04", "BP-V05"):
                put(rid, "na", vm_err)
        else:
            st, d, bad = _vm_rule(on, lambda v: v.get("tools") == "guestToolsRunning")
            put("BP-V01", st, d, bad)
            st, d, bad = _vm_rule(vms, lambda v: (all(n.lower().startswith("vmxnet3") for n in v["nics"]) if v.get("nics") else None))
            put("BP-V02", st, d, bad)

            def snap_ok(v):
                if not v.get("snapshots"):
                    return True
                return v["snapshots"] <= 3 and (now - (v.get("snap_oldest") or now)) <= 72 * 3600
            st, d, bad = _vm_rule(vms, snap_ok)
            put("BP-V03", st, d, bad)
            st, d, bad = _vm_rule(on, lambda v: not v.get("cdrom_connected"))
            put("BP-V04", st, d, bad)
            node = {}
            for hn in hl:
                h = hosts[hn]
                nn = int(h.get("numa_nodes") or h.get("sockets") or 0)
                node[hn] = math.floor((h.get("cores") or 0) / nn) if nn else 0
            st, d, bad = _vm_rule(on, lambda v: (v.get("vcpu", 0) <= node[v["host"]]) if node.get(v.get("host")) else None)
            put("BP-V05", st, d, bad)

        # ---- 점수·판정
        tot = got = 0.0
        must_fail = []
        for r in res:
            if r["status"] == "na":
                continue
            w = LEVELS[RULE[r["id"]]["level"]][1]
            tot += w
            got += w if r["status"] == "pass" else w / 2 if r["status"] == "partial" else 0
            if r["status"] == "fail" and RULE[r["id"]]["level"] == "must":
                must_fail.append(r["id"])
        score = round(got / tot * 100) if tot else None
        verdict = "not" if must_fail else "ok" if (score or 0) >= 90 else "partial"
        out.append({"cluster": cn, "hosts": len(hl), "vms": len(vms), "vsan": vsan, "vsan_esa": bool(c.get("vsan_esa")), "score": score,
                    "verdict": verdict, "must_fail": must_fail, "results": res})
    return {"clusters": out, "rules": RULES, "levels": {k: v[0] for k, v in LEVELS.items()}, "vm_error": vm_err,
            "vm_collected": bpv.get("collected"), "evaluated": now}


VERDICT = {"ok": "권장 구성", "partial": "부분 권장", "not": "권장 아님"}
