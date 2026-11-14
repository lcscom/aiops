"""What-If 시나리오 라이브러리(2.47.0) — 파트별로 분류한 장애·작업 시나리오(파트마다 20개 이상)

각 시나리오는 지금 수집된 구성(world 스냅숏)에서 가장 영향이 큰 대상을 골라
  · 장애 시뮬레이터 가정(failures: 호스트·클러스터·데이터스토어·스위치·Supervisor·VKS 노드·Avi …)과
  · 시뮬레이터 규칙으로는 표현되지 않는 지식(findings: 무엇이 멈추고 무엇이 계속되는지, 확인할 것)·VM 상태·플랫폼 항목
을 만든다. 대상이 없으면 '해당 없음'과 그 이유. 계산은 simulator.simulate 가 하며, 읽기 전용이다(명령 없음).
지식 문장은 일반적인 VMware 동작 기준이다 — 버전·설정에 따라 다를 수 있으니 '확인할 것'을 함께 둔다.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Callable

from . import checkbot as CB
from . import platsim as PS
from . import simulator as SIM

PARTS = [
    ("comp", "컴퓨트", "ESXi 호스트·클러스터·HA·DRS·유지보수"),
    ("stor", "스토리지", "vSAN·외장 스토리지·데이터스토어"),
    ("net", "물리 네트워크", "ToR·스파인·방화벽·라우터·vDS·VLAN"),
    ("nsx", "NSX", "Edge·T0/T1·BGP·NSX Manager·오버레이·분산 방화벽"),
    ("mgmt", "관리·공통 서비스", "vCenter·SDDC Manager·DNS·NTP·AD·KMS·인증서·백업 대상·알림"),
    ("k8s", "쿠버네티스", "Supervisor·VKS·vSphere Pod·레지스트리·CNI·CSI"),
    ("lb", "로드밸런서(Avi)", "컨트롤러·Service Engine·가상 서비스"),
    ("dr", "DR·데이터 보호", "SRM·복제·백업·랜섬웨어·작업 실수"),
]
LIB: list[dict] = []
NA = "해당 없음"


def sc(part: str, sid: str, title: str, desc: str):
    def deco(fn: Callable):
        LIB.append({"id": sid, "part": part, "title": title, "desc": desc, "fn": fn})
        return fn
    return deco


# ------------------------------------------------------------------ 구성 요약(대상 고르기)
class Ctx:
    def __init__(self, W: dict):
        self.W = W
        self.P = PS.build(W)
        self.hosts, self.clusters, self.ds, self.vms = [], [], [], []
        for vc in W["vcenters"]:
            T, V = vc["topo"], vc["topo"].get("vms") or {}
            for hn, h in (T.get("hosts") or {}).items():
                on = [n for n, v in V.items() if v.get("host") == hn and "poweredOn" in str(v.get("power"))]
                self.hosts.append({"vc": vc["name"], "name": hn, "cluster": h.get("cluster", ""), "on": len(on), "vms": on,
                                   "mem": sum(int(V[n].get("mem_mb") or 0) for n in on), "model": h.get("hw_model") or (vc["health"].get(hn) or {}).get("model", ""),
                                   "pnics": h.get("pnics") or []})
            for cn, c in (T.get("clusters") or {}).items():
                hc = vc["hclusters"].get(cn) or {}
                self.clusters.append({"vc": vc["name"], "name": cn, "hosts": [x for x in c.get("hosts", []) if x in (T.get("hosts") or {})],
                                      "ha": bool(c.get("ha", hc.get("ha"))), "drs": bool(c.get("drs", hc.get("drs"))), "vsan": bool(c.get("vsan") or hc.get("vsan")),
                                      "iso": hc.get("ha_isolation", ""), "evc": hc.get("evc", ""),
                                      "on": sum(1 for v in V.values() if v.get("cluster") == cn and "poweredOn" in str(v.get("power")))})
            for dn, d in (T.get("datastores") or {}).items():
                if not d.get("capacity_gb"):
                    continue
                vv = [n for n, v in V.items() if dn in (v.get("datastores") or [])]
                self.ds.append({"vc": vc["name"], "name": dn, "type": str(d.get("type", "")), "local": d.get("local") is True, "used": CB._used_pct(d),
                                "cap": d.get("capacity_gb") or 0, "vms": vv, "on": sum(1 for n in vv if "poweredOn" in str(V[n].get("power"))),
                                "prov": sum(float(V[n].get("prov_gb") or 0) for n in vv), "snaps": sum(int(V[n].get("snapshots") or 0) for n in vv),
                                "remote": d.get("remote", ""), "array": d.get("array", "")})
            for n, v in V.items():
                self.vms.append({"vc": vc["name"], "name": n, "host": v.get("host", ""), "cluster": v.get("cluster", ""), "on": "poweredOn" in str(v.get("power")),
                                 "nets": v.get("networks") or [], "ips": v.get("ips") or [], "mem": int(v.get("mem_mb") or 0), "snaps": int(v.get("snapshots") or 0),
                                 "disk": float(v.get("disk_gb") or 0), "mgmt": CB._mgmt_kind(n, W) or "", "os": str(v.get("os", ""))})
        self.nets = {(vc["name"], k): x for vc in W["vcenters"] for k, x in ((vc["topo"].get("networks") or {}).items())}

    # 고르기
    def busiest_host(self, pred=None):
        hs = [h for h in self.hosts if (pred is None or pred(h))]
        return max(hs, key=lambda h: (h["on"], h["mem"]), default=None)

    def big_cluster(self, pred=None, min_hosts=1):
        cs = [c for c in self.clusters if len(c["hosts"]) >= min_hosts and (pred is None or pred(c))]
        return max(cs, key=lambda c: (c["on"], len(c["hosts"])), default=None)

    def hosts_of(self, c):
        return sorted((h for h in self.hosts if h["vc"] == c["vc"] and h["name"] in c["hosts"]), key=lambda h: (-h["on"], -h["mem"]))

    def shared_ds(self, pred=None):
        ds = [d for d in self.ds if not d["local"] and (pred is None or pred(d))]
        return max(ds, key=lambda d: (d["on"], d["used"]), default=None)

    def mgmt(self, kind):
        return [v for v in self.vms if v["mgmt"] == kind]

    def vms_where(self, pred):
        return [v for v in self.vms if pred(v)]

    def nsx_net(self, vc, n):
        x = self.nets.get((vc, n)) or {}
        return x.get("kind") in ("opaque", "nsx") or str(n).startswith("seg-") or bool(x.get("nsx"))


# ------------------------------------------------------------------ 결과 조각
def F(t, vc, tg):
    return {"type": t, "vcenter": vc, "target": tg}


def N(sev, text):
    return {"sev": sev, "text": text}


def out(tgt="", f=None, n=None, vms=None, items=None, acts=None, pods=None, marks=None):
    return {"target": tgt, "failures": f or [], "notes": n or [], "vms": vms or [], "items": items or [], "actions": acts or [], "pods": pods or [], "marks": marks or {}}


def OK(text):
    """대상이 없어서가 아니라 '위험한 구성이 없어서' 통과"""
    return out("이 환경", n=[N("pass", text)])


def vmarks(vms, state, why):
    return [(v["vc"], v["name"], state, why) for v in vms]


def svc(tgt, stops, keeps, checks, sev="warn", vms=None, items=None):
    """지식형 — 무엇이 멈추고(stops) 무엇이 계속되는지(keeps), 확인할 것(checks)"""
    n = [N(sev, f"멈추는 것: {x}") for x in stops] + [N("pass", f"계속되는 것: {x}") for x in keeps]
    return out(tgt, n=n, acts=checks, vms=vms, items=items)


def workloads(c: Ctx, state: str, text: str, pred=None):
    items, pods = [], []
    for k in c.P["vks"]:
        for w in k["workloads"]:
            if w["kind"] in ("ds", "static") or (pred and not pred(k, w)):
                continue
            items.append({"kind": "VKS 워크로드", "name": f"{w['ns']}/{w['name']}", "state": state, "text": text, "scope": k["cluster"]})
            pods += [{"cluster": k["cluster"], "ns": w["ns"], "pod": p["name"], "node": p["node"], "workload": w["name"], "kind": w["kind"],
                      "state": {"stop": "stuck", "risk": "frozen", "boot": "resched", "ok": "kept"}[state], "text": text} for p in w["pods"]]
    return items, pods


# ================================================================== 1. 컴퓨트
@sc("comp", "c01", "가장 붐비는 ESXi 호스트 장애", "PSOD·전원·메인보드로 켜진 VM 이 가장 많은 호스트가 꺼짐 — HA 재시작 용량·재시작 못 하는 VM")
def _c01(c):
    h = c.busiest_host()
    return out(h["name"], [F("host_down", h["vc"], h["name"])]) if h else NA


@sc("comp", "c02", "같은 클러스터 호스트 2대 동시 장애", "같은 랙 전원·공통 펌웨어 버그로 두 대가 같이 꺼짐 — N+1 설계를 넘는 경우")
def _c02(c):
    cl = c.big_cluster(min_hosts=3)
    if not cl:
        return "호스트 3대 이상 클러스터 없음"
    hs = c.hosts_of(cl)[:2]
    return out(f"{cl['name']}: {hs[0]['name']} + {hs[1]['name']}", [F("host_down", h["vc"], h["name"]) for h in hs])


@sc("comp", "c03", "호스트 유지보수 모드(패치·부품 교체)", "켜진 VM 을 vMotion 으로 비우고 호스트를 내림 — vMotion 을 막는 VM·남은 용량")
def _c03(c):
    h = c.busiest_host()
    return out(h["name"], [F("host_maint", h["vc"], h["name"])]) if h else NA


@sc("comp", "c04", "유지보수 중 다른 호스트 장애", "한 대를 패치로 뺀 사이 다른 한 대가 PSOD — 가장 흔한 '설마' 장애")
def _c04(c):
    cl = c.big_cluster(min_hosts=3)
    if not cl:
        return "호스트 3대 이상 클러스터 없음"
    a, b = c.hosts_of(cl)[:2]
    return out(f"{b['name']} 유지보수 + {a['name']} 장애", [F("host_maint", b["vc"], b["name"]), F("host_down", a["vc"], a["name"])])


@sc("comp", "c05", "클러스터 롤링 패치", "클러스터 호스트를 한 대씩 유지보수 모드로 — 가장 나쁜 순간의 남은 용량")
def _c05(c):
    cl = c.big_cluster(min_hosts=2)
    return out(cl["name"], [F("host_maint", cl["vc"], cl["name"])]) if cl else NA


@sc("comp", "c06", "클러스터 전체 장애", "공통 전원·스토리지·네트워크로 클러스터가 통째로 멈춤")
def _c06(c):
    cl = c.big_cluster()
    return out(cl["name"], [F("cluster_down", cl["vc"], cl["name"])]) if cl else NA


@sc("comp", "c07", "랙 전원 장애(같은 ToR 에 붙은 호스트 전부)", "같은 스위치 쌍에 연결된 호스트를 한 랙으로 보고 모두 꺼짐")
def _c07(c):
    ph = (c.W.get("phys") or {}).get("hosts") or {}
    g: dict[tuple, list] = {}
    for hn, h in ph.items():
        sw = tuple(sorted({n.get("switch") for n in (h.get("nics") or {}).values() if n.get("switch")}))
        if sw:
            g.setdefault(sw, []).append((h.get("vcenter", ""), hn))
    if not g:
        return "물리 결선(LLDP) 정보 없음 — 네트워크 커넥터·vDS LLDP 필요"
    sw, hs = max(g.items(), key=lambda kv: len(kv[1]))
    return out(f"{' + '.join(sw)} 의 호스트 {len(hs)}대", [F("host_down", vc, h) for vc, h in hs[:SIM.MAX_FAIL]],
               n=[N("warn", f"랙 하나 = 스위치 {' · '.join(sw)} 에 붙은 호스트로 가정 — 실제 랙 배치와 다르면 vSphere 의 랙/Zone 정보로 확인")])


@sc("comp", "c08", "같은 모델 호스트 공통 결함(펌웨어·BIOS 버그)", "같은 하드웨어 모델 두 대가 같은 버그로 연달아 PSOD")
def _c08(c):
    g: dict[tuple, list] = {}
    for h in c.hosts:
        if h["model"]:
            g.setdefault((h["vc"], h["cluster"], h["model"]), []).append(h)
    g = {k: v for k, v in g.items() if len(v) >= 2}
    if not g:
        return "같은 클러스터에 같은 모델 호스트 2대 이상 없음(또는 모델 정보 없음)"
    k, hs = max(g.items(), key=lambda kv: sum(h["on"] for h in kv[1]))
    hs = sorted(hs, key=lambda h: -h["on"])[:2]
    return out(f"{k[2]} ×2 ({k[1]})", [F("host_down", h["vc"], h["name"]) for h in hs],
               acts=["같은 모델·펌웨어 호스트에 Broadcom·제조사 권고(KB·펌웨어 공지)가 있는지 확인하고, 펌웨어는 한 대씩 단계적으로"])


@sc("comp", "c09", "HA 가 꺼진 클러스터의 호스트 장애", "HA 가 꺼져 있으면 장애 호스트의 VM 은 아무도 다시 켜지 않음")
def _c09(c):
    cl = c.big_cluster(pred=lambda x: not x["ha"])
    if not cl:
        return OK("HA 가 꺼진 클러스터 없음")
    h = c.hosts_of(cl)[0]
    return out(h["name"], [F("host_down", h["vc"], h["name"])])


@sc("comp", "c10", "모든 클러스터 N+1 검증", "클러스터마다 가장 붐비는 호스트 하나씩 동시에 꺼짐 — 어느 클러스터가 N+1 을 못 지키는지")
def _c10(c):
    fs = []
    for cl in c.clusters:
        hs = c.hosts_of(cl)
        if len(hs) >= 2:
            fs.append(F("host_down", hs[0]["vc"], hs[0]["name"]))
    return out(f"클러스터 {len(fs)}개", fs[:SIM.MAX_FAIL]) if fs else "호스트 2대 이상 클러스터 없음"


@sc("comp", "c11", "호스트 관리망 단절(HA 격리)", "관리 VMkernel 이 끊겨 호스트가 격리됨 — 격리 대응 설정에 따라 VM 이 남거나 다른 호스트에서 다시 켜짐")
def _c11(c):
    h = c.busiest_host()
    if not h:
        return NA
    cl = next((x for x in c.clusters if x["vc"] == h["vc"] and x["name"] == h["cluster"]), {})
    iso = cl.get("iso") or ""
    vv = [v for v in c.vms if v["vc"] == h["vc"] and v["host"] == h["name"] and v["on"]]
    if iso not in ("", "none", "clusterIsolationResponse"):          # 끄기·게스트 종료 대응
        vms, n = vmarks(vv, "restart", f"HA 격리 대응({iso}) — 끄고 다른 호스트에서 다시 켬"), N("warn", f"격리 대응이 '{iso}' — VM {len(vv)}대가 꺼졌다 다른 호스트에서 다시 켜집니다")
    else:
        vms, n = [], N("pass", f"격리 대응이 '{iso or '켜 둠(기본)'}' — VM {len(vv)}대는 그대로 돎(VM 네트워크가 살아 있으면 서비스 계속)")
    return out(h["name"], n=[N("warn", "vCenter 에서 호스트가 '응답 없음' — 그 호스트 VM 의 관리·vMotion·백업 스냅숏이 멈춤"), n,
                             N("warn", "관리망과 VM 망이 같은 업링크면 VM 통신도 같이 끊겼을 수 있음 — 그 경우 '켜 둠' 이면 VM 이 고립된 채 남음")],
               vms=vms, marks={f"host:{h['vc']}/{h['name']}": "isolated"},
               acts=["HA 격리 주소(das.isolationaddress)·데이터스토어 하트비트 2개 이상·격리 대응 값을 업무 특성에 맞게 정했는지 확인"])


@sc("comp", "c12", "호스트 vMotion 망 장애", "vMotion VMkernel 이 끊김 — 그 호스트로/에서 VM 을 옮길 수 없음(유지보수·DRS 균형 불가)")
def _c12(c):
    h = c.busiest_host()
    if not h:
        return NA
    vv = [v for v in c.vms if v["vc"] == h["vc"] and v["host"] == h["name"] and v["on"]]
    return out(h["name"], n=[N("warn", f"VM {len(vv)}대는 계속 돌지만 다른 호스트로 옮길 수 없음 — 이 상태에서 유지보수가 필요하면 VM 을 꺼야 함"),
                             N("warn", "DRS 가 이 호스트를 균형 대상에서 빼므로 다른 호스트 부하가 올라갈 수 있음")],
               vms=vmarks(vv, "blocked", "vMotion 망 장애 — 옮길 수 없음"))


@sc("comp", "c13", "부팅 장치(SD·USB·BOSS) 장애", "부팅 장치가 고장 — ESXi 는 메모리에서 계속 돌지만 재부팅·설정 저장·패치가 안 됨")
def _c13(c):
    h = c.busiest_host()
    return out(h["name"], n=[N("pass", "실행 중 VM 은 계속"), N("warn", "구성 변경이 저장되지 않고 재부팅하면 켜지지 않음 — 이 호스트는 다음 패치 전에 장치 교체 필요"),
                             N("warn", "SD·USB 부팅은 ESXi 8 부터 권장하지 않음(OSDATA 를 영구 장치로)")],
               marks={f"host:{h['vc']}/{h['name']}": "affected"}, acts=["부팅 장치 상태(esxcli storage core device list·하드웨어 상태)와 OSDATA 위치 확인"]) if h else NA


@sc("comp", "c14", "메모리 DIMM 장애(정정 불가 오류)", "UE 메모리 오류로 호스트가 PSOD 후 메모리가 줄어든 채로 돌아옴")
def _c14(c):
    h = c.busiest_host()
    if not h:
        return NA
    return out(h["name"], [F("host_down", h["vc"], h["name"])], n=[N("warn", "돌아온 뒤에도 메모리 용량이 줄어 HA 여유가 그만큼 줄어듦 — 교체 전까지 이 호스트에 VM 을 몰지 말 것")],
               acts=["하드웨어 상태(IPMI·Redfish)의 메모리 경고와 정정 가능 오류(CE) 증가 추세를 먼저 확인"])


@sc("comp", "c15", "전원공급장치(PSU) 1개 장애", "이중화 PSU 중 하나가 고장 — 대개 영향 없음, 남은 하나마저 고장 나면 호스트 장애")
def _c15(c):
    h = c.busiest_host()
    return out(h["name"], n=[N("pass", "PSU 2개 이중화면 호스트는 계속 돎"), N("warn", "같은 PDU·같은 전원 계통에 두 PSU 가 다 꽂혀 있으면 계통 장애 하나로 호스트가 꺼짐")],
               acts=["PSU 두 개가 서로 다른 PDU·전원 계통(A/B)에 꽂혔는지 확인", "BMC 경고(PSU redundancy lost)가 알림으로 오는지 확인"]) if h else NA


@sc("comp", "c16", "DRS 가 꺼진 클러스터 유지보수", "DRS 가 꺼져 있으면 유지보수 모드가 VM 을 자동으로 비우지 않음")
def _c16(c):
    cl = c.big_cluster(pred=lambda x: not x["drs"], min_hosts=2)
    if not cl:
        return OK("DRS 가 꺼진 클러스터 없음")
    h = c.hosts_of(cl)[0]
    return out(h["name"], [F("host_maint", h["vc"], h["name"])], n=[N("warn", f"DRS 꺼짐 — 켜진 VM {h['on']}대를 사람이 하나씩 vMotion 해야 유지보수 모드가 끝남")])


@sc("comp", "c17", "패스스루(GPU·NIC)·USB VM 이 있는 호스트 장애", "PCI 패스스루·USB 를 쓰는 VM 은 다른 호스트에서 켜지지 않음")
def _c17(c):
    bp = {}
    for vc in c.W["vcenters"]:
        for n, x in (vc.get("bp") or {}).items():
            if x.get("passthru") or x.get("usb"):
                bp[(vc["name"], n)] = x
    hs = Counter((vc, (next((v for v in c.vms if v["vc"] == vc and v["name"] == n), {}) or {}).get("host", "")) for vc, n in bp)
    hs = Counter({k: v for k, v in hs.items() if k[1]})
    if not hs:
        return "패스스루·USB VM 없음(또는 권장 구성 판독 미수집)"
    (vc, h), _ = hs.most_common(1)[0]
    return out(h, [F("host_down", vc, h)], acts=["패스스루 VM 은 같은 장치가 있는 대기 호스트를 두거나 vGPU(공유)·DirectPath I/O with vMotion 지원 여부 검토"])


@sc("comp", "c18", "로컬 디스크 VM 이 있는 호스트 장애", "로컬 데이터스토어에 있는 VM 은 다른 호스트에서 켤 수 없음")
def _c18(c):
    loc = [d for d in c.ds if d["local"] and d["vms"]]
    if not loc:
        return OK("로컬 데이터스토어에 VM 없음")
    d = max(loc, key=lambda d: len(d["vms"]))
    h = next((v["host"] for v in c.vms if v["vc"] == d["vc"] and v["name"] in d["vms"]), "")
    return out(h, [F("host_down", d["vc"], h)])


@sc("comp", "c19", "ESXi 업그레이드(클러스터 롤링)", "vLCM 이미지로 클러스터를 한 대씩 업그레이드 — 버전 혼재 기간·vSAN 데이터 이동")
def _c19(c):
    cl = c.big_cluster(min_hosts=2)
    if not cl:
        return NA
    return out(cl["name"], [F("host_maint", cl["vc"], cl["name"])],
               n=[N("warn", "업그레이드 동안 ESXi 버전이 섞임 — vCenter 가 먼저 같은 버전 이상이어야 함"),
                  N("warn" if cl["vsan"] else "pass", "vSAN 이면 유지보수 때 '접근성 보장' 데이터 이동·재동기화가 끝나야 다음 호스트로" if cl["vsan"] else "vSAN 아님")],
               acts=["vLCM 사전 점검(하드웨어 호환성·드라이버·펌웨어)·vCenter 백업 확인", "업그레이드 순서: vCenter → (NSX) → ESXi"])


@sc("comp", "c20", "호스트 2대 동시 유지보수", "작업 시간을 줄이려고 두 대를 같이 유지보수 — 남은 용량·vSAN 호스트 수")
def _c20(c):
    cl = c.big_cluster(min_hosts=3)
    if not cl:
        return "호스트 3대 이상 클러스터 없음"
    hs = c.hosts_of(cl)[:2]
    return out(" + ".join(h["name"] for h in hs), [F("host_maint", h["vc"], h["name"]) for h in hs])


@sc("comp", "c21", "CPU 세대가 섞인 클러스터의 vMotion(EVC)", "EVC 없이 다른 세대 CPU 가 섞이면 새 세대에서 켠 VM 을 옛 세대로 옮길 수 없음")
def _c21(c):
    for cl in c.clusters:
        cpus = {str(((next((vc for vc in c.W["vcenters"] if vc["name"] == cl["vc"]), {})["topo"].get("hosts") or {}).get(x) or {}).get("cpu_model", "")) for x in cl["hosts"]} - {""}
        if len(cpus) >= 2:
            return out(cl["name"], n=[N("fail" if not cl["evc"] else "pass", f"CPU 가 {len(cpus)}종({', '.join(sorted(cpus))}) — EVC {'꺼짐: 세대 사이 vMotion·HA 재시작 위치가 제한됨' if not cl['evc'] else cl['evc'] + ' 로 맞춤'}")],
                       acts=["EVC 모드를 가장 옛 세대에 맞추거나 세대별로 클러스터를 나누세요"] if not cl["evc"] else [])
    return OK("모든 클러스터가 CPU 한 종류")


@sc("comp", "c22", "vCenter 가 멈춘 상태에서 호스트 장애", "vCenter 업그레이드 중에 호스트가 꺼짐 — HA(FDM)는 vCenter 없이도 동작하는지")
def _c22(c):
    h = c.busiest_host()
    if not h:
        return NA
    return out(f"{h['vc']} 중단 + {h['name']} 장애", [F("vcenter_upgrade", h["vc"], h["vc"]), F("host_down", h["vc"], h["name"])],
               n=[N("pass", "vSphere HA 는 각 호스트의 FDM 이 처리하므로 vCenter 없이도 VM 을 다시 켬"),
                  N("warn", "DRS 는 vCenter 가 있어야 동작 — 재시작 위치가 고르게 나뉘지 않을 수 있음")])


# ================================================================== 2. 스토리지
@sc("stor", "s01", "가장 붐비는 공유 데이터스토어 APD/PDL", "모든 경로가 끊기거나(APD) 장치가 사라짐(PDL) — 그 위 VM I/O 정지")
def _s01(c):
    d = c.shared_ds()
    return out(d["name"], [F("ds_apd", d["vc"], d["name"])]) if d else "공유 데이터스토어 없음"


@sc("stor", "s02", "가장 찬 데이터스토어 가득 참", "공간이 다 차서 씬 디스크·스냅숏·스왑을 못 씀 — VM 이 멈춤")
def _s02(c):
    ds = [d for d in c.ds if not d["local"]]
    d = max(ds, key=lambda d: d["used"], default=None)
    return out(f"{d['name']} ({d['used']}%)", [F("ds_full", d["vc"], d["name"])]) if d else NA


@sc("stor", "s03", "외장 SAN 어레이 전체 장애", "어레이(컨트롤러 둘 다)가 멈춤 — 그 어레이의 데이터스토어 전부")
def _s03(c):
    a = next((x for x in ((c.W.get("phys") or {}).get("storage") or {}).values() if x.get("kind") != "nfs"), None)
    return out(a["name"], [F("storage_down", "", a["name"])]) if a else "외장 SAN 어레이 없음"


@sc("stor", "s04", "NFS 서버 장애", "NAS 가 멈춤 — 그 NFS 데이터스토어 전부(백업·ISO·템플릿 보관이 많음)")
def _s04(c):
    a = next((x for x in ((c.W.get("phys") or {}).get("storage") or {}).values() if x.get("kind") == "nfs"), None)
    return out(a["name"], [F("storage_down", "", a["name"])]) if a else "NFS 데이터스토어 없음"


@sc("stor", "s05", "vSAN 호스트 1대 장애", "vSAN 클러스터 호스트가 꺼짐 — FTT=1 객체는 한 복사본으로 계속, 60분 뒤 재구성")
def _s05(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"])
    if not cl:
        return "vSAN 클러스터 없음"
    h = c.hosts_of(cl)[0]
    return out(h["name"], [F("host_down", h["vc"], h["name"])],
               n=[N("warn", "FTT=1 객체는 복사본 하나로 버팀 — 이 동안 다른 호스트·디스크가 하나 더 고장 나면 데이터 접근 불가"),
                  N("warn", "기본 60분(복구 지연) 뒤 다른 호스트에 다시 만듦 — 그만큼 여유 공간 필요")])


@sc("stor", "s06", "vSAN 호스트 2대 동시 장애", "FTT=1 정책이면 두 복사본을 다 잃는 객체가 생김 — 그 VM 은 멈춤")
def _s06(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"], min_hosts=3)
    if not cl:
        return "vSAN 클러스터(3대 이상) 없음"
    hs = c.hosts_of(cl)[:2]
    return out(" + ".join(h["name"] for h in hs), [F("host_down", h["vc"], h["name"]) for h in hs],
               n=[N("fail", "FTT=1(RAID-1·RAID-5) 객체 중 두 구성요소가 이 두 호스트에 있던 것은 접근 불가 — 어떤 VM 인지는 객체 배치에 따라 다름"),
                  N("warn", "FTT=2(RAID-6·3-way mirror) 정책 VM 은 계속")], acts=["중요 VM 은 FTT=2 정책 또는 장애 도메인(랙) 구성을 검토"])


@sc("stor", "s07", "vSAN 디스크(캐시·디스크 그룹) 장애", "디스크 하나가 고장 — OSA 캐시 디스크면 디스크 그룹 전체가 빠짐")
def _s07(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"])
    if not cl:
        return "vSAN 클러스터 없음"
    h = c.hosts_of(cl)[0]
    return out(h["name"], n=[N("pass", "VM 은 다른 복사본으로 계속(FTT ≥ 1)"), N("warn", "고장 즉시(디스크 오류는 지연 없이) 다른 곳에 다시 만듦 — 재동기화 I/O 로 성능이 떨어질 수 있음"),
                             N("warn", "OSA 캐시 디스크 고장이면 그 디스크 그룹 용량 전체가 빠짐(ESA 는 디스크 하나만)")],
               marks={f"host:{h['vc']}/{h['name']}": "affected"}, acts=["vSAN 상태의 '재동기화 중 객체'·여유 공간(호스트 1대 분량 이상) 확인"])


@sc("stor", "s08", "vSAN 망 단절(호스트 1대 파티션)", "vSAN VMkernel 이 끊긴 호스트는 다수 파티션에서 떨어짐 — 그 호스트 VM 은 HA 가 다른 호스트에서 다시 켬")
def _s08(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"], min_hosts=3)
    if not cl:
        return "vSAN 클러스터(3대 이상) 없음"
    h = c.hosts_of(cl)[0]
    vv = [v for v in c.vms if v["vc"] == h["vc"] and v["host"] == h["name"] and v["on"]]
    return out(h["name"], vms=vmarks(vv, "restart", "vSAN 파티션 — 객체가 다수 쪽에 남아 HA 가 다른 호스트에서 다시 켬"),
               n=[N("warn", "vSAN 클러스터에서 HA 는 vSAN 망으로 하트비트 — 파티션된 호스트의 VM 은 격리 대응에 따라 꺼지고 다른 호스트에서 켜짐")],
               marks={f"host:{h['vc']}/{h['name']}": "isolated"})


@sc("stor", "s09", "vSAN 리빌드 여유(호스트 1대 분량) 부족", "호스트 1대가 빠진 뒤 그 데이터를 다시 만들 공간이 있는지")
def _s09(c):
    r = []
    for cl in [x for x in c.clusters if x["vsan"]]:
        d = next((d for d in c.ds if d["vc"] == cl["vc"] and "vsan" in d["type"].lower() and set(v for v in d["vms"]) & {v["name"] for v in c.vms if v["cluster"] == cl["name"]}), None)
        n = len(cl["hosts"])
        if not d or n < 2:
            continue
        after = round(d["used"] * n / (n - 1), 1)
        r.append(N("fail" if after >= 90 else "warn" if after >= 80 else "pass", f"{cl['name']}: 지금 {d['used']}% → 호스트 1대 뺀 뒤 {after}% (호스트 {n}대 균등 가정)"))
    return out(f"vSAN 클러스터 {len(r)}개", n=r, acts=["vSAN 여유는 '호스트 1대 분량 + 운영 예비'를 남기세요(용량 화면의 예약 설정)"]) if r else "vSAN 클러스터 없음"


@sc("stor", "s10", "스냅숏 누적으로 데이터스토어 가득 참", "오래된 스냅숏의 델타 디스크가 자라 공간이 참")
def _s10(c):
    ds = [d for d in c.ds if d["snaps"] and not d["local"]]
    if not ds:
        return OK("스냅숏 있는 공유 데이터스토어 없음")
    d = max(ds, key=lambda d: (d["snaps"], d["used"]))
    return out(f"{d['name']} (스냅숏 {d['snaps']}개)", [F("ds_full", d["vc"], d["name"])], acts=["72시간 넘은 스냅숏 정리, 백업 제품의 스냅숏 남김 여부 확인"])


@sc("stor", "s11", "씬 프로비저닝 과할당", "VM 디스크 최대 크기 합이 데이터스토어보다 큼 — 한꺼번에 차면 가득 참")
def _s11(c):
    ds = [d for d in c.ds if d["cap"] and not d["local"] and d["prov"]]
    if not ds:
        return NA
    d = max(ds, key=lambda d: d["prov"] / d["cap"])
    ratio = round(d["prov"] / d["cap"] * 100)
    if ratio < 100:
        return out(f"{d['name']} ({ratio}%)", n=[N("pass", f"프로비저닝 합이 용량의 {ratio}% — 과할당 아님")])
    return out(f"{d['name']} (프로비저닝 {ratio}%)", [F("ds_full", d["vc"], d["name"])], n=[N("warn", f"프로비저닝 합이 용량의 {ratio}% — 디스크가 다 차면 공간이 모자람")])


@sc("stor", "s12", "SAN 경로 하나(HBA·포트) 장애", "멀티패스 중 경로 하나가 끊김 — 경로가 2개 이상이면 계속")
def _s12(c):
    ds = [d for d in c.ds if not d["local"] and (d["array"] or "vmfs" in d["type"].lower())]
    if not ds:
        return "외장 블록(VMFS) 데이터스토어 없음"
    return out(f"VMFS {len(ds)}개", n=[N("pass", "경로가 2개 이상이면 남은 경로로 계속(PSP 에 따라 잠깐 지연)"),
                                       N("warn", "경로가 하나뿐인 LUN 은 그대로 APD — 경로 수는 이 포털이 아직 모음 밖")],
               acts=["esxcli storage nmp device list 로 LUN 마다 경로 2개 이상·PSP(Round Robin)·어레이 권장 설정 확인"])


@sc("stor", "s13", "SAN 패브릭 한쪽(FC·iSCSI 스위치) 장애", "A·B 패브릭 중 하나가 멈춤 — 모든 호스트가 경로 절반을 잃음")
def _s13(c):
    ds = [d for d in c.ds if not d["local"] and (d["array"] or "vmfs" in d["type"].lower())]
    if not ds:
        return "외장 블록(VMFS) 데이터스토어 없음"
    return out(f"VMFS {len(ds)}개", n=[N("pass", "패브릭 이중화면 계속"), N("warn", "모든 호스트가 같은 패브릭 하나에만 연결돼 있으면 전부 APD"),
                                       N("warn", "남은 경로로 몰려 지연 증가 가능")], acts=["호스트마다 HBA 두 개가 서로 다른 패브릭에 연결됐는지 확인"])


@sc("stor", "s14", "스토리지 컨트롤러 펌웨어 업그레이드", "컨트롤러를 한쪽씩 재부팅 — 경로 전환 동안 I/O 가 잠깐 멈춤")
def _s14(c):
    ds = [d for d in c.ds if not d["local"] and (d["array"] or d["remote"])]
    if not ds:
        return "외장 스토리지 데이터스토어 없음"
    d = max(ds, key=lambda d: d["on"])
    vv = [v for v in c.vms if v["vc"] == d["vc"] and v["name"] in d["vms"] and v["on"]]
    return out(d["array"] or d["remote"] or d["name"], vms=vmarks(vv, "pause", "컨트롤러 전환 — I/O 가 수 초~수십 초 멈춤"),
               n=[N("warn", "게스트 OS 디스크 타임아웃(Linux 180초·Windows 60초 권장)보다 짧으면 VM 은 계속"), N("warn", "DB 클러스터·하트비트가 짧은 앱은 장애 조치가 일어날 수 있음")],
               acts=["어레이 업그레이드 호환 매트릭스·VMware HCL 확인, 업무 외 시간에"])


@sc("stor", "s15", "로컬 디스크 고장(로컬 데이터스토어 PDL)", "호스트 로컬 디스크가 죽음 — 그 위 VM 은 복구 전까지 못 씀")
def _s15(c):
    loc = [d for d in c.ds if d["local"] and d["vms"]]
    if not loc:
        return OK("로컬 데이터스토어에 VM 없음")
    d = max(loc, key=lambda d: len(d["vms"]))
    return out(d["name"], [F("ds_apd", d["vc"], d["name"])], acts=["로컬 디스크 VM 은 공유 스토리지로 옮기거나 백업 주기 확인"])


@sc("stor", "s16", "작업 실수 — 데이터스토어 언마운트·LUN 매핑 해제", "운영 중인 LUN 을 실수로 내리거나 호스트 매핑을 뺌 → PDL")
def _s16(c):
    d = c.shared_ds()
    return out(d["name"], [F("ds_apd", d["vc"], d["name"])], n=[N("warn", "PDL 이면 HA(VMCP)가 VM 을 끄고 다른 호스트에서 켜려 하지만 다른 호스트도 못 보면 실패")],
               acts=["LUN 회수 전 '데이터스토어 언마운트 사전 점검'(VM·템플릿·하트비트·스크래치 사용 여부) 절차를 변경 절차서에"]) if d else NA


@sc("stor", "s17", "vSAN 호스트 유지보수 — 전체 데이터 이동", "유지보수 모드에서 '전체 데이터 이동'을 고르면 그 호스트 데이터를 다른 호스트로 모두 복사")
def _s17(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"], min_hosts=3)
    if not cl:
        return "vSAN 클러스터(3대 이상) 없음"
    h = c.hosts_of(cl)[0]
    return out(h["name"], [F("host_maint", h["vc"], h["name"])], n=[N("warn", "전체 데이터 이동은 시간이 오래 걸리고 남은 호스트에 공간이 필요 — 짧은 작업이면 '접근성 보장'"),
                                                                     N("warn", "호스트 3대 vSAN 은 전체 데이터 이동을 할 수 없음(복사본 둘 + 증인 자리 부족)")])


@sc("stor", "s18", "백업 저장소(NFS·백업용 데이터스토어) 장애", "백업이 저장되는 곳이 멈춤 — 백업 작업 실패·복원 불가")
def _s18(c):
    d = next((d for d in c.ds if "backup" in d["name"].lower() or "bak" in d["name"].lower()), None)
    if not d:
        return "이름에 backup 이 들어간 데이터스토어 없음"
    return out(d["name"], [F("ds_apd", d["vc"], d["name"])], n=[N("warn", "그동안 백업이 쌓이지 않음 — 이 기간에 장애가 겹치면 복원 시점이 오래됨")])


@sc("stor", "s19", "스크래치·스왑 위치 데이터스토어 장애", "호스트 스크래치(로그·코어 덤프)·VM 스왑 파일을 둔 데이터스토어가 사라짐")
def _s19(c):
    return out("호스트 스크래치·VM 스왑", n=[N("warn", "스크래치가 사라지면 호스트 로그가 메모리(ramdisk)로 가고 오래 쌓으면 꽉 참"),
                                           N("warn", "VM 스왑 파일 위치가 사라지면 그 VM 은 켤 수 없음(실행 중이면 스왑이 필요할 때 멈춤)")],
               acts=["호스트 ScratchConfig·OSDATA 위치와 클러스터 스왑 파일 정책(VM 과 같은 위치 권장) 확인"])


@sc("stor", "s20", "vVols VASA 공급자 장애", "VASA 공급자가 멈춤 — 실행 중 VM 은 계속, 전원·스냅숏·복제 같은 제어 작업 실패")
def _s20(c):
    ds = [d for d in c.ds if "vvol" in d["type"].lower()]
    if not ds:
        return "vVols 데이터스토어 없음"
    return svc(", ".join(d["name"] for d in ds), ["vVols VM 전원 켜기·스냅숏·복제·새 VM"], ["실행 중 VM I/O"], ["VASA 공급자 이중화·인증서 확인"])


@sc("stor", "s21", "스토리지 지연 급증(어레이 과부하)", "백업·리빌드가 몰려 지연이 수십 ms 로 — VM 이 느려짐")
def _s21(c):
    d = c.shared_ds()
    if not d:
        return NA
    vv = [v for v in c.vms if v["vc"] == d["vc"] and v["name"] in d["vms"] and v["on"]]
    return out(d["name"], vms=vmarks(vv, "pause", "스토리지 지연 급증 — 느려짐"), n=[N("warn", f"VM {len(vv)}대가 같은 데이터스토어 — 지연이 오래가면 앱 타임아웃")],
               acts=["성능 화면의 디스크 지연(장치·커널) 기준선과 SIOC·백업 시간대 분산 확인"])


@sc("stor", "s22", "vSAN 데이터스토어 가득 참", "vSAN 이 다 차서 새 쓰기를 못 함 — VM 멈춤, 리빌드도 불가")
def _s22(c):
    d = max((d for d in c.ds if "vsan" in d["type"].lower()), key=lambda d: d["used"], default=None)
    return out(f"{d['name']} ({d['used']}%)", [F("ds_full", d["vc"], d["name"])]) if d else "vSAN 데이터스토어 없음"


# ================================================================== 3. 물리 네트워크
def _sw(c, role=None):
    sws = ((c.W.get("phys") or {}).get("switches") or {})
    out_ = []
    hc: Counter = Counter()
    for hn, h in ((c.W.get("phys") or {}).get("hosts") or {}).items():
        for n in (h.get("nics") or {}).values():
            if n.get("switch"):
                hc[n["switch"]] += 1
    for n, s in sws.items():
        if role is None or str(s.get("role", "")).lower() in role:
            out_.append((n, s, hc.get(n, 0)))
    return sorted(out_, key=lambda x: -x[2])


@sc("net", "n01", "ToR(리프) 스위치 1대 장애", "호스트가 가장 많이 붙은 스위치가 멈춤 — 업링크 이중화·NSX BGP")
def _n01(c):
    s = _sw(c)
    return out(s[0][0], [F("switch_down", "", s[0][0])]) if s and s[0][2] else "스위치·결선 정보 없음"


@sc("net", "n02", "MLAG·vPC 한 쌍 전체 장애", "같은 쌍 두 대가 같이 멈춤(공통 버그·전원) — 그 랙 호스트 고립")
def _n02(c):
    s = _sw(c)
    for n, x, _ in s:
        if x.get("mlag"):
            pair = [m for m, y in ((c.W.get("phys") or {}).get("switches") or {}).items() if y.get("mlag") == x["mlag"]]
            return out(" + ".join(pair), [F("switch_down", "", m) for m in pair])
    return "MLAG·vPC 쌍 없음"


@sc("net", "n03", "스파인 1대 장애", "스파인 하나가 멈춤 — 리프의 위쪽 경로가 남은 스파인으로")
def _n03(c):
    s = _sw(c, ("spine", "core"))
    return out(s[0][0], [F("switch_down", "", s[0][0])]) if s else "스파인·코어 스위치 없음"


@sc("net", "n04", "스파인 전체 장애", "스파인이 모두 멈춤 — 리프 사이·외부 경로가 끊김")
def _n04(c):
    s = _sw(c, ("spine", "core"))
    return out(" + ".join(x[0] for x in s), [F("switch_down", "", x[0]) for x in s[:SIM.MAX_FAIL]]) if s else "스파인·코어 스위치 없음"


def _dev(c, kinds):
    return [d for d in ((c.W.get("phys") or {}).get("devices") or {}).values() if d.get("kind") in kinds]


@sc("net", "n05", "방화벽 1대 장애", "방화벽 한 대가 멈춤 — HA 쌍이면 대기 장비로 넘어감")
def _n05(c):
    d = _dev(c, ("firewall",))
    return out(d[0]["name"], [F("device_down", "", d[0]["name"])]) if d else "방화벽 정보 없음"


@sc("net", "n06", "방화벽·라우터 전체 장애", "외부로 나가는 장비가 모두 멈춤 — 북남(외부) 통신 끊김")
def _n06(c):
    d = _dev(c, ("firewall", "router"))
    return out(" + ".join(x["name"] for x in d), [F("device_down", "", x["name"]) for x in d]) if d else "방화벽·라우터 정보 없음"


@sc("net", "n07", "호스트 업링크(물리 NIC) 1개 장애", "케이블·SFP·스위치 포트 하나가 끊김")
def _n07(c):
    h = c.busiest_host()
    return out(h["name"], [F("uplink_loss", h["vc"], h["name"])]) if h else NA


@sc("net", "n08", "이미 업링크가 하나 죽은 호스트의 남은 업링크 장애", "이중화가 이미 깨진 호스트 — 남은 하나가 끊기면 고립")
def _n08(c):
    ph = (c.W.get("phys") or {}).get("hosts") or {}
    for hn, h in ph.items():
        nics = h.get("nics") or {}
        if len(nics) >= 2 and any(not n.get("up") for n in nics.values()) and any(n.get("up") for n in nics.values()):
            sw = next(n["switch"] for n in nics.values() if n.get("up") and n.get("switch"))
            return out(f"{hn} (남은 업링크 → {sw})", [F("switch_down", "", sw)], n=[N("fail", f"{hn} 은 업링크가 이미 하나 내려가 있음 — 지금 고쳐야 할 단일 장애점")])
    return OK("업링크가 하나만 살아 있는 호스트 없음") if ph else "결선 정보 없음"


@sc("net", "n09", "MLAG peer-link 장애(split-brain)", "두 스위치를 잇는 peer-link 가 끊김 — 보조 스위치가 MLAG 포트를 내림")
def _n09(c):
    s = _sw(c)
    for n, x, _ in s:
        if x.get("mlag"):
            pair = sorted(m for m, y in ((c.W.get("phys") or {}).get("switches") or {}).items() if y.get("mlag") == x["mlag"])
            return out(f"{x['mlag']} 보조 {pair[-1]}", [F("switch_down", "", pair[-1])],
                       n=[N("warn", "peer-keepalive 가 살아 있으면 보조 쪽만 MLAG 포트를 내림 — 호스트는 주 스위치 업링크로 계속"),
                          N("fail", "keepalive 도 끊기면 양쪽이 모두 주인이 되는 split-brain — 루프·MAC 흔들림")], acts=["peer-link 를 두 개 이상 포트로, keepalive 는 별도 경로로"])
    return "MLAG·vPC 쌍 없음"


@sc("net", "n10", "관리망(VLAN) 장애 — 클러스터 전체", "관리 VLAN 이 끊김 — 모든 호스트가 vCenter 와 끊기고 HA 하트비트가 격리 판정")
def _n10(c):
    cl = c.big_cluster(min_hosts=2)
    if not cl:
        return NA
    return out(cl["name"], n=[N("fail", f"vCenter 에서 호스트 {len(cl['hosts'])}대가 '응답 없음' — 관리·vMotion·백업·모니터링이 멈춤"),
                              N("warn" if cl["iso"] not in ("", "none", "clusterIsolationResponse") else "pass", f"격리 대응 '{cl['iso'] or '켜 둠'}' — 모든 호스트가 격리되면 다시 켤 곳이 없어 VM 은 대개 그대로 돎"),
                              N("pass", "VM 망이 다른 업링크·VLAN 이면 서비스는 계속")],
               marks={f"host:{cl['vc']}/{h}": "isolated" for h in cl["hosts"]}, acts=["관리망을 이중 스위치·이중 업링크로, HA 격리 주소를 관리망 게이트웨이 외에 하나 더"])


@sc("net", "n11", "vMotion 망 전체 장애", "모든 호스트의 vMotion VLAN 이 끊김 — DRS 균형·유지보수 비우기 불가")
def _n11(c):
    vv = [v for v in c.vms if v["on"]]
    return out(f"호스트 {len(c.hosts)}대", vms=vmarks(vv, "blocked", "vMotion 망 장애 — 옮길 수 없음"),
               n=[N("warn", "서비스는 계속, 이 동안 패치·하드웨어 교체 유지보수를 할 수 없음")]) if vv else NA


@sc("net", "n12", "vSAN 망 전체 장애", "vSAN VLAN 이 끊김 — 호스트마다 혼자 남아 대부분의 객체에 접근 불가")
def _n12(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"])
    if not cl:
        return "vSAN 클러스터 없음"
    vv = [v for v in c.vms if v["vc"] == cl["vc"] and v["cluster"] == cl["name"] and v["on"]]
    return out(cl["name"], vms=vmarks(vv, "io", "vSAN 망 장애 — 객체 접근 불가(I/O 멈춤)"), n=[N("fail", "vSAN 클러스터 파티션 — 거의 모든 VM 디스크 I/O 멈춤")],
               acts=["vSAN VMkernel 을 이중 업링크(액티브·스탠바이)·이중 스위치로"])


@sc("net", "n13", "MTU 불일치(점보 프레임)", "스위치 한 구간의 MTU 가 9000 이 아님 — 큰 패킷만 버려짐")
def _n13(c):
    vs = [x for x in c.clusters if x["vsan"]]
    return out("vSAN·vMotion·NSX 오버레이", n=[N("warn", "작은 패킷(핑)은 통과해 '연결은 되는데' vSAN 파티션·vMotion 실패·오버레이 통신 장애로 나타남"),
                                               N("warn" if vs else "pass", f"vSAN 클러스터 {len(vs)}개가 영향 대상" if vs else "vSAN 없음")],
               acts=["vmkping -d -s 8972 로 vSAN·vMotion VMkernel 사이 경로 MTU 확인(NSX TEP 은 1600 이상)"])


@sc("net", "n14", "브로드캐스트 스톰·STP 루프", "루프가 생겨 스위치 쌍 CPU·대역폭이 포화 — 그 스위치들이 사실상 멈춤")
def _n14(c):
    s = _sw(c)
    for n, x, _ in s:
        if x.get("mlag"):
            pair = [m for m, y in ((c.W.get("phys") or {}).get("switches") or {}).items() if y.get("mlag") == x["mlag"]]
            return out(" + ".join(pair), [F("switch_down", "", m) for m in pair], n=[N("warn", "VM 의 브리지·잘못된 NIC 팀 구성도 루프 원인 — vDS 는 STP 를 하지 않음")],
                       acts=["ESXi 쪽 포트는 PortFast(edge)+BPDU Guard, 스톰 컨트롤 임계 확인"])
    return out(s[0][0], [F("switch_down", "", s[0][0])]) if s else "스위치 정보 없음"


@sc("net", "n15", "업링크 대역폭 포화(백업·vMotion 몰림)", "백업 시간대에 업링크가 꽉 참 — 지연·패킷 손실")
def _n15(c):
    return out("업링크", n=[N("warn", "VM 지연·vSAN 지연이 같이 올라감 — 장애는 아니지만 업무 시간에 겹치면 체감 장애"),
                           N("pass", "NIOC(네트워크 I/O 제어)로 vSAN·관리 트래픽 몫을 보장하면 완화")], acts=["네트워크 트래픽 화면의 시간대별 사용률과 백업 시간 분산", "vDS NIOC 공유 값 확인"])


@sc("net", "n16", "같은 NIC 드라이버 전체 결함", "같은 NIC 드라이버·펌웨어를 쓰는 모든 호스트가 업링크를 잃음(드라이버 버그)")
def _n16(c):
    g: dict[str, list] = {}
    for h in c.hosts:
        for n in h["pnics"]:
            if n.get("driver"):
                g.setdefault(n["driver"], []).append(h)
                break
    if not g:
        return "NIC 드라이버 정보 없음"
    drv, hs = max(g.items(), key=lambda kv: len(kv[1]))
    return out(f"{drv} ({len(hs)}대)", [F("uplink_loss", h["vc"], h["name"]) for h in hs[:SIM.MAX_FAIL]],
               acts=[f"{drv} 드라이버·펌웨어 버전을 VMware HCL 과 제조사 권고에 맞추고, 같은 날 전부 바꾸지 말 것"])


@sc("net", "n17", "LACP 협상 실패", "스위치·vDS LACP 설정이 어긋나 LAG 멤버가 빠짐")
def _n17(c):
    return out("vDS LAG", n=[N("warn", "LAG 멤버가 하나 빠지면 대역폭 절반, 다 빠지면 그 포트그룹 VM 고립"), N("pass", "LACP 를 안 쓰고 '물리 NIC 부하 기반' 팀 구성이면 해당 없음")],
               acts=["vDS LACP 모드(active)·해시·스위치 port-channel 설정 일치 확인"])


@sc("net", "n18", "스위치 OS 업그레이드(한 대씩)", "ISSU 가 없는 스위치는 재부팅 — 그동안 그 스위치 업링크가 끊김")
def _n18(c):
    s = _sw(c, ("leaf", "tor", "access", ""))
    return out(s[0][0], [F("switch_down", "", s[0][0])], n=[N("warn", "두 번째 스위치는 첫 번째가 완전히 올라오고 MLAG 동기화가 끝난 뒤에")]) if s else "스위치 정보 없음"


@sc("net", "n19", "트렁크 VLAN 누락(포트그룹 하나)", "스위치 트렁크에서 VLAN 하나를 빼먹음 — 그 포트그룹 VM 만 통신 불가")
def _n19(c):
    cnt: Counter = Counter()
    for v in c.vms:
        for n in v["nets"]:
            x = c.nets.get((v["vc"], n)) or {}
            if x.get("vlan"):
                cnt[(v["vc"], n)] += v["on"]
    if not cnt:
        return "VLAN 포트그룹 정보 없음"
    (vc, pg), _ = cnt.most_common(1)[0]
    vv = [v for v in c.vms if v["vc"] == vc and pg in v["nets"] and v["on"]]
    return out(f"{pg} (VLAN {c.nets[(vc, pg)].get('vlan')})", vms=vmarks(vv, "net", f"포트그룹 {pg} VLAN 누락 — 통신 불가"),
               acts=["스위치 변경 뒤 vDS 상태 점검(VLAN·MTU 헬스 체크)을 켜 두세요"])


@sc("net", "n20", "대외 회선(인터넷·대외기관) 장애", "외부 라우터 쪽 회선이 끊김 — 대외 서비스·외부 연계")
def _n20(c):
    d = _dev(c, ("router",))
    return out(" + ".join(x["name"] for x in d), [F("device_down", "", x["name"]) for x in d]) if d else "라우터 정보 없음"


@sc("net", "n21", "VM IP 충돌", "같은 IP 를 쓰는 VM 이 둘 — 간헐적 통신 장애")
def _n21(c):
    seen: dict[str, list] = {}
    for v in c.vms:
        for ip in v["ips"][:4]:
            seen.setdefault(ip, []).append(v)
    dup = {ip: vs for ip, vs in seen.items() if len(vs) >= 2 and not ip.startswith(("169.254.", "127."))}
    if not dup:
        return out("VM IP", n=[N("pass", "VMware Tools 가 보고한 IP 중 겹치는 것 없음")])
    vv = [v for vs in dup.values() for v in vs]
    return out(f"겹치는 IP {len(dup)}개", vms=vmarks(vv, "net", "IP 충돌"), n=[N("fail", f"{ip}: {', '.join(x['name'] for x in vs)}") for ip, vs in list(dup.items())[:10]])


@sc("net", "n22", "코어 라우터 1대 장애", "라우터 이중화 중 하나가 멈춤 — 경로 재수렴")
def _n22(c):
    d = _dev(c, ("router",))
    return out(d[0]["name"], [F("device_down", "", d[0]["name"])]) if d else "라우터 정보 없음"


# ================================================================== 4. NSX
def _nsx_vms(c):
    return [v for v in c.vms if v["on"] and any(c.nsx_net(v["vc"], n) for n in v["nets"])]


def _mgr(c, kind="NSX Manager"):
    return c.mgmt(kind)


@sc("nsx", "x01", "Edge 노드 1대 장애", "Edge VM 하나가 멈춤 — 액티브·스탠바이 T0/T1 은 대기 Edge 로 전환(수 초)")
def _x01(c):
    if not c.W["edges"]:
        return "NSX Edge 없음"
    e = c.W["edges"][0]
    vm = next((v for v in c.vms if v["name"] == e["name"]), None)
    return out(e["name"], vms=vmarks([vm], "down", "Edge 노드 장애(가정)") if vm else [],
               n=[N("pass", "같은 Edge 클러스터에 다른 Edge 가 있으면 T0/T1 서비스(라우팅·NAT·LB)가 넘어감 — BGP 재수렴·세션 끊김 수 초"),
                  N("warn", "상태 저장 서비스(NAT·방화벽 세션)는 넘어가며 세션이 끊길 수 있음")])


@sc("nsx", "x02", "Edge 클러스터 전체 장애", "Edge 가 모두 멈춤 — 오버레이 VM 의 외부(북남) 통신·게이트웨이 서비스 중단")
def _x02(c):
    if not c.W["edges"]:
        return "NSX Edge 없음"
    ec = Counter(e["edge_cluster"] for e in c.W["edges"]).most_common(1)[0][0]
    vv = _nsx_vms(c)
    return out(ec, [F("edge_down", "", ec)], vms=vmarks(vv, "ext", "Edge 클러스터 장애 — 외부 통신 끊김"))


@sc("nsx", "x03", "Edge 가 가장 많은 호스트 장애", "Edge VM 이 몰린 호스트가 꺼짐 — HA 가 다시 켜는 동안 북남 통신")
def _x03(c):
    if not c.W["edges"]:
        return "NSX Edge 없음"
    moid = {(vc["name"], h.get("moid")): n for vc in c.W["vcenters"] for n, h in (vc["topo"].get("hosts") or {}).items()}
    cnt = Counter(next(((vc, n) for (vc, m), n in moid.items() if m == e["host_moid"]), ("", "")) for e in c.W["edges"])
    (vc, h), k = cnt.most_common(1)[0]
    return out(f"{h} (Edge {k}대)", [F("host_down", vc, h)]) if h else "Edge 호스트를 찾지 못함"


@sc("nsx", "x04", "T0 BGP 피어 1개 다운", "Edge 와 물리 라우터 사이 BGP 세션 하나가 끊김 — ECMP·다른 피어로 계속")
def _x04(c):
    b = (c.W.get("phys") or {}).get("bgp") or []
    if not b:
        return "BGP 정보 없음(NSX·네트워크 커넥터)"
    return out(f"{b[0].get('tier0', '')} ↔ {b[0].get('switch', '')}", n=[N("pass" if len(b) >= 2 else "fail", f"BGP 세션 {len(b)}개 중 1개 — " + ("남은 세션으로 계속" if len(b) >= 2 else "세션이 하나뿐이라 외부 통신 끊김")),
                                                                          N("warn", "BFD 가 없으면 끊김 감지가 hold timer(기본 180초)까지 늦어짐")], acts=["T0 BGP 에 BFD 를 켜고 피어를 리프 두 대에 나눠 두세요"])


@sc("nsx", "x05", "T0 BGP 전체 다운", "모든 BGP 세션이 끊김 — 오버레이 VM 의 외부 통신 끊김")
def _x05(c):
    vv = _nsx_vms(c)
    return out("T0 업링크 전체", vms=vmarks(vv, "ext", "T0 BGP 전체 다운 — 외부 통신 끊김"), n=[N("fail", f"오버레이 VM {len(vv)}대 외부 통신 끊김(동서 통신은 계속)" if vv else "오버레이 세그먼트 VM 을 찾지 못함 — NSX 세그먼트 포트그룹 이름 확인")])


def _nsxmgr(c, k, total=3):
    m = _mgr(c)
    tag = f"NSX Manager {k}/{len(m) or total}"
    lost = m[:k]
    quorum = k * 2 < (len(m) or total)
    n = [N("pass" if quorum else "fail", "과반이 남아 관리 계속" if quorum else "관리 클러스터 쿼럼 상실 — 정책·세그먼트·방화벽 규칙 변경, 새 VM 연결 구성 불가")]
    n += [N("pass", "데이터 경로(이미 설정된 세그먼트·분산 라우팅·분산 방화벽·Edge)는 호스트·Edge 에 내려가 있어 계속")]
    return out(tag, vms=vmarks(lost, "down", "NSX Manager 장애(가정)"), n=n, acts=["NSX Manager 3대를 서로 다른 호스트에(반선호도), 백업(SFTP) 성공 여부 확인"])


@sc("nsx", "x06", "NSX Manager 1대 장애", "관리 클러스터 3대 중 1대")
def _x06(c):
    return _nsxmgr(c, 1)


@sc("nsx", "x07", "NSX Manager 2대 장애(쿼럼 상실)", "3대 중 2대 — 관리 기능 멈춤")
def _x07(c):
    return _nsxmgr(c, 2)


@sc("nsx", "x08", "NSX Manager 전체 장애", "관리 클러스터 전체 — 복구는 백업에서")
def _x08(c):
    r = _nsxmgr(c, 3)
    r["notes"].append(N("fail", "새 VM 을 NSX 세그먼트에 연결하거나 방화벽 규칙을 바꿀 수 없음 — 복구는 SFTP 백업에서"))
    return r


@sc("nsx", "x09", "오버레이(TEP) 망 장애 — 클러스터", "호스트 TEP 사이 Geneve 통신이 끊김 — 다른 호스트 VM 과 오버레이 통신 불가")
def _x09(c):
    cl = c.big_cluster()
    vv = [v for v in _nsx_vms(c) if v["cluster"] == (cl or {}).get("name")]
    return out(cl["name"] if cl else "오버레이", vms=vmarks(vv, "net", "TEP 망 장애 — 오버레이 통신 끊김"),
               n=[N("fail" if vv else "warn", f"오버레이 VM {len(vv)}대 — 같은 호스트 안 VM 끼리만 통신" if vv else "오버레이 세그먼트 VM 을 찾지 못함")],
               acts=["TEP VLAN·MTU(1600 이상)·TEP 이중화(멀티 TEP) 확인"])


@sc("nsx", "x10", "분산 방화벽 규칙 실수(전체 차단)", "맨 아래 기본 규칙을 '차단'으로 바꾸거나 넓은 차단 규칙을 위에 둠")
def _x10(c):
    vv = _nsx_vms(c)
    return out("DFW", vms=vmarks(vv, "net", "DFW 전체 차단"), n=[N("fail", f"오버레이 VM {len(vv)}대 통신 차단 — 규칙은 즉시 모든 호스트에 반영"), N("warn", "VLAN 세그먼트 VM 도 DFW 적용 대상이면 같이 막힘")],
               acts=["DFW 변경은 '초안 저장·적용 전 검토', 관리 VM·NSX Manager 는 제외 목록에", "규칙 적용 기록(NSX 감사 로그)으로 되돌리기"])


@sc("nsx", "x11", "NSX 업그레이드(Edge 롤링)", "Edge 를 하나씩 업그레이드 — 전환 때마다 북남 통신이 잠깐 끊김")
def _x11(c):
    vv = _nsx_vms(c)
    return out("NSX", vms=vmarks(vv, "pause", "Edge 전환 — 북남 통신 잠깐 끊김"), n=[N("warn", "Edge 마다 한 번씩 수 초 전환 — 세션 기반 앱(DB 연결·VPN)은 재접속"),
                                                                                 N("warn", "업그레이드 순서: Edge → 호스트 → Manager(NSX 업그레이드 코디네이터)")])


@sc("nsx", "x12", "T1 게이트웨이 서비스(NAT·LB·VPN) 장애", "T1 의 상태 저장 서비스가 멈춤 — 그 T1 뒤 서비스")
def _x12(c):
    return svc("T1 서비스", ["NAT 로 나가는 통신·T1 로드밸런서·IPsec VPN"], ["분산 라우팅(DR)으로 가는 동서 통신"], ["T1 서비스 라우터(SR)가 액티브·스탠바이 Edge 두 대에 있는지 확인"])


@sc("nsx", "x13", "NSX 인증서 만료", "NSX Manager·클러스터 인증서가 만료 — vCenter 연동·API·UI 접속 실패")
def _x13(c):
    ce = [x for x in c.W["certs"] if "nsx" in (str(x.get("system", "")) + str(x.get("kind", ""))).lower()]
    n = [N("fail" if x.get("band") in ("expired", "crit") else "warn", f"{x.get('name')}: {x.get('days_left')}일 남음") for x in ce[:5]] or [N("pass", "임박한 NSX 인증서 없음(수집 기준)")]
    return out("NSX 인증서", n=n + [N("warn", "만료되면 vCenter 플러그인·Compute Manager·자동화 도구 연결이 끊김(데이터 경로는 계속)")])


@sc("nsx", "x14", "VPC 외부 연결 장애", "VPC 의 외부(공용) 서브넷이 쓰는 T0·Edge 가 끊김")
def _x14(c):
    return svc("NSX VPC", ["VPC 공용 서브넷의 외부 통신·외부 IP(NAT)"], ["VPC 안 동서 통신"], ["VPC 외부 연결 게이트웨이·Edge 클러스터 이중화 확인"])


@sc("nsx", "x15", "Edge 업링크 한쪽(ToR) 장애", "BGP 피어가 붙은 리프 하나가 멈춤 — 다른 리프 피어로 계속되는지")
def _x15(c):
    b = (c.W.get("phys") or {}).get("bgp") or []
    if not b:
        return "BGP 정보 없음"
    sw = Counter(x.get("switch") for x in b if x.get("switch")).most_common(1)
    return out(sw[0][0], [F("switch_down", "", sw[0][0])]) if sw else "BGP 피어 스위치 정보 없음"


@sc("nsx", "x16", "NSX DHCP 서버 장애", "세그먼트 DHCP 를 주는 게이트웨이·Edge 가 멈춤")
def _x16(c):
    return svc("NSX DHCP", ["새로 켜지거나 임대가 끝난 VM 의 IP 받기"], ["이미 IP 를 받은 VM(임대 기간 동안)"], ["DHCP 를 쓰는 세그먼트·임대 시간 확인, 중요 서버는 고정 IP"])


@sc("nsx", "x17", "Geneve MTU 부족", "물리망 MTU 가 1600 미만 — 큰 패킷의 오버레이 통신 실패")
def _x17(c):
    return out("오버레이", n=[N("warn", "핑은 되지만 파일 전송·DB 같은 큰 패킷 통신이 실패 — '되다 말다' 장애"), N("pass", "MTU 9000 권장(최소 1600)")],
               acts=["호스트 TEP 사이 vmkping ++netstack=vxlan -d -s 1572 로 확인"])


@sc("nsx", "x18", "NSX-vCenter 연결(Compute Manager) 끊김", "NSX Manager 가 vCenter 와 연결을 잃음")
def _x18(c):
    return svc("Compute Manager", ["새 호스트 준비·Edge 배포·VM 태그 기반 그룹 갱신"], ["이미 준비된 호스트의 데이터 경로·기존 방화벽 규칙"],
               ["vCenter 인증서·서비스 계정 비밀번호 바뀐 뒤 Compute Manager 재등록 여부"])


@sc("nsx", "x19", "Edge 자원 포화(CPU·세션)", "Edge VM CPU 가 포화 — 북남 지연·패킷 손실")
def _x19(c):
    return out("Edge", n=[N("warn", "Edge 크기(Medium·Large)에 비해 처리량·NAT 세션이 많으면 지연"), N("pass", "Edge 클러스터 확장·Large 이상·베어메탈 Edge 로 완화")],
               acts=["Edge CPU·데이터 경로 코어 사용률 기준선 확인"])


@sc("nsx", "x20", "NSX 백업 실패 상태에서 Manager 손상", "백업이 오래됐는데 Manager 클러스터를 잃음 — 마지막 백업 이후 변경이 사라짐")
def _x20(c):
    b = {k: v for k, v in (c.W.get("appliance_backup") or {}).items() if "nsx" in k.lower() or "nsx" in str(v.get("product", "")).lower()}
    if not b:
        return out("NSX 백업", n=[N("warn", "NSX 백업 상태를 모름 — SFTP 백업 설정·최근 성공 시각 확인 필요")])
    import time as _t
    n = []
    for k, v in b.items():
        age = (_t.time() - (v.get("last_success") or 0)) / 86400 if v.get("last_success") else None
        n.append(N("fail" if age is None or age > 2 else "pass", f"{k}: 마지막 성공 {'없음' if age is None else f'{age:.1f}일 전'}"))
    return out("NSX 백업", n=n)


@sc("nsx", "x21", "Edge 두 대가 같은 호스트", "Edge 클러스터 멤버가 한 호스트에 몰림 — 호스트 하나로 Edge 전부")
def _x21(c):
    by: dict[str, set] = {}
    for e in c.W["edges"]:
        by.setdefault(e["edge_cluster"], set()).add(e["host_moid"])
    bad = [(ec, hs) for ec, hs in by.items() if len(hs) == 1 and sum(1 for e in c.W["edges"] if e["edge_cluster"] == ec) >= 2]
    if not c.W["edges"]:
        return "NSX Edge 없음"
    if not bad:
        return out("Edge 배치", n=[N("pass", "Edge 클러스터마다 Edge 가 서로 다른 호스트에 있음")])
    moid = {h.get("moid"): (vc["name"], n) for vc in c.W["vcenters"] for n, h in (vc["topo"].get("hosts") or {}).items()}
    vc, h = moid.get(next(iter(bad[0][1])), ("", ""))
    return out(f"{bad[0][0]} @ {h}", [F("host_down", vc, h)] if h else [], n=[N("fail", f"Edge 클러스터 {bad[0][0]} 의 Edge 가 모두 {h} 에 있음")])


# ================================================================== 5. 관리·공통 서비스
@sc("mgmt", "m01", "vCenter 업그레이드·중단", "vCenter 가 멈춤 — 관리·DRS·자동화가 멈추고 HA 는 계속")
def _m01(c):
    vc = c.W["vcenters"][0] if c.W["vcenters"] else None
    return out(vc["name"], [F("vcenter_upgrade", vc["name"], vc["name"])]) if vc else NA


@sc("mgmt", "m02", "vCenter 머신 인증서 만료", "vCenter 인증서가 만료 — 브라우저·API·연동 제품 접속 실패")
def _m02(c):
    ce = [x for x in c.W["certs"] if "vcenter" in (str(x.get("kind", "")) + str(x.get("system", ""))).lower()]
    return svc("vCenter 인증서", ["vSphere Client 접속(경고)·인증서 검증하는 연동(NSX Compute Manager·SRM·백업·VCF Operations·자동화 도구)"],
               ["실행 중 VM·HA·vSAN 데이터 경로"], ["인증서 만료 달력 확인, 교체는 vSphere Client 인증서 관리 또는 SDDC Manager 로"],
               sev="fail" if any(x.get("band") in ("expired", "crit") for x in ce) else "warn")


@sc("mgmt", "m03", "vCenter 디스크(/storage/log·DB) 가득 참", "vCenter 파티션이 차서 vpxd 서비스가 멈춤")
def _m03(c):
    vc = c.W["vcenters"][0] if c.W["vcenters"] else None
    return out(vc["name"], [F("vcenter_upgrade", vc["name"], vc["name"])], n=[N("warn", "디스크 정리·파티션 확장 뒤 서비스 재시작 필요 — 그동안 관리 중단")],
               acts=["vCenter 파티션 사용률(VAMI·VCF Operations) 경고를 80% 로"]) if vc else NA


@sc("mgmt", "m04", "AD·LDAP(ID 원천) 장애", "vCenter·NSX 가 쓰는 AD 가 응답 없음")
def _m04(c):
    return svc("AD·LDAP", ["AD 계정 로그인(vCenter·NSX·SDDC Manager·VCF Operations)·AD 서비스 계정을 쓰는 자동화"], ["로컬 계정(administrator@vsphere.local 등) 로그인·실행 중 VM"],
               ["비상용 로컬 관리자 계정과 비밀번호 보관 위치 확인", "ID 원천에 도메인 컨트롤러 2대 이상"])


@sc("mgmt", "m05", "DNS 장애", "내부 DNS 가 응답 없음 — VCF 구성요소는 FQDN 으로 서로 찾음")
def _m05(c):
    return svc("DNS", ["vCenter 의 호스트 재연결·호스트 추가·vLCM·SDDC Manager 작업·NSX 연동·인증서 검증·AD 로그인", "재부팅한 관리 어플라이언스 서비스 기동"],
               ["실행 중 VM·이미 구성된 HA·vSAN 데이터 경로·VM 사이 IP 통신"], ["DNS 서버 2대 이상(정방향·역방향), 관리 어플라이언스마다 DNS 두 개 설정"], sev="fail")


@sc("mgmt", "m06", "NTP 장애·시간 틀어짐", "시간 원천이 멈춰 구성요소 시간이 서로 어긋남")
def _m06(c):
    return svc("NTP", ["5분 넘게 어긋나면 SSO·AD(Kerberos) 로그인 실패·인증서 검증 오류", "vSAN 상태 경고·로그 시간 비교 불가"], ["실행 중 VM"],
               ["NTP 서버 2대 이상·호스트·어플라이언스 모두 같은 원천", "VM 은 호스트 시간 동기화와 게스트 NTP 를 같이 켜지 말 것"])


@sc("mgmt", "m07", "SDDC Manager 장애", "VCF 수명 주기 관리가 멈춤")
def _m07(c):
    vv = c.mgmt("SDDC Manager")
    return svc("SDDC Manager", ["업그레이드·패치·워크로드 도메인 작업·호스트 추가·비밀번호·인증서 교체"], ["실행 중 워크로드·vCenter·NSX 관리"],
               ["SDDC Manager 백업(SFTP) 성공 여부"], vms=vmarks(vv, "down", "SDDC Manager 장애(가정)"))


@sc("mgmt", "m08", "VCF Operations 장애", "모니터링·용량 분석 플랫폼이 멈춤")
def _m08(c):
    return svc("VCF Operations", ["경고·대시보드·용량 분석·컴플라이언스 — 장애를 늦게 알게 됨"], ["실행 중 워크로드·DRS·HA"],
               ["VCF Operations 클러스터 노드 이중화·이 포털의 독립 알림 경로 확인"], vms=vmarks(c.mgmt("VCF Operations"), "down", "VCF Operations 장애(가정)"))


@sc("mgmt", "m09", "VCF Logs(로그 수집) 장애", "중앙 로그 수집이 멈춤 — 감사·장애 분석 공백")
def _m09(c):
    return svc("VCF Logs", ["로그 수집·검색·감사 기록 — 장애 원인 분석 근거가 사라짐"], ["ESXi 로컬 로그(용량 한도 안)·실행 중 워크로드"],
               ["로그 전달 대상 2곳(VCF Logs + SIEM) 여부"], vms=vmarks(c.mgmt("VCF Logs"), "down", "VCF Logs 장애(가정)"))


@sc("mgmt", "m10", "VCF Automation 장애", "셀프 서비스 포털·자동화가 멈춤")
def _m10(c):
    return svc("VCF Automation", ["셀프 서비스 VM·네임스페이스 요청·블루프린트 배포"], ["이미 배포된 워크로드"], ["자동화 의존 업무(신규 서비스 개통)의 대체 절차"],
               vms=vmarks(c.mgmt("VCF Automation"), "down", "VCF Automation 장애(가정)"))


@sc("mgmt", "m11", "키 관리 서버(KMS) 장애", "외부 KMS 가 응답 없음 — 암호화 VM·vSAN 암호화")
def _m11(c):
    return svc("KMS", ["새 암호화 작업(VM 암호화·키 교체)", "키 지속성(Key Persistence)이 꺼진 호스트는 재부팅 후 암호화된 VM·vSAN 디스크를 열지 못할 수 있음"],
               ["실행 중 암호화 VM·호스트가 메모리에 키를 가진 동안의 I/O"], ["KMS 클러스터 2대 이상 또는 vSphere Native Key Provider 백업, 키 지속성 설정 확인"], sev="fail")


@sc("mgmt", "m12", "SFTP 백업 대상 장애", "vCenter·NSX·SDDC Manager 파일 백업을 받는 SFTP 가 멈춤")
def _m12(c):
    return svc("SFTP 백업", ["관리 구성요소 파일 기반 백업 — 이 기간에 관리 구성요소가 손상되면 오래된 백업으로 복원"], ["실행 중 모든 것"],
               ["백업 성공 알림·SFTP 서버를 관리 클러스터 밖에"])


@sc("mgmt", "m13", "알림 경로(SMTP·SNMP·웹훅) 장애", "메일·문자·웹훅 알림이 나가지 않음 — 장애를 아무도 모름")
def _m13(c):
    return svc("알림 경로", ["장애 알림 전달 — 감지는 되지만 사람이 모름"], ["수집·탐지"], ["알림 경로 2개(메일 + 메신저·문자) 와 '알림 보내기 시험' 주기"])


@sc("mgmt", "m14", "온라인 저장소(Depot)·프록시 장애", "패치·업그레이드 번들을 받을 수 없음")
def _m14(c):
    return svc("Depot·프록시", ["업그레이드 번들 내려받기·vLCM 온라인 저장소 동기화·HCL 갱신"], ["실행 중 모든 것"], ["망분리 환경은 오프라인 Depot 준비 여부"], sev="pass")


@sc("mgmt", "m15", "라이선스 만료", "VCF·vSphere 라이선스 기간이 끝남")
def _m15(c):
    return svc("라이선스", ["만료 뒤 새 호스트 추가·일부 기능(버전에 따라 VM 전원 켜기 등)이 막힐 수 있음"], ["대개 실행 중 VM"],
               ["라이선스 관리 화면의 만료일·갱신 일정, 만료 90·30일 전 알림"])


@sc("mgmt", "m16", "ESXi 호스트 인증서 만료", "호스트 인증서가 만료 — vCenter 연결이 끊길 수 있음")
def _m16(c):
    return svc("ESXi 인증서", ["vCenter 와 호스트 연결(인증서 검증)·호스트 관리 작업"], ["실행 중 VM·HA"], ["VMCA 모드면 자동 갱신 상태, 사용자 인증서면 만료 달력"])


@sc("mgmt", "m17", "vCenter VM 이 있는 호스트 장애", "vCenter 어플라이언스가 올라간 호스트가 꺼짐 — HA 가 vCenter 를 다시 켤 때까지 관리 불가")
def _m17(c):
    v = (c.mgmt("vCenter") or [None])[0]
    if not v:
        return "vCenter VM 을 인벤토리에서 찾지 못함(다른 vCenter 가 관리하거나 이름 규칙이 다름)"
    return out(f"{v['name']} @ {v['host']}", [F("host_down", v["vc"], v["host"])], acts=["vCenter VM 의 HA 재시작 우선순위를 '최고'로"])


@sc("mgmt", "m18", "관리 클러스터 전체 장애", "vCenter·NSX Manager·SDDC Manager 가 있는 클러스터가 멈춤")
def _m18(c):
    vs = [v for v in c.vms if v["mgmt"] in ("vCenter", "NSX Manager", "SDDC Manager")]
    if not vs:
        return "관리 VM 을 찾지 못함"
    vc, cl = Counter((v["vc"], v["cluster"]) for v in vs).most_common(1)[0][0]
    return out(cl, [F("cluster_down", vc, cl)], n=[N("fail", "관리 구성요소가 모두 멈춤 — 워크로드 도메인은 계속 돌지만 관리·변경 불가")])


@sc("mgmt", "m19", "관리자 비밀번호 만료(administrator@vsphere.local 등)", "SSO 관리자·서비스 계정 비밀번호가 만료")
def _m19(c):
    return svc("관리자 계정", ["그 계정을 쓰는 연동(백업·모니터링·자동화)·로그인"], ["실행 중 모든 것"],
               ["SSO 비밀번호 만료 정책(기본 90일)·서비스 계정 만료일·SDDC Manager 비밀번호 교체 일정"])


@sc("mgmt", "m20", "이 포털(VCF AIOps) 장애", "관제 포털이 멈춤 — 수집·탐지·알림 공백")
def _m20(c):
    return svc("VCF AIOps", ["로그·이벤트 수집·이상징후·알림·모바일 알림"], ["vCenter·VCF Operations 자체 경고"],
               ["포털 서비스 상태(heartbeat)를 다른 시스템(VCF Operations·외부 감시)이 감시하는지 확인"])


@sc("mgmt", "m21", "Syslog 수집기 장애", "ESXi·스위치·NSX syslog 를 받는 곳이 멈춤")
def _m21(c):
    return svc("Syslog", ["원격 로그 저장 — ESXi 는 로컬 버퍼(기본 수 MB)만큼만 보관"], ["실행 중 모든 것"], ["syslog 대상 2곳·TCP/TLS 사용·로컬 보관 크기"])


@sc("mgmt", "m22", "vCenter VM 데이터스토어 장애", "vCenter 가 놓인 데이터스토어가 APD — vCenter 가 멈춤")
def _m22(c):
    v = (c.mgmt("vCenter") or [None])[0]
    if not v:
        return "vCenter VM 을 찾지 못함"
    vc = next(x for x in c.W["vcenters"] if x["name"] == v["vc"])
    ds = ((vc["topo"].get("vms") or {}).get(v["name"]) or {}).get("datastores") or []
    return out(f"{ds[0]} (vCenter)", [F("ds_apd", v["vc"], ds[0])]) if ds else "vCenter 데이터스토어를 모름"


# ================================================================== 6. 쿠버네티스
def _k(c):
    return c.P["vks"][0] if c.P["vks"] else None


def _s(c):
    return c.P["supervisors"][0] if c.P["supervisors"] else None


@sc("k8s", "k01", "Supervisor 컨트롤 플레인 장애", "Supervisor API 가 멈춤 — VKS·vSphere Pod 수명 주기")
def _k01(c):
    s = _s(c)
    return out(s["name"], [F("sup_down", s["vcenter"], s["name"])]) if s else "Supervisor 없음"


@sc("k8s", "k02", "Supervisor 업그레이드", "컨트롤 플레인 VM 롤링 교체 — API 잠깐씩 끊김")
def _k02(c):
    s = _s(c)
    return out(s["name"], [F("sup_upgrade", s["vcenter"], s["name"])]) if s else "Supervisor 없음"


@sc("k8s", "k03", "Supervisor 컨트롤 플레인 VM 호스트 장애", "컨트롤 플레인 VM 한 대가 있는 호스트가 꺼짐")
def _k03(c):
    s = _s(c)
    if not s or not s["cp"]:
        return "Supervisor 컨트롤 플레인 VM 을 찾지 못함"
    return out(s["cp"][0]["host"], [F("host_down", s["vcenter"], s["cp"][0]["host"])])


@sc("k8s", "k04", "Supervisor 컨트롤 플레인 VM 2대의 호스트 장애", "호스트 2대가 같이 꺼져 컨트롤 플레인 과반 상실")
def _k04(c):
    s = _s(c)
    if not s or len(s["cp"]) < 2:
        return "Supervisor 컨트롤 플레인 VM 2대 이상을 찾지 못함"
    hs = list(dict.fromkeys(x["host"] for x in s["cp"]))[:2]
    return out(" + ".join(hs), [F("host_down", s["vcenter"], h) for h in hs])


@sc("k8s", "k05", "VKS 컨트롤 플레인 장애", "VKS 클러스터의 컨트롤 플레인 노드가 모두 멈춤")
def _k05(c):
    k = _k(c)
    return out(k["cluster"], [F("vks_cp_down", "", k["cluster"])]) if k else "VKS 클러스터 없음"


@sc("k8s", "k06", "VKS 롤링 업그레이드", "노드를 한 대씩 새 노드로 교체")
def _k06(c):
    k = _k(c)
    return out(k["cluster"], [F("vks_upgrade", "", k["cluster"])]) if k else "VKS 클러스터 없음"


@sc("k8s", "k07", "Pod 가 가장 많은 워커 노드 장애", "워커 하나가 멈춤 — 그 노드 Pod 를 다른 노드로")
def _k07(c):
    k = _k(c)
    w = max((n for n in (k or {}).get("nodes", []) if not n["cp"]), key=lambda n: n["pods"], default=None)
    return out(w["name"], [F("node_down", "", f"{k['cluster']}/{w['name']}")]) if w else "VKS 워커 노드 없음"


@sc("k8s", "k08", "워커 노드 전체 장애", "모든 워커가 멈춤 — 일반 워크로드가 갈 곳이 없음")
def _k08(c):
    k = _k(c)
    ws = [n for n in (k or {}).get("nodes", []) if not n["cp"]]
    return out(f"워커 {len(ws)}대", [F("node_down", "", f"{k['cluster']}/{n['name']}") for n in ws[:SIM.MAX_FAIL]]) if ws else "VKS 워커 노드 없음"


@sc("k8s", "k09", "컨트롤 플레인 노드 1대 장애", "3대 중 1대 — 쿼럼 유지")
def _k09(c):
    k = _k(c)
    cp = [n for n in (k or {}).get("nodes", []) if n["cp"]]
    return out(cp[0]["name"], [F("node_down", "", f"{k['cluster']}/{cp[0]['name']}")]) if cp else "VKS 컨트롤 플레인 노드 정보 없음"


@sc("k8s", "k10", "컨트롤 플레인 노드 2대 장애", "3대 중 2대 — 쿼럼 상실")
def _k10(c):
    k = _k(c)
    cp = [n for n in (k or {}).get("nodes", []) if n["cp"]]
    return out(" + ".join(n["name"] for n in cp[:2]), [F("node_down", "", f"{k['cluster']}/{n['name']}") for n in cp[:2]]) if len(cp) >= 2 else "컨트롤 플레인 노드 2대 이상 없음"


@sc("k8s", "k11", "VKS 노드가 가장 많은 호스트 장애", "한 호스트에 몰린 노드가 같이 꺼짐")
def _k11(c):
    cnt = Counter((n["vcenter"], n["host"]) for k in c.P["vks"] for n in k["nodes"] if n["host"])
    if not cnt:
        return "VKS 노드 VM 을 찾지 못함"
    (vc, h), m = cnt.most_common(1)[0]
    return out(f"{h} (노드 {m}대)", [F("host_down", vc, h)])


@sc("k8s", "k12", "이미지 레지스트리(Harbor) 장애", "컨테이너 이미지를 받을 수 없음")
def _k12(c):
    it, pods = workloads(c, "risk", "실행 중 Pod 는 계속 — 다시 뜨거나 새로 배포하면 이미지를 못 받아 ImagePullBackOff(노드에 캐시 없으면)")
    r = out("Harbor", items=it, pods=pods, acts=["Harbor 이중화·이미지 캐시(노드)·imagePullPolicy(IfNotPresent) 확인"])
    r["notes"] = [N("warn", f"워크로드 {len(it)}개 — 배포·확장·재시작이 이미지 받기에서 멈춤")]
    return r if it else "VKS 워크로드 정보 없음"


@sc("k8s", "k13", "VKS 클러스터 인증서 만료", "kube API·etcd 인증서가 만료 — kubectl·컨트롤러 통신 실패")
def _k13(c):
    ce = [x for x in c.W["certs"] if any(k in (str(x.get("kind", "")) + str(x.get("system", ""))).lower() for k in ("api", "etcd", "vks", "kube"))]
    n = [N("fail" if x.get("band") in ("expired", "crit") else "warn", f"{x.get('system')} {x.get('kind')}: {x.get('days_left')}일") for x in ce[:5]] or [N("pass", "임박한 VKS 인증서 없음(수집 기준)")]
    return out("VKS 인증서", n=n + [N("warn", "만료되면 API 서버·컨트롤러가 통신 못 해 Pod 스케줄링·자동 복구가 멈춤(실행 중 Pod 는 계속)")],
               acts=["VKS 는 업그레이드(노드 교체) 때 인증서가 갱신됨 — 1년 넘게 업그레이드 안 한 클러스터 확인"])


@sc("k8s", "k14", "VKS 노드 데이터스토어 장애", "노드 VM 이 가장 많이 놓인 데이터스토어가 APD")
def _k14(c):
    cnt: Counter = Counter()
    for k in c.P["vks"]:
        for n in k["nodes"]:
            vc = next((x for x in c.W["vcenters"] if x["name"] == n["vcenter"]), None)
            for d in (((vc or {}).get("topo") or {}).get("vms", {}).get(n["name"]) or {}).get("datastores") or []:
                cnt[(n["vcenter"], d)] += 1
    if not cnt:
        return "VKS 노드 VM 을 찾지 못함"
    (vc, d), m = cnt.most_common(1)[0]
    return out(f"{d} (노드 {m}대)", [F("ds_apd", vc, d)])


@sc("k8s", "k15", "CNI(Antrea·Calico) 장애", "Pod 네트워크 에이전트가 멈춤 — Pod 사이 통신 불가")
def _k15(c):
    it, pods = workloads(c, "stop", "Pod 네트워크 끊김 — 서비스 사이 호출 실패")
    r = out("CNI", items=it, pods=pods, acts=["CNI DaemonSet 상태·버전, 노드 재부팅 뒤 CNI 정상 기동 확인"])
    r["notes"] = [N("fail", f"워크로드 {len(it)}개 통신 불가")]
    return r if it else "VKS 워크로드 정보 없음"


@sc("k8s", "k16", "CSI(CNS 볼륨) 장애", "vSphere CSI 가 볼륨을 붙이지 못함 — 상태 저장 Pod 재배치 불가")
def _k16(c):
    it, pods = workloads(c, "risk", "실행 중이면 계속 — 노드를 옮기면 볼륨을 못 붙여 Pending", pred=lambda k, w: w["kind"] == "sts")
    r = out("vSphere CSI", items=it, pods=pods)
    r["notes"] = [N("warn", f"StatefulSet {len(it)}개 — 재배치·확장 때 볼륨 연결 실패"), N("pass", "상태 없는(Deployment) 워크로드는 영향 적음")]
    return r


@sc("k8s", "k17", "네임스페이스 자원 한도 초과", "vSphere 네임스페이스 CPU·메모리·스토리지 한도에 닿음")
def _k17(c):
    return svc("네임스페이스 한도", ["새 Pod·노드 추가·VKS 확장"], ["실행 중 Pod"], ["네임스페이스 한도와 실제 요청량 비교(VKS 확장 전)"])


@sc("k8s", "k18", "작업 실수 — vSphere 네임스페이스 삭제", "네임스페이스를 지우면 그 안의 VKS 클러스터·vSphere Pod·PVC 가 함께 삭제")
def _k18(c):
    s = _s(c)
    if not s or not s["namespaces"]:
        return "vSphere 네임스페이스 정보 없음"
    ns = s["namespaces"][0]
    it, pods = workloads(c, "stop", f"네임스페이스 {ns} 삭제 — 클러스터째 사라짐(복구는 백업에서)", pred=lambda k, w: k["cluster"].split("/")[0] == ns)
    r = out(ns, items=it, pods=pods, acts=["네임스페이스 삭제 권한을 최소화, Velero 등 쿠버네티스 백업 확인"])
    r["notes"] = [N("fail", f"네임스페이스 {ns} 안 VKS 워크로드 {len(it)}개·PVC 삭제 — 되돌릴 수 없음")]
    return r


@sc("k8s", "k19", "Ingress(Contour)·L7 장애", "Ingress 컨트롤러가 멈춤 — HTTP 진입이 막힘")
def _k19(c):
    return svc("Ingress", ["Ingress 로 들어오는 HTTP(S) 서비스"], ["LoadBalancer 타입 서비스·클러스터 안 통신"], ["Ingress 컨트롤러 replicas ≥ 2·노드 분산"])


@sc("k8s", "k20", "vSphere Pod 가 있는 호스트 장애", "vSphere Pod(CRX)가 놓인 호스트가 꺼짐")
def _k20(c):
    s = _s(c)
    if not s or not s["pods"]:
        return "vSphere Pod 없음"
    h = Counter(p["host"] for p in s["pods"]).most_common(1)[0][0]
    return out(h, [F("host_down", s["vcenter"], h)])


@sc("k8s", "k21", "kube API 로드밸런서(VIP) 장애", "Supervisor·VKS API VIP 를 주는 NSX·Avi LB 가 멈춤")
def _k21(c):
    return svc("API VIP", ["kubectl·CI/CD·AKO 등 API 를 쓰는 도구"], ["실행 중 Pod·클러스터 안 통신"], ["API VIP 를 주는 LB(Avi·NSX) 이중화 확인"])


@sc("k8s", "k22", "VKS 콘텐츠 라이브러리 동기화 실패", "노드 이미지(VKr)를 받지 못함 — 새 버전 배포·업그레이드 불가")
def _k22(c):
    return svc("콘텐츠 라이브러리", ["VKS 새 클러스터·업그레이드·노드 교체(새 이미지 필요 시)"], ["실행 중 클러스터"], ["구독 라이브러리 동기화 상태·망분리 환경 로컬 라이브러리"], sev="pass")


# ================================================================== 7. 로드밸런서(Avi)
def _a(c):
    return c.P["avi"][0] if c.P["avi"] else None


def _vs_on(a, se):
    return sum(1 for v in a["vs"] if se in (v.get("ses") or [])) or len(next((x for x in a["se"] if x["name"] == se), {}).get("vs") or [])


@sc("lb", "a01", "가상 서비스가 가장 많은 SE 장애", "Service Engine 하나가 멈춤")
def _a01(c):
    a = _a(c)
    if not a or not a["se"]:
        return "Avi SE 없음"
    s = max(a["se"], key=lambda x: _vs_on(a, x["name"]))
    return out(s["name"], [F("avi_se_down", "", f"{a['name']}/{s['name']}")])


@sc("lb", "a02", "SE 그룹 전체 장애", "SE 그룹의 SE 가 모두 멈춤")
def _a02(c):
    a = _a(c)
    if not a or not a["se"]:
        return "Avi SE 없음"
    g = Counter(x.get("group", "") for x in a["se"]).most_common(1)[0][0]
    ss = [x for x in a["se"] if x.get("group", "") == g]
    return out(f"{g} (SE {len(ss)})", [F("avi_se_down", "", f"{a['name']}/{x['name']}") for x in ss[:SIM.MAX_FAIL]])


@sc("lb", "a03", "컨트롤러 1대 장애", "3대 중 1대")
def _a03(c):
    a = _a(c)
    return out(a["controllers"][0]["name"], [F("avi_ctrl_down", "", f"{a['name']}/{a['controllers'][0]['name']}")]) if a and a["controllers"] else "Avi 컨트롤러 정보 없음"


@sc("lb", "a04", "컨트롤러 2대 장애(쿼럼 상실)", "3대 중 2대")
def _a04(c):
    a = _a(c)
    if not a or len(a["controllers"]) < 2:
        return "Avi 컨트롤러 2대 이상 없음"
    return out(" + ".join(x["name"] for x in a["controllers"][:2]), [F("avi_ctrl_down", "", f"{a['name']}/{x['name']}") for x in a["controllers"][:2]])


@sc("lb", "a05", "컨트롤러 전체 장애", "컨트롤러 클러스터 전체 — SE 는 마지막 구성으로 계속")
def _a05(c):
    a = _a(c)
    if not a or not a["controllers"]:
        return "Avi 컨트롤러 정보 없음"
    return out("컨트롤러 전체", [F("avi_ctrl_down", "", f"{a['name']}/{x['name']}") for x in a["controllers"]])


@sc("lb", "a06", "SE 가 있는 호스트 장애", "SE VM 이 놓인 호스트가 꺼짐")
def _a06(c):
    a = _a(c)
    s = max((x for x in (a or {}).get("se", []) if x.get("host")), key=lambda x: _vs_on(a, x["name"]), default=None)
    if not s:
        return "SE 호스트 정보 없음"
    vc = next((h["vc"] for h in c.hosts if h["name"] == s["host"]), "")
    return out(f"{s['host']} ({s['name']})", [F("host_down", vc, s["host"])])


@sc("lb", "a07", "컨트롤러가 가장 많은 호스트 장애", "컨트롤러 노드가 몰린 호스트가 꺼짐")
def _a07(c):
    a = _a(c)
    cnt = Counter((x["vcenter"], x["host"]) for x in (a or {}).get("controllers", []) if x["host"])
    if not cnt:
        return "컨트롤러 VM 을 찾지 못함"
    (vc, h), m = cnt.most_common(1)[0]
    return out(f"{h} (컨트롤러 {m}대)", [F("host_down", vc, h)])


@sc("lb", "a08", "SE 롤링 업그레이드", "SE 를 한 대씩 교체 — SE 하나에만 놓인 가상 서비스는 잠깐 끊김")
def _a08(c):
    a = _a(c)
    if not a or not a["se"]:
        return "Avi SE 없음"
    single = [v["name"] for v in a["vs"] if len(v.get("ses") or []) == 1]
    return out(a["name"], n=[N("warn" if single else "pass", f"SE 하나에만 놓인 가상 서비스 {len(single)}개는 업그레이드 때 잠깐 끊김" + (f" ({', '.join(single[:5])})" if single else "")),
                             N("pass", "SE 그룹을 나눠 업그레이드(중요 그룹은 마지막)하면 위험을 줄임")],
               items=[{"kind": "가상 서비스", "name": v, "state": "boot", "text": "SE 교체 때 잠깐 끊김"} for v in single])


@sc("lb", "a09", "컨트롤러 업그레이드", "컨트롤러 클러스터 업그레이드 — 관리 중단, 데이터 경로는 계속")
def _a09(c):
    a = _a(c)
    if not a:
        return "Avi 없음"
    return out(a["name"], n=[N("warn", "업그레이드 동안 구성 변경·AKO 동기화·SE 장애 복구 불가"), N("pass", "SE 는 계속 트래픽 처리")],
               marks={f"avictrl:/{a['name']}/{x['name']}": "maint" for x in a["controllers"]}, acts=["업그레이드 전 컨트롤러 백업·SE 그룹 업그레이드 계획"])


@sc("lb", "a10", "VIP(데이터) 네트워크 장애", "SE 데이터 vNIC 의 VIP 망이 끊김 — 모든 가상 서비스")
def _a10(c):
    a = _a(c)
    if not a or not a["vs"]:
        return "Avi 가상 서비스 없음"
    return out(a["name"], items=[{"kind": "가상 서비스", "name": v["name"], "state": "stop", "text": "VIP 망 끊김"} for v in a["vs"]],
               n=[N("fail", f"가상 서비스 {len(a['vs'])}개 중단")])


@sc("lb", "a11", "SE 관리망 단절", "SE 와 컨트롤러 사이가 끊김 — SE 는 계속, 컨트롤러는 SE 를 잃은 것으로 봄")
def _a11(c):
    return svc("SE 관리망", ["구성 반영·통계·로그·SE 상태 감시 — 컨트롤러가 다른 SE 에 서비스를 다시 놓으면 같은 VIP 가 두 곳에서 응답할 수 있음"], ["데이터 경로(마지막 구성)"],
               ["SE 관리 vNIC 망 이중화·컨트롤러-SE 방화벽 포트"])


@sc("lb", "a12", "백엔드 서버가 한 호스트에 몰린 풀", "풀 멤버 VM 이 모두 한 호스트에 — 호스트 하나로 서비스 중단")
def _a12(c):
    return svc("풀 멤버 배치", ["멤버가 한 호스트·한 데이터스토어에 몰린 풀의 서비스"], ["멤버가 나뉜 풀"],
               ["논리 토폴로지 화면에서 VIP → 풀 → VM → 호스트 연결을 보고, 같은 풀 VM 에 DRS 반선호도"])


@sc("lb", "a13", "가상 서비스 인증서 만료", "VS 의 SSL 인증서가 만료 — 클라이언트 접속 실패")
def _a13(c):
    ce = [x for x in c.W["certs"] if "avi" in (str(x.get("system", "")) + str(x.get("kind", ""))).lower()]
    return out("Avi 인증서", n=[N("fail" if x.get("band") in ("expired", "crit") else "warn", f"{x.get('name')}: {x.get('days_left')}일") for x in ce[:5]]
               or [N("pass", "임박한 Avi 인증서 없음(수집 기준)")], acts=["Avi 인증서 자동 갱신(ACME)·만료 경고 설정"])


@sc("lb", "a14", "SE 용량 포화(연결·처리량)", "트래픽이 SE 용량을 넘음 — 지연·연결 거부")
def _a14(c):
    return svc("SE 용량", ["피크 때 새 연결(연결 거부·지연)"], ["평소 트래픽"], ["SE 그룹 자동 확장(scale-out)·SE 크기(vCPU) 기준 확인"])


@sc("lb", "a15", "AKO(쿠버네티스 연동) 장애", "AKO 가 멈춤 — 쿠버네티스 Service·Ingress 변경이 Avi 에 반영 안 됨")
def _a15(c):
    return svc("AKO", ["새 LoadBalancer Service·Ingress 생성·변경 반영"], ["이미 만들어진 가상 서비스"], ["AKO Pod 상태·컨트롤러 연결"], sev="warn")


@sc("lb", "a16", "GSLB 사이트 장애", "GSLB 의 한 사이트가 멈춤 — DNS 응답을 다른 사이트로")
def _a16(c):
    return svc("GSLB", ["멈춘 사이트로 향하던 DNS 응답(TTL 만큼 지연)"], ["다른 사이트 서비스"], ["GSLB 상태 감시·TTL 값 확인(GSLB 를 쓰지 않으면 해당 없음)"], sev="pass")


@sc("lb", "a17", "DNS 가상 서비스 장애", "Avi 가 주는 DNS VS 가 멈춤")
def _a17(c):
    return svc("Avi DNS", ["Avi DNS 로 이름을 받던 서비스(GSLB·AKO 위임 영역)"], ["다른 DNS 로 받는 이름"], ["DNS VS 를 SE 2개 이상에"], sev="warn")


@sc("lb", "a18", "Avi-vCenter 연결(클라우드 커넥터) 끊김", "컨트롤러가 vCenter 와 연결을 잃음")
def _a18(c):
    return svc("Avi 클라우드", ["새 SE 만들기·SE 장애 복구(새 SE 배치)"], ["기존 SE·가상 서비스"], ["Avi 클라우드 계정 비밀번호·vCenter 인증서 교체 뒤 재연결"])


@sc("lb", "a19", "SE 그룹 최대 SE 수 도달", "SE 를 더 만들 수 없음 — SE 장애 때 재배치 불가")
def _a19(c):
    return svc("SE 그룹 한도", ["SE 장애·확장 때 새 SE"], ["지금 SE"], ["SE 그룹 최대 SE 수·버퍼 SE 설정 확인"])


@sc("lb", "a20", "WAF 정책 오탐 차단", "WAF 규칙이 정상 요청을 막음")
def _a20(c):
    return svc("WAF", ["WAF 가 켜진 가상 서비스의 일부 요청"], ["WAF 없는 서비스"], ["WAF 를 '탐지' 모드로 먼저 운영, 예외 규칙 관리"], sev="warn")


@sc("lb", "a21", "Avi 라이선스 만료", "Avi 라이선스(코어) 기간이 끝남")
def _a21(c):
    return svc("Avi 라이선스", ["새 SE·확장(버전에 따라 동작 다름)"], ["대개 기존 SE"], ["라이선스 만료일과 SE 코어 사용량"])


@sc("lb", "a22", "컨트롤러 2대가 같은 호스트", "컨트롤러 노드가 한 호스트에 몰림 — 호스트 하나로 쿼럼 상실")
def _a22(c):
    a = _a(c)
    if not a or not a["controllers"]:
        return "Avi 컨트롤러 정보 없음"
    cnt = Counter((x["vcenter"], x["host"]) for x in a["controllers"] if x["host"])
    if not cnt or cnt.most_common(1)[0][1] < 2:
        return out("컨트롤러 배치", n=[N("pass", "컨트롤러가 서로 다른 호스트에 있음")])
    (vc, h), m = cnt.most_common(1)[0]
    return out(f"{h} (컨트롤러 {m}대)", [F("host_down", vc, h)])


# ================================================================== 8. DR·데이터 보호
@sc("dr", "d01", "사이트 전체 장애", "데이터센터 전체가 멈춤 — SRM 보호 VM 만 DR 사이트에서 복구")
def _d01(c):
    fs = [F("cluster_down", cl["vc"], cl["name"]) for cl in c.clusters][:SIM.MAX_FAIL]
    prot = c.W.get("srm_protected") or set()
    on = [v for v in c.vms if v["on"]]
    p = [v for v in on if v["name"].lower() in prot]
    return out(f"클러스터 {len(fs)}개", fs, n=[N("fail" if len(p) < len(on) else "pass", f"켜진 VM {len(on)}대 중 SRM 보호 {len(p)}대 — 나머지 {len(on) - len(p)}대는 백업에서 복원해야 함"
                                               if c.W.get("srm_on") else "SRM 이 연결되지 않음 — DR 사이트 복구 계획을 확인할 수 없음")])


@sc("dr", "d02", "SRM 서버 장애", "Site Recovery Manager 가 멈춤 — 복구 계획을 실행할 수 없음")
def _d02(c):
    return svc("SRM", ["복구 계획 실행·시험·보호 그룹 변경"], ["복제(vSphere Replication·어레이 복제)는 계속"], ["SRM 어플라이언스 백업·DR 쪽 SRM 상태"], sev="fail" if c.W.get("srm_on") else "warn",
               vms=vmarks(c.mgmt("SRM·복제"), "down", "SRM 장애(가정)"))


@sc("dr", "d03", "복제 중단(vSphere Replication·어레이 복제)", "복제가 멈춤 — RPO 가 계속 늘어남")
def _d03(c):
    return svc("복제", ["DR 사이트 데이터 최신화 — 멈춘 시간만큼 RPO 위반"], ["운영 사이트 서비스"], ["복제 상태·RPO 위반 알림(DR·보호 화면)"])


@sc("dr", "d04", "RPO 위반 상태에서 사이트 장애", "복제가 밀린 상태로 장애 — 마지막 복제 이후 데이터 손실")
def _d04(c):
    return svc("RPO 위반 + 장애", ["복제가 밀린 만큼의 데이터"], ["복제가 최신인 보호 그룹"], ["DR·보호 화면의 RPO 위반 보호 그룹을 먼저 해결"], sev="fail")


def _bk(c, word):
    import time as _t
    b = {k: v for k, v in (c.W.get("appliance_backup") or {}).items() if word in k.lower() or word in str(v.get("product", "")).lower()}
    if not b:
        return [N("warn", f"{word} 백업 상태를 모름 — 수집되지 않음")]
    out_ = []
    for k, v in b.items():
        age = (_t.time() - v["last_success"]) / 86400 if v.get("last_success") else None
        out_.append(N("fail" if age is None or age > 2 else "pass", f"{k}: 마지막 성공 {'없음' if age is None else f'{age:.1f}일 전'}"))
    return out_


@sc("dr", "d05", "vCenter 손상 + 백업 상태", "vCenter DB 가 손상 — 파일 백업에서 복원할 수 있는지")
def _d05(c):
    vc = c.W["vcenters"][0] if c.W["vcenters"] else None
    return out("vCenter 복원", [F("vcenter_upgrade", vc["name"], vc["name"])] if vc else [], n=_bk(c, "vcenter") + [N("warn", "복원 뒤 마지막 백업 이후의 구성 변경(분산 스위치·권한 등)은 다시 해야 함")])


@sc("dr", "d06", "NSX Manager 손상 + 백업 상태", "NSX 를 백업에서 복원할 수 있는지")
def _d06(c):
    return out("NSX 복원", n=_bk(c, "nsx"))


@sc("dr", "d07", "SDDC Manager 손상 + 백업 상태", "SDDC Manager 를 백업에서 복원할 수 있는지")
def _d07(c):
    return out("SDDC Manager 복원", n=_bk(c, "sddc"))


@sc("dr", "d08", "VM 백업 서버 장애", "VM 이미지 백업(Veeam·Commvault 등) 서버가 멈춤")
def _d08(c):
    return svc("VM 백업", ["예약 백업 — 그동안 복원 시점이 오래됨", "백업 제품이 만든 스냅숏이 남으면 데이터스토어가 참"], ["실행 중 VM"], ["백업 서버 이중화, 실패 알림, 남은 백업 스냅숏 점검"])


@sc("dr", "d09", "랜섬웨어(게스트 암호화) — 클러스터", "가장 큰 클러스터의 VM 게스트가 암호화됨")
def _d09(c):
    cl = c.big_cluster()
    if not cl:
        return NA
    vv = [v for v in c.vms if v["vc"] == cl["vc"] and v["cluster"] == cl["name"] and v["on"]]
    return out(cl["name"], vms=vmarks(vv, "down", "랜섬웨어 — 게스트 데이터 암호화"),
               n=[N("fail", f"VM {len(vv)}대 서비스 중단 — 복원은 감염 이전·변경 불가(immutable) 백업에서"), N("warn", "같은 망의 백업 서버·관리 계정까지 감염되면 복원 자체가 막힘")],
               acts=["백업 저장소를 변경 불가·분리(air-gap)로, 관리 계정 MFA, 복원 시험 주기"])


@sc("dr", "d10", "작업 실수 — 스냅숏 되돌림", "엉뚱한 VM 을 오래된 스냅숏으로 되돌림 — 그 이후 데이터 손실")
def _d10(c):
    vv = [v for v in c.vms if v["snaps"]]
    if not vv:
        return out("스냅숏", n=[N("pass", "스냅숏 있는 VM 없음")])
    return out(f"스냅숏 VM {len(vv)}대", n=[N("warn", f"스냅숏이 있는 VM {len(vv)}대 — 되돌리면 스냅숏 이후 데이터가 사라짐")],
               acts=["VM 액티비티의 '스냅숏 되돌림' 위험 신호·보호 VM 목록 확인"])


@sc("dr", "d11", "작업 실수 — 중요 VM 삭제", "관리·중요 VM 을 디스크까지 삭제")
def _d11(c):
    v = next((v for v in c.vms if v["mgmt"]), None) or max(c.vms, key=lambda v: v["mem"], default=None)
    return out(v["name"], vms=vmarks([v], "down", "VM 삭제(디스크 포함)"), n=[N("fail", "복구는 백업에서만 — 백업 시점 이후 데이터는 사라짐")],
               acts=["삭제 권한 최소화, VM 액티비티의 '보호 VM 삭제' 알림 켜기"]) if v else NA


@sc("dr", "d12", "복구 계획 시험 실패", "DR 시험에서 VM 이 켜지지 않거나 네트워크 매핑이 틀림")
def _d12(c):
    return svc("DR 시험", ["실제 재해 때 같은 실패 — 시험에서 고치지 않으면"], ["운영 서비스"], ["분기마다 복구 계획 시험, 실패 단계(전원·IP·스크립트) 기록"], sev="warn")


@sc("dr", "d13", "DR 사이트 용량 부족", "DR 사이트에 보호 VM 을 다 켤 자원이 없음")
def _d13(c):
    prot = c.W.get("srm_protected") or set()
    vv = [v for v in c.vms if v["name"].lower() in prot]
    mem = sum(v["mem"] for v in vv) / 1024
    return out("DR 용량", n=[N("warn", f"보호 VM {len(vv)}대 · 메모리 {mem:.0f} GB 를 DR 사이트가 받아야 함 — DR 클러스터 여유와 비교")],
               acts=["DR 수용 가정(용량 화면)으로 DR 사이트 여유 확인"])


@sc("dr", "d14", "DR 전환 때 IP 재지정 실패", "DR 사이트에서 IP 를 바꾸는 단계가 실패 — VM 은 켜졌지만 접속 불가")
def _d14(c):
    return svc("Re-IP", ["IP 를 바꿔야 하는 VM 의 서비스·DNS 갱신"], ["같은 IP 대역을 늘린(L2 확장) 구성"], ["복구 계획의 IP 맞춤 설정·DNS 갱신 스크립트 시험"])


@sc("dr", "d15", "SRM 보호 밖 중요 VM 장애", "메모리 큰 VM 중 SRM 보호에 없는 것이 손상")
def _d15(c):
    prot = c.W.get("srm_protected") or set()
    vv = sorted((v for v in c.vms if v["on"] and v["name"].lower() not in prot and not v["mgmt"]), key=lambda v: -v["mem"])[:5]
    if not vv:
        return out("보호", n=[N("pass", "켜진 업무 VM 이 모두 SRM 보호 안에 있음")])
    return out(f"보호 밖 VM {len(vv)}대", vms=vmarks(vv, "down", "보호 밖 VM 손상 — 백업 복원 필요"),
               n=[N("warn", f"SRM 보호 밖: {', '.join(v['name'] for v in vv)}" if c.W.get("srm_on") else "SRM 연결 없음 — 보호 여부를 확인할 수 없음")])


@sc("dr", "d16", "데이터스토어 손상 + 복원 시간", "데이터스토어를 잃고 백업에서 VM 을 되살리는 데 걸리는 시간")
def _d16(c):
    d = c.shared_ds()
    if not d:
        return NA
    gb = sum(v["disk"] for v in c.vms if v["vc"] == d["vc"] and v["name"] in d["vms"])
    hrs = gb / 1024 / 1.0
    return out(d["name"], [F("ds_apd", d["vc"], d["name"])], n=[N("warn", f"복원할 디스크 약 {gb:,.0f} GB — 1 TB/시간 복원 속도면 약 {hrs:.1f} 시간(실제 속도로 다시 계산)")])


@sc("dr", "d17", "백업 저장소 가득 참", "백업 저장소가 차서 새 백업이 실패")
def _d17(c):
    return svc("백업 저장소", ["새 백업 — 보관 정책보다 오래된 시점만 남음"], ["실행 중 VM·기존 백업 복원"], ["백업 저장소 용량 추세·보관 기간"])


@sc("dr", "d18", "오래된 스냅숏 커밋(삭제) 때 I/O 멈춤", "큰 델타 디스크를 합칠 때 VM 이 잠깐 멈춤(stun)")
def _d18(c):
    vv = [v for v in c.vms if v["snaps"] and v["on"]]
    if not vv:
        return out("스냅숏", n=[N("pass", "스냅숏 있는 켜진 VM 없음")])
    return out(f"VM {len(vv)}대", vms=vmarks(vv, "pause", "스냅숏 커밋 — 잠깐 멈춤(stun)"), n=[N("warn", "델타가 클수록 커밋이 길고 마지막에 VM 이 잠깐 멈춤 — 업무 외 시간에")])


@sc("dr", "d19", "vSAN 데이터 손실(FTT 초과)", "FTT=1 객체의 두 복사본이 있는 호스트 2대를 잃음 — 복구는 백업에서")
def _d19(c):
    cl = c.big_cluster(pred=lambda x: x["vsan"], min_hosts=3)
    if not cl:
        return "vSAN 클러스터(3대 이상) 없음"
    hs = c.hosts_of(cl)[:2]
    return out(" + ".join(h["name"] for h in hs), [F("host_down", h["vc"], h["name"]) for h in hs],
               n=[N("fail", "호스트가 돌아오지 못하면(디스크 손상) FTT=1 객체 일부는 영구 손실 — 백업 복원"), N("warn", "호스트가 돌아오면 데이터는 다시 보임(일시적 접근 불가)")])


@sc("dr", "d20", "백업 없이 업그레이드 실패", "관리 구성요소 업그레이드가 중간에 실패 — 되돌릴 백업·스냅숏이 없음")
def _d20(c):
    n = _bk(c, "vcenter") + _bk(c, "nsx") + _bk(c, "sddc")
    return out("업그레이드 대비", n=n, acts=["업그레이드 직전: 파일 백업 + (지원되면) 오프라인 스냅숏, SDDC Manager 사전 점검"])


# ------------------------------------------------------------------ 실행
def catalog(W: dict) -> dict[str, Any]:
    """대상 고르기까지(시뮬레이션 전) — 파트별 시나리오 목록·적용 여부"""
    c = Ctx(W)
    items = []
    for s in LIB:
        try:
            r = s["fn"](c)
        except Exception as e:  # noqa: BLE001
            r = f"계산 오류: {type(e).__name__}"
        na = isinstance(r, str)
        items.append({"id": s["id"], "part": s["part"], "title": s["title"], "desc": s["desc"], "applicable": not na,
                      "why_na": r if na else "", "target": "" if na else r["target"],
                      "failures": [] if na else [f | {"label": _label(f["type"])} for f in r["failures"]]})
    return {"parts": [{"key": k, "label": l, "desc": d, "count": sum(1 for x in items if x["part"] == k)} for k, l, d in PARTS], "items": items}


def _label(t: str) -> str:
    for acts in SIM.ACTIONS.values():
        for tt, lab in acts:
            if tt == t:
                return lab
    return t


def run(W: dict, sid: str) -> dict[str, Any]:
    s = next((x for x in LIB if x["id"] == sid), None)
    if not s:
        raise KeyError(sid)
    c = Ctx(W)
    r = s["fn"](c)
    if isinstance(r, str):
        return {"id": sid, "title": s["title"], "part": s["part"], "applicable": False, "why_na": r, "verdict": "none"}
    tag = s["title"]
    extra = {"vms": r["vms"], "findings": [{"sev": n["sev"], "text": f"[{tag}] {n['text']}"} for n in r["notes"]], "actions": r["actions"],
             "items": r["items"], "pods": r["pods"], "marks": r["marks"]}
    res = SIM.simulate(W, r["failures"], extra)
    return res | {"id": sid, "title": s["title"], "part": s["part"], "desc": s["desc"], "applicable": True, "target": r["target"],
                  "failures_in": [f | {"label": _label(f["type"])} for f in r["failures"]]}


def run_all(W: dict) -> dict[str, Any]:
    out_ = []
    for s in LIB:
        try:
            r = run(W, s["id"])
        except Exception as e:  # noqa: BLE001
            r = {"id": s["id"], "title": s["title"], "part": s["part"], "applicable": False, "why_na": f"계산 오류: {type(e).__name__}: {e}"[:200], "verdict": "none"}
        if r.get("applicable"):
            c = r.get("counts") or {}
            pc = (r.get("platform") or {}).get("counts") or {}
            top = next((f["text"] for f in r["findings"] if f["sev"] == "fail"), "") or next((f["text"] for f in r["findings"] if f["sev"] == "warn"), "")
            out_.append({"id": r["id"], "part": r["part"], "title": r["title"], "target": r["target"], "applicable": True, "verdict": r["verdict"],
                         "stop": sum(c.get(k, 0) for k in ("down", "io", "net", "ext")) + pc.get("stop", 0), "risk": sum(c.get(k, 0) for k in ("maybe", "blocked")) + pc.get("risk", 0),
                         "boot": sum(c.get(k, 0) for k in ("restart", "pause")) + pc.get("boot", 0), "pods": sum(1 for p in (r.get("platform") or {}).get("pods") or [] if p["state"] != "kept"), "top": top[:220]})
        else:
            out_.append({"id": r["id"], "part": r["part"], "title": r["title"], "applicable": False, "why_na": r.get("why_na", ""), "verdict": "none"})
    cnt = Counter((x["part"], x["verdict"]) for x in out_)
    return {"parts": [{"key": k, "label": l, "desc": d, "total": sum(1 for x in out_ if x["part"] == k),
                       "fail": cnt[(k, "fail")], "warn": cnt[(k, "warn")], "pass": cnt[(k, "pass")], "na": cnt[(k, "none")]} for k, l, d in PARTS], "items": out_}


# ------------------------------------------------------------------ 2.48.0 연속 검증 — 기록·변화 감지·보고서
class LibWatch:
    """시나리오 라이브러리 + 단일 장애점 순위를 주기적으로 계산해 기록하고, 지난번보다 새로 실패한 시나리오를 이상징후로 알림"""
    def __init__(self, engine, interval_h: float = 6.0):
        self.e = engine
        self.interval_h = interval_h
        self._ready = False
        self.state = {"last": 0.0, "error": ""}

    async def ensure(self):
        if not self._ready:
            await self.e.store.x("CREATE TABLE IF NOT EXISTS scnlib_runs(ts REAL PRIMARY KEY, data TEXT)")
            self._ready = True

    async def last(self) -> dict | None:
        await self.ensure()
        import json
        r = await self.e.store.q1("SELECT ts, data FROM scnlib_runs ORDER BY ts DESC LIMIT 1")
        return {"ts": r["ts"], **json.loads(r["data"])} if r else None

    async def history(self, n: int = 30) -> list[dict]:
        await self.ensure()
        import json
        rows = await self.e.store.q("SELECT ts, data FROM scnlib_runs ORDER BY ts DESC LIMIT ?", (max(1, min(200, n)),))
        out_ = []
        for r in rows:
            d = json.loads(r["data"])
            out_.append({"ts": r["ts"], "counts": d.get("counts", {}), "spof": d.get("spof", 0), "new_fail": d.get("new_fail", []), "fixed": d.get("fixed", [])})
        return out_

    @staticmethod
    def diff(prev: dict | None, cur: dict) -> dict:
        if not prev:
            return {"new_fail": [], "fixed": [], "prev_ts": None}
        pv = prev.get("verdicts") or {}
        nf = [i for i, v in cur["verdicts"].items() if v == "fail" and pv.get(i) not in ("fail", None)]
        fx = [i for i, v in cur["verdicts"].items() if pv.get(i) == "fail" and v in ("pass", "warn")]
        return {"new_fail": nf, "fixed": fx, "prev_ts": prev.get("ts")}

    async def snapshot(self, W: dict, reason: str = "loop") -> dict:
        import asyncio
        import json
        import time as _t

        from . import spof as SP
        await self.ensure()
        lib = await asyncio.to_thread(run_all, W)
        sp = await asyncio.to_thread(SP.scan, W, 10)
        verd = {x["id"]: x["verdict"] for x in lib["items"]}
        cur = {"verdicts": verd, "counts": dict(Counter(verd.values())), "spof": sp["spof"],
               "spof_top": [{k: x.get(k) for k in ("kind", "name", "score", "verdict", "why")} for x in sp["top"][:10]], "reason": reason}
        prev = await self.last()
        d = self.diff(prev, cur)
        cur.update(new_fail=d["new_fail"], fixed=d["fixed"])
        now = _t.time()
        await self.e.store.x("INSERT OR REPLACE INTO scnlib_runs(ts, data) VALUES(?,?)", (now, json.dumps(cur, ensure_ascii=False)))
        await self.e.store.x("DELETE FROM scnlib_runs WHERE ts < ?", (now - 90 * 86400,))
        self.state.update(last=now, error="")
        ingest = getattr(self.e, "ingest", None)
        if ingest and d["new_fail"]:
            from .models import LogEvent
            titles = {s["id"]: s["title"] for s in LIB}
            ev = LogEvent(source="aiops", connector="whatif", severity="warning", kind="health", host="", entity="what-if:library",
                          message=f"What-If 시나리오 {len(d['new_fail'])}개가 새로 실패로 바뀌었습니다: " + ", ".join(f"{i} {titles.get(i, '')}" for i in d["new_fail"][:5]),
                          attrs={"app": "whatif", "new_fail": d["new_fail"][:50]})
            x = ingest(ev)
            if asyncio.iscoroutine(x):
                await x
        return {**cur, "ts": now, "prev_ts": d["prev_ts"]}

    async def loop(self, beat=lambda: None):
        import asyncio
        import time as _t

        from .checkbot import build_world
        await asyncio.sleep(420)
        while True:
            beat()
            try:
                last = await self.last()
                if not last or _t.time() - last["ts"] >= self.interval_h * 3600 - 60:
                    await self.snapshot(build_world(self.e))
            except Exception as ex:  # noqa: BLE001
                self.state["error"] = f"{type(ex).__name__}: {ex}"[:200]
            await asyncio.sleep(900)


def to_markdown(lib: dict, sp: dict | None = None, diff: dict | None = None, ts: float | None = None) -> str:
    import time as _t
    titles = {s["id"]: s["title"] for s in LIB}
    L_ = [f"# What-If 점검 보고서", "", f"- 작성: {_t.strftime('%Y-%m-%d %H:%M', _t.localtime(ts or _t.time()))} (VCF AIOps · 시뮬레이션 전용 — 장비에 명령 없음)",
          f"- 시나리오 {len(lib['items'])}개 · 실패 {sum(1 for x in lib['items'] if x['verdict'] == 'fail')} · 주의 {sum(1 for x in lib['items'] if x['verdict'] == 'warn')} · "
          f"통과 {sum(1 for x in lib['items'] if x['verdict'] == 'pass')} · 해당 없음 {sum(1 for x in lib['items'] if x['verdict'] == 'none')}", ""]
    if diff and (diff.get("new_fail") or diff.get("fixed")):
        L_ += ["## 지난번과 달라진 것", ""] + [f"- 새로 실패: {i} {titles.get(i, '')}" for i in diff.get("new_fail", [])] + [f"- 해소: {i} {titles.get(i, '')}" for i in diff.get("fixed", [])] + [""]
    L_ += ["## 파트별", "", "| 파트 | 시나리오 | 실패 | 주의 | 통과 | 해당 없음 |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    L_ += [f"| {p['label']} | {p['total']} | {p['fail']} | {p['warn']} | {p['pass']} | {p['na']} |" for p in lib["parts"]] + [""]
    if sp:
        L_ += ["## 단일 장애점 상위 10", "", f"객체 {sp['scanned']}개를 하나씩 고장 내 계산 · {sp['rule']}", "", "| 순위 | 종류 | 이름 | 점수 | 중단 VM | 재시작 불확실 | 중단 워크로드·VIP | 이유 |",
               "| ---: | --- | --- | ---: | ---: | ---: | ---: | --- |"]
        L_ += [f"| {i + 1} | {x['kind']} | {x['name']} | {x['score']} | {x.get('stop', 0)} | {x.get('maybe', 0)} | {x.get('pstop', 0)} | {str(x.get('why', '')).split('] ', 1)[-1].replace('|', '/')[:120]} |"
               for i, x in enumerate(sp["top"][:10])] + [""]
    parts = {k: l for k, l, _ in PARTS}
    for k, _, _ in PARTS:
        fs = [x for x in lib["items"] if x["part"] == k and x["verdict"] in ("fail", "warn")]
        if not fs:
            continue
        L_ += [f"## {parts[k]} — 실패·주의", ""]
        for x in sorted(fs, key=lambda x: x["verdict"] != "fail"):
            L_.append(f"- **[{'실패' if x['verdict'] == 'fail' else '주의'}] {x['id']} {x['title']}** — 대상 {x.get('target', '')}"
                      + (f" · 중단 {x['stop']}" if x.get("stop") else "") + (f" · 위험 {x['risk']}" if x.get("risk") else "")
                      + (f" · Pod {x['pods']}" if x.get("pods") else "") + (f"\n  - {x['top'].split('] ', 1)[-1]}" if x.get("top") else ""))
        L_.append("")
    L_ += ["---", "판정은 수집된 구성과 일반적인 VMware 동작 기준의 계산입니다. 실제 동작은 버전·설정에 따라 다를 수 있습니다."]
    return "\n".join(L_)
