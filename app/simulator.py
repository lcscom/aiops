"""장애 시뮬레이터(2.39.0) — vSphere Client 처럼 인벤토리를 보여 주고, 객체를 눌러 장애·작업 상태로 만들면 영향받는 리소스를 바로 계산한다.

계산은 AI 체크봇과 같은 규칙 엔진(checkbot.evaluate)을 쓰고, 여러 장애를 겹치면
  · 같은 클러스터에서 빠지는 호스트(장애 + 유지보수)를 합쳐 남은 용량·vSAN 호스트 수를 다시 본다
  · 꺼진 호스트 전체를 놓고 VKS 컨트롤 플레인·NSX Edge·Avi SE 이중화가 함께 꺼지는지 다시 본다
  · VM·호스트·데이터스토어·클러스터마다 상태(멈춤·I/O 멈춤·네트워크 끊김·재시작 못할 수 있음·vMotion 불가·HA 재시작·vMotion 이동)를 하나로 정한다
읽기 전용 — 실제 인프라에는 아무것도 하지 않는다.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from . import checkbot as CB
from . import platsim as PS

ACTIONS = {
    "vcenter": [("vcenter_upgrade", "중단·업그레이드")],
    "cluster": [("cluster_down", "전체 장애"), ("host_maint", "롤링 유지보수")],
    "host": [("host_down", "장애(PSOD·전원)"), ("host_maint", "유지보수 모드"), ("uplink_loss", "업링크(NIC) 장애")],
    "datastore": [("ds_apd", "APD/PDL"), ("ds_full", "가득 참")],
    "edge": [("edge_down", "Edge 장애")],
    "switch": [("switch_down", "스위치 장애")],
    "device": [("device_down", "장애")],
    "storage": [("storage_down", "어레이 장애")],
    **PS.ACTIONS,                                   # 2.46.0 Supervisor · VKS · VKS 노드 · Avi 컨트롤러 · Avi SE
}
VM_STATES = {  # 우선순위 높은 것부터
    "down": "멈춤", "io": "I/O 멈춤", "net": "네트워크 끊김", "ext": "외부 통신 끊김", "maybe": "재시작 못할 수 있음", "blocked": "vMotion 불가",
    "restart": "HA 재시작(재부팅)", "pause": "잠깐 멈춤(수 초~수 분)", "vmotion": "vMotion 이동(무중단)", "offline": "꺼진 VM(파일 접근 불가)",
}
RANK = {k: i for i, k in enumerate(VM_STATES)}
MAX_FAIL = 12


def inventory(world: dict) -> dict[str, Any]:
    out = []
    for vc in world["vcenters"]:
        T = vc["topo"]
        H, V, D = T.get("hosts") or {}, T.get("vms") or {}, T.get("datastores") or {}
        by_host: dict[str, list] = {}
        for n, v in sorted(V.items()):
            by_host.setdefault(v.get("host", ""), []).append(
                {"name": n, "on": "poweredOn" in str(v.get("power")), "mgmt": CB._mgmt_kind(n, world) or "", "vcpu": int(v.get("vcpu") or 0),
                 "mem_gb": round(int(v.get("mem_mb") or 0) / 1024, 1)})
        vks = {n.get("name"): k["cluster"] for k in world["vks"] for n in k["nodes"]}
        for lst in by_host.values():
            for x in lst:
                if x["name"] in vks:
                    x["vks"] = vks[x["name"]]
        dcs: dict[str, list] = {}
        for cn, c in sorted((T.get("clusters") or {}).items()):
            dc = Counter(v.get("datacenter") for v in V.values() if v.get("cluster") == cn and v.get("datacenter")).most_common(1)
            hosts = [{"name": h, "maint": bool(H[h].get("maintenance")), "conn": str(H[h].get("conn", "connected") or "connected"),
                      "vms": by_host.get(h, [])} for h in c.get("hosts", []) if h in H]
            dcs.setdefault(dc[0][0] if dc else "", []).append({"name": cn, "ha": bool(c.get("ha")), "drs": bool(c.get("drs")), "vsan": bool(c.get("vsan")), "hosts": hosts})
        ds = [{"name": dn, "type": d.get("type", ""), "capacity_gb": d.get("capacity_gb") or 0, "used_pct": CB._used_pct(d), "local": d.get("local") is True,
               "hosts": sum(1 for h in H.values() if dn in (h.get("datastores") or [])), "vms": sum(1 for v in V.values() if dn in (v.get("datastores") or []))}
              for dn, d in sorted(D.items()) if d.get("capacity_gb")]
        out.append({"name": vc["name"], "host": vc.get("host", ""), "datacenters": [{"name": k, "clusters": v} for k, v in sorted(dcs.items())], "datastores": ds})
    moid = {h.get("moid"): n for vc in world["vcenters"] for n, h in (vc["topo"].get("hosts") or {}).items()}
    edges: dict[str, list] = {}
    for e in world["edges"]:
        edges.setdefault(e["edge_cluster"], []).append({"name": e["name"], "host": moid.get(e["host_moid"], e["host_moid"])})
    ph = world.get("phys") or {}
    hosts_of: dict[str, list] = {}
    for hn, h in (ph.get("hosts") or {}).items():
        for nic, n in h["nics"].items():
            if n.get("switch"):
                hosts_of.setdefault(n["switch"], []).append({"host": hn, "vcenter": h.get("vcenter", ""), "nic": nic, "port": n.get("port", ""), "up": n.get("up")})
    order = {"border": 0, "edge": 0, "spine": 1, "core": 1, "leaf": 2, "tor": 2, "access": 2}
    phys = {"devices": [{"name": d["name"], "kind": d["kind"], "switches": d["switches"], "source": d.get("source", "")} for d in sorted((ph.get("devices") or {}).values(), key=lambda x: (x["kind"] != "firewall", x["name"]))],
            "switches": [{"name": n, "role": sw.get("role", ""), "mlag": sw.get("mlag", ""), "vendor": sw.get("vendor", ""), "model": sw.get("model", ""),
                          "uplinks": sorted({l["to"] for l in sw["links"] if l["kind"] == "switch" and order.get(str((ph["switches"].get(l["to"]) or {}).get("role", "")).lower(), 3) < order.get(str(sw.get("role", "")).lower(), 3)}),
                          "hosts": sorted(hosts_of.get(n, []), key=lambda x: (x["host"], x["nic"]))}
                         for n, sw in sorted((ph.get("switches") or {}).items(), key=lambda kv: (order.get(str(kv[1].get("role", "")).lower(), 3), kv[1].get("mlag", ""), kv[0]))],
            "storage": [{"name": a["name"], "kind": a["kind"], "note": a.get("note", ""), "source": a.get("source", ""), "datastores": a["datastores"]} for a in sorted((ph.get("storage") or {}).values(), key=lambda x: x["name"])],
            "servers": ph.get("servers") or {}, "collected": ph.get("collected") or {}}
    return {"vcenters": out, "edge_clusters": [{"name": k, "edges": v} for k, v in sorted(edges.items())], "phys": phys, "platform": PS.build(world),
            "actions": {k: [{"type": t, "label": l} for t, l in v] for k, v in ACTIONS.items()}, "states": VM_STATES, "max": MAX_FAIL}


def _vm_state(t: str, reason: str) -> str:
    if t == "host_down":
        return "restart" if reason.startswith("HA 가 다른 호스트") else "down"
    return {"cluster_down": "down", "ds_apd": "io", "ds_full": "down", "uplink_loss": "net", "host_maint": "blocked"}.get(t, "down")


def _norm(world: dict, f: dict) -> dict | None:
    t, tg, vcn = f.get("type"), str(f.get("target") or ""), str(f.get("vcenter") or "")
    ph = world.get("phys") or {}
    if t == "switch_down":
        return {"type": t, "target": tg} if tg in (ph.get("switches") or {}) else None
    if t == "device_down":
        return {"type": t, "target": tg} if tg in (ph.get("devices") or {}) else None
    if t == "storage_down":
        return {"type": t, "target": tg} if tg in (ph.get("storage") or {}) else None
    if t == "edge_down":
        return {"type": t, "target": tg} if tg in {e["edge_cluster"] for e in world["edges"]} else None
    vc = CB._vc(world, vcn)
    if not vc:
        return None
    T = vc["topo"]
    if t in ("host_down", "uplink_loss", "host_maint") and tg in (T.get("hosts") or {}):
        return {"type": t, "vcenter": vcn, "target": tg, "cluster": T["hosts"][tg].get("cluster", ""), "scope": "host"}
    if t in ("cluster_down", "host_maint") and tg in (T.get("clusters") or {}):
        return {"type": t, "vcenter": vcn, "target": tg, "cluster": tg, "scope": "cluster"}
    if t in ("ds_apd", "ds_full") and tg in (T.get("datastores") or {}):
        return {"type": t, "vcenter": vcn, "target": tg}
    if t == "vcenter_upgrade":
        return {"type": t, "vcenter": vcn, "target": vc.get("host") or vcn}
    return None


STOP_NOW = ("down", "io", "net", "ext", "restart", "maybe", "pause")
REPAIR_H = 4.0                                      # 2.48.0 가정 — 고장 장비 수리·교체·복구까지(시간)


def timeline(vm_list: list[dict], plat: dict, repair_h: float = REPAIR_H) -> dict[str, Any]:
    """2.48.0 시간에 따른 영향 — 즉시 / 1분 / 5분 / 복구 전까지 / 복구 후. 켜진 VM·Pod·가상 서비스(VIP) 수와 VM 다운타임 합"""
    on = [x for x in vm_list if x["state"] != "offline" and x.get("power") == "on"]
    c = Counter(x["state"] for x in on)
    pods = [p for p in plat.get("pods") or [] if p["state"] not in ("kept", "frozen")]
    pc = Counter(p["state"] for p in pods)
    vips = [i for i in plat.get("items") or [] if i["kind"] == "가상 서비스" and i["state"] in ("stop", "boot")]
    vc = Counter(i["state"] for i in vips)
    hard = c["down"] + c["io"] + c["net"] + c["ext"]
    ph = [
        {"t": "즉시", "desc": "장애 순간 — 멈추는 VM·Pod·VIP 전부", "vms": hard + c["restart"] + c["maybe"] + c["pause"], "pods": len(pods), "vips": len(vips)},
        {"t": "~1분", "desc": "I/O·통신이 잠깐 멈춘 VM 회복, HA 가 장애 감지(약 15초) 후 재시작 시작", "vms": hard + c["restart"] + c["maybe"], "pods": len(pods), "vips": len(vips)},
        {"t": "~5분", "desc": "HA 가 다른 호스트에서 다시 켜고 OS 부팅, Pod 다시 배치, VIP 를 다른 SE 에", "vms": hard + c["maybe"], "pods": pc["stuck"] + pc["unsure"] + pc["gone"], "vips": vc["stop"]},
        {"t": "복구 전까지", "desc": f"장비·서비스를 고칠 때까지(가정 {repair_h:g}시간) — 재시작 불확실(용량 부족)은 운영자 조치 필요", "vms": hard + c["maybe"],
         "pods": pc["stuck"] + pc["unsure"] + pc["gone"], "vips": vc["stop"]},
        {"t": "복구 후", "desc": "장비 복구 — vSAN 재동기화·DRS 재균형이 이어질 수 있음", "vms": 0, "pods": 0, "vips": 0},
    ]
    rm = repair_h * 60
    lo = hard * rm + c["restart"] * 2 + c["maybe"] * 5 + c["pause"] * 0.1
    hi = hard * rm + c["restart"] * 5 + c["maybe"] * rm + c["pause"] * 1
    return {"phases": ph, "vm_minutes": [round(lo), round(hi)], "repair_h": repair_h,
            "assume": "HA 재시작 = 감지 약 15초 + 재시작·OS 부팅 2~5분 · 잠깐 멈춤 = 수 초~1분 · 고장 장비 복구 = " + f"{repair_h:g}시간(가정)"}


def simulate(world: dict, failures: list[dict], extra_in: dict | None = None) -> dict[str, Any]:
    """extra_in(2.47.0 시나리오 라이브러리) = {vms:[(vc, vm, state, reason)], findings:[{sev,text}], actions:[...], items:[...], pods:[...], marks:{...}}"""
    X = extra_in or {}
    fs, seen = [], set()
    P = PS.build(world)
    pfs: list[dict] = []
    for f in failures[:MAX_FAIL]:
        if isinstance(f, dict) and f.get("type") in PS.TYPES:          # 플랫폼 가정은 따로(아래 PS.evaluate)
            n = PS.norm(P, f)
            if n and (n["type"], n.get("vcenter", ""), n["target"]) not in seen:
                seen.add((n["type"], n.get("vcenter", ""), n["target"]))
                pfs.append(n)
            continue
        n = _norm(world, f) if isinstance(f, dict) else None
        if n and (n["type"], n.get("vcenter", ""), n["target"]) not in seen:
            seen.add((n["type"], n.get("vcenter", ""), n["target"]))
            fs.append(n)
    dead_cl = {(f["vcenter"], f["target"]) for f in fs if f["type"] == "cluster_down"}
    parts, skipped = [], []
    netf = [f for f in fs if f["type"] in ("switch_down", "device_down")]
    if netf:                                                     # 스위치·방화벽·라우터는 한꺼번에(경로는 겹쳐서 끊기므로)
        sw = [f["target"] for f in netf if f["type"] == "switch_down"]
        dv = [f["target"] for f in netf if f["type"] == "device_down"]
        r = CB.evaluate(world, {"type": "switch_down" if sw else "device_down", "target": " + ".join(sw + dv), "switches": sw, "devices": dv, "id": "net"})
        r["sim_key"] = "net"
        r["kind"] = "물리 네트워크"
        parts.append(r)
    for f in fs:
        if f in netf:
            continue
        if f.get("cluster") and f["type"] != "cluster_down" and (f["vcenter"], f["cluster"]) in dead_cl:
            skipped.append(f)                                    # 클러스터가 통째로 멈추면 그 안의 호스트 장애는 따로 볼 필요 없음
            continue
        sp = {**f, "id": f"{f['type']}:{f.get('vcenter', '')}:{f['target']}"}
        if f["type"] == "host_maint" and f.get("scope") == "host":
            sp["host"] = f["target"]
        r = CB.evaluate(world, sp)
        r["sim_key"] = sp["id"]
        if sp.get("host"):
            r["kind"] = "호스트 유지보수"
        parts.append(r)
    marks: dict[str, str] = {}
    vms: dict[tuple, dict] = {}

    def vm_mark(vcn: str, row: dict, st: str):
        k = (vcn, row["name"])
        cur = vms.get(k)
        if not cur or RANK[st] < RANK[cur["state"]]:
            vms[k] = {**row, "vcenter": vcn, "state": st, "state_label": VM_STATES[st], "by": []}
            if cur:
                vms[k]["by"] = cur["by"]
        vms[k]["by"].append(row["reason"])

    extra: list[dict] = []
    for p in parts:
        vcn = p.get("vcenter", "")
        for row in p["vms"]:
            vcx = vcn or next((v["name"] for v in world["vcenters"] if row["name"] in (v["topo"].get("vms") or {})), "")
            vm_mark(vcx, row, "offline" if row["power"] != "on" else row.get("state") or _vm_state(p["type"], row["reason"]))
    # 유지보수 호스트의 나머지 켜진 VM 은 vMotion 으로 무중단 이동
    for f in fs:
        if f["type"] == "host_maint" and f not in skipped:
            vc = CB._vc(world, f["vcenter"])
            T = vc["topo"]
            hs = {f["target"]} if f.get("scope") == "host" else set((T.get("clusters") or {}).get(f["target"], {}).get("hosts", []))
            for n, v in (T.get("vms") or {}).items():
                if v.get("host") in hs and "poweredOn" in str(v.get("power")):
                    vm_mark(f["vcenter"], CB._vm_row(n, v, "유지보수 — vMotion 으로 다른 호스트에 옮김(무중단)" if f.get("scope") == "host" else "롤링 유지보수 때 차례로 vMotion"), "vmotion")
    # 같은 클러스터에서 빠지는 호스트를 합쳐 다시 계산
    removed: dict[tuple, dict] = {}
    for f in fs:
        if f in skipped or f.get("scope") != "host" or f["type"] not in ("host_down", "host_maint"):
            continue
        r = removed.setdefault((f["vcenter"], f["cluster"]), {"down": set(), "maint": set()})
        r["down" if f["type"] == "host_down" else "maint"].add(f["target"])
    bad_cl = set()
    for (vcn, cl), r in removed.items():
        allh = r["down"] | r["maint"]
        vc = CB._vc(world, vcn)
        info = CB._cl_info(vc, cl)
        members = [h for h in info.get("hosts", []) if h in (vc["topo"].get("hosts") or {})]
        if len(allh) >= 2:
            cap = CB._capacity(vc, cl, sorted(allh), consume_ha=bool(r["down"]))
            lab = f"[클러스터 {cl} 합산 · 빠지는 호스트 {len(allh)}대: 장애 {len(r['down'])} · 유지보수 {len(r['maint'])}]"
            if cap and (cap.get("why") or cap["verdict"] == "bad"):
                bad_cl.add((vcn, cl))
                extra.append({"sev": "fail", "text": f"{lab} " + (cap.get("why") or f"남은 호스트 {cap.get('hosts_left')}대로 용량이 모자랍니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%"
                                                                                       + (f", 같은 사양 {cap['hosts_needed']}대 부족" if cap.get("hosts_needed") else "") + ")")})
            elif cap and cap["verdict"] == "warn":
                extra.append({"sev": "warn", "text": f"{lab} 남은 용량이 빠듯합니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%)"})
            elif cap:
                extra.append({"sev": "pass", "text": f"{lab} 남은 호스트가 받아냅니다(CPU {cap.get('cpu_pct')}% · 메모리 {cap.get('mem_pct')}%)"})
            if info.get("vsan"):
                left = len(members) - len(allh)
                if left < 3:
                    extra.append({"sev": "fail", "text": f"{lab} vSAN 호스트가 {left}대만 남아 FTT=1 객체에 접근하지 못할 수 있습니다"})
        elif any(p.get("capacity", {}).get("verdict") == "bad" or p.get("capacity", {}).get("why") for p in parts if p.get("vcenter") == vcn and p.get("cluster") == cl):
            bad_cl.add((vcn, cl))
    for (vcn, name), x in vms.items():
        if x["state"] == "restart" and (vcn, x.get("cluster", "")) in bad_cl:
            x["state"], x["state_label"] = "maybe", VM_STATES["maybe"]
    # 꺼진 호스트 전체로 이중화 묶음 다시 확인
    for vc in world["vcenters"]:
        lost = {f["target"] for f in fs if f.get("vcenter") == vc["name"] and f["type"] == "host_down" and f not in skipped}
        lost |= {h for f in fs if f.get("vcenter") == vc["name"] and f["type"] == "cluster_down" for h in (vc["topo"].get("clusters") or {}).get(f["target"], {}).get("hosts", [])}
        if len(lost) >= 2:
            known = {f["text"] for p in parts for f in p["findings"]}
            cp_said = any("컨트롤 플레인" in t for t in known)
            for t in CB._colocated(world, vc, lost):
                if t not in known and not (cp_said and t.startswith("VKS")):
                    extra.append({"sev": "fail", "text": f"[겹친 장애] {t}"})
    # 2.46.0 플랫폼 계층 — 직접 가정 + 위에서 잃은 VM·호스트로 Supervisor·VKS·Avi 판정
    lost_hosts = {(f["vcenter"], f["target"]) for f in fs if f["type"] == "host_down" and f not in skipped}
    for f in fs:
        if f["type"] == "cluster_down":
            vc = CB._vc(world, f["vcenter"])
            lost_hosts |= {(f["vcenter"], h) for h in (vc["topo"].get("clusters") or {}).get(f["target"], {}).get("hosts", [])}
    for vcn, n, stt, why in X.get("vms") or []:                       # 시나리오가 직접 정한 VM 상태
        v = next((vc["topo"].get("vms", {}).get(n) for vc in world["vcenters"] if vc["name"] == vcn), None)
        if v is not None:
            vm_mark(vcn, CB._vm_row(n, v, why), "offline" if "poweredOn" not in str(v.get("power")) else stt)
    plat = PS.evaluate(P, pfs, {k: x["state"] for k, x in vms.items()}, lost_hosts) if (pfs or vms or lost_hosts) else {"findings": [], "items": [], "marks": {}, "vms": [], "actions": [], "pods": []}
    Vx = {(vc["name"], n): v for vc in world["vcenters"] for n, v in (vc["topo"].get("vms") or {}).items()}
    for vcn, n, stt, why in plat["vms"]:
        if (vcn, n) in Vx:
            v = Vx[(vcn, n)]
            vm_mark(vcn, CB._vm_row(n, v, why), "offline" if "poweredOn" not in str(v.get("power")) else stt)
    extra += plat["findings"] + [dict(f) for f in X.get("findings") or []]
    plat["items"] = plat["items"] + list(X.get("items") or [])
    plat["pods"] = plat.get("pods", []) + list(X.get("pods") or [])
    plat["actions"] = plat["actions"] + list(X.get("actions") or [])
    plat["marks"] = {**(X.get("marks") or {}), **plat["marks"]}
    F = [{"sev": f["sev"], "text": f"[{p['kind']} · {p['target']}] {f['text']}", "key": p["sim_key"]} for p in parts for f in p["findings"]] + extra
    # 객체 표시
    for f in fs:
        if f in skipped:
            continue
        vcn = f.get("vcenter", "")
        st = {"host_down": "failed", "host_maint": "maint", "uplink_loss": "net", "cluster_down": "failed", "ds_apd": "failed", "ds_full": "full", "vcenter_upgrade": "failed",
              "edge_down": "failed", "switch_down": "failed", "device_down": "failed", "storage_down": "failed"}[f["type"]]
        kind = {"edge_down": "edge", "vcenter_upgrade": "vc", "switch_down": "switch", "device_down": "device", "storage_down": "storage"}.get(f["type"]) or \
            ("ds" if f["type"].startswith("ds_") else f.get("scope", "host"))
        marks[f"{kind}:{vcn}/{f['target'] if kind != 'vc' else vcn}"] = st
        if f["type"] == "cluster_down":
            vc = CB._vc(world, vcn)
            for h in (vc["topo"].get("clusters") or {}).get(f["target"], {}).get("hosts", []):
                marks.setdefault(f"host:{vcn}/{h}", "failed")
    for p in parts:
        for hk, m in (p.get("host_marks") or {}).items():
            marks.setdefault(f"host:{hk}", {"isolated": "isolated", "extlost": "extlost", "degraded": "halfnet"}.get(m, "affected"))
        if p["type"] == "storage_down":
            for d in ((world.get("phys") or {}).get("storage") or {}).get(p["target"], {}).get("datastores", []):
                marks[f"ds:{d['vcenter']}/{d['name']}"] = "failed"
            for h in p["hosts"]:
                for v in world["vcenters"]:
                    if h in (v["topo"].get("hosts") or {}):
                        marks.setdefault(f"host:{v['name']}/{h}", "affected")
    for (vcn, cl) in removed:
        marks.setdefault(f"cluster:{vcn}/{cl}", "degraded")
    for (vcn, n), x in vms.items():
        marks[f"vm:{vcn}/{n}"] = x["state"]
    for k_, m_ in plat["marks"].items():
        marks.setdefault(k_, m_)
    hosts_hit = {(p.get("vcenter", ""), h) for p in parts if p["type"] in ("ds_apd",) for h in p["hosts"]}
    for vcn, h in hosts_hit:
        marks.setdefault(f"host:{vcn}/{h}", "affected")
    svc, seen_s = [], set()
    for p in parts:
        for s_ in p["services"]:
            k = (s_["kind"], s_["name"])
            if k not in seen_s:
                seen_s.add(k)
                svc.append(s_)
    for s_ in svc:
        if s_["kind"] == "NSX Edge":
            for e in world["edges"]:
                if e["name"] == s_["name"]:
                    marks.setdefault(f"edge:/{e['edge_cluster']}", "affected")
    vks: dict[str, dict] = {}
    for p in parts:
        for c in p["vks"]["clusters"]:
            cur = vks.setdefault(c["cluster"], {**c, "nodes": set(), "control_plane_lost": set(), "pod_list": set(), "namespaces": set()})
            cur["nodes"] |= set(c["nodes"])
            cur["control_plane_lost"] |= set(c["control_plane_lost"])
            cur["pod_list"] |= set(c["pod_list"])
            cur["namespaces"] |= set(c["namespaces"])
    vks_out = [{**c, "nodes": sorted(c["nodes"]), "control_plane_lost": sorted(c["control_plane_lost"]), "pod_list": sorted(c["pod_list"])[:200],
                "namespaces": sorted(c["namespaces"]), "pods": len(c["pod_list"])} for c in vks.values()]
    for c in vks_out:
        per = max((len(x["control_plane_lost"]) for p in parts for x in p["vks"]["clusters"] if x["cluster"] == c["cluster"]), default=0)
        n, tot = len(c["control_plane_lost"]), c.get("control_plane_total", 0)
        if n > per and tot and n * 2 >= tot:
            F.append({"sev": "fail", "text": f"[겹친 장애] VKS '{c['cluster']}' 컨트롤 플레인 {n}/{tot}대를 함께 잃습니다 — 클러스터 API 가 멈춥니다"})
    vm_list = sorted(vms.values(), key=lambda x: (RANK[x["state"]], x["name"]))
    for x in vm_list:
        x["by"] = sorted(set(x["by"]))
    sev = max((CB.SEV.get(f["sev"], 1) for f in F), default=1)
    actions: list[str] = []
    for p in parts:
        for a in p.get("actions") or []:
            if a not in actions:
                actions.append(a)
    for a in plat["actions"]:
        if a not in actions:
            actions.append(a)
    if any("겹친 장애" in f["text"] for f in extra) and not any("반선호도" in a for a in actions):
        actions.append("이중화 묶음(VKS 컨트롤 플레인·NSX Edge·Avi SE)을 서로 다른 호스트·랙에 두도록 반선호도 규칙을 확인하세요")
    pl_cnt = dict(Counter(i["state"] for i in plat["items"]))
    return {"failures": [{k: f[k] for k in ("type", "vcenter", "target") if k in f} | {"kind": CB.TYPES[f["type"]][0], "skipped": f in skipped} for f in fs]
            + [{k: f[k] for k in ("type", "vcenter", "target") if k in f} | {"kind": PS.TYPES[f["type"]][0], "skipped": False} for f in pfs],
            "platform": {"items": plat["items"], "counts": pl_cnt, "pods": plat["pods"][:2000], "pod_counts": dict(Counter(p["state"] for p in plat["pods"]))},
            "verdict": {3: "fail", 2: "warn", 1: "pass"}[sev] if fs or pfs or X else "none", "findings": F, "actions": actions[:10], "vms": vm_list,
            "counts": dict(Counter(x["state"] for x in vm_list)), "vms_on": sum(1 for x in vm_list if x["power"] == "on"),
            "services": svc, "vks": {"clusters": vks_out}, "marks": marks, "states": VM_STATES,
            "timeline": timeline(vm_list, plat, float(X.get("repair_h") or REPAIR_H))}
