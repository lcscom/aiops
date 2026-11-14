"""물리 → 논리 토폴로지(스택 뷰) — 연결된 커넥터가 본 것을 계층으로 이어 붙인다.

  ⓪ 패브릭 인터커넥트(UCS) ─ ① 섀시 ─ ② 물리 서버(블레이드·랙·BMC) ─ ③ ESXi 호스트 ─ ④ 가상 스위치(VDS)
  ─ ⑤ Edge·SE·VM(VM 은 정확한 이름으로 개별 표시, 호스트당 vm_limit 초과분만 '외 N개') ─ ⑥ Pod(VKS 노드 VM 아래)
  ─ ⑦ Edge 클러스터·SE 그룹 ─ ⑧ Tier-0·가상 서비스 ─ ⑨ Tier-1·세그먼트·포트그룹(VM 이 붙은 네트워크)

연결 근거
  서버 ↔ ESXi : SMBIOS UUID(바이트 순서 차이 허용) → S/N → 이름(esxi_host 설정·서비스 프로필명)
  Edge ↔ ESXi : NSX vm_deployment_config.host_id(vCenter 호스트 moid) → 같은 이름의 VM 위치
  SE ↔ ESXi   : Avi host_ref(실행 호스트) → 같은 이름의 VM 위치
  SE ↔ VS     : virtualservice runtime.vip_summary[].service_engine
  VM ↔ 네트워크 : vCenter VM.network(포트그룹 이름) = NSX 세그먼트 이름이면 세그먼트, 아니면 포트그룹
  Pod ↔ VM    : Kubernetes spec.nodeName = vCenter VM 이름(VKS 워커·컨트롤 플레인 노드는 VM)
  흐름도(flow) : VS 풀 멤버 IP ↔ VM guest IP · Pod IP · 노드 InternalIP
  Edge 클러스터 ↔ T0/T1 : locale-services.edge_cluster_path, T1 ↔ T0 : tier0_path
상태는 커넥터가 본 운영 상태 + 열린 이상징후(위험=장애, 오류·경고=주의)를 겹쳐 판정.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any

LAYERS = ["패브릭", "섀시", "물리 서버", "ESXi 호스트", "가상 스위치", "Edge · SE · VM", "Pod (VKS)", "Edge 클러스터 · SE 그룹", "Tier-0 · 가상 서비스",
          "Tier-1 · 세그먼트 · 포트그룹"]
L_VM, L_POD, L_EC, L_T0, L_T1 = 5, 6, 7, 8, 9
POD_ST = {"Running": "ok", "Succeeded": "maint", "Pending": "warn", "Failed": "down", "Unknown": "unknown"}


def _short(h: str) -> str:
    h = str(h or "").split(":")[0].lower().strip()
    return h if re.fullmatch(r"[\d.]+", h) else h.split(".")[0]


def uuid_variants(u: str) -> set[str]:
    """SMBIOS UUID — 장비(BMC·UCS)와 ESXi 가 앞 세 필드의 바이트 순서를 다르게 보고하는 경우가 있어 둘 다 비교"""
    u = str(u or "").lower().strip()
    h = u.replace("-", "")
    if not re.fullmatch(r"[0-9a-f]{32}", h) or set(h) == {"0"}:
        return set()
    sw = h[6:8] + h[4:6] + h[2:4] + h[0:2] + h[10:12] + h[8:10] + h[14:16] + h[12:14] + h[16:]
    fmt = lambda x: f"{x[:8]}-{x[8:12]}-{x[12:16]}-{x[16:20]}-{x[20:]}"   # noqa: E731
    return {fmt(h), fmt(sw)}


def host_for_hw(connectors, uuid: str, serial: str) -> str:
    """서버 UUID·S/N → vCenter ESXi 호스트 이름(없으면 빈 문자열)"""
    us = uuid_variants(uuid)
    ser = str(serial or "").lower()
    if not us and not ser:
        return ""
    hit_s = []
    for c in connectors:
        if getattr(c, "type", "") != "vcenter":
            continue
        for hn, h in (getattr(c, "topology", {}) or {}).get("hosts", {}).items():
            if us and str(h.get("uuid", "")).lower() in us:
                return hn
            if ser and str(h.get("serial", "")).lower() == ser:
                hit_s.append(hn)
    return hit_s[0] if len(hit_s) == 1 else ""


def _vm_state(v: dict) -> str:
    if v.get("power") != "poweredOn":
        return "maint"
    return {"red": "down", "yellow": "warn"}.get(str(v.get("status") or ""), "ok")


def _vm_sub(v: dict) -> str:
    bits = [str(v.get("os") or "")[:40], f"{v.get('vcpu', '-')} vCPU · {round((v.get('mem_mb') or 0) / 1024, 1)} GB"]
    if v.get("ips"):
        bits.append(", ".join(v["ips"][:3]))
    return " · ".join(b for b in bits if b)


def build(engine, now: float | None = None, vm_limit: int = 60, pod_limit: int = 25, vms: bool = True, pods: bool = True) -> dict[str, Any]:
    """vm_limit: ESXi 호스트당 개별 표시할 VM 수(0 = 전부), pod_limit: 노드당 Pod 수(0 = 전부). vms/pods=False 면 묶음만"""
    now = now or time.time()
    nodes: dict[str, dict] = {}
    links: list[tuple[str, str, str]] = []

    def node(nid, layer, label, kind, state="unknown", sub="", group="", **meta):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "layer": layer, "label": label, "kind": kind, "state": state, "sub": sub, "group": group, **meta}
        return nodes[nid]

    def link(a, b, kind=""):
        if a in nodes and b in nodes and a != b:
            links.append((a, b, kind))

    conns = [c for c in engine.connectors if getattr(c, "enabled", True)]
    # 다른 계층에 이미 개체로 그리는 VM(Edge·SE)은 VM 으로 중복 표시하지 않음 · VKS 노드 VM 은 항상 개별 표시
    special = {str(n).lower() for c in conns if c.type == "nsx" for n in (getattr(c, "edges", {}) or {}).values()}
    special |= {str(n).lower() for c in conns if c.type == "avi" for n in (getattr(c, "se", {}) or {})}
    k8s_nodes = {str(n.get("name", "")).lower() for c in conns if c.type == "vks" for n in ((getattr(c, "inv", {}) or {}).get("nodes") or [])}
    alert_names: set[str] = set()
    for a in list(engine.anomalies.values()):
        if not a.ack and now - a.last_seen < 1800:
            for k in ((a.event or {}).get("host"), (a.event or {}).get("entity")):
                if k:
                    alert_names.add(str(k).lower())
    nsx_segs = {str(sg.get("name", "")): (c.name, sg) for c in conns if c.type == "nsx" for sg in ((getattr(c, "inv", {}) or {}).get("segments") or [])
                if sg.get("name")}
    # ---------------------------------------------------------------- ③ ESXi 호스트·④ VDS·⑤ VM (vCenter)
    host_by_uuid, host_by_serial, host_by_name, host_by_moid, vm_host = {}, {}, {}, {}, {}
    vm_node: dict[str, str] = {}                    # VM 이름(소문자) → 노드 id
    for c in [c for c in conns if c.type == "vcenter"]:
        t = getattr(c, "topology", {}) or {}
        hosts, vmd = t.get("hosts", {}), t.get("vms", {})
        nets = t.get("networks", {}) or {}
        by_host: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        for vn, v in vmd.items():
            by_host[v.get("host", "")].append((vn, v))
            vm_host[vn.lower()] = (c.name, v.get("host", ""))
        for hn, h in hosts.items():
            st = "down" if h.get("conn") not in ("connected", "") else "maint" if h.get("maintenance") else \
                {"red": "down", "yellow": "warn"}.get(h.get("status"), "ok")
            hid = f"host:{c.name}:{hn}"
            cpu = round(h["cpu_used_mhz"] / h["cpu_mhz"] * 100) if h.get("cpu_mhz") else None
            mem = round(h["mem_used_mb"] / h["mem_mb"] * 100) if h.get("mem_mb") else None
            hv = by_host.get(hn, [])
            node(hid, 3, hn, "esxi", st, f"{h.get('hw_vendor', '')} {h.get('hw_model', '')}".strip(), group=h.get("cluster", "") or "(독립)",
                 vcenter=c.name, moid=h.get("moid", ""), cpu=cpu, mem=mem, vms=len(hv), serial=h.get("serial", ""), uuid=h.get("uuid", ""),
                 pnics=h.get("pnics", []), switches=h.get("switches", []), esx=f"{h.get('esx_version', '')} ({h.get('esx_build', '')})".strip(" ()"),
                 vsan=(h.get("vsan") or {}).get("role") or ("vSAN" if h.get("vsan") else ""))
            for u in uuid_variants(h.get("uuid", "")):
                host_by_uuid[u] = hid
            if h.get("serial"):
                k = str(h["serial"]).lower()
                host_by_serial[k] = "" if k in host_by_serial else hid      # 중복 S/N(가상·미설정 장비)은 근거로 쓰지 않음
            host_by_name[_short(hn)] = hid
            host_by_name[hn.lower()] = hid
            if h.get("moid"):
                host_by_moid[h["moid"]] = hid
            for sw in h.get("switches", []):
                if sw.get("kind") == "vds":
                    node(f"vds:{c.name}:{sw['name']}", 4, sw["name"], "vds", "ok", "Distributed Switch", vcenter=c.name)
                    link(hid, f"vds:{c.name}:{sw['name']}", ",".join(sw.get("uplinks", [])))
            plain = [(vn, v) for vn, v in hv if vn.lower() not in special]
            # 우선순위: 이상징후 → VKS 노드 → 켜짐 → 이름
            plain.sort(key=lambda x: (x[0].lower() not in alert_names, x[0].lower() not in k8s_nodes, x[1].get("power") != "poweredOn", x[0].lower()))
            show = plain if (vms and not vm_limit) else plain[:vm_limit] if vms else [x for x in plain if x[0].lower() in k8s_nodes or x[0].lower() in alert_names]
            for vn, v in show:
                vid = f"vm:{c.name}:{vn}"
                node(vid, L_VM, vn, "vm", _vm_state(v), _vm_sub(v), group=h.get("cluster", ""), vcenter=c.name, host=hn, power=v.get("power", ""),
                     ips=v.get("ips", []), os=v.get("os", ""), vcpu=v.get("vcpu"), mem_gb=round((v.get("mem_mb") or 0) / 1024, 1),
                     folder=v.get("folder", ""), tags=v.get("tags", []), networks=v.get("networks", []), datastores=v.get("datastores", []),
                     k8s=vn.lower() in k8s_nodes)
                vm_node[vn.lower()] = vid
                link(hid, vid, "VM")
                for net in v.get("networks", [])[:6]:
                    if not net:
                        continue
                    if net in nsx_segs:
                        nname, sg = nsx_segs[net]
                        nid = f"nseg:{nname}:{net}"
                        node(nid, L_T1, net, "segment", "ok", (f"NSX 세그먼트 {sg.get('gateway', '') or ''}" + (f" · VLAN {sg['vlan']}" if sg.get("vlan") else "")).strip(), nsx=nname)
                    else:
                        ni = nets.get(net, {})
                        nid = f"pg:{c.name}:{net}"
                        node(nid, L_T1, net, "portgroup", "ok" if ni.get("accessible") is not False else "warn",
                             f"{ {'dvportgroup': '분산 포트그룹', 'opaque': 'NSX(opaque) 네트워크', 'portgroup': '표준 포트그룹'}.get(ni.get('kind', ''), '네트워크') }"
                             + (f" · VLAN {ni['vlan']}" if ni.get("vlan") not in (None, "") else "") + (f" · {ni['dvs']}" if ni.get("dvs") else ""))
                    link(vid, nid, "vNIC")
            rest = len(plain) - len(show)
            if rest > 0:
                on = sum(1 for x in plain if x[1].get("power") == "poweredOn") - sum(1 for x in show if x[1].get("power") == "poweredOn")
                node(f"vmg:{c.name}:{hn}", L_VM, f"외 VM {rest}개 (켜짐 {on})", "vmgroup", "ok", f"{hn} 의 나머지 VM — VM 표시 수를 늘리거나 검색", group=h.get("cluster", ""))
                link(hid, f"vmg:{c.name}:{hn}")

    def find_host(uuid="", serial="", *names) -> tuple[str, str]:
        for u in uuid_variants(uuid):
            if u in host_by_uuid:
                return host_by_uuid[u], "UUID"
        if serial and host_by_serial.get(str(serial).lower()):
            return host_by_serial[str(serial).lower()], "S/N"
        for n in names:
            if n and (str(n).lower() in host_by_name or _short(n) in host_by_name):
                return host_by_name.get(str(n).lower()) or host_by_name[_short(n)], "이름"
        return "", ""

    unmatched: list[dict] = []
    # ---------------------------------------------------------------- ⓪①② UCS Manager
    for c in [c for c in conns if c.type == "ucsm"]:
        u = getattr(c, "ucs", {}) or {}
        dom = (u.get("system") or {}).get("name") or c.name
        fi_ids = []
        for f in u.get("fis", []):
            fid = f"fi:{c.name}:{f['id']}"
            node(fid, 0, f"{dom} FI-{f['id']}", "fi", f.get("state", "unknown"), f"{f.get('model', '')} {f.get('ip', '')} {f.get('leadership', '')}".strip(), group=dom)
            fi_ids.append(fid)
        for ch in u.get("chassis", []):
            cid = f"ch:{c.name}:{ch['id']}"
            node(cid, 1, f"{dom} 섀시 {ch['id']}", "chassis", ch.get("state", "unknown"), f"{ch.get('model', '')} 전원 {ch.get('power', '')}", group=dom)
            for fid in fi_ids:
                link(fid, cid, "IOM")
        for b in c.servers() if hasattr(c, "servers") else []:
            sid = f"srv:{c.name}:{b['dn']}"
            label = b.get("profile") or b["dn"].replace("sys/", "")
            node(sid, 2, label, "blade" if b["kind"] == "blade" else "rack", b.get("state", "unknown"),
                 f"{b['dn'].replace('sys/', '')} · {b.get('model', '')} · {b.get('oper', '')} 전원 {b.get('power', '')}", group=dom,
                 serial=b.get("serial", ""), uuid=b.get("uuid", ""), source="UCS Manager")
            if b["kind"] == "blade" and b.get("chassis"):
                link(f"ch:{c.name}:{b['chassis']}", sid)
            else:
                for fid in fi_ids:
                    link(fid, sid, "FEX/직결")
            hid, how = find_host(b.get("uuid", ""), b.get("serial", ""), b.get("profile", ""), b.get("label", ""))
            if not hid and b.get("hw_uuid"):
                hid, how = find_host(b["hw_uuid"])
            if hid:
                nodes[sid]["match"] = how
                link(sid, hid, how)
            elif b.get("assoc") == "associated":
                unmatched.append({"server": label, "source": "UCS Manager", "serial": b.get("serial", ""), "uuid": b.get("uuid", "")})
    # ---------------------------------------------------------------- ② Redfish·CIMC 서버
    for c in [c for c in conns if c.type == "redfish"]:
        s = getattr(c, "server", {}) or {}
        sid = f"srv:{c.name}"
        ent = (c.entities() or [{}])[0] if hasattr(c, "entities") else {}
        cstate = c.state().get("state")
        st = ent.get("state") or ("down" if cstate == "down" else "unknown")
        node(sid, 2, getattr(c, "display", c.name), "server", st, f"{s.get('manufacturer', '') or getattr(c, 'vendor', '')} {s.get('model', '')} · BMC {c.host}".strip(),
             group="랙 서버", serial=s.get("serial", ""), uuid=s.get("uuid", ""), source=getattr(c, "vendor", "") or "Redfish",
             bmc_state=cstate, bmc_error=(c.state().get("last_error") or "")[:160])
        hid, how = find_host(s.get("uuid", ""), s.get("serial", ""), (getattr(c, "cfg", {}) or {}).get("esxi_host", ""), s.get("hostname", ""), getattr(c, "display", ""))
        if hid:
            nodes[sid]["match"] = how
            link(sid, hid, how)
        else:
            unmatched.append({"server": getattr(c, "display", c.name), "source": getattr(c, "vendor", "") or "Redfish", "serial": s.get("serial", ""),
                              "uuid": s.get("uuid", ""), "state": cstate})
    # ---------------------------------------------------------------- ⑤⑥⑦⑧ NSX
    for c in [c for c in conns if c.type == "nsx"]:
        inv = getattr(c, "inv", {}) or {}
        ei = getattr(c, "edge_info", {}) or {}
        es = getattr(c, "_edge_state", {}) or {}
        ec_name = {e.get("id", ""): e.get("name", "") for e in inv.get("edge_clusters", []) if e.get("id")}
        for tid, name in (getattr(c, "edges", {}) or {}).items():
            info = ei.get(tid, {})
            eid = f"edge:{c.name}:{tid}"
            st = {"UP": "ok", "DEGRADED": "warn", "DOWN": "down"}.get(es.get(tid, ""), "unknown")
            node(eid, 5, name, "edge", st, f"NSX Edge {info.get('form', '')} {info.get('mgmt_ip', '')}".strip(), nsx=c.name, detail=info.get("detail"))
            hid = host_by_moid.get(info.get("host_moid", "")) or ""
            if not hid and name.lower() in vm_host:
                vc, hn = vm_host[name.lower()]
                hid = f"host:{vc}:{hn}"
            if hid in nodes:
                link(hid, eid, "Edge VM")
            if info.get("edge_cluster"):
                cid = f"ec:{c.name}:{info['edge_cluster']}"
                node(cid, L_EC, info["edge_cluster"], "edge-cluster", "ok", "Edge 클러스터")
                link(eid, cid)
        for t0 in [x for x in inv.get("tier0", []) if x.get("id")]:
            tid = f"t0:{c.name}:{t0['id']}"
            node(tid, L_T0, t0.get("name") or t0["id"], "t0", "ok", f"Tier-0 {t0.get('ha_mode', '')}".strip())
            if t0.get("edge_cluster_id") and ec_name.get(t0["edge_cluster_id"]):
                link(f"ec:{c.name}:{ec_name[t0['edge_cluster_id']]}", tid)
        segs_by_t1: dict[str, int] = defaultdict(int)
        t1_ids = {x.get("id") for x in inv.get("tier1", [])}
        for sg in inv.get("segments", []):
            k = sg.get("tier1") or (sg.get("connected_to") if sg.get("connected_to") in t1_ids else "")
            if k:
                segs_by_t1[k] += 1
        for t1 in [x for x in inv.get("tier1", []) if x.get("id")]:
            tid = f"t1:{c.name}:{t1['id']}"
            node(tid, L_T1, t1.get("name") or t1["id"], "t1", "ok", f"Tier-1 · 세그먼트 {segs_by_t1.get(t1['id'], 0)}개")
            if t1.get("tier0"):
                link(f"t0:{c.name}:{t1['tier0']}", tid)
            if t1.get("edge_cluster_id") and ec_name.get(t1["edge_cluster_id"]):
                link(f"ec:{c.name}:{ec_name[t1['edge_cluster_id']]}", tid, "SR")
        for sg in inv.get("segments", []):                # VM 이 붙은 세그먼트만 노드로 있음 → T1 과 연결
            sid_ = f"nseg:{c.name}:{sg.get('name', '')}"
            ct = sg.get("tier1") or sg.get("connected_to") or ""
            if sid_ in nodes and ct and f"t1:{c.name}:{ct}" in nodes:
                link(f"t1:{c.name}:{ct}", sid_, "연결")
            elif sid_ in nodes and ct and f"t0:{c.name}:{ct}" in nodes:
                link(f"t0:{c.name}:{ct}", sid_, "연결")
        nsx_mgr = f"nsxm:{c.name}"
        st = "down" if c.state().get("state") == "down" else "ok"
        node(nsx_mgr, L_EC, f"NSX Manager {c.host.split(':')[0]}", "nsx-manager", st, "관리 평면")
    # ---------------------------------------------------------------- ⑤⑥⑦ Avi
    STM = {"OPER_UP": "ok", "OPER_DOWN": "down", "OPER_DISABLED": "maint", "OPER_INACTIVE": "maint"}
    for c in [c for c in conns if c.type == "avi"]:
        for name, se in (getattr(c, "se", {}) or {}).items():
            sid = f"se:{c.name}:{name}"
            node(sid, 5, name, "se", STM.get(se.get("state", ""), "warn" if se.get("state") else "unknown"),
                 f"Avi SE {se.get('mgmt_ip', '')} · 호스트 {se.get('host', '-')}", avi=c.name)
            hid = ""
            if se.get("host"):
                hid, _ = find_host("", "", se["host"])
            if not hid and name.lower() in vm_host:
                vc, hn = vm_host[name.lower()]
                hid = f"host:{vc}:{hn}"
            if hid:
                link(hid, sid, "SE VM")
            if se.get("se_group"):
                gid = f"seg:{c.name}:{se['se_group']}"
                node(gid, L_EC, se["se_group"], "se-group", "ok", "SE 그룹")
                link(sid, gid)
        for v in (c.vips() if hasattr(c, "vips") else []):
            vid = f"vs:{c.name}:{v['uuid']}"
            node(vid, L_T0, v["name"], "vs", STM.get(v.get("state", ""), "warn" if v.get("state") else "unknown"),
                 f"VIP {', '.join(v.get('vips') or [])}{':' + ','.join(str(p) for p in v.get('ports') or []) if v.get('ports') else ''} · Health {v.get('health') if v.get('health') is not None else '-'}")
            for se_name in (getattr(c, "vs", {}).get(v["uuid"], {}) or {}).get("ses", []):
                link(f"se:{c.name}:{se_name}", vid, "VIP 배치")
            if v.get("se_group") and not any(t == vid for _, t, _ in links):
                link(f"seg:{c.name}:{v['se_group']}", vid)
    # ---------------------------------------------------------------- ⑥ Pod (VKS) — 노드(VM) 아래
    for c in [c for c in conns if c.type == "vks"]:
        inv = getattr(c, "inv", {}) or {}
        label = getattr(c, "cluster_label", c.name)
        knodes = {str(n.get("name", "")): n for n in inv.get("nodes") or []}
        by_node: dict[str, list[dict]] = defaultdict(list)
        for p in inv.get("pods") or []:
            by_node[p.get("node") or ""].append(p)
        for kn, plist in by_node.items():
            parent = vm_node.get(kn.lower())
            if not parent:
                n = knodes.get(kn) or {}
                parent = f"knode:{c.name}:{kn or '(미배치)'}"
                hid = ""
                if kn.lower() in vm_host:
                    vc, hn = vm_host[kn.lower()]
                    hid = f"host:{vc}:{hn}"
                node(parent, L_VM, kn or "(미배치 Pod)", "k8s-node", {"True": "ok", "False": "down"}.get(n.get("ready", ""), "unknown") if kn else "warn",
                     f"{label} 노드 {n.get('ip', '')} · {','.join(n.get('roles') or [])}".strip(), group=label)
                if hid:
                    link(hid, parent, "노드 VM")
            else:
                nodes[parent]["k8s_cluster"] = label
            plist.sort(key=lambda p: (p.get("phase") == "Running", p.get("ns", ""), p.get("name", "")))
            show = plist if (pods and not pod_limit) else plist[:pod_limit] if pods else [p for p in plist if p.get("phase") not in ("Running", "Succeeded")][:pod_limit or 25]
            for p in show:
                pid = f"pod:{c.name}:{p.get('ns')}/{p.get('name')}"
                st = POD_ST.get(p.get("phase", ""), "unknown")
                if st == "ok" and (p.get("reason") or p.get("restarts", 0) > 20):
                    st = "warn"
                node(pid, L_POD, f"{p.get('ns')}/{p.get('name')}", "pod", st,
                     f"{label} · {p.get('phase', '')} {p.get('ready', '')}{' · ' + p['reason'] if p.get('reason') else ''} · 재시작 {p.get('restarts', 0)}"
                     + (f" · {p['ip']}" if p.get("ip") else ""), group=label, k8s_cluster=label, ns=p.get("ns"), ip=p.get("ip", ""), node_name=kn)
                link(parent, pid, "Pod")
            if len(plist) > len(show):
                node(f"podg:{c.name}:{kn}", L_POD, f"외 Pod {len(plist) - len(show)}개", "podgroup", "ok", f"{kn} 의 나머지 Pod", group=label)
                link(parent, f"podg:{c.name}:{kn}")
    # ---------------------------------------------------------------- 이상징후 겹침
    window = 1800
    sev_by: dict[str, int] = {}
    R = {"warning": 2, "error": 3, "critical": 4}
    for a in list(engine.anomalies.values()):
        if a.ack or now - a.last_seen > window or (a.ai or {}).get("is_anomaly") is False:
            continue
        e = a.event or {}
        for k in (e.get("host"), e.get("entity")):
            if k:
                k = str(k).lower()
                for kk in (k, _short(k), k.replace("edge:", "")):
                    sev_by[kk] = max(sev_by.get(kk, 0), R.get(a.severity, 0))
    for n in nodes.values():
        r = max(sev_by.get(n["label"].lower(), 0), sev_by.get(_short(n["label"]), 0))
        if r:
            n["alert"] = r
            if r >= 4:
                n["state"] = "down"
            elif r >= 2 and n["state"] in ("ok", "unknown"):
                n["state"] = "warn"
    used = {l for l in range(len(LAYERS)) if any(n["layer"] == l for n in nodes.values())}
    groups = sorted({n["group"] for n in nodes.values() if n["layer"] == 3 and n["group"]})
    return {"updated": now, "layers": LAYERS, "used_layers": sorted(used), "nodes": list(nodes.values()),
            "links": [{"s": a, "t": b, "k": k} for a, b, k in links], "clusters": groups, "unmatched": unmatched,
            "counts": {k: sum(1 for n in nodes.values() if n["kind"] == k) for k in ("fi", "chassis", "blade", "rack", "server", "esxi", "vds", "edge", "se", "vs", "t0", "t1",
                                                                                      "vm", "pod", "segment", "portgroup", "k8s-node")},
            "totals": {"vms": sum(len((getattr(c, "topology", {}) or {}).get("vms", {})) for c in conns if c.type == "vcenter"),
                       "pods": sum(len((getattr(c, "inv", {}) or {}).get("pods") or []) for c in conns if c.type == "vks")},
            "options": {"vm_limit": vm_limit, "pod_limit": pod_limit, "vms": vms, "pods": pods}}


def path_of(d: dict[str, Any], name: str) -> dict[str, Any] | None:
    """스택 토폴로지에서 이름이 같은 노드의 상위(물리 쪽)·하위(서비스 쪽) 경로 — 개체 상세·검색용"""
    if not name:
        return None
    n = str(name).lower()
    short = n.split(".")[0]
    nodes = {x["id"]: x for x in d.get("nodes", [])}
    hit = next((x for x in nodes.values() if str(x.get("label", "")).lower() == n), None) \
        or next((x for x in nodes.values() if str(x.get("label", "")).lower().split(".")[0] == short), None)
    if not hit:
        return None
    up: dict[str, list[str]] = defaultdict(list)
    down: dict[str, list[str]] = defaultdict(list)
    for l in d.get("links", []):
        up[l["t"]].append(l["s"])
        down[l["s"]].append(l["t"])

    def walk(start: str, g: dict, limit: int) -> list[str]:
        seen, out, q = {start}, [], list(g.get(start, []))
        while q and len(out) < limit:
            x = q.pop(0)
            if x in seen:
                continue
            seen.add(x)
            out.append(x)
            q += g.get(x, [])
        return out
    brief = lambda i: {k: nodes[i].get(k) for k in ("id", "label", "kind", "state", "layer", "sub")}
    return {"node": brief(hit["id"]), "up": [brief(i) for i in walk(hit["id"], up, 12)],
            "down": [brief(i) for i in walk(hit["id"], down, 40)]}


# ---------------------------------------------------------------- 서비스 흐름도
FLOW_STAGES = [("client", "클라이언트"), ("vs", "VIP · 가상 서비스"), ("se", "Service Engine"), ("pool", "풀"), ("member", "풀 멤버(VM·Pod)"),
               ("net", "세그먼트 · 포트그룹"), ("gw", "Tier-1 · Tier-0"), ("host", "ESXi 호스트"), ("server", "물리 서버")]


def _ip_index(conns) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for c in conns:
        if c.type == "vcenter":
            for vn, v in ((getattr(c, "topology", {}) or {}).get("vms", {}) or {}).items():
                for ip in v.get("ips") or []:
                    idx.setdefault(ip, {"kind": "vm", "name": vn, "vc": c.name, "host": v.get("host", ""), "networks": v.get("networks", []),
                                        "state": _vm_state(v), "sub": _vm_sub(v)})
    for c in conns:
        if c.type == "vks":
            inv = getattr(c, "inv", {}) or {}
            for n in inv.get("nodes") or []:
                if n.get("ip") and n["ip"] not in idx:
                    idx[n["ip"]] = {"kind": "k8s-node", "name": n.get("name", ""), "cluster": getattr(c, "cluster_label", c.name),
                                    "state": {"True": "ok", "False": "down"}.get(n.get("ready", ""), "unknown"), "sub": f"노드 {n.get('ip')}"}
            for p in inv.get("pods") or []:
                if p.get("ip") and p.get("ip") != p.get("host_ip"):           # hostNetwork Pod 는 노드 IP 와 같으므로 노드로 둔다
                    idx.setdefault(p["ip"], {"kind": "pod", "name": f"{p.get('ns')}/{p.get('name')}", "node": p.get("node", ""),
                                             "cluster": getattr(c, "cluster_label", c.name), "state": POD_ST.get(p.get("phase", ""), "unknown"),
                                             "sub": f"{p.get('phase', '')} {p.get('ready', '')} · 노드 {p.get('node', '')}"})
    return idx


def flow(engine, vs: str = "", vm: str = "", max_vs: int = 30) -> dict[str, Any]:
    conns = [c for c in engine.connectors if getattr(c, "enabled", True)]
    phys = build(engine, vms=False, pods=False, vm_limit=1)
    pn = {n["id"]: n for n in phys["nodes"]}
    host_server: dict[str, dict] = {}
    for l in phys["links"]:
        a, b = pn.get(l["s"]), pn.get(l["t"])
        if a and b and b["kind"] == "esxi" and a["kind"] in ("blade", "rack", "server"):
            host_server[b["label"].lower()] = a
    ipx = _ip_index(conns)
    vmx: dict[str, tuple[str, dict]] = {}
    for c in conns:
        if c.type == "vcenter":
            for vn, v in ((getattr(c, "topology", {}) or {}).get("vms", {}) or {}).items():
                vmx[vn.lower()] = (c.name, v)
    nsx_segs = {str(sg.get("name", "")): (c, sg) for c in conns if c.type == "nsx" for sg in ((getattr(c, "inv", {}) or {}).get("segments") or [])}
    nodes: dict[str, dict] = {}
    links: dict[tuple[str, str], dict] = {}

    def node(nid, stage, label, kind, state="ok", sub="", **kw):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "stage": stage, "label": label, "kind": kind, "state": state, "sub": sub, **kw}
        return nid

    def link(a, b, k="", w=None):
        if a in nodes and b in nodes and a != b:
            x = links.setdefault((a, b), {"s": a, "t": b, "k": k, "w": 0})
            if w:
                x["w"] += w

    def down_from_vm(vm_name: str, vid: str) -> None:
        """VM → 네트워크 → 게이트웨이 · VM → ESXi → 물리 서버"""
        hit = vmx.get(vm_name.lower())
        if not hit:
            return
        vc, v = hit
        for net in (v.get("networks") or [])[:4]:
            if net in nsx_segs:
                nc, sg = nsx_segs[net]
                nid = node(f"net:{net}", "net", net, "segment", "ok", f"NSX 세그먼트 {sg.get('gateway', '')}".strip())
                link(vid, nid, "vNIC")
                gw = sg.get("tier1") or sg.get("connected_to")
                if gw:
                    tid = lambda t: t.get("id") or t.get("name") or ""   # noqa: E731  (Policy id, 없으면 이름)
                    t1 = next((t for t in ((getattr(nc, "inv", {}) or {}).get("tier1") or []) if gw in (t.get("id"), t.get("name"))), None)
                    want0 = (t1 or {}).get("tier0") if t1 else gw
                    t0 = next((t for t in ((getattr(nc, "inv", {}) or {}).get("tier0") or []) if want0 and want0 in (t.get("id"), t.get("name"))), None)
                    if t1:
                        g1 = node(f"t1:{tid(t1)}", "gw", t1.get("name") or tid(t1), "t1", "ok", "Tier-1")
                        link(nid, g1, "")
                        if t0:
                            link(g1, node(f"t0:{tid(t0)}", "gw", t0.get("name") or tid(t0), "t0", "ok", f"Tier-0 {t0.get('ha_mode', '')}".strip()), "")
                    elif t0:
                        link(nid, node(f"t0:{tid(t0)}", "gw", t0.get("name") or tid(t0), "t0", "ok", "Tier-0"), "")
            elif net:
                link(vid, node(f"net:{net}", "net", net, "portgroup", "ok", "포트그룹"), "vNIC")
        hn = v.get("host", "")
        if hn:
            hid = node(f"host:{hn}", "host", hn, "esxi", "ok", v.get("cluster", ""))
            link(vid, hid, "실행")
            srv = host_server.get(hn.lower())
            if srv:
                link(hid, node(srv["id"], "server", srv["label"], srv["kind"], srv["state"], srv.get("sub", "")), srv.get("match", ""))

    def member_node(ip: str, port: Any, pool_id: str) -> None:
        m = ipx.get(ip)
        lab = f"{ip}:{port}" if port else ip
        if not m:
            mid = node(f"m:{ip}", "member", lab, "ip", "unknown", "VM·Pod 인벤토리에서 이 IP 를 찾지 못함(외부 서버·게스트 도구 미보고)")
            link(pool_id, mid, "")
            return
        if m["kind"] == "vm":
            mid = node(f"vm:{m['name']}", "member", m["name"], "vm", m["state"], f"{lab} · {m['sub']}")
            link(pool_id, mid, lab)
            down_from_vm(m["name"], mid)
        elif m["kind"] == "pod":
            mid = node(f"pod:{m['name']}", "member", m["name"], "pod", m["state"], f"{lab} · {m['cluster']} · {m['sub']}")
            link(pool_id, mid, lab)
            if m.get("node"):
                nvid = node(f"vm:{m['node']}", "member", m["node"], "vm", "ok", f"{m['cluster']} 노드 VM")
                link(mid, nvid, "노드")
                down_from_vm(m["node"], nvid)
        else:
            mid = node(f"vm:{m['name']}", "member", m["name"], "vm", m["state"], f"{lab} · {m['cluster']} 노드(NodePort)")
            link(pool_id, mid, lab)
            down_from_vm(m["name"], mid)

    vlist = []
    for c in conns:
        if c.type != "avi":
            continue
        vsd = getattr(c, "vs", {}) or {}
        pools = {p.get("name"): p for p in getattr(c, "pools", []) or []}
        for v in (c.vips() if hasattr(c, "vips") else []):
            vlist.append({"uuid": v["uuid"], "name": v["name"], "vips": v.get("vips"), "ports": v.get("ports"), "state": v.get("state"), "ctrl": c.name})
        sel = []
        for u, v in vsd.items():
            if vs and vs not in (u, v.get("name")):
                continue
            sel.append((u, v))
        if vm:
            want = vm.lower()
            vmips = {ip for ip, m in ipx.items() if m["name"].lower() == want or m.get("node", "").lower() == want}
            pl = (lambda v: c.vs_pools(v)) if hasattr(c, "vs_pools") else (lambda v: [pools[v["pool"]]] if v.get("pool") in pools else [])
            sel = [(u, v) for u, v in vsd.items() if any(mm.get("ip") in vmips for p_ in pl(v) for mm in p_.get("members", []))]
        for u, v in sorted(sel, key=lambda x: x[1].get("name", ""))[: (max_vs if not vs else 5)]:
            st = {"OPER_UP": "ok", "OPER_DOWN": "down"}.get(v.get("state", ""), "warn" if v.get("state") else "unknown")
            m = v.get("metrics") or {}
            last = {k: next((x for x in reversed(vals) if x is not None), None) for k, vals in m.items()}
            vid = node(f"vs:{u}", "vs", v.get("name", u), "vs", st,
                       f"VIP {', '.join(v.get('vips') or [])}{':' + ','.join(map(str, v.get('ports') or [])) if v.get('ports') else ''} · Health {v.get('health', '-')}",
                       bw=last.get("bw"), rps=last.get("rps"), cps=last.get("cps"), uuid=u)
            eu = None
            for (uu, _mins, _lim), ent in (getattr(c, "_eu_cache", {}) or {}).items():
                if uu == u:
                    eu = ent["data"]
            if eu and eu.get("top_clients"):
                for tc in eu["top_clients"][:6]:
                    cid = node(f"cl:{tc['ip']}", "client", tc["ip"] or "(미상)", "client", "warn" if tc.get("err") else "ok",
                               f"요청 {tc['n']} · {tc.get('os') or ''} {tc.get('browser') or ''} {tc.get('location') or ''}".strip())
                    link(cid, vid, "요청", tc["n"])
                if eu.get("unique_clients", 0) > 6:
                    link(node(f"cl:others:{u}", "client", f"외 클라이언트 {eu['unique_clients'] - 6}", "client", "ok", f"최근 {eu.get('minutes')}분"), vid, "")
            else:
                link(node("cl:any", "client", "클라이언트", "client", "ok", "End user 분석을 열면 상위 클라이언트 IP 로 펼쳐짐"), vid, "")
            for se_name in v.get("ses") or []:
                se = (getattr(c, "se", {}) or {}).get(se_name, {})
                sid = node(f"se:{se_name}", "se", se_name, "se", {"OPER_UP": "ok", "OPER_DOWN": "down"}.get(se.get("state", ""), "unknown"),
                           f"SE 그룹 {se.get('se_group', '-')} · {se.get('mgmt_ip', '')}")
                link(vid, sid, "VIP 배치")
                if se.get("host"):
                    hid = node(f"host:{se['host']}", "host", se["host"], "esxi", "ok", "")
                    link(sid, hid, "SE VM")
                    srv = host_server.get(str(se["host"]).lower())
                    if srv:
                        link(hid, node(srv["id"], "server", srv["label"], srv["kind"], srv["state"], srv.get("sub", "")), "")
            plist = c.vs_pools(v) if hasattr(c, "vs_pools") else ([pools[v["pool"]]] if v.get("pool") in pools else [])
            for p in plist[:8]:                          # pool_ref·풀 그룹·L4 정책(AKO)으로 붙은 풀 모두
                pid = node(f"pool:{p['name']}", "pool", p["name"], "pool",
                           "down" if p.get("up") == 0 and p.get("servers") else "warn" if p.get("up") is not None and p.get("servers") and p["up"] < p["servers"] else "ok",
                           f"멤버 {p.get('up', '-')}/{p.get('servers', '-')} up · Health {p.get('health', '-')}")
                for s_ in [x for x in nodes if x.startswith("se:")]:
                    if (s_, vid) in links or (vid, s_) in links:
                        link(s_, pid, "부하분산")
                if not v.get("ses"):
                    link(vid, pid, "")
                for mm in (p.get("members") or [])[:64]:
                    if mm.get("ip"):
                        member_node(mm["ip"], mm.get("port"), pid)
    if vm and not any(n["stage"] == "member" for n in nodes.values()):
        hit = vmx.get(vm.lower())
        if hit:
            vid = node(f"vm:{vm}", "member", vm, "vm", _vm_state(hit[1]), _vm_sub(hit[1]))
            down_from_vm(vm, vid)
    used = [s for s in FLOW_STAGES if any(n["stage"] == s[0] for n in nodes.values())]
    return {"mode": "vs" if vs else "vm" if vm else "all", "vs": vs, "vm": vm, "stages": [{"key": k, "title": t} for k, t in used],
            "nodes": list(nodes.values()), "links": list(links.values()), "vs_list": sorted(vlist, key=lambda x: x["name"])[:2000],
            "generated": time.time()}
