"""호스트 평가(영역별 점검 → 판정) + 플릿 집계(용량·ToR 리프 쌍·펌웨어/BIOS 편차·노드 수)"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from . import bios as B
from . import rules as R
from . import security as S

VERDICT = {"ready": "준비됨", "actions": "조치 후 가능", "not_ready": "불가", "unknown": "확인 필요"}
MIN_HOSTS_DOC = ("https://techdocs.broadcom.com/us/en/vmware-cis/vcf/vcf-9-0-and-later/9-1/deployment/converging-your-existing-vsphere-infrastructure-to-a-vcf-or-vvf-platform-/"
                 "supported-and-not-supported-configurations.html")


def memory_grid(h: dict, channels: int) -> list[dict]:
    """소켓 × 채널 격자(DIMM 시각화용). 채널 위치를 보고하지 않는 BMC 는 슬롯 번호 순으로(채널을 추정하지 않음)"""
    dimms = h.get("dimms") or []
    letters = [chr(65 + i) for i in range(max(1, channels))]
    known = any(str(d.get("channel") or "") for d in dimms)
    by: dict[int, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for d in dimms:
        s = d.get("socket") or 1
        if known:
            ch = str(d.get("channel") or "")
            if ch.isdigit():
                ch = letters[int(ch) % len(letters)]
            ch = ch or "?"
        else:
            m = re.findall(r"\d+", str(d.get("locator") or ""))
            ch = f"#{m[-1]}" if m else "?"
        by[s][ch].append({"slot": d.get("slot") or d.get("locator"), "loc": d.get("locator"), "present": d.get("present"), "gib": d.get("size_gib"),
                          "speed": d.get("speed"), "rated": d.get("rated"), "health": d.get("health")})
    out = []
    for s in sorted(by):
        if known:
            keys = letters + sorted(k for k in by[s] if k not in letters)
        else:
            keys = sorted(by[s], key=lambda k: int(k[1:]) if k[1:].isdigit() else 999)
        chs = [{"ch": ch, "dimms": by[s].get(ch, []), "populated": sum(1 for x in by[s].get(ch, []) if x["present"])} for ch in keys if known and ch in letters or by[s].get(ch)]
        out.append({"socket": s, "channels": chs, "by_slot": not known})
    return out


def assess_host(h: dict, hcl=None, sel_days: int = 30) -> dict[str, Any]:
    cpu_rows, cpu = R.eval_cpu(h)
    mem_rows, mem = R.eval_memory(h, cpu)
    net_rows, net = R.eval_network(h)
    sto_rows, sto = R.eval_storage(h, net.get("max_up_gbps"), cpu, mem, hcl)
    plat = R.eval_platform(h, cpu)
    sel = R.eval_sel(h, sel_days)
    bios = B.evaluate(h, esa_candidate=sto.get("direct_nvme", 0) > 0)
    if bios["rows"]:
        for r in bios["rows"]:
            if r["status"] == "drift" and r["severity"] in ("blocker", "warn") and r["id"] != "boot":   # 부팅 모드는 platform boot.uefi 가 판정
                plat.append(R.chk("bios", f"bios.{r['id']}", f"BIOS: {r['title']}", "fail" if r["severity"] == "blocker" else "warn",
                                  f"{r['attribute']}={r['current']}", r["why"]))
    sec = S.audit(h)
    secs = S.score(sec)
    for r in h.get("pcie") or []:
        if hcl and hcl.loaded and r.get("class") in ("NetworkController", "MassStorageController") and r.get("vid"):
            r["hcl"] = hcl.match_pci(r["vid"], r["did"], r.get("svid", ""), r.get("ssid", ""), r.get("model") or r.get("name"))
        if r.get("lanes") and r.get("max_lanes") and r["lanes"] < r["max_lanes"]:
            plat.append(R.chk("platform", f"pcie.{r['id']}", f"PCIe 링크 폭 {r.get('name') or r['id']}", "warn", f"x{r['lanes']} / 최대 x{r['max_lanes']}", "슬롯·라이저 확인(성능 저하)"))
    checks = cpu_rows + mem_rows + sto_rows + net_rows + plat + sel
    # 판정: 차단 항목(cpu·boot·vsan 아닌 '필수') 실패 → 불가, 그 외 경고·실패 → 조치 후 가능
    block_ids = {"cpu.class", "cpu.mixed", "boot.uefi", "bios.virt", "bios.iommu"}
    blocking = [c for c in checks if c["status"] == "fail" and (c["id"] in block_ids)]
    if blocking:
        verdict = "not_ready"
    elif any(c["status"] in ("fail", "warn") for c in checks):
        verdict = "actions"
    elif any(c["id"] == "cpu.class" and c["status"] == "unknown" for c in checks):
        verdict = "unknown"
    else:
        verdict = "ready"
    actions = [c for c in sorted(checks, key=lambda c: -R.STATUS_RANK.get(c["status"], 0)) if c["status"] in ("fail", "warn") and c.get("fix")]
    s = h.get("system") or {}
    return {"verdict": verdict, "verdict_label": VERDICT[verdict], "blocking": [c["title"] for c in blocking],
            "summary": {"vendor": h.get("vendor"), "model": s.get("model"), "serial": s.get("serial"), "uuid": s.get("uuid"), "bios": s.get("bios_version"),
                        "bmc_fw": (h.get("bmc") or {}).get("fw"), "bmc_model": (h.get("bmc") or {}).get("model"), "hostname": s.get("hostname"), "power": s.get("power"),
                        "cpu": cpu, "memory": mem, "storage": sto, "network": net},
            "checks": checks, "counts": dict(Counter(c["status"] for c in checks)), "actions": [{"title": a["title"], "status": a["status"], "fix": a["fix"]} for a in actions[:15]],
            "security": {"rows": sec, "score": secs}, "bios": bios, "memory_grid": memory_grid(h, cpu.get("channels") or 8),
            "areas": {a: (R.worst([c for c in checks if c["area"] == a]) if any(c["area"] == a for c in checks) else
                      ({"pass": "pass", "info": "pass", "warn": "warn", "fail": "fail"}.get(bios["status"], "unknown") if a == "bios" else "unknown"))
                      for a in ("cpu", "memory", "storage", "vsan", "network", "platform", "bios", "events")}}


def fleet(hosts: list[dict]) -> dict[str, Any]:
    """hosts: [{target, host(정규화), result(assess_host)}] — 실패 호스트 제외"""
    ok = [x for x in hosts if x.get("result")]
    tot = {"hosts": len(ok), "failed": len(hosts) - len(ok), "sockets": 0, "cores": 0, "threads": 0, "mem_gib": 0, "nvme_tb": 0.0, "power_w": 0.0}
    for x in ok:
        sm = x["result"]["summary"]
        tot["sockets"] += sm["cpu"].get("sockets") or 0
        tot["cores"] += sm["cpu"].get("cores") or 0
        tot["threads"] += sm["cpu"].get("threads") or 0
        tot["mem_gib"] += sm["memory"].get("total_gib") or 0
        tot["nvme_tb"] += sm["storage"].get("nvme_tb") or 0
        tot["power_w"] += (x["host"].get("power") or {}).get("consumed_w") or 0
    tot["nvme_tb"] = round(tot["nvme_tb"], 2)
    verdicts = Counter(x["result"]["verdict"] for x in ok)
    vsan = Counter(x["result"]["summary"]["storage"].get("verdict") for x in ok)
    cpu_tiers = Counter(x["result"]["summary"]["cpu"].get("label") for x in ok)
    ready_hosts = verdicts.get("ready", 0) + verdicts.get("actions", 0)
    nodes = {"count": ready_hosts, "simple_vsan": ready_hosts >= 3, "simple_ext": ready_hosts >= 2, "ha": ready_hosts >= 4, "doc": MIN_HOSTS_DOC,
             "note": "VCF 9.1 문서 기준 — Simple: vSAN 3대(외부 스토리지 2대), HA: 4대(NSX Manager 3노드 분산)"}
    # 같은 모델 간 BIOS·BMC·NIC 펌웨어 편차
    drift = []
    by_model: dict[str, list[dict]] = defaultdict(list)
    for x in ok:
        by_model[x["result"]["summary"].get("model") or "?"].append(x)
    for model, xs in by_model.items():
        if len(xs) < 2:
            continue
        for key, label in (("bios", "BIOS"), ("bmc_fw", "BMC 펌웨어")):
            vals = Counter(x["result"]["summary"].get(key) for x in xs)
            if len(vals) > 1:
                drift.append({"model": model, "item": label, "values": [{"value": v, "hosts": [y["target"] for y in xs if y["result"]["summary"].get(key) == v]} for v in vals]})
        nicfw = Counter(tuple(sorted({p.get("fw") for p in x["host"].get("nics") or [] if p.get("fw")})) for x in xs)
        if len(nicfw) > 1:
            drift.append({"model": model, "item": "NIC 펌웨어", "values": [{"value": ", ".join(v) or "-", "hosts": [y["target"] for y in xs if tuple(sorted({p.get('fw') for p in y['host'].get('nics') or [] if p.get('fw')})) == v]} for v in nicfw]})
        base = xs[0]
        for y in xs[1:]:
            d = B.drift_between(base["host"], y["host"])
            if d:
                drift.append({"model": model, "item": f"BIOS 설정 {len(d)}개", "values": [{"value": f"기준 {base['target']}", "hosts": [base["target"]]},
                                                                                         {"value": "; ".join(f"{z['attribute']}: {z['a']}→{z['b']}" for z in d[:6]), "hosts": [y["target"]]}]})
    return {"totals": tot, "verdicts": dict(verdicts), "vsan": dict(vsan), "cpu_tiers": dict(cpu_tiers), "nodes": nodes, "tor": tor(ok), "drift": drift,
            "security": _fleet_sec(ok)}


def _fleet_sec(ok: list[dict]) -> dict:
    p = sum(x["result"]["security"]["score"]["pass"] for x in ok)
    f = sum(x["result"]["security"]["score"]["fail"] for x in ok)
    worst = Counter()
    for x in ok:
        for r in x["result"]["security"]["rows"]:
            if r["status"] == "fail":
                worst[(r["id"], r["title"])] += 1
    return {"compliance": round(p / (p + f) * 100, 1) if p + f else None, "top_fail": [{"id": k[0], "title": k[1], "hosts": n} for k, n in worst.most_common(8)]}


def tor(ok: list[dict]) -> dict[str, Any]:
    """LLDP 이웃 → 스위치별 연결 호스트, 리프 쌍(공통 호스트 많은 순 탐욕 매칭), 단일 홈·오결선"""
    sw_hosts: dict[str, set] = defaultdict(set)
    links = []
    host_sw: dict[str, Counter] = defaultdict(Counter)
    for x in ok:
        for p in x["host"].get("nics") or []:
            l = p.get("lldp") or {}
            key = l.get("system_name") or l.get("chassis_id")
            if not key or str(p.get("link", "")).lower() != "up":
                continue
            sw_hosts[key].add(x["target"])
            host_sw[x["target"]][key] += 1
            links.append({"host": x["target"], "nic": f"{p.get('adapter')}/{p.get('port')}", "speed": p.get("speed_gbps"), "switch": key, "port": l.get("port_id"), "mgmt_ip": l.get("mgmt_ip")})
    pairs, used = [], set()
    cand = []
    sws = sorted(sw_hosts)
    for i, a in enumerate(sws):
        for b in sws[i + 1:]:
            common = sw_hosts[a] & sw_hosts[b]
            if len(common) >= 2 or (common and len(ok) <= 2):
                cand.append((len(common), a, b))
    for n, a, b in sorted(cand, reverse=True):
        if a in used or b in used:
            continue
        used |= {a, b}
        pairs.append({"a": a, "b": b, "dual": sorted(sw_hosts[a] & sw_hosts[b]), "only_a": sorted(sw_hosts[a] - sw_hosts[b]), "only_b": sorted(sw_hosts[b] - sw_hosts[a])})
    hosts = []
    for x in ok:
        c = host_sw.get(x["target"], Counter())
        state = "dual" if len(c) >= 2 else ("single" if len(c) == 1 else "unknown")
        hosts.append({"host": x["target"], "switches": dict(c), "state": state, "miscabled": state == "single" and sum(c.values()) >= 2})
    known = [h for h in hosts if h["state"] != "unknown"]
    return {"switches": [{"name": k, "hosts": sorted(v)} for k, v in sorted(sw_hosts.items())], "pairs": pairs, "hosts": hosts, "links": links,
            "redundancy_pct": round(sum(1 for h in known if h["state"] == "dual") / len(known) * 100, 1) if known else None}
