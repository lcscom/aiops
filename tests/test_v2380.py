"""2.38.0 — AI 체크봇: what-if 시나리오 대량 생성·검증(호스트 장애·롤링 유지보수·유지보수 중 장애·클러스터 장애·APD·가득 참·업링크·vCenter 업그레이드·Edge·인증서·복합),
영향 리소스 목록(VM·호스트·관리 서비스·VKS 파드), 이력 가중치, AI 제안 검증·가명화, 연속 실행·새 실패 알림, API·화면"""
import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _vm(host, ds, power="poweredOn", vcpu=4, mem=16384):
    return {"host": host, "cluster": "c1", "power": power, "vcpu": vcpu, "mem_mb": mem, "disk_gb": 100, "datastores": ds}


def _world_conns(ha=True, single_uplink=True):
    H = {f"h{i}": {"cpu_mhz": 160000, "core_mhz": 2500, "mem_mb": 1024000, "cpu_used_mhz": 30000, "mem_used_mb": 300000, "sockets": 2, "cluster": "c1",
                   "moid": f"host-{i}", "datastores": ["ds1"] + (["local-h0"] if i == 0 else [])} for i in range(4)}
    vms = {"vcsa01": _vm("h0", ["ds1"]), "db-local": _vm("h0", ["local-h0"]), "gpu-vm": _vm("h1", ["ds1"]), "iso-vm": _vm("h1", ["ds1"]),
           "cp-1": _vm("h2", ["ds1"]), "cp-2": _vm("h2", ["ds1"]), "cp-3": _vm("h3", ["ds1"]), "w-1": _vm("h3", ["ds1"]),
           "edge-01": _vm("h3", ["ds1"]), "off-vm": _vm("h1", ["ds1"], power="poweredOff")}
    topo = {"clusters": {"c1": {"hosts": list(H), "ha": ha, "drs": True, "vsan": False}}, "hosts": H, "vms": vms,
            "datastores": {"ds1": {"capacity_gb": 10000, "free_gb": 400, "type": "VMFS"}, "local-h0": {"capacity_gb": 500, "free_gb": 100, "local": True}}}
    sw2 = [{"name": "vds", "kind": "dvs", "uplinks": ["vmnic0", "vmnic1"]}]
    health = {f"h{i}": {"version": "8.0.3" if i else "8.0.2", "vswitches": ([{"name": "vSwitch0", "kind": "std", "uplinks": ["vmnic0"]}] if i == 0 and single_uplink else sw2),
                        "vmks": [{"device": "vmk0", "services": ["management"], "switch": "vSwitch0" if i == 0 else "vds"}]} for i in range(4)}
    bp = {"vms": [{"name": "gpu-vm", "passthru": 1, "usb": 0, "cdrom_connected": 0}, {"name": "iso-vm", "passthru": 0, "usb": 0, "cdrom_connected": 1}]}
    vc = NS(name="vc1", type="vcenter", enabled=True, host="vc1.bank.local", topology=topo,
            health_snap={"hosts": health, "clusters": {"c1": {"drs_behavior": "fullyAutomated"}}, "bp_vms": bp},
            vks={"supervisors": [{"name": "sv1"}]}, protection={"kind": "appliance_backup", "product": "vCenter", "configured": True, "last_success": time.time() - 5 * 86400})
    vks = NS(name="tkc-pay", type="vks", enabled=True, cluster_label="pay", role="workload",
             inv={"nodes": [{"name": "cp-1", "roles": ["control-plane"]}, {"name": "cp-2", "roles": ["control-plane"]}, {"name": "cp-3", "roles": ["control-plane"]},
                            {"name": "w-1", "roles": []}],
                  "pods": [{"ns": "pay", "name": "api-1", "node": "w-1"}, {"ns": "kube-system", "name": "etcd-cp-1", "node": "cp-1"}, {"ns": "kube-system", "name": "etcd-cp-2", "node": "cp-2"}]})
    nsx = NS(name="nsx1", type="nsx", enabled=True, edge_info={"t1": {"name": "edge-01", "host_moid": "host-3", "edge_cluster": "ec1"},
                                                               "t2": {"name": "edge-02", "host_moid": "host-3", "edge_cluster": "ec1"}})
    srm = NS(name="srm1", type="srm", enabled=True, protection={"groups": [], "vms": [{"group": "G", "name": "VCSA01"}]})
    return [vc, vks, nsx, srm]


def _world(**k):
    return CB.build_world(NS(connectors=_world_conns(**k), certs=NS(last={"items": [
        {"system": "pay", "kind": "API 서버", "name": "pay-apiserver", "band": "crit", "days_left": 5, "renew": "kubeadm certs renew"},
        {"system": "vc1", "kind": "vCenter 머신 SSL", "name": "vc1", "band": "ok", "days_left": 300}]})))


def _by(results, t, target=None):
    return [r for r in results if r["type"] == t and (target is None or r["target"] == target)]


def test_generate_mass_scenarios():
    w = _world()
    assert w["srm_on"] and w["srm_protected"] == {"vcsa01"} and len(w["edges"]) == 2 and len(w["certs"]) == 1     # ok 인증서는 시나리오 아님
    specs = CB.generate(w, {("vc1", "ds1"): 40})
    cnt = {}
    for s in specs:
        cnt[s["type"]] = cnt.get(s["type"], 0) + 1
    assert cnt == {"host_down": 4, "uplink_loss": 4, "host_maint": 1, "maint_plus_fail": 1, "cluster_down": 1, "ds_apd": 1, "ds_full": 1,
                   "vcenter_upgrade": 1, "edge_down": 1, "cert_expire": 1, "storage_down": 1}
    assert len({s["id"] for s in specs}) == len(specs) and all(s["origin"] == "rule" for s in specs)
    assert not _by(specs, "ds_apd", "local-h0")                                   # 로컬 데이터스토어는 APD 시나리오 아님


def test_host_down_affected_resources():
    w = _world()
    r = CB.evaluate(w, {"type": "host_down", "vcenter": "vc1", "cluster": "c1", "target": "h0", "id": "x"})
    assert r["verdict"] == "fail" and r["hosts"] == ["h0"]
    names = {v["name"]: v for v in r["vms"]}
    assert set(names) == {"vcsa01", "db-local"} and "로컬" in names["db-local"]["reason"] and "HA 가" in names["vcsa01"]["reason"]
    assert any(s["kind"] == "vCenter" and s["name"] == "vcsa01" for s in r["services"])
    assert r["capacity"]["verdict"] in ("ok", "warn") and any("다시 켤 수 없습니다" in f["text"] for f in r["findings"])
    assert any("공유 데이터스토어" in a for a in r["actions"])
    # VKS 컨트롤 플레인 2/3 이 같은 호스트 — 과반 손실
    r2 = CB.evaluate(w, {"type": "host_down", "vcenter": "vc1", "cluster": "c1", "target": "h2", "id": "y"})
    k = r2["vks"]["clusters"][0]
    assert k["cluster"] == "pay" and k["control_plane_lost"] == ["cp-1", "cp-2"] and k["pods"] == 2 and r2["verdict"] == "fail"
    assert any("컨트롤 플레인 2/3" in f["text"] for f in r2["findings"]) and any("반선호도" in a or "vSphere Zone" in a for a in r2["actions"])
    # HA 꺼짐
    r3 = CB.evaluate(_world(ha=False), {"type": "host_down", "vcenter": "vc1", "cluster": "c1", "target": "h1", "id": "z"})
    assert r3["verdict"] == "fail" and any("HA 가 꺼져" in f["text"] for f in r3["findings"])
    assert r3["impact"]["vms_on"] == 2 and r3["impact"]["vms"] == 2                # 꺼진 VM 은 영향 목록에 넣지 않음


def test_maint_uplink_apd_edge_cluster_vc_cert():
    w = _world()
    m = CB.evaluate(w, {"type": "host_maint", "vcenter": "vc1", "cluster": "c1", "target": "c1", "id": "m"})
    bl = {v["name"]: v["reason"] for v in m["vms"]}
    assert "PCI 패스스루" in bl["gpu-vm"] and "CD-ROM" in bl["iso-vm"] and "로컬 디스크" in bl["db-local"] and m["verdict"] == "fail"
    assert sum(1 for f in m["findings"] if f["sev"] == "fail" and "vMotion" in f["text"]) == 1 and any("CD-ROM·ISO" in f["text"] for f in m["findings"])
    u0 = CB.evaluate(w, {"type": "uplink_loss", "vcenter": "vc1", "cluster": "c1", "target": "h0", "id": "u"})
    assert u0["verdict"] == "fail" and "management" in u0["findings"][0]["text"] and len(u0["vms"]) == 2
    assert CB.evaluate(w, {"type": "uplink_loss", "vcenter": "vc1", "cluster": "c1", "target": "h1", "id": "u1"})["verdict"] == "pass"
    a = CB.evaluate(w, {"type": "ds_apd", "vcenter": "vc1", "target": "ds1", "id": "a"})
    assert a["verdict"] == "fail" and a["impact"]["vms_on"] == 8 and len(a["hosts"]) == 4
    assert {s["kind"] for s in a["services"]} >= {"vCenter", "NSX Edge"} and a["vks"]["clusters"][0]["nodes_total"] == 4
    f = CB.evaluate(w, {"type": "ds_full", "vcenter": "vc1", "target": "ds1", "days": 10, "id": "f"})
    assert f["verdict"] == "fail" and "96.0%" in f["findings"][0]["text"]
    e = CB.evaluate(w, {"type": "edge_down", "target": "ec1", "id": "e"})
    assert e["verdict"] == "fail" and e["hosts"] == ["h3"] and "같은 호스트" in e["findings"][0]["text"]
    c = CB.evaluate(w, {"type": "cluster_down", "vcenter": "vc1", "cluster": "c1", "target": "c1", "id": "c"})
    assert c["verdict"] == "fail" and any("SRM 보호 밖 VM 8대" in x["text"] for x in c["findings"])
    assert {v["name"]: v["reason"] for v in c["vms"]}["vcsa01"] == "클러스터와 함께 멈춤"
    u = CB.evaluate(w, {"type": "vcenter_upgrade", "vcenter": "vc1", "target": "vc1.bank.local", "id": "v"})
    assert u["verdict"] == "warn" and any("48시간" in x["text"] for x in u["findings"]) and any("ESXi 버전이 섞여" in x["text"] for x in u["findings"])
    assert any(s["kind"] == "VKS Supervisor" for s in u["services"]) and any(s["kind"] == "SRM" for s in u["services"])
    ce = CB.evaluate(w, {"type": "cert_expire", "target": "x", "cert": w["certs"][0], "id": "ce"})
    assert ce["verdict"] == "fail" and "5일 뒤" in ce["findings"][0]["text"] and ce["actions"] == ["kubeadm certs renew"]


def test_ai_parse_and_compound():
    w = _world()
    txt = "설명 무시 ```json\n" + json.dumps([
        {"title": "h1 장애 중 ds1 APD", "why": "가장 붐빔", "steps": [{"type": "host_down", "vcenter": "vc1", "target": "h1"}, {"type": "ds_apd", "vcenter": "vc1", "target": "ds1"}]},
        {"title": "두 호스트", "steps": [{"type": "host_down", "vcenter": "vc1", "target": "h0"}, {"type": "host_down", "vcenter": "vc1", "target": "h2"}]},
        {"title": "가짜", "steps": [{"type": "host_down", "vcenter": "vc1", "target": "nope"}, {"type": "rm -rf", "target": "h1"}]},
        {"title": "한 단계뿐", "steps": [{"type": "edge_down", "target": "ec1"}]}], ensure_ascii=False) + "\n```"
    ps = CB.parse_ai(txt, w)
    assert [p["target"] for p in ps] == ["h1 장애 중 ds1 APD", "두 호스트"] and all(p["origin"] == "ai" and p["type"] == "compound" for p in ps)
    assert CB.parse_ai("JSON 없음", w) == [] and CB.parse_ai("[{bad", w) == []
    r = CB.evaluate_compound(w, ps[1])
    # 같은 클러스터 두 호스트 장애 → 한꺼번에 용량·VM 합산(유지보수 중 장애와 같은 계산)
    assert r["verdict"] == "fail" and set(r["hosts"]) == {"h0", "h2"} and any("[유지보수 중 다른 호스트 장애 · h0 + h2]" in f["text"] for f in r["findings"])
    assert len({v["name"] for v in r["vms"]}) == len(r["vms"]) == 4
    brief, names = CB.inventory_brief(w, {"host_down": 2})
    assert {"vc1", "c1", "h0", "ds1"} <= set(names) and "local-h0" not in names and brief["history_30d"] == {"host_down": 2}


def test_history_weight_and_score(tmp_path):
    async def main():
        e = _engine(tmp_path)
        now = time.time()
        rows = [("a1", "Host esx01 not responding", "", now), ("a2", "vobd: APD start on naa.1", "", now), ("a3", "Permanent Device Loss", "", now),
                ("a4", "old psod", "", now - 40 * 86400)]
        for i, t, m, ts in rows:
            await e.store.x("INSERT INTO anomalies(id,created,last_seen,severity,status,ack,body) VALUES(?,?,?,?,?,?,?)",
                            (i, ts, ts, "error", "open", 0, json.dumps({"title": t, "event": {"message": m}})))
        return await CB.history_counts(e.store)
    h = _run(main())
    assert h["host_down"] == 1 and h["ds_apd"] == 2                                # 30일 넘은 것은 빼고
    w = _world()
    r = CB.evaluate(w, {"type": "ds_apd", "vcenter": "vc1", "target": "ds1", "id": "a"})
    assert CB.score(r, {"ds_apd": 10}) > CB.score(r, {}) > CB.score({**r, "verdict": "warn"}, {})


def test_bot_run_events_ai_and_api(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_checkbot import build_router
    e = _engine(tmp_path)
    got, seen = [], {}

    class Cap:
        async def overview(self, days=None):
            return {"items": [{"kind": "datastore", "vcenter": "vc1", "name": "ds1", "forecast": {"days_to": {"90": 30}}}]}

    class LLM:
        def order(self, task):
            return ["fake"]

        async def complete(self, system, user, max_tokens=0, task="", names=None):
            seen.setdefault("names", names)
            if "JSON 배열" in system:
                return json.dumps([{"title": "h1+ds1", "steps": [{"type": "host_down", "vcenter": "vc1", "target": "h1"}, {"type": "ds_apd", "vcenter": "vc1", "target": "ds1"}]}])
            return "**가장 위험한 것** — ds1 APD\n1. HA 켜기"

    conns = _world_conns(single_uplink=False)
    eng = NS(store=e.store, connectors=conns, capacity=Cap(), llm=LLM(), certs=NS(last={}), ingest=lambda ev: got.append(ev))
    bot = CB.CheckBot(eng)

    async def audit(*a, **k):
        return None
    app = FastAPI()
    app.include_router(build_router(eng, bot, lambda r: {"user": "op"}, audit))
    with TestClient(app) as cl:
        assert cl.get("/api/checkbot", params={"run": 0}).json()["summary"] is None
        d = cl.post("/api/checkbot/run", json={}).json()
        s = d["summary"]
        assert s["ai"] is True and s["ai_scenarios"] == 1 and d["ai"]["proposed"] == 1 and "HA 켜기" in d["ai"]["summary"]
        assert "h1" in seen["names"] and s["by_type"]["compound"]["n"] >= 2 and s["new_fail"] == 0 and got == []     # 첫 실행은 알림 없음
        lst = cl.get("/api/checkbot", params={"verdict": "fail", "type": "host_down"}).json()
        assert lst["matched"] == len(lst["results"]) > 0 and all(x["verdict"] == "fail" and x["type"] == "host_down" for x in lst["results"])
        assert lst["results"] == sorted(lst["results"], key=lambda x: -x["score"]) and "vms" not in lst["results"][0]
        ai = [x for x in cl.get("/api/checkbot", params={"verdict": ""}).json()["results"] if x["origin"] == "ai"]
        assert ai and ai[0]["target"] == "h1+ds1"
        one = cl.get("/api/checkbot/scenario", params={"id": "uplink_loss:vc1:h0"}).json()
        assert one["verdict"] == "pass" and cl.get("/api/checkbot/scenario", params={"id": "nope"}).status_code == 404
        q = cl.get("/api/checkbot", params={"q": "gpu-vm", "verdict": ""}).json()
        assert q["matched"] > 0 and all(x["impact"]["vms"] for x in q["results"])
        csv = cl.get("/api/checkbot.csv", params={"id": "host_down:vc1:h0"}).content.decode("utf-8-sig")
        assert "vcsa01" in csv and "db-local" in csv and "판단" in csv
        assert cl.get("/api/checkbot.csv").content.decode("utf-8-sig").startswith("위험점수,")
        # 인프라가 나빠지면(h0 업링크가 1개로) → 다음 실행에서 새 실패로 알림
        conns[0].health_snap["hosts"]["h0"]["vswitches"] = [{"name": "vSwitch0", "kind": "std", "uplinks": ["vmnic0"]}]
        conns[0].health_snap["hosts"]["h0"]["vmks"] = [{"device": "vmk0", "services": ["management"], "switch": "vSwitch0"}]
        d2 = cl.post("/api/checkbot/run", json={"ai": False}).json()
        assert d2["summary"]["new_fail"] == 1 and d2["summary"]["ai"] is False and d2["summary"]["ai_scenarios"] == 1   # AI 시나리오는 계속 검증
        assert len(got) == 1 and got[0].attrs["scenario"] == "uplink_loss:vc1:h0" and got[0].source == "aiops"
        h = cl.get("/api/checkbot/history").json()["runs"]
        assert len(h) == 2 and h[-1]["new_fail"] == 1
    # 저장된 실행으로 다시 열기(재시작 뒤)
    b2 = CB.CheckBot(eng)
    last = _run(b2.latest())
    assert last["summary"]["scenarios"] == d2["summary"]["scenarios"] and _run(b2.ensure()) is None and len(b2.ai_extra) == 1


def test_ui_wiring():
    js = (S / "checkbot.js").read_text(encoding="utf-8")
    for k in ("/api/checkbot/run", "/api/checkbot/scenario", "/api/checkbot.csv", "nav-bot", "drawer-bot", "cb-badge", "영향받는 VM"):
        assert k in js, k
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-bot"' in html and 'id="drawer-bot"' in html and "/static/checkbot.js" in html
    assert '"life", "bot", "chg", "rd"' in (S / "navgroup.js").read_text(encoding="utf-8")       # 2.41.1 점검·진단으로 이동
    assert 'tile("bot"' in (S / "mobile.js").read_text(encoding="utf-8")
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert 'S.spawn("checkbot"' in main and '"bot": bot' in main
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/checkbot/run$", "operate"' in auth
    import subprocess
    for f in ("checkbot.js", "mobile.js", "navgroup.js", "i18n-en.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
