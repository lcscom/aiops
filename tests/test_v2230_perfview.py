"""2.23.0 호스트·VM 성능 상세 — 카운터 변환·집계, 데모·vcsim 경로, API, 화면 연결"""
import asyncio
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_perfcalc_units_and_aggregation():
    from app.perfcalc import build, latest, summarize
    ts = [40.0, 0.0, 20.0]                                     # 뒤섞인 순서 → 오름차순
    raw = [("cpu.usage.average", "", [3000, 1000, 2000]),     # 1/100 %
           ("cpu.ready.summation", "", [800, 400, -1]),       # ms/20초, vCPU 4 → %
           ("mem.consumed.average", "", [2048, 1024, 1536]),   # KB → MB
           ("virtualDisk.numberReadAveraged.average", "scsi0:0", [30, 10, 20]),
           ("virtualDisk.numberReadAveraged.average", "scsi0:1", [3, 1, 2]),
           ("virtualDisk.totalReadLatency.average", "scsi0:0", [5, 1, 2]),
           ("virtualDisk.totalReadLatency.average", "scsi0:1", [9, 3, 1]),
           ("net.received.average", "", [100, 0, 50]),          # KBps → bit/s
           ("net.received.average", "4000", [100, 0, 50]),
           ("net.packetsRx.summation", "4000", [200, 0, 100])]  # 간격 합 → /s
    b = build(raw, ts, 20, "vm", vcpu=4)
    s = b["series"]
    assert b["ts"] == [0.0, 20.0, 40.0]
    assert s["cpu.usage_pct"] == [10.0, 20.0, 30.0]
    assert s["cpu.ready_pct"][0] == pytest.approx(400 / 20000 * 100 / 4) and s["cpu.ready_pct"][1] is None
    assert s["mem.consumed_mb"] == [1.0, 1.5, 2.0]
    assert s["disk.read_iops"] == [11, 22, 33]                                   # 디스크별 합
    assert s["disk.read_lat_ms"] == [3, 2, 9]                                    # 디스크별 최대
    assert s["net.rx_bps"][2] == 100 * 8 * 1024                                  # 집계("") 우선
    d0 = b["instances"]["disk"][0]
    assert d0["id"] == "scsi0:0" and d0["read_iops"] == 30 and d0["read_iops_max"] == 30 and d0["read_iops_avg"] == 20
    assert b["instances"]["net"][0]["rx_pps"] == 10.0
    assert "mem.swapped.average" in b["missing"]
    sm = summarize(s)
    assert sm["cpu.usage_pct"] == {"last": 30.0, "avg": 20.0, "max": 30.0, "min": 10.0}
    lt = latest(raw, 20, "vm", 4)
    assert lt["cpu_pct"] == 20.0 and lt["iops"] == 22


def _demo_engine(monkeypatch):
    import app.main as M
    from app.connectors.demo import demo_perf_latest, demo_perf_series, demo_topology

    class C:
        type, name, enabled = "vcenter", "demo-vc", True
        topology = demo_topology()
        perf_series = staticmethod(demo_perf_series)
        perf_latest = staticmethod(demo_perf_latest)
    monkeypatch.setattr(M.ENGINE, "connectors", [C()])
    from app.perfview import PerfView
    return M, PerfView(M.ENGINE), C


def test_perfview_demo(monkeypatch):
    M, P, C = _demo_engine(monkeypatch)
    vms = P.entities("vm")
    hosts = P.entities("host")
    assert vms and hosts and all(v["kind"] == "vm" for v in vms)
    on = next(v for v in vms if v["state"] == "poweredOn")

    async def go():
        t = await P.top("vm")
        assert t["measured"] >= 1 and all("cpu_pct" in r["now"] for r in t["rows"])
        assert (await P.top("vm")) is t                                      # 60초 캐시
        d = await P.detail("vm", on["name"], "", "rt")
        assert len(d["ts"]) == 180 and d["series"]["cpu.usage_pct"] and d["info"]["host"] == on["host"]
        assert {r["id"] for r in d["instances"]["disk"]} == {"scsi0:0", "scsi0:1"}
        h = await P.detail("host", hosts[0]["name"], "", "7d")
        assert h["interval"] == 1800 and h["info"]["vms_total"] >= 0 and "disk.device_lat_ms" in h["series"]
        assert P.csv(h).splitlines()[0].startswith("﻿time,")
        with pytest.raises(KeyError):
            await P.detail("vm", "nope", "", "rt")
        bad = await P.detail("vm", on["name"], "", "weird")
        assert bad["range"] == "rt"
    asyncio.run(go())


def test_perf_api_rbac_and_errors():
    from fastapi import HTTPException

    import app.main as M
    from app.security.auth import ROUTE_RULES

    def perm(m, p):
        for mm, rx, pr in ROUTE_RULES:
            if (mm == "*" or mm == m) and re.search(rx, p):
                return pr
    for p in ("/api/perf/entities", "/api/perf/top", "/api/perf/detail", "/api/perf/detail.csv"):
        assert perm("GET", p) == "view"
    with pytest.raises(HTTPException) as ex:
        asyncio.run(M.perf_entities("datastore"))
    assert ex.value.status_code == 400


def test_vcsim_perf():
    import socket
    try:
        socket.create_connection(("127.0.0.1", 8989), timeout=1).close()
    except OSError:
        pytest.skip("vcsim 없음")
    from app.connectors.vcenter import VCenterConnector
    c = VCenterConnector({"name": "sim", "host": "127.0.0.1:8989", "username": "user", "password": "pass", "verify_tls": False}, lambda e: None)
    try:
        topo = c._refresh_topology()
    except Exception as ex:  # noqa: BLE001
        pytest.skip(f"vcsim 접속 불가: {type(ex).__name__}")
    vm = next(v for v in topo["vms"].values() if v["power"] == "poweredOn")
    d = c.perf_series("vm", vm["moid"], "rt", 1)
    assert d["ts"] and d["series"].get("cpu.usage_pct") and not d["error"]
    h = next(iter(topo["hosts"].values()))
    hd = c.perf_series("host", h["moid"], "1d")
    assert hd["interval"] == 300 and "cpu.usage_pct" in hd["series"]
    lt = c.perf_latest("vm", [("x", vm["moid"], 1)])
    assert "x" in lt and lt["x"]["cpu_pct"] is not None


def test_ui_wiring():
    html = (ROOT / "app/static/index.html").read_text(encoding="utf-8")
    assert 'id="nav-pf"' in html and 'id="drawer-pf"' in html and html.index("/static/perfview.js") < html.index("/static/layout.js")
    assert re.search(r'"g-perf".*\["pf", "sli"', (ROOT / "app/static/navgroup.js").read_text(encoding="utf-8"))
    assert "AIOPS_PERF" in (ROOT / "app/static/ux.js").read_text(encoding="utf-8")
    assert subprocess.run(["node", "-e", f"new Function(require('fs').readFileSync('{ROOT / 'app/static/perfview.js'}','utf8'))"]).returncode == 0
    en = (ROOT / "app/static/i18n-en.js").read_text(encoding="utf-8")
    for k in ("호스트·VM 성능", "지금 부하 측정", "CPU ready(vCPU 평균)", "가상 디스크별"):
        assert f'"{k}":' in en


def test_qa_fixes(monkeypatch):
    """QA: 순위 IOPS 2배(종류별 카운터), 다시 측정 30초 제한, 오류 결과 캐시 안 함, 커넥터 잠금 묶음 단위"""
    from app.perfcalc import LATEST_COUNTERS
    assert not any(k.startswith("disk.number") for k in LATEST_COUNTERS["vm"])
    assert not any(k.startswith("virtualDisk.") for k in LATEST_COUNTERS["host"])
    M, P, C = _demo_engine(monkeypatch)
    calls = []
    orig = C.perf_latest

    def counting(kind, items, *a, **k):
        calls.append(1)
        return orig(kind, items)
    C.perf_latest = staticmethod(counting)
    n = {"x": 0}

    def flaky(kind, moid, rng="rt", vcpu=1, labels=None):
        n["x"] += 1
        return {"ts": [], "series": {}, "instances": {}, "interval": 20, "missing": [], "error": "QueryPerf: 끊김"}
    C.perf_series = staticmethod(flaky)
    on = next(v for v in P.entities("vm") if v["state"] == "poweredOn")

    async def go():
        await P.top("vm")
        await asyncio.gather(*[P.top("vm", fresh=True) for _ in range(5)])
        assert len(calls) == 1                                       # 연타·동시 요청 — 한 번만 측정
        await P.detail("vm", on["name"])
        await P.detail("vm", on["name"])
        assert n["x"] == 2                                           # 오류 결과는 캐시하지 않음
    asyncio.run(go())
    src = (ROOT / "app/connectors/vcenter.py").read_text(encoding="utf-8")
    i = src.index("def perf_latest")
    assert "def run(chunk)" in src[i:i + 3000] and "한 대씩 다시" in src[i:i + 3000]
