"""2.24.0 성능 자동 진단·AI 해설·비교/히트맵 화면"""
import asyncio
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _rt(**series):
    n = max(len(v) for v in series.values())
    return {"ts": list(range(n)), "series": series, "instances": {"disk": [], "net": []}}


def test_rules_vm():
    from app.perfdiag import diagnose
    rt = _rt(**{"cpu.ready_pct": [12.0] * 30, "cpu.costop_pct": [4.0] * 30, "cpu.usage_pct": [50.0] * 30, "mem.balloon_mb": [0.0] * 29 + [256.0],
               "disk.read_lat_ms": [25.0] * 30, "disk.write_lat_ms": [30.0] * 30})
    rt["instances"]["net"] = [{"id": "4000", "drop_rx_max": 5, "drop_tx_max": 0, "drop_rx_avg": 1.0}]
    g = diagnose("vm", rt, None, {"vcpu": 8, "host_cpu_pct": 91.0}, [{"name": "noisy", "cpu_mhz": 9000}, {"name": "me", "cpu_mhz": 1000}])
    t = {f["title"]: f for f in g["findings"]}
    assert g["level"] == "critical" and t["CPU 경합(ready)"]["sev"] == "critical" and "호스트 CPU 91%" in t["CPU 경합(ready)"]["evidence"]
    assert "vCPU 과다 할당 의심(co-stop)" in t and "메모리 회수 발생(balloon)" in t and t["디스크 지연"]["sev"] == "warning"
    assert "네트워크 패킷 드롭" in t and t["같은 호스트에서 CPU 를 많이 쓰는 VM"]["sev"] == "warning" and "noisy 90%" in t["같은 호스트에서 CPU 를 많이 쓰는 VM"]["evidence"]
    assert g["findings"][0]["sev"] == "critical"                                   # 위험이 먼저


def test_rules_host_and_baseline():
    from app.perfdiag import diagnose
    rt = _rt(**{"disk.read_lat_ms": [30.0] * 20, "disk.write_lat_ms": [30.0] * 20, "disk.device_lat_ms": [27.0] * 20, "disk.kernel_lat_ms": [0.3] * 20,
               "mem.swapin_Bps": [0.0] * 17 + [4096.0] * 3, "cpu.usage_pct": [60.0] * 20})
    day = _rt(**{"cpu.usage_pct": [20.0] * 288})
    g = diagnose("host", rt, day, {}, [])
    t = {f["title"]: f for f in g["findings"]}
    assert "DAVG" in t["디스크 지연"]["evidence"] and "스토리지" in t["디스크 지연"]["advice"]
    assert t["호스트 스왑 발생"]["sev"] == "critical"
    assert "평소보다 높은 CPU 사용률" in t and g["baseline"]["cpu.usage_pct"]["avg24"] == 20.0
    rt2 = _rt(**{"disk.read_lat_ms": [25.0] * 20, "disk.write_lat_ms": [25.0] * 20, "disk.device_lat_ms": [3.0] * 20, "disk.kernel_lat_ms": [6.0] * 20})
    assert "큐 깊이" in {f["title"]: f for f in diagnose("host", rt2, None, {}, [])["findings"]}["디스크 지연"]["advice"]
    quiet = diagnose("vm", _rt(**{"cpu.usage_pct": [5.0] * 10, "cpu.ready_pct": [0.5] * 10}), _rt(**{"cpu.usage_pct": [4.0] * 100}), {"vcpu": 8}, [])
    assert quiet["level"] == "ok" and any(f["title"] == "vCPU 과다 할당 후보" for f in quiet["findings"])


def test_detail_has_diag_and_explain(monkeypatch):
    import app.main as M
    from app.connectors.demo import demo_perf_latest, demo_perf_series, demo_topology

    class C:
        type, name, enabled = "vcenter", "demo-vc", True
        topology = demo_topology()
        perf_series = staticmethod(demo_perf_series)
        perf_latest = staticmethod(demo_perf_latest)
    monkeypatch.setattr(M.ENGINE, "connectors", [C()])
    from app.perfview import PerfView
    P = PerfView(M.ENGINE)
    seen = {}

    async def fake(system, user, max_tokens=0, task="", names=None):
        seen.update(system=system, user=user, names=names)
        return "요약: 이상 없음"
    monkeypatch.setattr(M.ENGINE.llm, "complete", fake)
    vm = next(e for e in P.entities("vm") if e["state"] == "poweredOn")

    async def go():
        d = await P.detail("vm", vm["name"], "", "rt")
        assert "diag" in d and d["diag"]["level"] in ("ok", "warning", "critical") and "cpu.usage_pct" in d["diag"]["baseline"]
        assert "diag" not in await P.detail("vm", vm["name"], "", "7d")
        txt = await P.explain("vm", vm["name"])
        assert txt.startswith("요약") and vm["name"] in seen["names"] and vm["host"] in seen["names"]
        assert "자동진단" in seen["user"]
    asyncio.run(go())


def test_rbac_and_ui():
    from app.security.auth import ROUTE_RULES

    def perm(m, p):
        for mm, rx, pr in ROUTE_RULES:
            if (mm == "*" or mm == m) and re.search(rx, p):
                return pr
    assert perm("POST", "/api/perf/explain") == "operate" and perm("GET", "/api/perf/detail") == "view"
    js = (ROOT / "app/static/perfview.js").read_text(encoding="utf-8")
    for s in ("diagBox", "/api/perf/explain", "addCmp", "chartT", "pf-tile", "data-cmp-del"):
        assert s in js
    assert subprocess.run(["node", "-e", f"new Function(require('fs').readFileSync('{ROOT / 'app/static/perfview.js'}','utf8'))"]).returncode == 0
    en = (ROOT / "app/static/i18n-en.js").read_text(encoding="utf-8")
    for k in ("비교에 추가", "AI 해설", "CPU 경합(ready)", "특이 사항 없음"):
        assert f'"{k}":' in en


def test_qa_false_positives_and_self(monkeypatch):
    from app.perfdiag import diagnose
    rt = _rt(**{"mem.balloon_mb": [0.5] * 30, "cpu.usage_pct": [95.0] * 30, "cpu.ready_pct": [0.2] * 30, "mem.swapin_Bps": [0.0] * 30})
    rt["instances"]["net"] = [{"id": "4000", "drop_rx_max": 1, "drop_tx_max": 0, "drop_rx_avg": 1 / 30}]
    g = diagnose("vm", rt, None, {"vcpu": 2, "mem_mb": 8192, "_self": "me", "host_cpu_used_mhz": 20000},
                 [{"name": "me", "cpu_mhz": 12000}, {"name": "other", "cpu_mhz": 3000}])
    t = {f["title"]: f for f in g["findings"]}
    assert "메모리 회수 발생(balloon)" not in t and "네트워크 패킷 드롭" not in t           # 0.5 MB · 드롭 1개는 무시
    nb = t["같은 호스트에서 CPU 를 많이 쓰는 VM"]
    assert "me " not in nb["evidence"] and "other 15%" in nb["evidence"] and nb["sev"] == "info"   # 자기 제외 · 분모 = 호스트 사용량 · 자기 포화는 이웃 탓 아님
    h = diagnose("host", _rt(**{"mem.swapin_Bps": [0.0] * 29 + [1024.0]}), None, {}, [])
    assert {f["title"]: f for f in h["findings"]}["호스트 스왑(일시)"]["sev"] == "info"


def test_explain_masks_datastore_labels(monkeypatch):
    import app.main as M
    from app.perfview import PerfView

    class C:
        type, name, enabled = "vcenter", "vc", True
        topology = {"hosts": {"esx-a": {"moid": "host-1", "cluster": "CL-GOLD", "cpu_mhz": 10000, "cpu_used_mhz": 5000, "datastores": ["san-gold-01"]}},
                    "vms": {"app-db-01": {"moid": "vm-1", "host": "esx-a", "power": "poweredOn", "cpu_mhz": 900}}, "datastores": {}}

        @staticmethod
        def perf_series(kind, moid, rng="rt", vcpu=1, labels=None):
            from app.perfcalc import build
            b = build([("disk.totalReadLatency.average", "naa.1", [30, 30]), ("cpu.usage.average", "", [5000, 5000])], [0, 20], 20, kind)
            b["instances"]["disk"][0]["label"] = "san-gold-01"
            b["error"] = ""
            return b
    monkeypatch.setattr(M.ENGINE, "connectors", [C()])
    seen = {}

    async def fake(system, user, max_tokens=0, task="", names=None):
        seen["names"] = names
        return "ok"
    monkeypatch.setattr(M.ENGINE.llm, "complete", fake)
    asyncio.run(PerfView(M.ENGINE).explain("host", "esx-a"))
    assert {"esx-a", "CL-GOLD", "san-gold-01", "app-db-01"} <= set(seen["names"])
