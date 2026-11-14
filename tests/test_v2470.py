"""2.47.0 — What-If 시나리오 라이브러리(파트별 20개 이상) · 영향받는 Pod 하나하나"""
import subprocess
from collections import Counter
from pathlib import Path

from app import scenlib as L
from app import simulator as SIM
from tests.test_v2460 import _world

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_parts_20_each():
    ids = [s["id"] for s in L.LIB]
    assert len(ids) == len(set(ids))
    cnt = Counter(s["part"] for s in L.LIB)
    assert set(cnt) == {k for k, _, _ in L.PARTS} and min(cnt.values()) >= 20, cnt
    cat = L.catalog(_world())
    assert all(p["count"] >= 20 for p in cat["parts"]) and len(cat["items"]) == len(L.LIB)
    for x in cat["items"]:
        assert x["applicable"] or x["why_na"], x["id"]                                      # 해당 없음이면 이유


def test_run_all_no_errors():
    r = L.run_all(_world())
    assert not [x for x in r["items"] if str(x.get("why_na", "")).startswith("계산 오류")]
    assert sum(p["total"] for p in r["parts"]) == len(L.LIB)
    v = Counter(x["verdict"] for x in r["items"])
    assert v["fail"] and v["warn"] and v["pass"]


def test_pods_listed_one_by_one():
    r = SIM.simulate(_world(), [{"type": "node_down", "target": "pay/w-1"}])
    ps = r["platform"]["pods"]
    by = {p["pod"]: p for p in ps}
    # w-1 의 Pod: api-1(단일)·web 1개·db-0 → 다시 배치 못 함(워커 1대뿐), cp-3 의 web 은 계속
    assert by["db-0"]["state"] == "stuck" and by["web-6d8f7c9b4-ab12c"]["state"] == "stuck" and by["web-6d8f7c9b4-cd34e"]["state"] == "kept"
    assert all({"cluster", "ns", "pod", "node", "workload", "kind", "state", "text"} <= set(p) for p in ps)
    assert r["platform"]["pod_counts"]["stuck"] >= 2
    s = SIM.simulate(_world(), [{"type": "sup_down", "vcenter": "vc1", "target": "c1"}])
    st = {p["pod"]: p["state"] for p in s["platform"]["pods"]}
    assert st["pod-a"] == "frozen" and st["db-0"] == "frozen"                                # Supervisor 장애 — 모든 Pod 계속(복구 불가)


def test_specific_scenarios():
    W = _world()
    k = L.run(W, "k07")
    assert k["applicable"] and k["failures_in"][0]["type"] == "node_down" and k["platform"]["pods"]
    d = L.run(W, "m05")
    assert d["verdict"] == "fail" and any("계속되는 것" in f["text"] for f in d["findings"]) and not d["failures"]
    a = L.run(W, "a10")
    assert {i["name"] for i in a["platform"]["items"] if i["state"] == "stop"} == {"vs-a", "vs-b"}
    h = L.run(W, "k15")
    assert all(i["state"] == "stop" for i in h["platform"]["items"]) and h["platform"]["pods"]
    n = L.run(W, "n21")
    assert n["applicable"]
    x = L.run(W, "c02")
    assert len(x["failures_in"]) == 2 and x["verdict"] in ("fail", "warn")
    try:
        L.run(W, "zz")
    except KeyError:
        pass
    else:
        raise AssertionError


def test_api_and_ui():
    auth = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert 'r"^/api/checkbot/library/run$", "view"' in auth
    api = (ROOT / "app" / "api_checkbot.py").read_text(encoding="utf-8")
    assert '"/api/checkbot/library"' in api and '"applied": False' in api
    src = (ROOT / "app" / "scenlib.py").read_text(encoding="utf-8")
    for bad in ("requests", "httpx", "subprocess", "PowerOff", "ReconfigVM", ".post("):
        assert bad not in src
    html = (ROOT / "app" / "static" / "index.html").read_text(encoding="utf-8")
    assert 'data-cbmode="lib"' in html and 'id="lib-body"' in html and "/static/scnlib.js" in html
    for f in ("scnlib.js", "sim.js", "checkbot.js"):
        subprocess.run(["node", "--check", str(ROOT / "app" / "static" / f)], check=True)
