"""2.40.0 — 장애 시뮬레이터 단순화 + '절대 실제로 작동하지 않음' 보증
  · 계산은 커넥터 자료의 깊은 복사 스냅숏 위에서만 — 커넥터 메서드 호출·속성 변경·저장소 쓰기 없음
  · 시뮬레이터 모듈은 표준 라이브러리와 체크봇 규칙 엔진만 가져옴(네트워크·SDK 없음)
  · 계산 코드·화면 코드에 인프라 변경 API 이름이 없음, 화면은 조회·계산 API 두 개만 부름"""
import ast
import copy
import re
from pathlib import Path
from types import SimpleNamespace as NS

from app import checkbot as CB
from app import simulator as SIM
from tests.test_v2380 import _world_conns

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"
CHANGE_API = re.compile(r"PowerO(ff|n)|EnterMaintenance|ExitMaintenance|Reboot(Host|Guest)|Shutdown(Host|Guest)|Destroy|Relocate|Migrate(VM|_Task)|Unregister|"
                        r"ReconfigVM|Disconnect(Host)?_Task|RemoveDatastore|Unmount|\.delete\(|\.put\(|\.patch\(|requests\.|httpx\.|urllib|import socket|socket\.socket|subprocess|paramiko", re.I)


class Spy:
    """커넥터 대역 — 속성 읽기만 허용하고, 메서드 호출·속성 쓰기가 있으면 기록"""

    def __init__(self, real, log):
        object.__setattr__(self, "_r", real)
        object.__setattr__(self, "_log", log)

    def __getattr__(self, k):
        v = getattr(self._r, k)
        if callable(v):
            log = self._log

            def trap(*a, **kw):
                log.append(f"call {k}")
                raise AssertionError(f"시뮬레이터가 커넥터 메서드 {k} 를 불렀습니다")
            return trap
        return v

    def __setattr__(self, k, v):
        self._log.append(f"set {k}")
        raise AssertionError(f"시뮬레이터가 커넥터 속성 {k} 를 바꿨습니다")


def _fails():
    return [{"type": t, "vcenter": "vc1", "target": g} for t, g in [("host_down", "h0"), ("host_maint", "h1"), ("uplink_loss", "h2"), ("ds_apd", "ds1"), ("ds_full", "ds1"),
                                                                     ("cluster_down", "c1"), ("host_maint", "c1"), ("vcenter_upgrade", "vc1")]] + [{"type": "edge_down", "target": "ec1"}]


def test_simulation_never_touches_connectors():
    conns = _world_conns()
    before = copy.deepcopy([c.__dict__ for c in conns])
    log: list = []
    eng = NS(connectors=[Spy(c, log) for c in conns], certs=NS(last={}))
    w = CB.build_world(eng)
    snap = copy.deepcopy(w)
    for i in range(len(_fails())):                                # 모든 종류를 하나씩, 그리고 전부 겹쳐서
        SIM.simulate(w, _fails()[i:i + 1])
    r = SIM.simulate(w, _fails())
    SIM.inventory(w)
    assert log == [] and [c.__dict__ for c in conns] == before   # 커넥터에는 읽기만
    assert w == snap                                             # 계산이 스냅숏도 바꾸지 않음(30초 캐시 재사용에 안전)
    assert r["verdict"] == "fail" and len(r["failures"]) == 9
    # 스냅숏은 깊은 복사 — 계산 쪽에서 바꿔도 커넥터 자료는 그대로
    w["vcenters"][0]["topo"]["hosts"]["h0"]["cpu_mhz"] = 1
    assert conns[0].topology["hosts"]["h0"]["cpu_mhz"] == 160000


def test_simulator_imports_and_no_change_api():
    tree = ast.parse((ROOT / "app" / "simulator.py").read_text(encoding="utf-8"))
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom):
            mods.add(("." * n.level) + (n.module or ""))
    assert mods <= {"__future__", "collections", "typing", "."}, mods     # '.' = from . import checkbot
    for f in ("simulator.py", "whatif.py", "platsim.py", "scenlib.py"):
        src = (ROOT / "app" / f).read_text(encoding="utf-8")
        assert not CHANGE_API.search(src), (f, CHANGE_API.search(src))
    src = (ROOT / "app" / "checkbot.py").read_text(encoding="utf-8")
    body = src[src.index("def evaluate("):src.index("def score(")]                 # 판정 계산부
    assert not CHANGE_API.search(body)
    js = (S / "sim.js").read_text(encoding="utf-8")
    calls = re.findall(r'A\.api\("(\w+)", "([^"]+)"', js)
    assert sorted(set(calls)) == [("GET", "/api/checkbot/inventory"), ("GET", "/api/checkbot?verdict=fail&limit=8&run=0"), ("POST", "/api/checkbot/library/run"),
                                  ("POST", "/api/checkbot/refresh"), ("POST", "/api/checkbot/simulate")]   # 2.47.0 library/run — 계산만(view)
    assert not re.search(r"fetch\(|XMLHttpRequest|WebSocket|sendBeacon", js) and "시뮬레이션 전용" in js


def test_api_marks_simulation_and_no_writes(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_checkbot import build_router
    from tests.test_v2110_support import _engine
    e = _engine(tmp_path)
    writes: list = []

    class RO:
        async def x(self, *a, **k):
            writes.append(a[0][:40])

        async def q(self, *a, **k):
            return await e.store.q(*a, **k)

        async def q1(self, *a, **k):
            return await e.store.q1(*a, **k)
    log: list = []
    conns = _world_conns()
    eng = NS(store=RO(), connectors=[Spy(c, log) for c in conns], certs=NS(last={}), llm=None)
    audits: list = []

    async def audit(*a, **k):
        audits.append(a)
    app = FastAPI()
    app.include_router(build_router(eng, CB.CheckBot(eng, {"ai": False}), lambda r: {"user": "u"}, audit))
    with TestClient(app) as cl:
        inv = cl.get("/api/checkbot/inventory").json()
        assert inv["simulation_only"] is True
        for _ in range(3):
            r = cl.post("/api/checkbot/simulate", json={"failures": _fails()}).json()
            assert r["simulation_only"] is True and r["applied"] is False and r["verdict"] == "fail"
    assert writes == [] and audits == [] and log == []           # 저장소 쓰기·감사·커넥터 호출 없음


def test_ui_simple():
    js = (S / "sim.js").read_text(encoding="utf-8")
    for k in ("서비스 중단", "위험", "재부팅", "무중단 이동", "영향 지도", "sm-safe", "data-menu", "무엇이 고장 나면?"):
        assert k in js, k
    css = (S / "style.css").read_text(encoding="utf-8")
    assert ".sm-safe" in css and ".sm-cell" in css and css.count("/* 2.39.0 장애 시뮬레이터 */") == 0
    import subprocess
    subprocess.run(["node", "--check", str(S / "sim.js")], check=True)
