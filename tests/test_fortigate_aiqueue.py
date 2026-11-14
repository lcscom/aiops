"""FortiGate syslog 집계·위협 탐지 / AI 분석 대기열 / 발견 커넥터 정리"""
import asyncio
import time

from app.aiqueue import AIQueue
from app.connectors.syslog import parse
from app.fortigate import FortiProcessor, is_fortigate, parse_line

DEV = 'date=2026-10-12 time=10:01:02 devname="FGVM01" devid="FGVMSLTM26022394" eventtime=1760230862123456789 tz="+0900" vd="root"'
FAIL = (f'<185>{DEV} logid="0100032002" type="event" subtype="system" level="alert" logdesc="Admin login failed" user="admin" '
        f'ui="https(203.0.113.7)" srcip=203.0.113.7 action="login" status="failed" reason="name_invalid" '
        f'msg="Administrator admin login failed from https(203.0.113.7) because of invalid user name"')
OK = (f'<189>{DEV} logid="0100032001" type="event" subtype="system" level="information" user="admin" ui="ssh(203.0.113.7)" '
      f'action="login" status="success" srcip=203.0.113.7 msg="Administrator admin logged in successfully"')
VPN = (f'<189>{DEV} logid="0101039426" type="event" subtype="vpn" level="alert" action="ssl-login-fail" tunneltype="ssl-web" '
       f'remip=198.51.100.9 user="test" msg="SSL user failed to logged in"')
TR = (f'<189>{DEV} logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=45.1.2.3 srcport=5555 dstip=10.0.0.5 '
      f'dstport=PORT proto=6 action="deny" policyid=0 service="tcp/PORT"')
IPS = (f'<185>{DEV} logid="0419016384" type="utm" subtype="ips" level="alert" severity="critical" srcip=45.9.9.9 dstip=10.0.0.5 '
       f'dstport=443 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" attackid=51006')


class FakeEngine:
    connectors: list = []

    def __init__(self):
        self.out = []

    def submit(self, ev):
        self.out.append(ev)
        return True


def test_parse_fortigate_kv():
    assert is_fortigate(FAIL) and not is_fortigate("<13>Oct 12 10:00:00 esx01 vmkernel: hello")
    ev = parse(FAIL, "10.1.1.1")
    assert ev.source == "fortigate" and ev.host == "FGVM01" and ev.entity == "event/system"
    assert ev.severity == "critical" and ev.attrs["fg_srcip"] == "203.0.113.7" and ev.attrs["fg_status"] == "failed"
    assert abs(ev.ts - 1760230862.12) < 1
    t = parse_line(TR.replace("PORT", "22"), "x")
    assert t.severity == "info" and "45.1.2.3" in t.message


def test_bruteforce_threshold_escalation_and_success_after_fail():
    e = FakeEngine()
    fp = FortiProcessor(e, {"bf_threshold": 10, "bf_critical": 50})
    stored = [fp.handle(parse(FAIL, "p")) for _ in range(60)]
    assert all(x is not None and x.attrs.get("no_anomaly") for x in stored)       # 개별 실패는 저장만
    alerts = [x for x in e.out if x.attrs.get("category") == "brute-force"]
    assert [a.severity for a in alerts] == ["error", "critical"]                  # 10회 경보, 50회 critical 상향(재알림 억제 무시)
    assert alerts[0].attrs["fp"] == "fg-bf|203.0.113.7" and alerts[0].attrs["force_anomaly"]
    for _ in range(12):
        fp.handle(parse(VPN, "p"))
    assert any("198.51.100.9" in x.message and "SSL-VPN" in x.message for x in e.out)
    fp.handle(parse(OK, "p"))
    assert any("후 성공" in x.message and x.severity == "critical" for x in e.out)
    assert fp.metric("fortigate.login_failures_5m")["203.0.113.7"] == 60
    s = fp.snapshot()
    assert s["kpi"]["attackers"] == 2 and s["bruteforce"][0]["success_after"]


def test_traffic_aggregate_scan_and_summary():
    e = FakeEngine()
    fp = FortiProcessor(e, {"scan_ports": 20})
    res = [fp.handle(parse(TR.replace("PORT", str(p % 40)), "p")) for p in range(400)]
    assert all(r is None for r in res) and fp.stats["aggregated"] == 400
    fp._roll(time.time() + 61)
    kinds = [x.entity for x in e.out]
    assert "traffic/summary" in kinds and "security/port-scan" in kinds
    assert fp.metric("fortigate.denied_per_min")["FGVM01"] == 400
    s = fp.snapshot()
    assert s["top_src"][0] == {"srcip": "45.1.2.3", "count": 400}
    fp2 = FortiProcessor(FakeEngine(), {"traffic_mode": "store"})
    r = fp2.handle(parse(TR.replace("PORT", "1"), "p"))
    assert r is not None and r.attrs["no_anomaly"]


def test_ips_dedupe():
    fp = FortiProcessor(FakeEngine(), {"ips_store_max": 5})
    res = [fp.handle(parse(IPS, "p")) for _ in range(10)]
    assert res[0] is not None and not res[0].attrs.get("no_anomaly") and res[0].severity == "critical"
    assert sum(1 for r in res[1:5] if r and r.attrs.get("no_anomaly")) == 4 and all(r is None for r in res[5:])
    assert fp.snapshot()["ips"][0]["count"] == 10


def test_aiqueue_priority_coalesce_shed_quota_age():
    skipped = {}
    L = asyncio.new_event_loop()
    q = AIQueue({"batch_interval": 0.1, "batch_size": 3, "batch_max": 6, "queue_shed_at": 4, "queue_source_quota": 3, "queue_max": 8, "queue_max_age": 60},
                on_skip=lambda a, w: skipped.__setitem__(a, w))
    assert q.put("w1", "warning", "esxi", "t1") == "queued"
    assert q.put("c1", "critical", "nsx", "t2") == "queued"
    assert q.put("w2", "warning", "esxi", "t1") == "coalesced"                  # 같은 소스·패턴 → 병합
    assert q.put("e1", "error", "esxi", "t3") == "queued"
    assert q.put("w3", "warning", "esxi", "t4") == "queued"
    assert q.put("w4", "warning", "esxi", "t5").startswith("skipped:소스 할당")    # esxi 3건 초과
    assert q.depth() == 5
    q.put("i1", "info", "vks", "t6")                                              # 고유 4건 이상 → warning 이하 차단
    assert q.stats["shed"] == 1
    for k in range(4):
        assert q.put(f"x{k}", "error", f"s{k}", f"u{k}") == "queued"
    assert len(q.items) == 8
    assert q.put("c2", "critical", "z", "zz") == "queued" and len(q.items) == 8   # 가득 → 가장 낮은 것(w3) 밀어냄
    assert "w3" in skipped
    ids = L.run_until_complete(q.get_batch(0.1))
    assert ids[:2] == ["c1", "c2"]
    for i in ids:
        q.take(i)
    q.items["w1"]["t"] -= 120                                                     # 노화
    rest = []
    while True:
        b = L.run_until_complete(q.get_batch(0.05))
        if not b:
            break
        rest += b
        for i in b:
            q.take(i)
    assert "w1" not in rest and "w1" in skipped and "w2" in skipped              # 대표가 노화되면 병합분도 생략
    assert q.put("m", "info", "x", manual=True) == "queued"                      # 수동 재분석은 차단 대상 아님
    snap = q.snapshot()
    assert snap["stats"]["coalesced"] == 1 and "limits" in snap


def test_aiqueue_take_returns_followers():
    L = asyncio.new_event_loop()
    q = AIQueue({"batch_size": 2, "batch_interval": 0.1})
    q.put("a", "error", "nsx", "t")
    q.put("b", "error", "nsx", "t")
    q.put("c", "critical", "nsx", "t")
    ids = L.run_until_complete(q.get_batch(0.1))
    assert ids == ["a"] and q.take("a") == ["b", "c"] and q.depth() == 0          # critical 합류 → 대표 우선순위 상향


def test_engine_fortigate_and_shared_analysis(tmp_path):
    from app.config import DEFAULTS, _merge
    from app.models import LogEvent
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False, "batch_interval": 0.05},
                            "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        calls = []

        class LLM:
            status = {}

            async def analyze(self, items, **kw):
                calls.append([i["id"] for i in items])
                return {i["id"]: {"summary": "s", "category": "storage", "severity": "error", "title": "T"} for i in items}
        e.llm = LLM()
        for _ in range(30):
            e.submit(parse(FAIL, "10.1.1.1"))
        for p in range(200):
            e.submit(parse(TR.replace("PORT", str(p)), "10.1.1.1"))
        for h in ("esx01", "esx02", "esx03"):                    # 같은 패턴 다른 호스트 → 병합 분석
            e.submit(LogEvent(source="esxi", connector="syslog", host=h, entity=h, severity="error",
                              message="Lost access to volume 64f2a1b3-55aa12cd-77ee-0050569a1b2c (datastore1) due to connectivity issues"))
        w = asyncio.create_task(e.pipeline_worker())
        await asyncio.sleep(0.3)
        lw = asyncio.create_task(e.llm_worker())
        await asyncio.sleep(1.0)
        w.cancel(); lw.cancel()
        return e, calls
    e, calls = asyncio.run(main())
    bf = [a for a in e.anomalies.values() if a.category == "brute-force"]
    assert len(bf) == 1 and bf[0].status == "rule_only" and bf[0].count >= 1 and bf[0].severity in ("error", "critical")
    assert e.pipe["aggregated"] == 200
    esx = [a for a in e.anomalies.values() if a.event.get("source") == "esxi"]
    assert len(esx) == 3 and all(a.status == "analyzed" for a in esx)
    assert sum(len(c) for c in calls) < 3 and sum(1 for a in esx if a.ai.get("shared_from")) >= 1


def test_prune_discovered_connectors(tmp_path):
    from types import SimpleNamespace as NS
    from app.config import DEFAULTS, _merge
    cfg = _merge(DEFAULTS, {"server": {"db_path": str(tmp_path / "a.db")}, "llm": {"enabled": False}, "rag": {"enabled": False}})

    async def main():
        from app.engine import Engine
        e = Engine(cfg)
        vc = NS(name="vc1", type="vcenter", enabled=True, cfg={})
        k1 = NS(name="vks-a", type="vks", enabled=True, cfg={}, discovered_by="vc1")
        k2 = NS(name="vks-b", type="vks", enabled=True, cfg={}, discovered_by="vc1")
        k3 = NS(name="vks-c", type="vks", enabled=True, cfg={}, discovered_by="vc-gone")
        e.connectors = [vc, k1, k2, k3]
        r1 = e.prune_discovered()                                  # 만든 vCenter 가 없는 것
        e.cfg["vks_overrides"] = {"excluded": ["vks-b"]}
        r2 = e.prune_discovered()                                  # 사용자가 삭제(제외)한 것
        e.connectors.remove(vc)
        r3 = e.prune_discovered()                                  # vCenter 삭제 → 남은 발견분 정리
        return r1, r2, r3, e.connectors
    r1, r2, r3, left = asyncio.run(main())
    assert r1 == ["vks-c"] and r2 == ["vks-b"] and r3 == ["vks-a"] and left == []
