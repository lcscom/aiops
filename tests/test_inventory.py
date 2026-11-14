"""전체 인벤토리 — 데모 커넥터로 종류별 행·검색·상태 필터·정렬·CSV·관련 개체."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import inventory  # noqa: E402
from app.connectors.demo import DemoGenerator  # noqa: E402
from app.engine import Engine  # noqa: E402


async def _emit(_):
    pass


def rows():
    g = DemoGenerator({"rate": 1}, _emit)
    eng = SimpleNamespace(connectors=g.fakes, agents=SimpleNamespace(items={"db01": {"host": "db01", "kind": "vm", "os": "linux", "state": "ok",
                                                                                     "info": {"distro": "photon"}, "agent": "rsyslog", "last_seen": 1.0}}))
    eng.bmc_inventory = lambda: Engine.bmc_inventory(eng)
    return inventory.build(eng)


def test_kinds_and_fields():
    r = rows()
    kinds = {x["kind"] for x in r}
    assert {"vm", "host", "cluster", "datastore", "network", "nsx-t0", "nsx-t1", "nsx-segment", "nsx-edge", "avi-vs", "avi-pool",
            "vks-cluster", "pod", "server", "agent", "component"} <= kinds
    h = next(x for x in r if x["kind"] == "host" and x["name"] == "esx03.vcf.lab")
    assert h["vendor"] == "HPE" and h["bmc"] == "demo-redfish" and h["vms"] > 0
    a = next(x for x in r if x["kind"] == "agent")
    assert a["distro"] == "photon"


def test_query_filter_sort_csv():
    r = rows()
    q = inventory.query(r, "vm", q="windows cluster-01")
    assert q["total"] and all("Windows" in x["os"] and x["cluster"] == "Cluster-01" for x in q["items"])
    off = inventory.query(r, "vm", state="off")
    assert off["total"] == 1 and off["states"]["off"] == 1
    s = inventory.query(r, "vm", sort="mem_gb", desc=True)["items"]
    assert s[0]["mem_gb"] >= s[-1]["mem_gb"]
    csv = inventory.to_csv(inventory.query(r, "host")["items"], "host")
    assert csv.startswith("﻿이름,상태,클러스터") and "esx01.vcf.lab" in csv
