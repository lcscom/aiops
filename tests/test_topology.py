"""고객 환경 토폴로지 — 연결된 커넥터(데모 커넥터 사용)로 도메인·vCenter·클러스터·호스트·BMC·NSX·ALB·VKS 조립."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import topology  # noqa: E402
from app.connectors.demo import DemoGenerator  # noqa: E402
from app.engine import Engine  # noqa: E402


async def _emit(_):
    pass


def fake_engine():
    g = DemoGenerator({"rate": 1}, _emit)
    eng = SimpleNamespace(connectors=g.fakes, agents=SimpleNamespace(items={"core-bank-db01": {"state": "ok"}}))
    eng.bmc_inventory = lambda: Engine.bmc_inventory(eng)
    return eng


def test_build_from_connectors():
    d = topology.build(fake_engine())
    assert not d["empty"]
    assert [x["name"] for x in d["domains"]] == ["vcf-m01"] and d["domains"][0]["source"] == "sddc"
    assert set(d["domains"][0]["members"]) == {"vc:demo-vcenter", "nsx:demo-nsx"}
    vc = d["vcenters"][0]
    assert [c["name"] for c in vc["clusters"]] == ["Cluster-01", "Cluster-02"]
    h3 = next(h for c in vc["clusters"] for h in c["hosts"] if h["name"] == "esx03.vcf.lab")
    assert h3["bmc"] and h3["bmc"]["fw"].startswith("iLO")                 # Redfish 커넥터(esxi_host) ↔ 호스트 연결
    assert any(h["agents"] for c in vc["clusters"] for h in c["hosts"])    # 에이전트 설치 VM 수
    c2 = vc["clusters"][1]
    assert c2["supervisor"]["endpoint"] == "10.20.0.10"
    assert d["counts"]["vips"] == 5 and d["avi"][0]["vs"][0]["last"]["bw"] > 0
    assert d["vks"][0]["pods_problem"] == 1 and d["mgmt"] and d["counts"]["edges"] == 4


def test_empty_and_inferred_domain():
    eng = SimpleNamespace(connectors=[], agents=None, bmc_inventory=lambda: {})
    assert topology.build(eng)["empty"]
    e = fake_engine()
    e.connectors = [c for c in e.connectors if c.type != "sddc"]
    d = topology.build(e)
    assert d["domains"][0]["source"] == "inferred" and "vc:demo-vcenter" in d["domains"][0]["members"]


def test_short_ip_not_collapsed():
    assert topology._short("10.0.0.5:443") == "10.0.0.5" and topology._short("esx01.bank.local") == "esx01"
