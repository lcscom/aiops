"""2.36.0 — vSAN 쓸 수 있는 용량·혼합 세대(EVC)·적정화 반영·분기 계획·비용 연결·클러스터 간 이동·DR 수용·보고서 묶음,
인증서 만료 달력(VKS)·구성 드리프트·버전 수명, 결함 수정(LDAP 문구·공용 AI 가명화·패치 기록·화면)"""
import asyncio
import datetime as dt
import io
import json
import socket
import ssl
import threading
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from app import whatif as W
from app import whatif_multi as WM
from app.cpugen import evc_review, generation
from tests.test_v2110_support import _engine

ROOT = Path(__file__).resolve().parents[1]
S = ROOT / "app" / "static"


def _run(c):
    return asyncio.new_event_loop().run_until_complete(c)


def _h(name, cores=64, ghz=2.5, mem_gb=1000, cpu_used=40000.0, mem_used_gb=400.0, sockets=2, model="Intel(R) Xeon(R) Gold 6338"):
    return {"name": name, "cpu_mhz": cores * ghz * 1000, "mem_mb": mem_gb * 1024.0, "core_mhz": ghz * 1000, "cpu_used": cpu_used, "mem_used": mem_used_gb * 1024,
            "sockets": sockets, "cpu_model": model}


def _base(n=4, esa=True, raw_gb=100000.0, free_gb=60000.0, evc=""):
    return {"hosts": [_h(f"e{i}") for i in range(n)], "vms_on": 100, "vcpu": 400, "vm_mem_mb": 0, "vsan": True, "vsan_esa": esa, "evc": evc,
            "ds_total_gb": raw_gb, "ds_free_gb": free_gb, "ds_count": 1, "vm_disk_gb": 20000.0, "vsan_raw_gb": raw_gb, "vsan_free_gb": free_gb}


# ---------------------------------------------------------------- CPU 세대·EVC
def test_cpu_generation_and_evc():
    g = lambda m: (generation(m) or {}).get("key")   # noqa: E731
    assert g("Intel(R) Xeon(R) Gold 6430") == "sapphirerapids" and g("Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz") == "cascadelake"
    assert g("Intel(R) Xeon(R) Platinum 8380") == "icelake" and g("Intel(R) Xeon(R) Gold 6148") == "skylake" and g("Intel(R) Xeon(R) CPU E5-2697 v4") == "broadwell"
    assert g("Intel(R) Xeon(R) Platinum 8380H") == "cascadelake"            # Cooper Lake → Cascade Lake 기준선
    assert g("AMD EPYC 7543 32-Core") == "zen3" and g("AMD EPYC 9554") == "zen4" and g("AMD EPYC 7742") == "zen2" and g("AMD EPYC 9655") == "zen5"
    assert generation("Intel(R) Xeon(R) Gold 6542Y")["sure"] is False and generation("Intel(R) Xeon(R) 6787P")["key"] == "xeon6" and generation("") is None
    r = evc_review(["Intel(R) Xeon(R) Gold 6248R"] * 3, "Intel(R) Xeon(R) Gold 6430")
    assert r["verdict"] == "warn" and r["needed_evc"] == "intel-cascadelake" and "영향이 없습니다" in r["items"][0]
    r = evc_review(["Intel(R) Xeon(R) Gold 6430"] * 3, "Intel(R) Xeon(R) Gold 6248R", "intel-sapphirerapids")
    assert r["verdict"] == "bad" and "EVCAdmissionFailed" in r["items"][0]
    assert evc_review(["Intel(R) Xeon(R) Gold 6430"], "AMD EPYC 9554")["verdict"] == "bad"
    assert evc_review(["Intel(R) Xeon(R) Gold 6430"] * 2, "Intel(R) Xeon(R) Gold 6430")["verdict"] == "ok"
    assert evc_review(["Intel(R) Xeon(R) Gold 6338"], "Intel(R) Xeon(R) Gold 6430", "intel-icelake")["verdict"] == "ok"
    assert evc_review(["X"], "")["verdict"] == "unknown"
    r = evc_review(["Intel(R) Xeon(R) Gold 6338"] * 2, "Intel(R) Xeon(R) Gold 6430")
    assert "KB 438859" in r["refs"]                                       # Ice Lake ↔ Sapphire Rapids HW v21 주의


# ---------------------------------------------------------------- vSAN
def test_vsan_scheme_and_usable():
    assert W.vsan_scheme("auto", 4, True)["scheme"] == "RAID-5 2+1" and W.vsan_scheme("auto", 6, True)["mult"] == 1.25
    assert W.vsan_scheme("auto", 6, False)["scheme"] == "RAID-1" and round(W.vsan_scheme("r5", 6, False)["mult"], 3) == 1.333
    assert W.vsan_scheme("r6", 6, True)["mult"] == 1.5 and W.vsan_scheme("r1f2", 5, False)["mult"] == 3.0 and W.vsan_scheme("??", 3, True)["policy"] == "r5"
    v = W.vsan_usable(100000, 60000, 4, True, "auto", 10, True, 1.0, hosts2=6, raw2_gb=150000, add_logical_gb=1000)
    # (100 TB × 0.9 − 25 TB) ÷ 1.5 = 43.3 TB, 쓰는 원시 40 TB → 논리 26.7 TB
    assert v["usable_tb"] == 43.3 and v["used_tb"] == 26.7 and v["pct"] == round(40000 / 1.5 / (65000 / 1.5) * 100, 1)
    a = v["after"]
    assert a["scheme"] == "RAID-5 4+1" and a["usable_tb"] == round((150000 * 0.9 - 25000) / 1.25 / 1000, 1) and "24시간" in a["scheme_note"]
    assert W.vsan_usable(100000, 60000, 4, True, "r1", 0, False, 2.0)["usable_tb"] == 100.0      # 절감률 2배·예비 없음 → 원시 ÷ 2 × 2
    s = W.simulate(_base(), {"add_hosts": 2, "host_flash_tb": 25, "add_vms": 10, "vm_disk_gb": 100, "vsan_reserve_pct": 10})
    assert s["vsan"]["after"]["raw_tb"] == 150.0 and s["vsan"]["after"]["used_tb"] == round(26.7 + 1.0, 1)
    with pytest.raises(ValueError):
        W.simulate(_base(), {"vsan_reserve_pct": 50})
    assert W.simulate({**_base(), "vsan": False}, {})["vsan"] is None


# ---------------------------------------------------------------- 혼합 세대·성능 계수·분기 계획·적정화
def test_simulate_evc_perf_quarters_rightsizing():
    b = _base()
    r = W.simulate(b, {"add_hosts": 1, "host_cores": 64, "host_core_ghz": 2.5, "host_mem_gb": 1000, "host_sockets": 2, "host_cpu_model": "Intel(R) Xeon(R) Gold 6430",
                       "perf_factor": 1.5})
    assert r["evc"]["verdict"] == "warn" and r["evc"]["core_ghz"]["perf_factor"] == 1.5
    assert r["after"]["cpu"]["total_ghz"] == round((4 * 160000 + 160000 * 1.5) / 1000, 1) and any("1.5배" in n for n in r["notes"])
    assert r["license"]["per_new_host"] == 64                              # 성능 계수는 코어 수(라이선스)를 바꾸지 않음
    q = W.simulate(b, {"growth_pct_year": 100, "add_hosts": 0}, today=dt.date(2026, 11, 11))["quarters"]
    assert q["basis"] == "growth" and [x["label"] for x in q["rows"]] == ["2026년 4분기(10~12월)", "2027년 1분기(1~3월)", "2027년 2분기(4~6월)", "2027년 3분기(7~9월)"]
    assert q["rows"][0]["end"] == "2026-12-31" and q["rows"][-1]["end"] == "2027-09-30"
    assert q["rows"][-1]["mem_gb"] > q["rows"][0]["mem_gb"] and q["rows"][-1]["hosts_add"] >= q["rows"][0]["hosts_add"]
    assert sum(x["add_this_q"] for x in q["rows"]) == q["rows"][-1]["hosts_add"] and q["rows"][0]["storage_pct"] is not None
    t = W.simulate(b, {}, {"cpu": 0.1, "mem": 0.2}, today=dt.date(2026, 3, 31))["quarters"]
    assert t["basis"] == "trend" and t["rows"][0]["label"].startswith("2026년 1분기") and t["rows"][0]["days"] == 0 and t["rows"][0]["storage_pct"] is None
    assert W.simulate(b, {})["quarters"]["rows"] == []
    full = {"hosts": [_h(f"e{i}", mem_used_gb=850) for i in range(4)], "vms_on": 100, "vcpu": 400}
    rec = {"cpu_mhz": 0.0, "mem_mb": 700 * 1024.0, "vcpu": 40, "vms_off": 5, "disk_gb": 0, "idle": 5, "oversized": 3, "undersized": 0, "powered_off": 0, "observed_days": 14}
    x = W.simulate(full, {"apply_rightsizing": True}, None, None, rec)
    assert x["rightsizing"]["hosts_needed_without"] > x["rightsizing"]["hosts_needed_with"] and x["rightsizing"]["deferred"] >= 1
    assert x["after"]["vms"] == 95 and x["after"]["mem"]["used_gb"] == 4 * 850 - 700
    assert W.simulate(full, {}, None, None, rec)["rightsizing"] is None         # 체크하지 않으면 반영 안 함


def test_rightsizing_reclaim():
    rs = {"days": 14, "idle": [{"vm": "a", "vcenter": "vc", "cluster": "c1", "vcpu": 4, "mem_gb": 16}, {"vm": "z", "vcenter": "vc", "cluster": "c2", "vcpu": 8, "mem_gb": 64}],
          "oversized": [{"vm": "b", "vcenter": "vc", "cluster": "c1", "vcpu": 8, "mem_gb": 32, "rec_vcpu": 4, "rec_mem_gb": 16}],
          "undersized": [{"vm": "u", "vcenter": "vc", "cluster": "c1", "vcpu": 2, "mem_gb": 4, "rec_vcpu": 3, "rec_mem_gb": 6}],
          "powered_off": [{"vm": "o", "vcenter": "vc", "cluster": "c1", "disk_gb": 500}]}
    r = WM.rightsizing_reclaim(rs, {"a": {"cpu_mhz": 300}}, "vc", "c1")
    assert r["cpu_mhz"] == 300 and r["mem_mb"] == (16 + 16 - 2) * 1024 and r["vcpu"] == 4 + 4 - 1 and r["vms_off"] == 1 and r["disk_gb"] == 500
    assert (r["idle"], r["oversized"], r["undersized"], r["powered_off"]) == (1, 1, 1, 1)


# ---------------------------------------------------------------- 이동·DR·비용
def _topo_vm(c, cpu=2000, mem=16384, disk=100, ds=("ds-a",), power="poweredOn", nets=("pg-1",)):
    return {"cluster": c, "cpu_mhz": cpu, "mem_mb": mem, "vcpu": 4, "disk_gb": disk, "datastores": list(ds), "power": power, "networks": list(nets)}


def test_move_and_dr():
    src = {**_base(n=3, evc="intel-sapphirerapids"), "hosts": [_h(f"s{i}", model="Intel(R) Xeon(R) Gold 6430") for i in range(3)]}
    dst = {**_base(n=3), "hosts": [_h(f"d{i}") for i in range(3)], "evc": ""}
    vms = [{**_topo_vm("src"), "name": "v1"}, {**_topo_vm("src", ds=("ds-local",)), "name": "v2"}, {**_topo_vm("src", power="poweredOff"), "name": "v3"}]
    dtopo = {"hosts": {f"d{i}": {"datastores": ["ds-a", "ds-b"]} for i in range(3)}, "networks": {"pg-1": {}}}
    r = WM.move(src, dst, vms, src_name="src", dst_name="dst", cross_vc=False, dst_topo=dtopo, ha=1, mem_util=50)
    assert r["moved"]["powered_on"] == 2 and r["moved"]["cpu_ghz"] == 4.0 and r["moved"]["mem_gb"] == 16.0 and r["moved"]["storage_vmotion_tb"] == 0.1
    assert r["target"]["after"]["mem"]["used_gb"] == r["target"]["before"]["mem"]["used_gb"] + 16
    assert r["source"]["after"]["vms"] == 98 and r["target"]["after"]["vms"] == 102
    lv = {c["level"] for c in r["checks"]}
    assert "warn" in lv and any("스토리지 vMotion" in c["text"] for c in r["checks"]) and any("CPU 기능 수준" in c["text"] and c["level"] == "warn" for c in r["checks"])
    x = WM.move(src, dst, vms[:1], src_name="src", dst_name="dst", cross_vc=True, dst_topo={**dtopo, "networks": {"other": {}}}, ha=1)
    assert any("pg-1" in c["text"] for c in x["checks"]) and any("교차 vCenter" in c["text"] for c in x["checks"]) and x["source"]["storage"]["added_tb"] == 0
    with pytest.raises(ValueError):
        WM.move(src, src, vms, src_name="a", dst_name="a", cross_vc=False, dst_topo=dtopo)
    d = WM.dr(dst, vms, ["ghost"], dst_name="dst", ha=1, mem_util=100, source="SRM")
    assert d["recovered"]["vms"] == 3 and d["missing_count"] == 1 and any("찾지 못해" in s for s in d["summary"])
    assert d["recovered"]["mem_gb"] == 48.0 and d["target"]["after"]["vms"] == 103
    big = WM.dr(dst, [{**_topo_vm("x", mem=1024 * 1024), "name": f"b{i}"} for i in range(3)], [], dst_name="dst")
    assert big["target"]["after"]["verdict"] == "bad" and big["target"]["hosts_needed"] and "서버" in big["summary"][0]


def test_cost_link():
    res = W.simulate(_base(), {"add_hosts": 2, "host_cores": 64, "host_mem_gb": 1000, "host_sockets": 2, "add_vms": 10})
    st = {"subscription_per_core_year": 350, "hw_per_host": 50000, "amort_years": 5, "facility_per_host_year": 2000, "vcf_currency": "USD", "commit": "ondemand", "tco_years": 5}
    pr = {"hours_per_month": 730, "providers": {"aws": {"label": "AWS", "region": "seoul", "storage": {"gb_month": 0.1},
                                                         "compute": [{"family": "m", "ratio": 4, "unit": 2, "linux": 0.2, "windows": 0.3, "verified": True, "sizes": [["m.xl", 4, 16]]}]}}}
    c = WM.cost(res, st, pr, add_vms=10, vm_vcpu=4, vm_mem_gb=16, vm_disk_gb=100)
    assert c["vcf"]["license_cores"] == 128 and c["vcf"]["annual"] == 128 * 350 + 2 * (10000 + 2000) and c["vcf"]["capex_hw"] == 100000
    assert c["vcf"]["tco"] == c["vcf"]["annual"] * 5 and c["vcf"]["per_vm_month"] == round(c["vcf"]["annual"] / 12 / 10, 1)
    a = c["cloud"][0]
    assert a["sku"] == "m.xl" and a["compute"] == round(0.2 * 2 * 730 * 10) and a["storage"] == 100
    none = WM.cost(res, {**st, "subscription_per_core_year": 0, "hw_per_host": 0, "facility_per_host_year": 0}, pr, add_vms=0, vm_vcpu=4, vm_mem_gb=16, vm_disk_gb=0)
    assert none["vcf"] is None and "원가 모델" in none["note"] and none["cloud"] == []
    need = WM.cost(W.simulate(_base(), {"add_hosts": 0}), st, pr, add_vms=0, vm_vcpu=4, vm_mem_gb=16, vm_disk_gb=0, hosts_planned=3)
    assert need["vcf"]["hosts"] == 3 and need["vcf"]["license_cores"] == 3 * 64


# ---------------------------------------------------------------- 보고서 묶음
def test_report_bundle_render():
    from app import reportbundle as RB
    sim = W.simulate(_base(), {"add_hosts": 2, "host_cores": 64, "host_mem_gb": 1000, "host_sockets": 2, "growth_pct_year": 20, "host_cpu_model": "Intel(R) Xeon(R) Gold 6430"})
    d = {"generated": "2026-11-11 10:00", "customer": "테스트은행", "errors": ["보안 판독: X"],
         "capacity": {"items": [{"kind": "cluster", "vcenter": "vc", "name": "c1", "hosts": 4, "cpu": 50.0, "mem": 70.0, "ha_n1": 90.0, "state": "warn",
                                 "forecast": {"days_to": {"90": 40}}, "forecast_mem": {"days_to": {"90": 20}}},
                                {"kind": "datastore", "vcenter": "vc", "name": "ds", "type": "vsan", "capacity_gb": 50000, "disk": 81.0, "state": "warn", "growth_gb_day": 5.0}]},
         "rightsizing": {"days": 14, "clusters": [{"cluster": "c1", "vms": 10, "oversized": 2, "idle": 1, "undersized": 0, "reclaim_vcpu": 8, "reclaim_mem_gb": 32}]},
         "scenarios": [{"meta": {"name": "증설안", "vcenter": "vc", "cluster": "c1"}, "result": sim}, {"meta": {"name": "사라진", "vcenter": "vc", "cluster": "x"}, "result": None}],
         "bestpractice": [{"vcenter": "vc", "cluster": "c1", "hosts": 4, "score": 70, "verdict": "not", "must_fail": ["HA-01"], "results": [{"id": "HA-01", "status": "fail", "detail": "HA 꺼짐"}]}],
         "bp_rules": {"HA-01": {"title": "vSphere HA 사용"}},
         "assessment": {"summary": {"ts": time.time(), "vcenters": 1, "hosts": 4, "counts": {"PASS": 10, "FAIL": 2, "WARN": 1}, "score": 76.9, "cve": {"vulnerable": 1}},
                        "rows": [{"id": "HV-01", "kisa": "HV-01", "title": "SSH 꺼짐", "severity": "high", "status": "FAIL", "target": "e1", "current": "on", "expected": "off"}],
                        "cve": [{"id": "VMSA-2026-0001", "target": "e1", "build": "1", "fixed": "2", "severity": "CRITICAL", "verdict": "취약"}]}}
    B = RB.build(d)
    text = json.dumps(B, ensure_ascii=False)
    for k in ("테스트은행", "증설안", "분기", "vSAN 쓸 수 있는 용량", "혼합 세대", "vSphere HA 사용", "HV-01", "VMSA-2026-0001", "다시 계산하지 못했습니다", "보안 판독: X", "20일"):
        assert k in text, k
    h, mt, ext = RB.render(d, "html")
    assert ext == "html" and b"<table>" in h and b"&lt;" not in h.replace(b"&lt;", b"") and mt.startswith("text/html")
    x, mt, ext = RB.render(d, "docx")
    z = zipfile.ZipFile(io.BytesIO(x))
    assert ext == "docx" and set(z.namelist()) >= {"[Content_Types].xml", "word/document.xml", "word/styles.xml"}
    from xml.dom import minidom
    doc = minidom.parseString(z.read("word/document.xml"))
    assert "테스트은행" in doc.toxml() and doc.getElementsByTagName("w:tbl")
    p, mt, ext = RB.render(d, "pdf")
    assert ext == "pdf" and p[:5] == b"%PDF-" and len(p) > 5000
    from pypdf import PdfReader
    assert "증설안" in "".join(pg.extract_text() for pg in PdfReader(io.BytesIO(p)).pages).replace(" ", "").replace("\x00", "")


# ---------------------------------------------------------------- 인증서
def _selfsigned(days=30, cn="vks-api"):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.vks.lab")]), critical=False).sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM), k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def test_cert_parse_and_peer(tmp_path):
    from app import certs as CT
    pem, key = _selfsigned(30)
    c = CT._cert_from_pem(pem)
    assert c["subject"] == "vks-api" and c["self_signed"] and c["san"] == ["api.vks.lab"] and 28 * 86400 < c["not_after"] - time.time() < 31 * 86400
    (tmp_path / "c.pem").write_bytes(pem)
    (tmp_path / "k.pem").write_bytes(key)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        try:
            ctx.wrap_socket(conn, server_side=True).close()
        except Exception:  # noqa: BLE001
            conn.close()
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    p = CT.peer_cert("127.0.0.1", port)
    srv.close()
    assert p["subject"] == "vks-api" and abs(p["not_after"] - c["not_after"]) < 2
    tok = "x." + __import__("base64").urlsafe_b64encode(json.dumps({"exp": 2000000000}).encode()).decode().rstrip("=") + ".y"
    assert CT._jwt_exp(tok) == 2000000000 and CT._jwt_exp("garbage") is None
    assert CT._hostport("https://10.0.0.1:6443/x") == ("10.0.0.1", 6443) and CT._hostport("vc.lab") == ("vc.lab", 443) and CT._hostport("http://a") is None


def test_cert_scanner_bands_events_vks(tmp_path):
    from app import certs as CT
    pem, _ = _selfsigned(10, "kubelet")
    now = time.time()
    seen = []

    class FakeVks:
        type, name, enabled, role, auth_mode, cluster_label, base_url = "vks", "vks1", True, "workload", "token", "bank/wld1", "http://nohttps"
        _http = None

        async def _list(self, path, params=None, namespaced=True, limit_pages=20):
            if "cert-manager" in path:
                return [{"metadata": {"namespace": "bank", "name": "api-tls"}, "spec": {"dnsNames": ["api.bank"], "issuerRef": {"name": "ca"}},
                         "status": {"notAfter": dt.datetime.fromtimestamp(now + 5 * 86400, dt.timezone.utc).isoformat(), "conditions": [{"type": "Ready", "status": "False"}]}}]
            if "certificatesigningrequests" in path:
                import base64
                return [{"spec": {"signerName": "kubernetes.io/kubelet-serving", "username": "system:node:w1"}, "status": {"certificate": base64.b64encode(pem).decode()}}]
            if path == "/api/v1/nodes":
                return []
            raise RuntimeError(path)

    class FakeSup(FakeVks):
        name, role, cluster_label = "sup", "supervisor", "sup"

        async def _list(self, path, params=None, namespaced=True, limit_pages=20):
            if "kubeadmcontrolplanes" in path:
                return [{"metadata": {"namespace": "bank", "name": "wld1-cp", "labels": {"cluster.x-k8s.io/cluster-name": "wld1"}}, "spec": {"rolloutBefore": {"certificatesExpiryDays": 30}}}]
            if "machines" in path:
                return [{"metadata": {"namespace": "bank", "name": "wld1-cp-abc", "labels": {"cluster.x-k8s.io/cluster-name": "wld1"}},
                         "status": {"certificatesExpiryDate": dt.datetime.fromtimestamp(now + 200 * 86400, dt.timezone.utc).isoformat()}},
                        {"metadata": {"namespace": "bank", "name": "wld1-md-x"}, "status": {}}]
            if "cert-manager" in path:
                e = RuntimeError("404")
                e.response = NS(status_code=404)
                raise e
            raise RuntimeError(path)
    e = _engine(tmp_path)
    eng = NS(store=e.store, ingest=lambda ev: seen.append(ev),
             connectors=[FakeVks(), FakeSup(), NS(type="nsx", name="demo-nsx", enabled=True, demo=True),
                         NS(type="avi", name="avi1", enabled=True, demo_certs=[dict(src="avi", system="avi1", kind="관리 TLS", name="avi:443", not_after=now - 86400)]),
                         NS(type="vks", name="vksdemo", enabled=True, demo_certs=[dict(src="vks", system="vksdemo", kind="커넥터 토큰", name="tok", not_after=now + 3600, auto=True)])])
    sc = CT.CertScanner(eng)
    r = _run(sc.scan())
    by = {(x["system"], x["kind"]): x for x in r["items"]}
    cm = by[("vks1", "cert-manager")]
    assert cm["band"] == "crit" and cm["ready"] == "False" and cm["name"] == "bank/api-tls" and cm["subject"] == "api.bank"
    assert by[("vks1", "노드 CSR")]["band"] == "crit" and "system:node:w1" in by[("vks1", "노드 CSR")]["name"]
    cp = by[("sup", "컨트롤 플레인(kubeadm)")]
    assert cp["auto_renew_days"] == 30 and cp["band"] == "ok" and cp["cluster"] == "bank/wld1"
    assert by[("avi1", "관리 TLS")]["band"] == "expired" and by[("vksdemo", "커넥터 토큰")]["band"] == "auto"
    assert not any(x["system"] == "demo-nsx" for x in r["items"])          # 데모 가짜 커넥터에는 접속하지 않음
    assert any("cert-manager — 설치 안 됨" in x for x in r["skipped"]) and r["summary"]["expired"] == 1
    assert r["items"][0]["band"] == "expired"                              # 만료일 빠른 순
    sev = sorted(ev.severity for ev in seen)
    assert "critical" in sev and sev.count("error") == 2 and not any("tok" in ev.message for ev in seen)
    n = len(seen)
    _run(sc.scan())
    assert len(seen) == n                                                  # 같은 단계는 다시 알리지 않음
    st = _run(sc.save_settings({"warn_days": 90, "crit_days": 30, "extra": ["backup.bank:8443"]}))
    assert st["extra"] == ["backup.bank:8443"] and _run(sc.settings())["warn_days"] == 90
    with pytest.raises(ValueError):
        _run(sc.save_settings({"warn_days": 10, "crit_days": 20}))


# ---------------------------------------------------------------- 드리프트
def _snap(ntp3="ntp1", ssh=False, build="100", mtu=9000, drs="fullyAutomated"):
    H = {}
    for i in range(1, 4):
        H[f"e{i}"] = {"cluster": "c1", "conn": "connected", "version": "8.0.3", "build": build if i == 3 else "100", "bios": f"b{i}",
                      "ntp_servers": ["ntp1"] if i != 3 else [ntp3], "services": {"ntpd": True, "TSM-SSH": ssh and i == 2, "TSM": False}, "lockdown": "lockdownNormal",
                      "ht_active": True, "power_policy": "static", "nics": [{"device": "vmnic0", "driver": "bnxt", "driver_version": "1", "firmware": "f1", "speed": 25000}],
                      "vswitches": [{"name": "dvs", "mtu": 9000}], "vmks": [{"device": "vmk1", "mtu": mtu if i == 1 else 9000, "services": ["vsan"], "switch": "dvs"}], "hbas": []}
    H["off"] = {"cluster": "c1", "conn": "disconnected"}
    return {"hosts": H, "clusters": {"c1": {"ha": True, "drs": True, "drs_behavior": drs, "evc": ""}}}


def test_drift_normalize_diff_peers(tmp_path):
    from app import drift as D
    a = D.normalize(_snap())
    assert set(a["hosts"]) == {"e1", "e2", "e3"} and a["hosts"]["e1"]["nic:vmnic0:speed"] == "25000 Mb" and a["clusters"]["c1"]["drs_behavior"] == "fullyAutomated"
    assert D.peers(a) == []                                                # BIOS 는 호스트마다 달라도 제외
    b = D.normalize(_snap(ntp3="pool.ntp.org", ssh=True, build="200", mtu=1500, drs="manual"))
    ch = {(x["entity"], x["key"]): x for x in D.diff(a, b)}
    assert ch[("e3", "ntp")]["current"] == "pool.ntp.org" and ch[("e2", "ssh")]["severity"] == "warning" and ch[("e1", "vmk:vmk1:mtu")]["label"] == "VMkernel vmk1 MTU"
    assert ch[("c1", "drs_behavior")]["scope"] == "클러스터" and ch[("e3", "build")]["severity"] == "info"
    assert D.diff(a, b)[0]["severity"] == "warning"
    del b["hosts"]["e3"]
    assert any(x["key"] == "inventory" and x["current"] == "없음" for x in D.diff(a, b))
    p = {x["key"]: x for x in D.peers(D.normalize(_snap(ntp3="pool.ntp.org", ssh=True)))}
    assert p["ntp"]["majority"] == "ntp1" and p["ntp"]["hosts"] == ["e3"] and p["ssh"]["values"] == {"e2": "True"}
    e = _engine(tmp_path)
    ds = D.DriftStore(e.store)
    o = _run(ds.add("", "vc1", a, "op"))
    assert o["name"].startswith("기준선 ") and _run(ds.latest_for("vc1"))["data"] == a and _run(ds.get(999)) is None
    assert len(_run(ds.list())) == 1 and _run(ds.remove(o["id"])) and not _run(ds.remove(o["id"]))


# ---------------------------------------------------------------- 버전 수명
def test_lifecycle_eval_and_table(tmp_path):
    from app import lifecycle as LC
    tab = json.loads(LC.TABLE.read_text(encoding="utf-8"))
    assert LC._line_of("esxi", "8.0.3", ["7", "8", "9.0"]) == "8" and LC._line_of("vcf", "5.2.1.0", ["5.2", "9.0"]) == "5.2"
    assert LC._line_of("k8s", "1.30.1+vmware.1", ["1.3", "1.30"]) == "1.30" and LC._line_of("x", "10.1", ["1"]) is None
    rows = LC.evaluate([{"product": "esxi", "system": "vc", "version": "7.0.3", "build": "", "count": 2, "scope": "c1"},
                        {"product": "esxi", "system": "vc", "version": "8.0.3", "build": "", "count": 4, "scope": "c2"},
                        {"product": "k8s", "system": "vks", "version": "1.29.7+vmware.1", "build": "", "count": 1, "scope": "w"},
                        {"product": "avi", "system": "a", "version": "31.1.1", "build": "", "count": 1, "scope": "a"}], tab, today=dt.date(2026, 11, 11))
    by = {(r["product"], r["version"]): r for r in rows}
    assert by[("esxi", "7.0.3")]["state"] == "ended" and by[("esxi", "8.0.3")]["state"] == "soon" and by[("esxi", "8.0.3")]["days_left"] == 334
    assert by[("esxi", "8.0.3")]["next"]["line"] == "9.1" and by[("esxi", "8.0.3")]["verified"] is True
    assert by[("k8s", "1.29.7+vmware.1")]["next"]["line"] == "1.35"            # 이미 끝난 줄(1.30~1.34)은 다음 대상으로 내세우지 않음
    assert by[("avi", "31.1.1")]["state"] == "unknown" and rows[0]["state"] == "ended"
    assert all(e.get("src") for e in tab["entries"]) and {e["verified"] for e in tab["entries"]} == {True, False}
    with pytest.raises(ValueError):
        LC.validate({"entries": [{"product": "esxi", "line": "8"}]})
    with pytest.raises(ValueError):
        LC.validate({"entries": [{"product": "esxi", "line": "8", "eogs": "2027/10/11"}]})
    e = _engine(tmp_path)
    L = LC.Lifecycle(NS(store=e.store, connectors=[NS(type="vks", name="v", enabled=True, cluster_label="w", role="workload", _state={"checks": {"version": "ok v1.31.2+vmware.1"}}),
                                                   NS(type="vcenter", name="vc", enabled=True, host="vc.lab", about={"version": "8.0.3", "build": "1"},
                                                      health_snap={"hosts": {"e1": {"cluster": "c", "version": "8.0.3", "build": "1"}}, "clusters": {"c": {"vsan": True}}})]))
    rep = _run(L.report())
    assert {(r["product"], r["scope"]) for r in rep["rows"]} == {("k8s", "w"), ("vcenter", "vc.lab"), ("esxi", "c"), ("vsan", "c")} and not rep["table"]["custom"]
    _run(L.save_table({"entries": [{"product": "esxi", "line": "8", "eogs": "2030-01-01", "src": "test", "verified": True}]}))
    rep = _run(L.report())
    assert rep["table"]["custom"] and next(r for r in rep["rows"] if r["product"] == "esxi")["eogs"] == "2030-01-01"
    _run(L.reset_table())
    assert not _run(L.report())["table"]["custom"]


# ---------------------------------------------------------------- API·권한
def test_api_routes_and_rules(tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api_capacity import build_router
    from app.api_lifecycle import build_router as build_lc
    from app.certs import CertScanner
    from app.security.auth import AuthManager
    rp = AuthManager.required_perm
    assert rp("POST", "/api/capacity/whatif/move") == "view" and rp("POST", "/api/capacity/whatif/dr") == "view" and rp("GET", "/api/capacity/report-bundle") == "view"
    assert rp("GET", "/api/lifecycle/certs") == "view" and rp("POST", "/api/lifecycle/certs/scan") == "operate" and rp("PUT", "/api/lifecycle/certs/settings") == "settings"
    assert rp("POST", "/api/lifecycle/drift/baseline") == "operate" and rp("DELETE", "/api/lifecycle/drift/baseline/3") == "operate"
    assert rp("PUT", "/api/lifecycle/versions/table") == "settings" and rp("GET", "/api/lifecycle/certs.ics") == "view"
    H = {f"e{i}": {"cpu_mhz": 160000, "core_mhz": 2500, "mem_mb": 1024000, "cpu_used_mhz": 40000, "mem_used_mb": 400000, "sockets": 2, "datastores": ["ds"]} for i in (1, 2, 3)}
    H.update({f"f{i}": {"cpu_mhz": 160000, "core_mhz": 2500, "mem_mb": 1024000, "cpu_used_mhz": 40000, "mem_used_mb": 400000, "sockets": 2, "datastores": ["ds"]} for i in (1, 2, 3)})
    topo = {"clusters": {"a": {"hosts": ["e1", "e2", "e3"]}, "b": {"hosts": ["f1", "f2", "f3"]}}, "hosts": H, "datastores": {"ds": {"capacity_gb": 10000, "free_gb": 5000}},
            "vms": {"v1": {"cluster": "a", "power": "poweredOn", "vcpu": 4, "mem_mb": 8192, "cpu_mbz": 1, "cpu_mhz": 500, "disk_gb": 50, "datastores": ["ds"], "folder": "F"},
                    "v2": {"cluster": "a", "power": "poweredOff", "vcpu": 2, "mem_mb": 4096, "disk_gb": 20, "datastores": ["ds"]}}}

    class Cap:
        async def overview(self, days=None):
            return {"items": []}

        async def rightsizing(self, days=None):
            return {"days": 14, "idle": [{"vm": "v1", "vcenter": "vc1", "cluster": "a", "vcpu": 4, "mem_gb": 8}]}

    async def audit(*a, **k):
        return None
    e = _engine(tmp_path)
    vc = NS(name="vc1", type="vcenter", enabled=True, topology=topo, host="vc1", about={"version": "8.0.3"},
            health_snap={"hosts": {"e1": {"cluster": "a", "conn": "connected", "version": "8.0.3"}, "e2": {"cluster": "a", "conn": "connected", "version": "8.0.3"}}, "clusters": {}},
            health={"updated": 1})
    srm = NS(name="srm1", type="srm", enabled=True, protection={"groups": [{"name": "PG"}], "vms": [{"group": "PG", "name": "v1"}, {"group": "PG", "name": "nope"}]})
    eng = NS(capacity=Cap(), store=e.store, connectors=[vc, srm], assess=None)
    app = FastAPI()
    app.include_router(build_router(eng, {}, lambda r: {"user": "op"}, audit))
    CS = CertScanner(eng)
    app.include_router(build_lc(eng, CS, lambda r: {"user": "op"}, audit))
    with TestClient(app) as cl:
        r = cl.post("/api/capacity/whatif", json={"vcenter": "vc1", "cluster": "a", "apply_rightsizing": True}).json()
        assert r["rightsizing"]["idle"] == 1 and r["rightsizing"]["cpu_ghz"] == 0.5 and r["cost"] is None and "vsan_policies" in r
        assert cl.get("/api/capacity/whatif/vms", params={"vcenter": "vc1", "cluster": "a"}).json()["total"] == 2
        m = cl.post("/api/capacity/whatif/move", json={"vcenter": "vc1", "cluster": "a", "dst_cluster": "b", "vms": ["v1", "v2", "x"]}).json()
        assert m["moved"]["vms"] == 2 and m["moved"]["powered_on"] == 1 and m["checks"][0]["level"] == "ok"
        assert cl.post("/api/capacity/whatif/move", json={"vcenter": "vc1", "cluster": "a", "dst_cluster": "b", "vms": []}).status_code == 400
        assert cl.post("/api/capacity/whatif/move", json={"vcenter": "vc1", "cluster": "a", "dst_cluster": "zz", "vms": ["v1"]}).status_code == 404
        assert cl.get("/api/capacity/whatif/dr-sources").json()["groups"][0]["vms"] == 2
        d = cl.post("/api/capacity/whatif/dr", json={"dst_vcenter": "vc1", "dst_cluster": "b", "groups": [{"srm": "srm1", "name": "PG"}]}).json()
        assert d["recovered"]["vms"] == 1 and d["missing"] == ["nope"]
        d2 = cl.post("/api/capacity/whatif/dr", json={"dst_vcenter": "vc1", "dst_cluster": "b", "src_vcenter": "vc1", "src_cluster": "a", "include_off": True}).json()
        assert d2["recovered"]["vms"] == 2
        assert cl.post("/api/capacity/whatif/dr", json={"dst_vcenter": "vc1", "dst_cluster": "b"}).status_code == 400
        sc = cl.post("/api/capacity/whatif/scenarios", json={"name": "s", "vcenter": "vc1", "cluster": "a", "add_hosts": 1, "growth_pct_year": 10, "vsan_policy": "r1"}).json()
        assert sc["inputs"]["growth_pct_year"] == 10 and sc["inputs"]["vsan_policy"] == "r1"
        for f, magic in (("pdf", b"%PDF"), ("docx", b"PK"), ("html", b"<!doc")):
            rr = cl.get("/api/capacity/report-bundle", params={"format": f, "scenarios": str(sc["id"]), "customer": "고객"})
            assert rr.status_code == 200 and rr.content[:len(magic)] == magic and "attachment" in rr.headers["content-disposition"]
        assert cl.get("/api/capacity/report-bundle", params={"format": "xls"}).status_code == 400
        c0 = cl.get("/api/lifecycle/certs", params={"scan": 0}).json()
        assert c0["ts"] == 0 and c0["items"] == []
        dr = cl.get("/api/lifecycle/drift").json()
        assert dr["vcenter"] == "vc1" and dr["diff"] == [] and dr["hosts"] == 2
        b = cl.post("/api/lifecycle/drift/baseline", json={"vcenter": "vc1", "name": "골든"}).json()
        vc.health_snap["hosts"]["e2"]["version"] = "8.0.2"
        dr = cl.get("/api/lifecycle/drift", params={"vcenter": "vc1"}).json()
        assert dr["baseline"]["name"] == "골든" and dr["diff"][0]["current"] == "8.0.2" and dr["peers"]
        assert cl.delete(f"/api/lifecycle/drift/baseline/{b['id']}").status_code == 200
        v = cl.get("/api/lifecycle/versions").json()
        assert any(r["product"] == "vcenter" and r["line"] == "8" for r in v["rows"])
        assert cl.put("/api/lifecycle/versions/table", json={"entries": []}).status_code == 400
        CS.last = {"items": [{"source": "vks", "system": "v", "cluster": "c;1", "kind": "API 서버", "name": "a,b", "not_after": time.time() + 86400 * 3, "band": "crit",
                              "days_left": 3, "renew": "x"}], "ts": time.time(), "settings": {"warn_days": 60}}
        ics = cl.get("/api/lifecycle/certs.ics").text
        assert ics.startswith("BEGIN:VCALENDAR") and "TRIGGER:-P60D" in ics and "a\\,b" in ics and "c\\;1" in ics and "\r\n" in ics
        assert cl.get("/api/lifecycle/certs.csv").text.startswith("﻿만료일")


# ---------------------------------------------------------------- 결함 수정
def test_ldap_reason_generic_and_public_ai():
    src = (ROOT / "app" / "security" / "auth.py").read_text(encoding="utf-8")
    assert "reason = str(e)" not in src and "디렉터리 서버에 연결할 수 없습니다" in src
    from app.llm import LLMClient, _public_ai
    assert _public_ai("https://api.openai.com/v1") and _public_ai("https://x.openai.azure.com") and not _public_ai("https://pais.bank.example/v1")
    c = LLMClient({"providers": [{"name": "a", "type": "openai", "base_url": "https://api.anthropic.com", "external": False},
                                 {"name": "b", "type": "openai", "base_url": "https://api.openai.com/v1", "external": False, "allow_unmasked": True},
                                 {"name": "c", "type": "openai", "base_url": "https://llm.bank.example/v1", "external": False}]})
    assert c.providers["a"].external and c.providers["a"].forced_external and not c.providers["b"].external and not c.providers["c"].external


def test_patch_history_root_copy_and_ui_fixes():
    ctl = (ROOT / "scripts" / "linux" / "vcf-aiopsctl").read_text(encoding="utf-8")
    ap = (ROOT / "appliance" / "patch" / "apply.sh").read_text(encoding="utf-8")
    assert '"$RS/history.jsonl"' in ctl and '"$RS/history.jsonl"' in ap and "원본 우선" in ctl
    app_js = (S / "app.js").read_text(encoding="utf-8")
    assert "AbortController" in app_js and "연결이 끊겨 답변이 중간에 멈췄습니다" in app_js and "btn.disabled = true" in app_js
    cc = (S / "cloudcost.js").read_text(encoding="utf-8")
    assert "my !== seq" in cc and "st.dirty" in cc
    core = (S / "core.js").read_text(encoding="utf-8")
    assert 'e.key !== "Tab"' in core and "prev.focus" in core
    assert "--muted:#6b6b6b" in (S / "style.css").read_text(encoding="utf-8")
    en = (S / "i18n-en.js").read_text(encoding="utf-8")
    for k in ('"수명 주기 점검"', '"인증서 달력"', '"클러스터 간 이동"', '"분기별 증설 계획"', '"DR·보호"'):
        assert k in en, k


def test_ui_wiring():
    wi = (S / "whatif.js").read_text(encoding="utf-8")
    for k in ("data-wimode", "/api/capacity/whatif/move", "/api/capacity/whatif/dr", "/api/capacity/report-bundle", "function vsanBox", "function evcBox", "function quarterBox",
              "function costBox", "function rsBox", "apply_rightsizing", "growth_pct_year", "perf_factor", "vsan_policy"):
        assert k in wi, k
    lc = (S / "lifecycle.js").read_text(encoding="utf-8")
    for k in ("/api/lifecycle/certs", "/api/lifecycle/drift", "/api/lifecycle/versions", "certs.ics", "function calendar", "function vksPanel", "lf-mkbl"):
        assert k in lc, k
    html = (S / "index.html").read_text(encoding="utf-8")
    assert 'id="nav-life"' in html and 'id="drawer-life"' in html and "/static/lifecycle.js" in html
    assert '"life"' in (S / "navgroup.js").read_text(encoding="utf-8")
    import subprocess
    for f in ("whatif.js", "lifecycle.js", "app.js", "cloudcost.js", "core.js", "ai.js"):
        subprocess.run(["node", "--check", str(S / f)], check=True)
