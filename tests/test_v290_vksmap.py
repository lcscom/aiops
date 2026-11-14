"""2.9.0 VKS 구성도 — 리소스 요약(_compact) · 관계 그래프(Ingress→Service→워크로드→PVC→PV→SC, VIP↔Avi, 노드↔VM) · Supervisor 개요 · Mermaid"""
import asyncio
import json
from types import SimpleNamespace as NS
from urllib.parse import urlparse

import httpx

from app import vksmap
from app.connectors.kubernetes import VksConnector, _compact, _vol_refs

DEP = {"metadata": {"namespace": "shop", "name": "web"}, "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}},
       "template": {"spec": {"serviceAccountName": "web-sa", "containers": [{"image": "nginx:1.27", "envFrom": [{"secretRef": {"name": "web-secret"}}]}],
                             "volumes": [{"configMap": {"name": "web-cfg"}}, {"persistentVolumeClaim": {"claimName": "web-data"}}]}}},
       "status": {"readyReplicas": 2}}


def test_compact_and_vol_refs():
    w = _compact("deployments", DEP)
    assert w["kind"] == "Deployment" and w["want"] == 3 and w["ready"] == 2 and w["selector"] == {"app": "web"}
    assert w["cms"] == ["web-cfg"] and w["secrets"] == ["web-secret"] and w["pvcs"] == ["web-data"] and w["sa"] == "web-sa"
    svc = _compact("services", {"metadata": {"namespace": "shop", "name": "web"}, "spec": {"type": "LoadBalancer", "selector": {"app": "web"}, "ports": [{"port": 80}]},
                                "status": {"loadBalancer": {"ingress": [{"ip": "10.10.1.5"}]}}})
    assert svc["lb"] == ["10.10.1.5"] and svc["ports"] == ["80/TCP"]
    ing = _compact("ingresses", {"metadata": {"namespace": "shop", "name": "web"}, "spec": {"rules": [{"host": "shop.corp", "http": {"paths": [{"backend": {"service": {"name": "web"}}}]}}]}})
    assert ing["services"] == ["web"] and ing["hosts"] == ["shop.corp"]
    sc = _compact("storageclasses", {"metadata": {"name": "vsan-default", "annotations": {"storageclass.kubernetes.io/is-default-class": "true"}},
                                     "provisioner": "csi.vsphere.vmware.com", "parameters": {"storagePolicyName": "vSAN Default"}})
    assert sc["policy"] == "vSAN Default" and sc["default"]
    assert _vol_refs({"volumes": [{"projected": {"sources": [{"secret": {"name": "s1"}}]}}]})["secrets"] == ["s1"]


def _eng():
    pods = [{"ns": "shop", "name": f"web-7d-{i}", "node": "tkc-np-1", "phase": "Running", "ready": "1/1", "restarts": 0, "owner": "ReplicaSet", "owner_name": "web-7d",
             "labels": {"app": "web"}, "pvcs": ["web-data"], "cms": ["web-cfg"], "secrets": [], "sa": "web-sa"} for i in range(2)]
    pods.append({"ns": "shop", "name": "web-7d-x", "node": "tkc-np-1", "phase": "Pending", "ready": "0/1", "restarts": 4, "owner": "ReplicaSet", "owner_name": "web-7d",
                 "labels": {"app": "web"}, "pvcs": [], "cms": [], "secrets": [], "sa": ""})
    pods.append({"ns": "kube-system", "name": "coredns-1", "node": "tkc-cp-1", "phase": "Running", "ready": "1/1", "owner": "ReplicaSet", "owner_name": "coredns-1",
                 "labels": {"k8s-app": "kube-dns"}})
    topo = {"namespaces": [{"name": "shop"}, {"name": "kube-system"}], "deployments": [_compact("deployments", DEP)],
            "replicasets": [{"ns": "shop", "name": "web-7d", "owner": "web"}],
            "services": [{"ns": "shop", "name": "web", "type": "LoadBalancer", "cluster_ip": "10.96.0.10", "selector": {"app": "web"}, "ports": ["80/TCP"], "lb": ["10.10.1.5"]},
                         {"ns": "default", "name": "kubernetes", "type": "ClusterIP", "selector": {}}],
            "ingresses": [{"ns": "shop", "name": "web", "services": ["web"], "hosts": ["shop.corp"], "lb": []}],
            "pvcs": [{"ns": "shop", "name": "web-data", "volume": "pvc-123", "sc": "vsan-default", "phase": "Bound", "size": "10Gi"}],
            "pvs": [{"name": "pvc-123", "sc": "vsan-default", "phase": "Bound", "driver": "csi.vsphere.vmware.com", "size": "10Gi"}],
            "storageclasses": [{"name": "vsan-default", "provisioner": "csi.vsphere.vmware.com", "policy": "vSAN Default", "default": True}],
            "hpas": [{"ns": "shop", "name": "web", "target_kind": "Deployment", "target": "web", "min": 2, "max": 6, "current": 3}]}
    w = NS(type="vks", name="tkc01", role="workload", cluster_label="tkc01", base_url="https://tkc01:6443",
           inv={"pods": pods, "nodes": [{"name": "tkc-np-1", "ready": "True", "roles": ["worker"]}, {"name": "tkc-cp-1", "ready": "True", "roles": ["control-plane"]}],
                "topo": topo, "topo_errors": {"netpols": "HTTP 403"}, "topo_updated": 1.0})
    sup = NS(type="vks", name="sup1", role="supervisor", cluster_label="sup1", base_url="https://sup:6443",
             inv={"nodes": [{}, {}, {}], "clusters": [{"ns": "team-a", "name": "tkc01", "phase": "Provisioned", "ready": "True", "version": "v1.31"}],
                  "topo": {"namespaces": [{"name": "team-a"}, {"name": "team-b"}, {"name": "vmware-system-x"}],
                           "vms": [{"ns": "team-b", "name": "db-vm", "power": "PoweredOn", "class": "best-effort-large", "ip": "10.2.0.5"}]}})
    vc = NS(type="vcenter", name="vc", topology={"vms": {"tkc-np-1": {"host": "esx03.lab", "cluster": "CL1"}}})
    avi = NS(type="avi", name="avi", vs={"u1": {"name": "shop-web-vs", "state": "UP", "vips": ["10.10.1.5"]}})
    return NS(connectors=[w, sup, vc, avi])


def test_cluster_graph_relations():
    g = vksmap.cluster_graph(_eng(), "tkc01")
    ids = {n["id"]: n for n in g["nodes"]}
    e = {(x["from"], x["to"], x["kind"]) for x in g["edges"]}
    dep = ids["Deployment:shop/web"]
    assert dep["pods"] == 3 and dep["pods_ready"] == 2 and dep["pods_bad"] == 1 and dep["status"] == "warn" and dep["hpa"] == "2–6 (현재 3)"
    assert dep["cms"] == ["web-cfg"] and dep["secrets"] == ["web-secret"] and dep["on_nodes"] == ["tkc-np-1"]
    assert ("Ingress:shop/web", "Service:shop/web", "route") in e and ("Service:shop/web", "Deployment:shop/web", "select") in e
    assert ("VIP:shop/10.10.1.5", "Service:shop/web", "lb") in e and ids["VIP:shop/10.10.1.5"]["avi"] == "shop-web-vs (UP)"
    assert ("Deployment:shop/web", "PersistentVolumeClaim:shop/web-data", "mount") in e
    assert ("PersistentVolumeClaim:shop/web-data", "PersistentVolume:/pvc-123", "bind") in e and ("PersistentVolume:/pvc-123", "StorageClass:/vsan-default", "class") in e
    assert "정책 vSAN Default" in ids["StorageClass:/vsan-default"]["detail"]
    assert not any(n["ns"] == "kube-system" for n in g["nodes"]) and "Service:default/kubernetes" not in ids     # 시스템 네임스페이스 기본 제외
    kn = {n["name"]: n for n in g["k8s_nodes"]}
    assert kn["tkc-np-1"]["esxi"] == "esx03.lab" and kn["tkc-np-1"]["pods"] == 3 and not kn["tkc-cp-1"]["vm"]
    assert g["errors"] == {"netpols": "HTTP 403"} and "kube-system" in g["system_ns"]
    g2 = vksmap.cluster_graph(_eng(), "tkc01", system=True)
    assert any(n["id"] == "Deployment:kube-system/coredns-1" for n in g2["nodes"])
    g3 = vksmap.cluster_graph(_eng(), "tkc01", q="web-data")
    assert {n["kind"] for n in g3["nodes"]} == {"PersistentVolumeClaim", "Deployment", "PersistentVolume"}
    mm = vksmap.mermaid(g)
    assert mm.startswith("flowchart LR") and 'subgraph' in mm and "deploy: web" in mm and "-->|select|" in mm


def test_overview():
    o = vksmap.overview(_eng())
    s = o["supervisors"][0]
    names = [n["name"] for n in s["namespaces"]]
    assert names == ["team-a", "team-b"]                                               # 시스템 네임스페이스 제외
    a = s["namespaces"][0]["clusters"][0]
    assert a["connector"] == "tkc01" and a["nodes"] == 2 and a["pods"] == 4 and a["pods_bad"] == 1
    assert s["namespaces"][1]["vms"][0]["name"] == "db-vm" and o["standalone"] == []


def test_connector_topology_collection_skips_forbidden():
    seen = []

    def h(req):
        p = urlparse(str(req.url)).path
        seen.append(p)
        if p == "/version":
            return httpx.Response(200, json={"gitVersion": "v1.31"})
        if "networkpolicies" in p:
            return httpx.Response(403, json={})
        if "secrets" in p:
            raise AssertionError("Secret 은 조회하면 안 됨")
        if p == "/apis/apps/v1/deployments":
            return httpx.Response(200, json={"items": [DEP], "metadata": {}})
        return httpx.Response(200, json={"items": [], "metadata": {}})
    c = VksConnector({"name": "tkc01", "host": "tkc01", "token": "t"}, lambda e: None)
    c._http = httpx.AsyncClient(base_url="https://tkc01:6443", transport=httpx.MockTransport(h))
    asyncio.run(c.login())
    asyncio.run(c._topology())
    assert c.inv["topo"]["deployments"][0]["name"] == "web" and c.inv["topo_errors"] == {"netpols": "HTTP 403"}
    assert "/apis/networking.k8s.io/v1/ingresses" in seen and not any("vmoperator" in p for p in seen)        # 워크로드 클러스터는 Supervisor 리소스 안 읽음
