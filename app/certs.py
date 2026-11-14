"""인증서 만료 달력(2.36.0) — VKS 를 먼저, 그다음 vCenter·ESXi·NSX·SDDC Manager 와 모든 커넥터의 TLS 엔드포인트.

읽기 전용으로 모은다(시크릿·개인 키는 읽지 않는다):
  VKS(워크로드 클러스터 커넥터)
    · API 서버 인증서            kube-apiserver 의 TLS 핸드셰이크로 받은 서버 인증서(공개)
    · kubelet 서빙 인증서         노드 InternalIP:10250 TLS 핸드셰이크(어플라이언스에서 노드망에 닿을 때만)
    · kubelet·노드 CSR           certificates.k8s.io CSR 의 발급 인증서(발급 뒤 약 1시간 안에 정리되므로 있을 때만)
    · cert-manager Certificate    status.notAfter / renewalTime / Ready(인그레스·웹훅·앱 TLS)
    · 커넥터 토큰                 vSphere SSO 세션(JWT exp) — ServiceAccount 장기 토큰은 만료 없음
  VKS(Supervisor 커넥터)
    · 워크로드 클러스터 컨트롤 플레인  Cluster API Machine.status.certificatesExpiryDate(kubeadm 이 만든 인증서, 보통 1년)
    · 자동 갱신 설정               KubeadmControlPlane.spec.rolloutBefore.certificatesExpiryDays
  vCenter  · vCenter 머신 SSL(TLS) · ESXi 호스트 인증서(HostCertificateManager.certificateInfo)
  NSX      · /api/v1/trust-management/certificates(공개 인증서 PEM)
  그 밖의 커넥터 · 접속 주소의 TLS 서버 인증서
경고: 만료 60일 전 warning, 14일 전 error, 지난 것 critical(설정 가능) — 같은 단계는 한 번만 이벤트로.
"""
from __future__ import annotations

import asyncio
import inspect
import base64
import json
import socket
import ssl
import time
from typing import Any
from urllib.parse import urlparse

KV_SCHEMA = "CREATE TABLE IF NOT EXISTS lifecycle_kv(k TEXT PRIMARY KEY, v TEXT)"
DEFAULTS = {"warn_days": 60, "crit_days": 14, "interval_h": 12, "kubelet_probe": True, "extra": []}
RENEW = {
    "vks-apiserver": "워크로드 클러스터 컨트롤 플레인 롤링(kubectl patch kcp … rolloutAfter) 또는 VKr 업그레이드 시 갱신 — 1년 주기",
    "vks-cp": "Supervisor 에서 KubeadmControlPlane 롤링 재생성(rolloutAfter) — rolloutBefore.certificatesExpiryDays 로 자동화 가능",
    "vks-kubelet": "kubelet 서빙 인증서 자동 교체(serverTLSBootstrap) — 노드 재생성 시 새로 발급",
    "vks-certmanager": "cert-manager 가 renewalTime 에 자동 갱신 — Ready=False 면 Issuer·이벤트 확인",
    "vks-token": "커넥터가 만료 전 /wcp/login 으로 자동 재발급",
    "vcenter": "vSphere Client › 인증서 관리(머신 SSL) 또는 VMCA 갱신",
    "esxi": "vCenter 에서 호스트 › 인증서 › 갱신(VMCA 모드) — 사용자 지정 CA 면 새 인증서 교체",
    "nsx": "NSX › 시스템 › 인증서 — 만료 전 새 인증서를 가져와 서비스에 적용",
    "tls": "해당 장비의 인증서 교체 절차",
}


def _cert_from_der(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    c = x509.load_der_x509_certificate(der)
    cn = lambda n: next((a.value for a in n.get_attributes_for_oid(NameOID.COMMON_NAME)), n.rfc4514_string())   # noqa: E731
    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)[:5]
    except Exception:  # noqa: BLE001
        san = []
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
    return {"subject": str(cn(c.subject))[:160], "issuer": str(cn(c.issuer))[:160], "not_after": na.timestamp() if na.tzinfo else na.replace(tzinfo=None).timestamp(),
            "not_before": nb.timestamp(), "self_signed": c.subject == c.issuer, "san": [str(x) for x in san], "serial": format(c.serial_number, "x")[-16:]}


def _cert_from_pem(pem: str | bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    if isinstance(pem, str):
        pem = pem.encode()
    c = x509.load_pem_x509_certificate(pem)
    return _cert_from_der(c.public_bytes(Encoding.DER))


def peer_cert(host: str, port: int, timeout: float = 5.0) -> dict[str, Any]:
    """TLS 핸드셰이크로 서버 인증서만 받는다(검증하지 않음 — 만료일을 보려는 것)"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s, ctx.wrap_socket(s, server_hostname=host) as t:
        der = t.getpeercert(binary_form=True)
    if not der:
        raise ValueError("인증서 없음")
    return _cert_from_der(der)


def _hostport(url_or_host: str, default_port: int = 443) -> tuple[str, int] | None:
    s = str(url_or_host or "").strip()
    if not s:
        return None
    if "//" not in s:
        s = "https://" + s
    u = urlparse(s)
    if u.scheme == "http" or not u.hostname:
        return None
    return u.hostname, u.port or default_port


def _jwt_exp(tok: str) -> float | None:
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return float(json.loads(base64.urlsafe_b64decode(p)).get("exp") or 0) or None
    except Exception:  # noqa: BLE001
        return None


def _iso(s: str | None) -> float | None:
    if not s:
        return None
    try:
        import datetime as dt
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class CertScanner:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = {**DEFAULTS, **(cfg or {})}
        self.last: dict[str, Any] = {"items": [], "ts": 0, "errors": [], "skipped": []}
        self._band: dict[str, str] = {}
        self._busy = False

    # ---------------------------------------------------------------- 설정(운영 설정 문서에 저장)
    async def settings(self) -> dict[str, Any]:
        try:
            await self.e.store.x(KV_SCHEMA)
            r = await self.e.store.q1("SELECT v FROM lifecycle_kv WHERE k='certs.settings'")
            return {**self.cfg, **(json.loads(r["v"]) if r else {})}
        except Exception:  # noqa: BLE001
            return dict(self.cfg)

    async def save_settings(self, p: dict) -> dict[str, Any]:
        cur = await self.settings()
        for k in ("warn_days", "crit_days", "interval_h"):
            if k in p:
                v = int(p[k])
                if not 1 <= v <= 3650:
                    raise ValueError(f"{k}: 1~3650")
                cur[k] = v
        if cur["crit_days"] >= cur["warn_days"]:
            raise ValueError("위험 기준(일)은 주의 기준보다 작아야 합니다")
        if "kubelet_probe" in p:
            cur["kubelet_probe"] = bool(p["kubelet_probe"])
        if "extra" in p:
            ex = []
            for x in (p.get("extra") or [])[:100]:
                hp = _hostport(str(x))
                if not hp:
                    raise ValueError(f"주소 형식: {x} (host:port)")
                ex.append(f"{hp[0]}:{hp[1]}")
            cur["extra"] = ex
        await self.e.store.x(KV_SCHEMA)
        await self.e.store.x("INSERT OR REPLACE INTO lifecycle_kv(k,v) VALUES('certs.settings',?)", (json.dumps({k: cur[k] for k in DEFAULTS}),))
        self.cfg = cur
        return cur

    # ---------------------------------------------------------------- 수집
    def _item(self, *, src: str, system: str, kind: str, name: str, cert: dict | None = None, not_after: float | None = None, renew_key: str = "tls",
              cluster: str = "", **kw) -> dict[str, Any]:
        na = (cert or {}).get("not_after") if cert else not_after
        return {"source": src, "system": system, "cluster": cluster, "kind": kind, "name": name, "not_after": na,
                "subject": (cert or {}).get("subject", kw.pop("subject", "")), "issuer": (cert or {}).get("issuer", kw.pop("issuer", "")),
                "self_signed": (cert or {}).get("self_signed"), "san": (cert or {}).get("san", []), "renew": RENEW.get(renew_key, ""), **kw}

    async def _tls(self, items, errs, *, src, system, kind, target, renew_key="tls", cluster="", default_port=443):
        hp = _hostport(target, default_port)
        if not hp:
            return
        try:
            c = await asyncio.wait_for(asyncio.to_thread(peer_cert, hp[0], hp[1]), 8)
            items.append(self._item(src=src, system=system, kind=kind, name=f"{hp[0]}:{hp[1]}", cert=c, renew_key=renew_key, cluster=cluster,
                                    cmd=f"openssl s_client -connect {hp[0]}:{hp[1]} -servername {hp[0]} </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate"))
        except Exception as e:  # noqa: BLE001
            errs.append(f"{system} {hp[0]}:{hp[1]} — {type(e).__name__}")

    async def _vks(self, c, items, errs, skipped, st):
        label = getattr(c, "cluster_label", c.name)
        sup = getattr(c, "role", "") == "supervisor"
        await self._tls(items, errs, src="vks", system=c.name, kind="Supervisor API 서버" if sup else "API 서버", target=getattr(c, "base_url", ""),
                        renew_key="vks-cp" if sup else "vks-apiserver", cluster=label, default_port=6443)
        tok = str((getattr(c, "_http", None) and c.http.headers.get("Authorization")) or "").removeprefix("Bearer ").strip()
        if tok:
            exp = _jwt_exp(tok)
            sso = c.auth_mode == "vsphere"
            items.append(self._item(src="vks", system=c.name, cluster=label, kind="커넥터 토큰", name="vSphere SSO 세션" if sso else "ServiceAccount 토큰",
                                    not_after=exp, renew_key="vks-token", auto=sso,
                                    note="커넥터가 만료 전 자동 재발급" if sso else ("" if exp else "만료 없음(장기 토큰) — 주기적으로 교체 권장")))
        lst = getattr(c, "_list", None)
        if not lst:
            return
        # cert-manager
        try:
            for o in await lst("/apis/cert-manager.io/v1/certificates", namespaced=True, limit_pages=5):
                m, s = o.get("metadata") or {}, o.get("status") or {}
                ready = next((x.get("status") for x in s.get("conditions") or [] if x.get("type") == "Ready"), "")
                ns_, nm_ = m.get("namespace"), m.get("name")
                items.append(self._item(src="vks", system=c.name, cluster=label, kind="cert-manager", name=f"{ns_}/{nm_}",
                                        cmd=f"kubectl -n {ns_} describe certificate {nm_}\ncmctl renew {nm_} -n {ns_}    # cert-manager CLI — 즉시 갱신",
                                        not_after=_iso(s.get("notAfter")), renew_key="vks-certmanager", renewal=_iso(s.get("renewalTime")),
                                        ready=ready, subject=", ".join((o.get("spec") or {}).get("dnsNames") or [])[:160],
                                        issuer=((o.get("spec") or {}).get("issuerRef") or {}).get("name", "")))
        except Exception as e:  # noqa: BLE001
            code = getattr(getattr(e, "response", None), "status_code", None)
            (skipped if code == 404 else errs).append(f"{c.name} cert-manager — " + ("설치 안 됨" if code == 404 else f"{type(e).__name__} {code or ''}".strip()))
        # 노드·CSR
        if not sup:
            try:
                csr_latest: dict[tuple, dict] = {}
                for o in await lst("/apis/certificates.k8s.io/v1/certificatesigningrequests", namespaced=False, limit_pages=3):
                    pem = (o.get("status") or {}).get("certificate")
                    if not pem:
                        continue
                    cert = _cert_from_pem(base64.b64decode(pem))
                    sp = o.get("spec") or {}
                    k = (sp.get("signerName", ""), sp.get("username", ""))
                    if k not in csr_latest or cert["not_after"] > csr_latest[k]["not_after"]:
                        csr_latest[k] = cert
                for (signer, user), cert in csr_latest.items():
                    items.append(self._item(src="vks", system=c.name, cluster=label, kind="노드 CSR", name=f"{user} ({signer.split('/')[-1]})", cert=cert, renew_key="vks-kubelet"))
            except Exception as e:  # noqa: BLE001
                skipped.append(f"{c.name} CSR — {type(e).__name__}")
            if st.get("kubelet_probe"):
                try:
                    nodes = await lst("/api/v1/nodes", namespaced=False, limit_pages=2)
                    sem = asyncio.Semaphore(8)

                    async def probe(n):
                        ip = next((a.get("address") for a in (n.get("status") or {}).get("addresses") or [] if a.get("type") == "InternalIP"), "")
                        port = (((n.get("status") or {}).get("daemonEndpoints") or {}).get("kubeletEndpoint") or {}).get("Port") or 10250
                        if not ip:
                            return
                        async with sem:
                            try:
                                cert = await asyncio.wait_for(asyncio.to_thread(peer_cert, ip, int(port), 3.0), 5)
                                items.append(self._item(src="vks", system=c.name, cluster=label, kind="kubelet 서빙", name=(n.get("metadata") or {}).get("name", ip),
                                                        cert=cert, renew_key="vks-kubelet"))
                            except Exception:  # noqa: BLE001
                                skipped.append(f"{c.name} kubelet {(n.get('metadata') or {}).get('name', ip)} — 노드망에 닿지 않음")
                    await asyncio.gather(*(probe(n) for n in nodes[:200]))
                except Exception as e:  # noqa: BLE001
                    skipped.append(f"{c.name} 노드 목록 — {type(e).__name__}")
        else:
            # Supervisor: 워크로드 클러스터 컨트롤 플레인 인증서 만료(Cluster API)
            try:
                kcp = {}
                for o in await lst("/apis/controlplane.cluster.x-k8s.io/v1beta1/kubeadmcontrolplanes", namespaced=True, limit_pages=3):
                    m = o.get("metadata") or {}
                    kcp[(m.get("namespace"), (m.get("labels") or {}).get("cluster.x-k8s.io/cluster-name") or m.get("name"))] = \
                        ((o.get("spec") or {}).get("rolloutBefore") or {}).get("certificatesExpiryDays")
                for o in await lst("/apis/cluster.x-k8s.io/v1beta1/machines", namespaced=True, limit_pages=5):
                    m, s = o.get("metadata") or {}, o.get("status") or {}
                    if not s.get("certificatesExpiryDate"):
                        continue
                    cl = (m.get("labels") or {}).get("cluster.x-k8s.io/cluster-name", "")
                    auto = kcp.get((m.get("namespace"), cl))
                    items.append(self._item(src="vks", system=c.name, cluster=f"{m.get('namespace')}/{cl}", kind="컨트롤 플레인(kubeadm)", name=m.get("name", ""),
                                            cmd=(f"# Supervisor 에서 — 자동 갱신 설정 확인\nkubectl -n {m.get('namespace')} get kcp -l cluster.x-k8s.io/cluster-name={cl} "
                                                 "-o jsonpath='{.items[*].spec.rolloutBefore}'\n# 갱신 절차는 VKS 버전 문서(Broadcom TechDocs)의 인증서 교체 절을 따르세요"),
                                            not_after=_iso(s["certificatesExpiryDate"]), renew_key="vks-cp",
                                            auto_renew_days=auto, note=f"자동 갱신: 만료 {auto}일 전 롤링" if auto else "자동 갱신 설정 없음(rolloutBefore)"))
            except Exception as e:  # noqa: BLE001
                skipped.append(f"{c.name} Cluster API — {type(e).__name__}")

    async def _vcenter(self, c, items, errs):
        port = int((getattr(c, "cfg", {}) or {}).get("port") or 443)
        await self._tls(items, errs, src="vcenter", system=c.name, kind="vCenter 머신 SSL", target=f"{c.host}:{port}", renew_key="vcenter")
        fn = getattr(c, "collect_certs", None)
        if fn is None:
            return
        try:
            rows = await (c._tx("certs", fn) if hasattr(c, "_tx") else asyncio.to_thread(fn))
        except Exception as e:  # noqa: BLE001
            errs.append(f"{c.name} ESXi 인증서 — {type(e).__name__}")
            return
        for r in rows:
            if r.get("error"):
                errs.append(f"{c.name} {r['host']} — {r['error']}")
                continue
            items.append(self._item(src="esxi", system=c.name, kind="ESXi 호스트", name=r["host"], not_after=r.get("not_after"), renew_key="esxi",
                                    subject=r.get("subject", "")[:160], issuer=r.get("issuer", "")[:160], status=r.get("status", ""),
                                    cluster=r.get("cluster", "")))

    async def _nsx(self, c, items, errs):
        try:
            r = await c.http.get("/api/v1/trust-management/certificates")
            r.raise_for_status()
            for x in (r.json() or {}).get("results") or []:
                pem = x.get("pem_encoded") or ""
                if "BEGIN CERTIFICATE" not in pem:
                    continue
                cert = _cert_from_pem(pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
                items.append(self._item(src="nsx", system=c.name, kind="NSX 인증서", name=x.get("display_name") or x.get("id", ""), cert=cert, renew_key="nsx",
                                        used_by=len(x.get("used_by") or [])))
        except Exception as e:  # noqa: BLE001
            errs.append(f"{c.name} NSX 인증서 목록 — {type(e).__name__}")

    async def scan(self) -> dict[str, Any]:
        if self._busy:
            return self.last
        self._busy = True
        try:
            st = await self.settings()
            items: list[dict] = []
            errs: list[str] = []
            skipped: list[str] = []
            jobs = []
            for c in self.e.connectors:
                if not getattr(c, "enabled", True):
                    continue
                demo = getattr(c, "demo_certs", None)
                if demo is not None:
                    items += [self._item(**x) for x in demo]
                    continue
                if getattr(c, "demo", False):                  # 데모 가짜 커넥터 — 실제 주소가 아니므로 접속하지 않음
                    continue
                t = getattr(c, "type", "")
                if t == "vks":
                    jobs.append(self._vks(c, items, errs, skipped, st))
                elif t == "vcenter":
                    jobs.append(self._vcenter(c, items, errs))
                elif t in ("nsx",):
                    jobs.append(self._tls(items, errs, src=t, system=c.name, kind="관리 TLS", target=getattr(c, "base_url", "") or c.host, renew_key="nsx"))
                    jobs.append(self._nsx(c, items, errs))
                elif getattr(c, "base_url", "") or getattr(c, "host", ""):
                    tgt = getattr(c, "base_url", "") or c.host
                    if str(tgt).startswith("https") or (c.host and not str(tgt).startswith("http:")):
                        if t not in ("syslog", "snmp", "agent"):
                            jobs.append(self._tls(items, errs, src=t, system=c.name, kind="관리 TLS", target=tgt))
            for x in st.get("extra") or []:
                jobs.append(self._tls(items, errs, src="manual", system="직접 등록", kind="TLS", target=x))
            await asyncio.gather(*jobs, return_exceptions=True)
            now = time.time()
            seen = set()
            out = []
            for it in items:                                  # 같은 인증서(같은 대상·종류·이름)는 한 번만
                k = (it["system"], it["kind"], it["name"])
                if k in seen:
                    continue
                seen.add(k)
                na = it.get("not_after")
                it["days_left"] = int((na - now) // 86400) if na else None
                it["band"] = ("auto" if it.get("auto") else "none" if na is None else "expired" if na < now else "crit" if it["days_left"] < st["crit_days"]
                              else "warn" if it["days_left"] < st["warn_days"] else "ok")
                out.append(it)
            out.sort(key=lambda x: (x["not_after"] is None, x["not_after"] or 0))
            self.last = {"items": out, "ts": now, "errors": errs[:100], "skipped": skipped[:200], "settings": {k: st[k] for k in DEFAULTS},
                         "summary": {b: sum(1 for x in out if x["band"] == b) for b in ("expired", "crit", "warn", "ok", "none", "auto")}}
            await self._events(out)
            return self.last
        finally:
            self._busy = False

    async def _events(self, items: list[dict]) -> None:
        ingest = getattr(self.e, "ingest", None)
        if not ingest:
            return
        from .models import LogEvent
        sev = {"expired": "critical", "crit": "error", "warn": "warning"}
        for it in items:
            k = f"{it['system']}|{it['kind']}|{it['name']}"
            b = it["band"]
            if self._band.get(k) == b:
                continue
            first = k not in self._band
            self._band[k] = b
            if b not in sev or (first and b == "ok"):
                continue
            src = "vks" if it["source"] == "vks" else "vcenter" if it["source"] in ("vcenter", "esxi") else it["source"]
            msg = (f"인증서 만료됨 — {it['system']} {it['kind']} {it['name']}" if b == "expired" else
                   f"인증서 만료 {it['days_left']}일 전 — {it['system']} {it['kind']} {it['name']}")
            ev = LogEvent(source=src, connector="certs", message=msg, severity=sev[b], host=it["name"] if it["source"] == "esxi" else "", entity=it["name"],
                          kind="health", attrs={"app": "cert-expiry", "kind": it["kind"], "days_left": it["days_left"], "cluster": it.get("cluster", "")})
            ingest(ev) if not inspect.iscoroutinefunction(ingest) else await ingest(ev)

    async def loop(self, beat=lambda: None) -> None:
        await asyncio.sleep(180)
        while True:
            beat()
            try:
                st = await self.settings()
                if time.time() - self.last.get("ts", 0) > st["interval_h"] * 3600:
                    await self.scan()
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(600)
