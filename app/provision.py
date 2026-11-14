"""수집 전용(읽기 전용) 서비스 계정 자동 생성 — 커넥터 등록 화면에서 관리자 계정을 받아 그 자리에서 만든다.

관리자 자격 증명은 이 요청 안에서만 쓰고 저장하지 않는다(감사 로그에는 대상·결과만, 비밀값 없음).
제품별 방식(1차 문서 기준, docs/ACCOUNTS.md 에 출처):
  vCenter        SSO 사용자(govc sso.user.create — SSO Admin API) → 역할(System.Anonymous·View·Read [+Global.Diagnostics])
                 → vCenter 루트 권한(하위 전파) → vSphere 네임스페이스 VIEW(Supervisor/VKS 조회) → 유효 권한 검증
  NSX            4.1+: POST /api/v1/node/users?action=create_user → ?action=activate → 만료 끔(기본 Auditor 역할)
                 4.0 이하: 내장 audit(10002) 활성화
  VCF Operations POST /suite-api/api/auth/users  (role-permissions: ReadOnly, allowAllObjects)
  Ops for logs   POST /api/v2/users  (roleIds: 'View Only Admin', email 생략 → 비밀번호 직접 설정)
  SDDC Manager   POST /v1/users  (이미 있는 SSO 사용자 → VIEWER 역할)
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import shutil
import ssl
import subprocess
import time

import httpx

READ_PRIVS = ["System.Anonymous", "System.View", "System.Read"]
DIAG_PRIV = "Global.Diagnostics"
WRITE_PROBE = ["Folder.Create", "Datacenter.Create", "VirtualMachine.Interact.PowerOff", "VirtualMachine.Inventory.Delete",
               "VirtualMachine.Config.Settings", "Host.Config.Maintenance", "Host.Config.AdvancedConfig", "Host.Config.Network",
               "Datastore.DeleteFile", "Datastore.FileManagement", "Alarm.Acknowledge", "Alarm.Create", "Global.Settings",
               "Resource.HotMigrate", "Authorization.ModifyPermissions", "Sessions.TerminateSession"]
ROLE_NAME = "VCF-AIops-ReadOnly-Collector"
SUPPORTED = ("vcenter", "nsx", "vcfops", "vcflogs", "sddc")


class ProvisionError(RuntimeError):
    pass


def gen_password(n: int = 20) -> str:
    """vCenter SSO·NSX(12자+, 대·소·숫자·특수, 같은 문자 3연속 금지)·Ops·Logs 정책을 모두 만족 · 셸/YAML 안전 문자만."""
    up, lo, dg, sp = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#%^*-_=+"
    al = up + lo + dg + sp
    while True:
        pw = [secrets.choice(s) for s in (up, lo, dg, sp)] + [secrets.choice(al) for _ in range(n - 4)]
        secrets.SystemRandom().shuffle(pw)
        p = "".join(pw)
        if not re.search(r"(.)\1\1", p):
            return p


class Run:
    def __init__(self):
        self.steps: list[dict] = []
        self.warnings: list[str] = []

    def ok(self, step: str, detail: str = "") -> None:
        self.steps.append({"step": step, "ok": True, "detail": detail})

    def warn(self, step: str, detail: str) -> None:
        self.steps.append({"step": step, "ok": None, "detail": detail})
        self.warnings.append(f"{step}: {detail}")

    def fail(self, step: str, detail: str) -> None:
        self.steps.append({"step": step, "ok": False, "detail": detail})
        raise ProvisionError(f"{step}: {detail}")


def _client(base: str, verify: bool, timeout: float = 30) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base, verify=verify, timeout=httpx.Timeout(timeout, connect=8),
                             headers={"Accept": "application/json"}, follow_redirects=False)


def _host_port(host: str, default: int) -> tuple[str, int]:
    if host.startswith("["):
        h, _, p = host[1:].partition("]")
        return h, int(p.lstrip(":") or default)
    if host.count(":") == 1:
        h, p = host.split(":")
        return h, int(p)
    return host, default


# ============================================================================ vCenter
def govc_path() -> str | None:
    for p in (os.environ.get("AIOPS_GOVC"), "/opt/vcf-aiops/bin/govc", shutil.which("govc")):
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _govc(args: list[str], env: dict, timeout: int = 60) -> subprocess.CompletedProcess:
    exe = govc_path()
    if not exe:
        raise ProvisionError("govc 없음 — SSO 사용자 생성에 필요(어플라이언스는 /opt/vcf-aiops/bin/govc 포함, "
                             "직접 설치본은 https://github.com/vmware/govmomi/releases 의 govc 를 PATH 에 두세요)")
    return subprocess.run([exe, *args], env={**os.environ, **env}, text=True, capture_output=True, timeout=timeout)


def _vc_sync(p: dict, run: Run) -> dict:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim

    host, port = _host_port(p["host"], 443)
    user = p["new_user"] or "readonly@vsphere.local"
    if "@" not in user:
        dom = p["admin_user"].split("@", 1)[1] if "@" in p["admin_user"] else "vsphere.local"
        user = f"{user}@{dom}"
    name, domain = user.split("@", 1)
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", name):
        run.fail("입력", f"계정 이름 형식 오류: {name}")
    principal = f"{domain.upper()}\\{name}"
    privs = READ_PRIVS + ([] if p.get("no_diagnostics") else [DIAG_PRIV])
    pw = p.get("new_password") or gen_password()
    env = {"GOVC_URL": f"https://{host}:{port}/sdk", "GOVC_USERNAME": p["admin_user"], "GOVC_PASSWORD": p["admin_password"],
           "GOVC_INSECURE": "0" if p.get("verify_tls") else "1"}

    # 1) SSO 사용자
    ex = _govc(["sso.user.id", name], env)
    exists = ex.returncode == 0 and "person=" in ex.stdout
    if ex.returncode != 0 and ("NotAuthenticated" in ex.stderr or "Cannot complete login" in ex.stderr or "401" in ex.stderr):
        run.fail("관리자 로그인", ex.stderr.strip()[:300])
    if not exists:
        r = _govc(["sso.user.create", "-p", pw, "-d", "VCF AIops collector (read-only)", "-f", "VCF AIops", "-l", "Collector", name], env)
        if r.returncode != 0:
            run.fail("SSO 사용자 생성", (r.stderr or r.stdout).strip()[:400])
        run.ok("SSO 사용자 생성", user)
    elif p.get("reset_password"):
        r = _govc(["sso.user.update", "-p", pw, name], env)
        if r.returncode != 0:
            run.fail("SSO 비밀번호 재설정", (r.stderr or r.stdout).strip()[:400])
        run.ok("SSO 사용자 비밀번호 재설정", user)
    else:
        run.warn("SSO 사용자", f"{user} 이미 있음 — 비밀번호는 바꾸지 않음(재설정하려면 '기존 계정 비밀번호 재설정' 체크)")
        pw = ""
    grp = _govc(["sso.user.id", name], env)
    risky = [g for g in ("Administrators", "SystemConfiguration.Administrators", "SystemConfiguration.BashShellAdministrators",
                         "LicenseService.Administrators", "CAAdmins") if re.search(rf"\b{re.escape(g)}\b", grp.stdout.split("groups=", 1)[-1])]
    if risky:
        run.fail("SSO 그룹 점검", f"{user} 가 관리 그룹({', '.join(risky)})에 속해 있어 쓰기 권한이 생깁니다 — 그룹에서 제거 후 다시 실행")
    run.ok("SSO 그룹 점검", "관리 그룹 미소속")

    # 2) 역할·권한(pyVmomi)
    ctx = ssl.create_default_context()
    if not p.get("verify_tls"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=host, port=port, user=p["admin_user"], pwd=p["admin_password"], sslContext=ctx)
    try:
        content = si.RetrieveContent()
        am = content.authorizationManager
        role = next((r for r in am.roleList if r.name == ROLE_NAME), None)
        if role is None:
            rid = am.AddAuthorizationRole(name=ROLE_NAME, privIds=privs)
            run.ok("역할 생성", f"{ROLE_NAME}: {', '.join(privs)}")
        else:
            rid = role.roleId
            cur = set(role.privilege or [])
            extra = sorted(cur - set(privs) - {"System.Anonymous", "System.View", "System.Read"})
            if extra or not set(privs) <= cur:
                am.UpdateAuthorizationRole(roleId=rid, newName=ROLE_NAME, privIds=privs)
                run.ok("역할 정정", f"허용 목록으로 맞춤{(' (제거: ' + ', '.join(extra) + ')') if extra else ''}")
            else:
                run.ok("역할", "이미 허용 목록과 일치")
        root = content.rootFolder
        perm = vim.AuthorizationManager.Permission(principal=principal, group=False, roleId=rid, propagate=True)
        am.SetEntityPermissions(entity=root, permission=[perm])
        run.ok("권한 부여", f"vCenter 루트 · {principal} = {ROLE_NAME} (하위 전파)")
        # 3) 검증 — 유효 권한(그룹·상속 포함)
        allowed = set(privs) | {"System.Anonymous", "System.View", "System.Read"}
        try:
            res = am.FetchUserPrivilegeOnEntities(entities=[root], userName=principal)
            got = set()
            for r in res or []:
                got |= set(r.privileges or [])
            over = sorted(got - allowed)
            hp = am.HasUserPrivilegeOnEntities(entities=[root], userName=principal, privId=WRITE_PROBE)
            granted = sorted({a.privId for e in hp or [] for a in (e.privAvailability or []) if a.isGranted})
            if over or granted:
                # 방금 준 권한을 회수해 계정이 아무 권한도 갖지 않게 한 뒤 실패로 보고
                try:
                    am.RemoveEntityPermission(entity=root, user=principal, isGroup=False)
                    rollback = " · 방금 부여한 권한은 회수함"
                except Exception:  # noqa: BLE001
                    rollback = ""
                bad = over or granted
                run.fail("쓰기 불가 검증", f"허용 밖 유효 권한 {len(bad)}개(예: {', '.join(bad[:6])}) — 이 사용자/그룹에 다른 권한이 있습니다{rollback}")
            run.ok("쓰기 불가 검증", f"유효 권한 {len(got)}개 모두 읽기 · 대표 쓰기 권한 {len(WRITE_PROBE)}종 없음")
        except ProvisionError:
            raise
        except Exception as e:  # noqa: BLE001 — 6.5 미만 등
            run.warn("유효 권한 검증", f"조회 불가({type(e).__name__}) — 역할 정의로만 보장")
    finally:
        Disconnect(si)
    # 4) 새 계정 로그인 확인
    if pw:
        try:
            si2 = SmartConnect(host=host, port=port, user=user, pwd=pw, sslContext=ctx)
            n = len(si2.RetrieveContent().perfManager.perfCounter or [])
            Disconnect(si2)
            run.ok("새 계정 로그인", f"성능 카운터 {n}개 조회")
        except Exception as e:  # noqa: BLE001
            run.warn("새 계정 로그인", f"{type(e).__name__}: {e}"[:200])
    return {"username": user, "password": pw, "principal": principal, "role": ROLE_NAME, "privileges": privs}


async def _vc_namespaces(p: dict, user: str, run: Run) -> None:
    """vSphere 네임스페이스마다 VIEW — Supervisor/VKS 자동 발견·파드 조회용. 네임스페이스 기능이 없으면 건너뜀."""
    host, port = _host_port(p["host"], 443)
    name, domain = user.split("@", 1)
    async with _client(f"https://{host}:{port}", bool(p.get("verify_tls"))) as c:
        r = await c.post("/api/session", auth=(p["admin_user"], p["admin_password"]))
        if r.status_code >= 300:
            run.warn("네임스페이스 VIEW", f"REST 세션 실패 HTTP {r.status_code}")
            return
        c.headers["vmware-api-session-id"] = r.json()
        r = await c.get("/api/vcenter/namespaces/instances")
        if r.status_code == 404 or r.status_code >= 500:
            run.ok("네임스페이스 VIEW", "vSphere 네임스페이스 없음(Supervisor 미사용) — 건너뜀")
            return
        if r.status_code >= 300:
            run.warn("네임스페이스 VIEW", f"목록 HTTP {r.status_code}")
            return
        nss = [x.get("namespace") for x in r.json() if x.get("namespace")]
        done = 0
        for ns in nss:
            path = f"/api/vcenter/namespaces/instances/{ns}/access/{domain}/{name}"
            r = await c.post(path, params={"type": "USER"}, json={"role": "VIEW"})
            if r.status_code == 400 and "already" in r.text.lower():
                r = await c.put(path, params={"type": "USER"}, json={"role": "VIEW"})
            if r.status_code < 300:
                done += 1
        (run.ok if done == len(nss) else run.warn)("네임스페이스 VIEW", f"{done}/{len(nss)}개 네임스페이스에 VIEW 부여")
        await c.delete("/api/session")


K8S_READER_ROLE = {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
    "metadata": {"name": "vcf-aiops-reader", "labels": {"app.kubernetes.io/managed-by": "vcf-aiops"}},
    "rules": [
        {"apiGroups": [""], "resources": ["nodes", "pods", "pods/log", "events", "namespaces", "services", "endpoints",
                                          "persistentvolumes", "persistentvolumeclaims"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["events.k8s.io"], "resources": ["events"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["apps"], "resources": ["deployments", "replicasets", "statefulsets", "daemonsets"], "verbs": ["get", "list", "watch"]},
        # 2.9.0 구성도(읽기 전용) — Secret·ConfigMap 내용은 읽지 않음(파드 spec 의 이름 참조만 사용)
        {"apiGroups": ["batch"], "resources": ["jobs", "cronjobs"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["networking.k8s.io"], "resources": ["ingresses", "networkpolicies"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["storage.k8s.io"], "resources": ["storageclasses"], "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["autoscaling"], "resources": ["horizontalpodautoscalers"], "verbs": ["get", "list", "watch"]},
    ]}


async def _vks_rbac(p: dict, user: str, run: Run) -> None:
    """VKS 워크로드(TKG) 클러스터마다 읽기 전용 ClusterRole 을 만들고 sso:<user> 에 바인딩.
    vSphere 네임스페이스 VIEW 만으로는 워크로드 클러스터 안의 노드·파드를 볼 수 없어서(쓰기 동사 없음: get·list·watch)."""
    host, port = _host_port(p["host"], 443)
    verify = bool(p.get("verify_tls"))
    async with _client(f"https://{host}:{port}", verify) as c:
        r = await c.post("/api/session", auth=(p["admin_user"], p["admin_password"]))
        if r.status_code >= 300:
            return
        c.headers["vmware-api-session-id"] = r.json()
        r = await c.get("/api/vcenter/namespace-management/clusters")
        if r.status_code >= 300:
            return
        eps = []
        for x in r.json() or []:
            d = await c.get(f"/api/vcenter/namespace-management/clusters/{x.get('cluster')}")
            if d.status_code < 300 and d.json().get("api_server_cluster_endpoint"):
                eps.append(d.json()["api_server_cluster_endpoint"])
        await c.delete("/api/session")
    if not eps:
        return
    done, total, errs = 0, 0, []
    crb = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
           "metadata": {"name": "vcf-aiops-reader", "labels": {"app.kubernetes.io/managed-by": "vcf-aiops"}},
           "subjects": [{"kind": "User", "name": f"sso:{user}", "apiGroup": "rbac.authorization.k8s.io"}],
           "roleRef": {"kind": "ClusterRole", "name": "vcf-aiops-reader", "apiGroup": "rbac.authorization.k8s.io"}}
    async with httpx.AsyncClient(verify=verify, timeout=20) as h:
        for ep in eps:
            r = await h.post(f"https://{ep}/wcp/login", auth=(p["admin_user"], p["admin_password"]))
            if r.status_code >= 300:
                errs.append(f"{ep} Supervisor 로그인 HTTP {r.status_code}")
                continue
            tok = r.json().get("session_id")
            r = await h.get(f"https://{ep}:6443/apis/cluster.x-k8s.io/v1beta1/clusters", headers={"Authorization": f"Bearer {tok}"})
            if r.status_code >= 300:
                errs.append(f"{ep} CAPI 조회 HTTP {r.status_code}")
                continue
            for cl in r.json().get("items", []):
                md, sp = cl.get("metadata") or {}, (cl.get("spec") or {}).get("controlPlaneEndpoint") or {}
                if not sp.get("host"):
                    continue
                total += 1
                g = await h.post(f"https://{ep}/wcp/login", auth=(p["admin_user"], p["admin_password"]),
                                 json={"guest_cluster_name": md.get("name"), "guest_cluster_namespace": md.get("namespace")})
                if g.status_code >= 300 or not g.json().get("session_id"):
                    errs.append(f"{md.get('namespace')}/{md.get('name')} 로그인 HTTP {g.status_code}")
                    continue
                api = f"https://{sp['host']}:{sp.get('port') or 6443}"
                hd = {"Authorization": f"Bearer {g.json()['session_id']}"}
                ok = True
                for path, obj in (("/apis/rbac.authorization.k8s.io/v1/clusterroles", K8S_READER_ROLE),
                                  ("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", crb)):
                    w = await h.post(api + path, json=obj, headers=hd)
                    if w.status_code == 409:
                        w = await h.put(f"{api}{path}/{obj['metadata']['name']}", json=obj, headers=hd)
                    if w.status_code >= 300:
                        ok = False
                        errs.append(f"{md.get('namespace')}/{md.get('name')} {obj['kind']} HTTP {w.status_code}")
                        break
                done += ok
    if total:
        (run.ok if done == total else run.warn)("VKS 워크로드 클러스터 읽기 RBAC",
                                               f"{done}/{total}개 클러스터에 ClusterRole vcf-aiops-reader(get·list·watch) → sso:{user}"
                                               + (f" · 실패: {'; '.join(errs[:3])}" if errs else ""))
    elif errs:
        run.warn("VKS 워크로드 클러스터 읽기 RBAC", "; ".join(errs[:3]))


async def provision_vcenter(p: dict, run: Run) -> dict:
    res = await asyncio.to_thread(_vc_sync, p, run)
    try:
        await _vc_namespaces(p, res["username"], run)
    except Exception as e:  # noqa: BLE001
        run.warn("네임스페이스 VIEW", f"{type(e).__name__}: {e}"[:200])
    if p.get("vks_rbac", True):
        try:
            await _vks_rbac(p, res["username"], run)
        except Exception as e:  # noqa: BLE001
            run.warn("VKS 워크로드 클러스터 읽기 RBAC", f"{type(e).__name__}: {e}"[:200])
    return {**res, "steps": run.steps, "warnings": run.warnings}


# ============================================================================ NSX
async def provision_nsx(p: dict, run: Run) -> dict:
    host, port = _host_port(p["host"], 443)
    user = (p.get("new_user") or "svc-aiops-ro").split("@")[0]
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9@_.\-]{0,31}$", user) or user in ("root", "admin", "audit"):
        run.fail("입력", f"NSX 사용자 이름 형식 오류/예약어: {user}")
    pw = p.get("new_password") or gen_password()
    auth = (p["admin_user"], p["admin_password"])
    async with _client(f"https://{host}:{port}", bool(p.get("verify_tls"))) as c:
        r = await c.get("/api/v1/node/version", auth=auth)
        if r.status_code in (401, 403):
            run.fail("관리자 로그인", f"HTTP {r.status_code}")
        r.raise_for_status()
        ver = str(r.json().get("product_version") or r.json().get("node_version") or "")
        vt = tuple(int(x) for x in re.findall(r"\d+", ver)[:2]) or (0, 0)
        run.ok("관리자 로그인", f"NSX {ver}")
        users = (await c.get("/api/v1/node/users", auth=auth)).json().get("results", [])
        found = next((u for u in users if u.get("username") == user), None)
        if vt < (4, 1):
            found = next((u for u in users if str(u.get("userid")) == "10002"), None)
            user = (found or {}).get("username", "audit")
            run.warn("버전", f"NSX {ver} 는 새 로컬 사용자 생성을 지원하지 않음(4.1+) — 내장 읽기 전용 '{user}'(10002) 사용")
        if not found:
            r = await c.post("/api/v1/node/users", params={"action": "create_user"}, auth=auth,
                             json={"username": user, "full_name": "VCF AIops collector (read-only)", "password_change_frequency": 0})
            if r.status_code >= 300:
                run.fail("로컬 사용자 생성", f"HTTP {r.status_code} {r.text[:300]}")
            found = r.json()
            run.ok("로컬 사용자 생성", f"{user} (userid {found.get('userid')})")
        uid = found.get("userid")
        status = str(found.get("status", "")).upper()
        if status in ("NOT_ACTIVATED", ""):
            r = await c.post(f"/api/v1/node/users/{uid}", params={"action": "activate"}, auth=auth, json={"password": pw})
            if r.status_code >= 300:
                run.fail("활성화·비밀번호", f"HTTP {r.status_code} {r.text[:300]}")
            run.ok("활성화·비밀번호", "ACTIVE")
        elif p.get("reset_password"):
            r = await c.put(f"/api/v1/node/users/{uid}", auth=auth, json={"password": pw})
            if r.status_code >= 300:
                run.fail("비밀번호 재설정", f"HTTP {r.status_code} {r.text[:300]}")
            run.ok("비밀번호 재설정", user)
        else:
            run.warn("사용자", f"{user} 이미 활성 — 비밀번호는 바꾸지 않음(재설정하려면 체크)")
            pw = ""
        r = await c.put(f"/api/v1/node/users/{uid}", auth=auth, json={"password_change_frequency": 0})
        (run.ok if r.status_code < 300 else run.warn)("비밀번호 만료 끄기", "90일 만료 해제" if r.status_code < 300 else f"HTTP {r.status_code}")
        # 역할: 게스트/audit 사용자는 기본 Auditor — 확인, 없으면 바인딩 추가
        rb = await c.get("/api/v1/aaa/role-bindings", params={"name": user, "type": "local_user"}, auth=auth)
        roles = set()
        if rb.status_code < 300:
            for b in rb.json().get("results", []):
                for rp in b.get("roles_for_paths") or []:
                    roles |= {x.get("role") for x in rp.get("roles") or []}
                roles |= {x.get("role") for x in b.get("roles") or []}
        roles.discard(None)
        if roles - {"auditor"}:
            run.fail("역할 점검", f"{user} 에 auditor 외 역할: {', '.join(sorted(roles))} — NSX 사용자 관리에서 정리")
        if not roles:
            r = await c.post("/api/v1/aaa/role-bindings", auth=auth, json={
                "name": user, "type": "local_user", "read_roles_for_paths": True,
                "roles_for_paths": [{"path": "/", "roles": [{"role": "auditor"}]}]})
            (run.ok if r.status_code < 300 else run.warn)("역할", "auditor 바인딩 추가" if r.status_code < 300 else f"HTTP {r.status_code}")
        else:
            run.ok("역할", "auditor(읽기 전용)만 보유")
        if pw:
            await asyncio.sleep(2)
            r = await c.get("/api/v1/node/version", auth=(user, pw))
            (run.ok if r.status_code == 200 else run.warn)("새 계정 로그인", "OK" if r.status_code == 200 else f"HTTP {r.status_code} — 클러스터 동기화에 수 분 걸릴 수 있음")
    run.warn("클러스터", "3노드 NSX Manager 는 사용자·비밀번호가 다른 노드에 반영되는 데 몇 분 걸릴 수 있습니다")
    return {"username": user, "password": pw, "role": "auditor", "steps": run.steps, "warnings": run.warnings}


# ============================================================================ VCF Operations
async def provision_vcfops(p: dict, run: Run) -> dict:
    host, port = _host_port(p["host"], 443)
    user = (p.get("new_user") or "svc-aiops-ro").split("@")[0]
    pw = p.get("new_password") or gen_password()
    async with _client(f"https://{host}:{port}", bool(p.get("verify_tls"))) as c:
        body = {"username": p["admin_user"], "password": p["admin_password"]}
        if p.get("auth_source"):
            body["authSource"] = p["auth_source"]
        r = await c.post("/suite-api/api/auth/token/acquire", json=body)
        if r.status_code >= 300:
            run.fail("관리자 로그인", f"HTTP {r.status_code}")
        c.headers["Authorization"] = f"OpsToken {r.json()['token']}"
        run.ok("관리자 로그인", "OpsToken")
        roles = [x.get("name") for x in (await c.get("/suite-api/api/auth/roles")).json().get("userRoles", [])]
        role = "ReadOnly" if "ReadOnly" in roles or not roles else next((x for x in roles if "read" in x.lower()), "ReadOnly")
        lu = await c.get("/suite-api/api/auth/users", params={"username": user})
        ex = [u for u in (lu.json().get("users", []) if lu.status_code < 300 else []) if u.get("username") == user]
        if not ex:
            r = await c.post("/suite-api/api/auth/users", json={
                "username": user, "password": pw, "firstName": "VCF AIops", "lastName": "Collector", "enabled": True,
                "role-permissions": [{"roleName": role, "allowAllObjects": True}]})
            if r.status_code >= 300:
                run.fail("로컬 사용자 생성", f"HTTP {r.status_code} {r.text[:300]}")
            run.ok("로컬 사용자 생성", f"{user} · 역할 {role}(모든 개체)")
        else:
            uid = ex[0].get("id")
            r = await c.put(f"/suite-api/api/auth/users/{uid}/permissions", json={"roleName": role, "allowAllObjects": True})
            (run.ok if r.status_code < 300 else run.warn)("역할", f"{role}(모든 개체)" if r.status_code < 300 else f"HTTP {r.status_code}")
            run.warn("사용자", f"{user} 이미 있음 — 비밀번호는 VCF Operations 사용자 관리에서 재설정하세요")
            pw = ""
        if pw:
            r = await c.post("/suite-api/api/auth/token/acquire", json={"username": user, "password": pw}, headers={"Authorization": ""})
            (run.ok if r.status_code < 300 else run.warn)("새 계정 로그인", "OK" if r.status_code < 300 else f"HTTP {r.status_code}")
    return {"username": user, "password": pw, "role": role, "steps": run.steps, "warnings": run.warnings}


# ============================================================================ VCF Operations for logs
async def provision_vcflogs(p: dict, run: Run) -> dict:
    host, port = _host_port(p["host"], 9543)
    user = (p.get("new_user") or "svc-aiops-ro").split("@")[0]
    pw = p.get("new_password") or gen_password()
    async with _client(f"https://{host}:{port}", bool(p.get("verify_tls"))) as c:
        r = await c.post("/api/v2/sessions", json={"username": p["admin_user"], "password": p["admin_password"],
                                                  "provider": p.get("provider") or "Local"})
        if r.status_code >= 300:
            run.fail("관리자 로그인", f"HTTP {r.status_code}")
        c.headers["Authorization"] = f"Bearer {r.json()['sessionId']}"
        run.ok("관리자 로그인", "Bearer")
        roles = (await c.get("/api/v2/roles")).json()
        roles = roles.get("roles", roles) if isinstance(roles, dict) else roles
        pick = next((x for x in roles if x.get("name") == "View Only Admin"), None) or next((x for x in roles if x.get("name") == "User"), None)
        if not pick:
            run.fail("역할", "'View Only Admin'/'User' 역할을 찾지 못함")
        users = (await c.get("/api/v2/users")).json()
        users = users.get("users", users) if isinstance(users, dict) else users
        if not any(u.get("username") == user for u in users):
            r = await c.post("/api/v2/users", json={"username": user, "password": pw, "roleIds": [pick["id"]]})
            if r.status_code >= 300:
                run.fail("로컬 사용자 생성", f"HTTP {r.status_code} {r.text[:300]}")
            run.ok("로컬 사용자 생성", f"{user} · 역할 {pick['name']}")
        else:
            run.warn("사용자", f"{user} 이미 있음 — 비밀번호는 Operations for logs 에서 재설정하세요")
            pw = ""
        if pw:
            r = await c.post("/api/v2/sessions", json={"username": user, "password": pw, "provider": "Local"}, headers={"Authorization": ""})
            (run.ok if r.status_code < 300 else run.warn)("새 계정 로그인", "OK" if r.status_code < 300 else f"HTTP {r.status_code}")
    return {"username": user, "password": pw, "role": pick["name"], "steps": run.steps, "warnings": run.warnings}


# ============================================================================ SDDC Manager
async def provision_sddc(p: dict, run: Run) -> dict:
    """SDDC Manager 는 로컬 사용자가 없어 vCenter SSO 사용자에게 VIEWER 역할만 준다(관리 도메인 vCenter 에서 먼저 생성)."""
    host, port = _host_port(p["host"], 443)
    user = p.get("new_user") or "readonly@vsphere.local"
    if "@" not in user:
        run.fail("입력", "SSO 사용자를 user@domain 형식으로(관리 도메인 vCenter 에서 먼저 만든 계정)")
    name, domain = user.split("@", 1)
    async with _client(f"https://{host}:{port}", bool(p.get("verify_tls"))) as c:
        r = await c.post("/v1/tokens", json={"username": p["admin_user"], "password": p["admin_password"]})
        if r.status_code >= 300:
            run.fail("관리자 로그인", f"HTTP {r.status_code}")
        c.headers["Authorization"] = f"Bearer {r.json()['accessToken']}"
        run.ok("관리자 로그인", "Bearer")
        roles = (await c.get("/v1/roles")).json().get("elements", [])
        viewer = next((x for x in roles if str(x.get("name", "")).upper() == "VIEWER"), None)
        if not viewer:
            run.fail("역할", "VIEWER 역할 없음(VCF 4.1 이상 필요)")
        cur = (await c.get("/v1/users")).json().get("elements", [])
        if any(str(u.get("name", "")).lower() in (user.lower(), name.lower()) for u in cur):
            run.ok("사용자", f"{user} 이미 등록됨")
        else:
            r = await c.post("/v1/users", json=[{"name": user, "domain": domain, "type": "USER", "role": {"id": viewer["id"]}}])
            if r.status_code >= 300:
                r = await c.post("/v1/users", json=[{"name": name, "domain": domain, "type": "USER", "role": {"id": viewer["id"]}}])
            if r.status_code >= 300:
                run.fail("VIEWER 역할 부여", f"HTTP {r.status_code} {r.text[:300]}")
            run.ok("VIEWER 역할 부여", user)
        pw = p.get("new_password") or ""
        if pw:
            r = await c.post("/v1/tokens", json={"username": user, "password": pw}, headers={"Authorization": ""})
            (run.ok if r.status_code < 300 else run.warn)("새 계정 로그인", "OK" if r.status_code < 300 else f"HTTP {r.status_code}")
        else:
            run.warn("비밀번호", "SDDC Manager 는 SSO 비밀번호를 그대로 씀 — 커넥터에 그 SSO 계정 비밀번호를 입력하세요")
    return {"username": user, "password": pw, "role": "VIEWER", "steps": run.steps, "warnings": run.warnings}


HANDLERS = {"vcenter": provision_vcenter, "nsx": provision_nsx, "vcfops": provision_vcfops,
            "vcflogs": provision_vcflogs, "sddc": provision_sddc}


async def provision(p: dict) -> dict:
    t = p.get("type")
    if t not in HANDLERS:
        raise ProvisionError(f"지원하지 않는 유형: {t} (지원: {', '.join(SUPPORTED)})")
    for k in ("host", "admin_user", "admin_password"):
        if not p.get(k):
            raise ProvisionError(f"{k} 필요")
    t0 = time.time()
    run = Run()
    try:
        out = await HANDLERS[t](p, run)
        out["ok"] = True
    except ProvisionError as e:
        out = {"ok": False, "error": str(e), "steps": run.steps, "warnings": run.warnings}
    except httpx.HTTPError as e:
        out = {"ok": False, "error": f"연결 실패: {type(e).__name__}: {e}"[:300], "steps": run.steps}
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "InvalidLogin" in type(e).__name__ or "incorrect user name or password" in msg:
            msg = "관리자 로그인 실패(사용자 이름·비밀번호 확인)"
        out = {"ok": False, "error": f"{type(e).__name__}: {msg}"[:300], "steps": run.steps}
    out["elapsed_ms"] = int((time.time() - t0) * 1000)
    return out

