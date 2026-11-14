"""조치 게이트 — VMware-AIops 의 confirm 게이트(미리보기 → 차단 사유 → 확인 실행)를 승인 워크플로로 확장.

  1) 미리보기(preview)   읽기만으로 영향 범위(blast radius)·차단 사유(blockers) 측정, 아무것도 바꾸지 않음
  2) 요청(request)       차단 사유가 있으면 거부. 위험도 L2 → 운영자 즉시 실행, L3 이상 → 승인 대기
  3) 승인(approve)       관리자, 요청자와 다른 사람(4-eyes). 예외: admin 역할은 본인 요청도 승인 가능(actions.admin_self_approve, 감사로그에 self_approved 표시). 실행 직전 다시 측정 — 상태가 바뀌어 차단되면 실패 처리
  4) 실행·감사           결과·작업 ID·전/후 상태를 감사로그와 인시던트 이력에 기록. 장기 작업은 '진행 중'이면 재실행 금지
정책: actions.deny_environments 의 환경(예: prod) 커넥터에는 쓰기 조치 차단(VMware-AIops 환경 라벨 deny 규칙과 동일 개념)
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from .runtime import bg

SCHEMA = """
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, action TEXT, connector TEXT, target TEXT, params TEXT,
  level INTEGER, status TEXT, reason TEXT, requested_by TEXT, requested_at REAL, approved_by TEXT, approved_at REAL,
  executed_at REAL, finished_at REAL, preview TEXT, result TEXT, reject_reason TEXT);
CREATE INDEX IF NOT EXISTS ix_actions_status ON actions(status, requested_at);
"""

CATALOG: dict[str, dict[str, Any]] = {
    "vcenter.alarm.ack": {"label": "vCenter 알람 확인(Acknowledge)", "level": 2, "connector": "vcenter",
                          "params": ["entity", "alarm"], "optional": ["alarm"], "target": "entity", "reversible": True},
    "vcenter.host.maintenance.enter": {"label": "호스트 유지보수 모드 진입", "level": 3, "connector": "vcenter",
                                       "params": ["host"], "target": "host", "reversible": True},
    "vcenter.host.maintenance.exit": {"label": "호스트 유지보수 모드 해제", "level": 3, "connector": "vcenter",
                                      "params": ["host"], "target": "host", "reversible": True},
    "vcenter.vm.consolidate": {"label": "VM 디스크 통합(Consolidate)", "level": 3, "connector": "vcenter",
                               "params": ["vm"], "target": "vm", "reversible": False},
    "vcenter.service.restart": {"label": "vCenter 어플라이언스 서비스 재시작", "level": 3, "connector": "vcenter",
                                "params": ["service"], "target": "service", "reversible": False},
    "nsx.alarm.ack": {"label": "NSX 알람 확인(ACKNOWLEDGED)", "level": 2, "connector": "nsx",
                      "params": ["alarm_id"], "target": "alarm_id", "reversible": True},
    # 로그 전송 설정(전송 설정 점검 화면에서 요청) — 감사 대상 설정 변경이므로 L3(승인)
    "esxi.syslog.add": {"label": "ESXi 원격 syslog 에 이 서버 추가", "level": 3, "connector": "vcenter",
                        "params": ["scope"], "target": "scope", "reversible": True, "hidden": True},
    "vcenter.syslog.forward": {"label": "vCenter 원격 syslog 에 이 서버 추가", "level": 3, "connector": "vcenter",
                               "params": ["target"], "target": "target", "reversible": True, "hidden": True},
    "nsx.syslog.add": {"label": "NSX Manager/Edge syslog exporter 추가", "level": 3, "connector": "nsx",
                       "params": ["scope"], "target": "scope", "reversible": True, "hidden": True},
}
FWD = ("esxi.syslog.add", "vcenter.syslog.forward", "nsx.syslog.add")
STATUS_LABEL = {"pending_approval": "승인 대기", "approved": "승인됨", "running": "실행 중", "succeeded": "성공",
                "failed": "실패", "rejected": "반려", "expired": "만료", "blocked": "차단"}


class ActionGate:
    def __init__(self, engine, cfg: dict):
        self.e = engine
        self.cfg = cfg
        self.store = engine.store
        self.store.schema(SCHEMA)

    def _conn(self, name: str, kind: str):
        for c in self.e.connectors:
            if c.name == name and c.type == kind:
                return c
        raise KeyError(f"{kind} 커넥터 '{name}' 없음")

    def _policy(self, conn) -> str | None:
        env = (getattr(conn, "environment", "") or conn.cfg.get("environment", "") or "").lower()
        if env and env in [x.lower() for x in self.cfg.get("deny_environments", [])]:
            return f"정책: '{env}' 환경 커넥터는 쓰기 조치가 차단되어 있습니다(actions.deny_environments)"
        return None

    async def preview(self, action: str, connector: str, params: dict) -> dict[str, Any]:
        spec = CATALOG.get(action)
        if not spec:
            raise ValueError(f"알 수 없는 조치: {action}")
        if not self.cfg.get("enabled", True):
            return {"blast_radius": {}, "blockers": ["조치 기능 비활성(actions.enabled=false)"], "level": spec["level"]}
        missing = [p for p in spec["params"] if not params.get(p) and p not in spec.get("optional", [])]
        if missing:
            return {"blast_radius": {}, "blockers": [f"필수 값 누락: {', '.join(missing)}"], "level": spec["level"]}
        c = self._conn(connector, spec["connector"])
        pol = self._policy(c)
        if action in FWD:
            res = await self.e.forwarding.preview(action, connector, params)
        elif action == "vcenter.service.restart":
            res = await c.service_restart_preview(params["service"])
        elif action == "nsx.alarm.ack":
            r = await c.http.get(f"/api/v1/alarms/{params['alarm_id']}")
            if r.status_code >= 300:
                res = {"blast_radius": {"alarm_id": params["alarm_id"]}, "blockers": [f"알람 조회 실패 HTTP {r.status_code}"]}
            else:
                j = r.json()
                res = {"blast_radius": {k: j.get(k) for k in ("id", "feature_name", "event_type", "severity", "status", "node_display_name")},
                       "blockers": ["이미 확인/해결된 알람입니다"] if j.get("status") in ("ACKNOWLEDGED", "RESOLVED", "SUPPRESSED") else []}
        else:
            res = await asyncio.to_thread(c.action_preview, action, params)
        if pol:
            res["blockers"] = [pol] + res.get("blockers", [])
        res.update(level=spec["level"], label=spec["label"], reversible=spec["reversible"],
                   needs_approval=spec["level"] >= int(self.cfg.get("approval_min_level", 3)))
        return res

    async def _row(self, aid: int) -> dict:
        r = await self.store.q1("SELECT * FROM actions WHERE id=?", (aid,))
        if not r:
            raise KeyError(aid)
        for k in ("params", "preview", "result"):
            r[k] = json.loads(r[k]) if r[k] else None
        r["status_label"] = STATUS_LABEL.get(r["status"], r["status"])
        r["label"] = CATALOG.get(r["action"], {}).get("label", r["action"])
        return r

    async def request(self, action: str, connector: str, params: dict, reason: str, incident_id: str | None,
                      user: str, role: str, ip: str) -> dict:
        pv = await self.preview(action, connector, params)
        spec = CATALOG[action]
        target = str(params.get(spec["target"], ""))
        status = "blocked" if pv.get("blockers") else ("pending_approval" if pv["needs_approval"] else "approved")
        aid = await self.store.x(
            "INSERT INTO actions(incident_id,action,connector,target,params,level,status,reason,requested_by,requested_at,preview) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (incident_id, action, connector, target, json.dumps(params, ensure_ascii=False),
                                              spec["level"], status, reason[:500], user, time.time(), json.dumps(pv, ensure_ascii=False, default=str)))
        await self.e.audit.log("action.request", user=user, role=role, ip=ip, target=f"{action} {target}",
                               result=status, detail={"id": aid, "params": params, "blockers": pv.get("blockers")})
        if incident_id:
            await self.e.incidents.note(incident_id, user, "action", f"조치 요청 #{aid} {spec['label']} ({target}) — {STATUS_LABEL[status]}",
                                        {"action_id": aid})
        if status == "blocked":
            return await self._row(aid)
        if status == "pending_approval":
            await self.e.alerter.notify_text(f"[조치 승인 요청] #{aid} {spec['label']} — {target}",
                                             f"요청자 {user} · 사유: {reason}\n영향 범위: {json.dumps(pv.get('blast_radius'), ensure_ascii=False, default=str)[:600]}",
                                             "warning", str(aid))
            return await self._row(aid)
        bg(self._execute(aid, user))            # L2: 운영자 즉시 실행
        return await self._row(aid)

    async def approve(self, aid: int, user: str, role: str, ip: str) -> dict:
        r = await self._row(aid)
        if r["status"] != "pending_approval":
            raise ValueError(f"승인할 수 없는 상태: {STATUS_LABEL.get(r['status'])}")
        self_ok = r["requested_by"] == user
        if self_ok and not (role == "admin" and self.cfg.get("admin_self_approve", True)):
            raise PermissionError("요청자 본인은 승인할 수 없습니다(4-eyes 원칙 — admin 역할만 본인 승인 가능)")
        if time.time() - r["requested_at"] > float(self.cfg.get("approval_ttl_hours", 4)) * 3600:
            await self.store.x("UPDATE actions SET status='expired' WHERE id=?", (aid,))
            raise ValueError("승인 유효시간이 지났습니다 — 다시 요청하세요")
        await self.store.x("UPDATE actions SET status='approved', approved_by=?, approved_at=? WHERE id=?", (user, time.time(), aid))
        await self.e.audit.log("action.approve", user=user, role=role, ip=ip, target=f"{r['action']} {r['target']}",
                               detail={"id": aid, "self_approved": self_ok})
        if r["incident_id"]:
            await self.e.incidents.note(r["incident_id"], user, "action",
                                        f"조치 #{aid} {'본인 승인(admin)' if self_ok else '승인'} — 실행 직전 재측정 후 실행")
        bg(self._execute(aid, user))
        return await self._row(aid)

    async def reject(self, aid: int, user: str, role: str, ip: str, why: str) -> dict:
        r = await self._row(aid)
        if r["status"] != "pending_approval":
            raise ValueError("승인 대기 상태가 아닙니다")
        await self.store.x("UPDATE actions SET status='rejected', approved_by=?, approved_at=?, reject_reason=? WHERE id=?",
                           (user, time.time(), why[:500], aid))
        await self.e.audit.log("action.reject", user=user, role=role, ip=ip, target=f"{r['action']} {r['target']}",
                               detail={"id": aid, "reason": why})
        if r["incident_id"]:
            await self.e.incidents.note(r["incident_id"], user, "action", f"조치 #{aid} 반려: {why}")
        return await self._row(aid)

    async def _execute(self, aid: int, actor: str) -> None:
        r = await self._row(aid)
        spec = CATALOG[r["action"]]
        try:
            pv = await self.preview(r["action"], r["connector"], r["params"])     # 실행 직전 재측정
            if pv.get("blockers"):
                raise RuntimeError("실행 직전 재측정에서 차단: " + "; ".join(pv["blockers"]))
            await self.store.x("UPDATE actions SET status='running', executed_at=? WHERE id=?", (time.time(), aid))
            c = self._conn(r["connector"], spec["connector"])
            if r["action"] in FWD:
                res = await self.e.forwarding.execute(r["action"], r["connector"], r["params"])
            elif r["action"] == "vcenter.service.restart":
                res = await c.service_restart(r["params"]["service"])
            elif r["action"] == "nsx.alarm.ack":
                resp = await c.http.post(f"/api/v1/alarms/{r['params']['alarm_id']}",
                                         params={"action": "set_status", "new_status": "ACKNOWLEDGED"})
                res = {"result": "success" if resp.status_code < 300 else "error", "http": resp.status_code,
                       "error": resp.text[:300] if resp.status_code >= 300 else ""}
            else:
                res = await asyncio.to_thread(c.action_execute, r["action"], r["params"], float(self.cfg.get("task_timeout", 900)))
            after = None
            try:
                after = (await self.preview(r["action"], r["connector"], r["params"])).get("blast_radius")
            except Exception:  # noqa: BLE001
                pass
            res["before"] = pv.get("blast_radius")
            res["after"] = after
            status = "succeeded" if res.get("result") == "success" else ("running" if res.get("result") == "running" else "failed")
        except Exception as e:  # noqa: BLE001
            res, status = {"result": "error", "error": f"{type(e).__name__}: {e}"[:500]}, "failed"
        await self.store.x("UPDATE actions SET status=?, finished_at=?, result=? WHERE id=?",
                           (status, time.time(), json.dumps(res, ensure_ascii=False, default=str), aid))
        await self.e.audit.log("action.execute", user=actor, target=f"{r['action']} {r['target']}", result=status,
                               detail={"id": aid, "result": res})
        if r["incident_id"]:
            await self.e.incidents.note(r["incident_id"], actor, "action",
                                        f"조치 #{aid} {spec['label']} ({r['target']}) — {STATUS_LABEL[status]}"
                                        + (f": {res.get('error')}" if res.get("error") else ""), {"action_id": aid})
        await self.e.broadcast({"type": "action", "data": {"id": aid, "status": status, "incident_id": r["incident_id"]}})

    async def list(self, incident_id: str | None = None, status: str | None = None, limit: int = 200) -> list[dict]:
        sql, p = "SELECT id FROM actions WHERE 1=1", []
        if incident_id:
            sql += " AND incident_id=?"
            p.append(incident_id)
        if status:
            sql += " AND status=?"
            p.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        p.append(limit)
        return [await self._row(x["id"]) for x in await self.store.q(sql, p)]

    def catalog(self) -> list[dict]:
        return [{"action": k, **v, "needs_approval": v["level"] >= int(self.cfg.get("approval_min_level", 3)),
                 "connectors": [c.name for c in self.e.connectors if c.type == v["connector"] and not c.name.startswith("demo-")]}
                for k, v in CATALOG.items() if not v.get("hidden")]
