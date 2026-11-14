"""ITSM 연동 — ServiceNow Table API / 일반 웹훅.

ServiceNow
  생성  POST {instance}/api/now/table/incident   (short_description, description, urgency, impact, category, assignment_group, caller_id)
  갱신  PATCH {instance}/api/now/table/incident/{sys_id}  (work_notes, state)
  해결  state=6(Resolved) + close_code + close_notes   ※ 인스턴스별 close_code 값은 설정으로 지정
인증: Basic(전용 연동 계정) 또는 OAuth Bearer 토큰
"""
from __future__ import annotations

from typing import Any

import httpx

SEV_TO_SN = {"critical": ("1", "1"), "error": ("2", "2"), "warning": ("3", "3"), "info": ("3", "3")}   # (urgency, impact)
STATE_TO_SN = {"open": "1", "acknowledged": "2", "investigating": "2", "resolved": "6", "closed": "7"}


class ItsmClient:
    def __init__(self, cfg: dict):
        self.cfg = cfg or {}

    @property
    def kind(self) -> str:
        return str(self.cfg.get("type", "none"))

    def _sn(self) -> tuple[httpx.AsyncClient, str]:
        sn = self.cfg.get("servicenow") or {}
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        auth = None
        if sn.get("token"):
            headers["Authorization"] = f"Bearer {sn['token']}"
        else:
            auth = (sn.get("username", ""), sn.get("password", ""))
        return httpx.AsyncClient(base_url=sn["instance"].rstrip("/"), headers=headers, auth=auth, timeout=20,
                                 verify=sn.get("verify_tls", True)), sn.get("table", "incident")

    async def create(self, inc: dict, link: str) -> dict[str, Any] | None:
        if self.kind == "servicenow":
            sn = self.cfg.get("servicenow") or {}
            cli, table = self._sn()
            urg, imp = SEV_TO_SN.get(inc["severity"], ("3", "3"))
            body = {"short_description": f"[VCF AIops] {inc['title']}"[:160],
                    "description": f"{inc.get('summary') or ''}\n\n대상: {', '.join(inc.get('hosts') or [])}\n"
                                   f"상관 그룹: {inc.get('correlation_key')}\nAIOps: {link}",
                    "urgency": urg, "impact": imp, "category": sn.get("category", "Infrastructure")}
            for k in ("assignment_group", "caller_id", "cmdb_ci", "subcategory"):
                if sn.get(k):
                    body[k] = sn[k]
            async with cli:
                r = await cli.post(f"/api/now/table/{table}", json=body)
                r.raise_for_status()
                res = r.json().get("result", {})
            return {"system": "servicenow", "sys_id": res.get("sys_id"), "number": res.get("number"),
                    "url": f"{sn['instance'].rstrip('/')}/nav_to.do?uri={table}.do?sys_id={res.get('sys_id')}"}
        if self.kind == "webhook":
            wh = self.cfg.get("webhook") or {}
            async with httpx.AsyncClient(timeout=15, verify=wh.get("verify_tls", True)) as cli:
                r = await cli.post(wh["url"], json={"event": "incident.created", "incident": inc, "link": link},
                                   headers=wh.get("headers") or {})
                r.raise_for_status()
                ref = {}
                try:
                    ref = r.json() if r.content else {}
                except ValueError:
                    pass
            return {"system": "webhook", "number": str(ref.get("id") or ref.get("number") or ""), "url": ref.get("url", "")}
        return None

    async def update(self, inc: dict, ref: dict, note: str, status: str | None = None) -> None:
        if not ref:
            return
        if ref.get("system") == "servicenow" and ref.get("sys_id"):
            sn = self.cfg.get("servicenow") or {}
            cli, table = self._sn()
            body: dict[str, Any] = {"work_notes": note[:4000]}
            if status in STATE_TO_SN:
                body["state"] = STATE_TO_SN[status]
                if status in ("resolved", "closed"):
                    body["close_code"] = sn.get("close_code", "Solved (Permanently)")
                    body["close_notes"] = note[:4000]
            async with cli:
                r = await cli.patch(f"/api/now/table/{table}/{ref['sys_id']}", json=body)
                r.raise_for_status()
        elif ref.get("system") == "webhook":
            wh = self.cfg.get("webhook") or {}
            async with httpx.AsyncClient(timeout=15, verify=wh.get("verify_tls", True)) as cli:
                await cli.post(wh["url"], json={"event": f"incident.{status or 'updated'}", "incident": inc, "note": note},
                               headers=wh.get("headers") or {})

    async def test(self) -> dict[str, Any]:
        if self.kind == "servicenow":
            cli, table = self._sn()
            async with cli:
                r = await cli.get(f"/api/now/table/{table}", params={"sysparm_limit": 1, "sysparm_fields": "number"})
            return {"ok": r.status_code < 300, "http": r.status_code, "detail": r.text[:200] if r.status_code >= 300 else "조회 권한 확인됨"}
        if self.kind == "webhook":
            return {"ok": bool((self.cfg.get("webhook") or {}).get("url")), "detail": "URL 설정됨(전송 시험은 인시던트 생성 시)"}
        return {"ok": False, "detail": "ITSM 비활성(type: none)"}
