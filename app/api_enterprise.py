"""엔터프라이즈 API — 인시던트 · 조사 · 조치(승인) · 운영 설정 · 유지보수/사일런스 · 감사로그 · 리포트 · 백업 · 메트릭.

권한은 security.auth.ROUTE_RULES 가 미들웨어에서 먼저 판정한다(여기서는 업무 규칙만 검증).
"""
from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from .detect import Detector
from .httputil import disposition, finite
from .incidents import STATUS_LABEL, STATUSES
from .itsm import ItsmClient
from .models import SEV_RANK
from .security.audit import redact
from .security.secrets import keep_masked, mask_redirect
from .settings_store import CONNECTOR_SCHEMA, MANAGED_KEYS, _keep_secrets

NAME_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def _json(v: Any, default: Any) -> Any:
    try:
        return json.loads(v) if v else default
    except (TypeError, ValueError):
        return default


def _regex_ok(p: str | None, what: str) -> None:
    if p:
        try:
            re.compile(p)
        except re.error as e:
            raise HTTPException(400, f"{what} 정규식 오류: {e}")


def build_router(ENGINE, AUTH, SETTINGS, ACTIONS, REPORTER, CFG: dict,
                 who: Callable[[Request], dict], audit: Callable[..., Awaitable[None]]) -> APIRouter:
    r = APIRouter()
    INC = ENGINE.incidents

    def ip(request: Request) -> str:
        return request.client.host if request.client else "-"

    async def body(request: Request) -> dict:
        try:
            b = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "JSON 본문 필요")
        if not isinstance(b, dict):
            raise HTTPException(400, "JSON 객체 필요")
        return b

    # ================================================================== 인시던트
    @r.get("/api/incidents")
    async def incidents(status: str | None = None, q: str | None = None, days: int = 30, limit: int = 300):
        return await INC.list(status, q, max(1, min(days, 3650)), max(1, min(limit, 2000)))

    @r.get("/api/incidents/summary")
    async def incidents_summary(days: int = 7):
        now = time.time()
        return await INC.metrics(now - days * 86400, now)

    @r.get("/api/incidents/{inc_id}")
    async def incident(inc_id: str):
        inc = await INC.get(inc_id)
        if not inc:
            raise HTTPException(404)
        inc["notes"] = await INC.notes(inc_id)
        inc["actions"] = await ACTIONS.list(incident_id=inc_id)
        inc["anomalies"] = [ENGINE.anomalies[a].to_dict() for a in inc["anomaly_ids"][-100:] if a in ENGINE.anomalies]
        inc["topology"] = ENGINE.resolve(inc.get("primary_entity") or "")
        try:                                                  # 직전 VM 변경(대상 VM > 같은 호스트 > 같은 클러스터)
            inc["vm_changes"] = await asyncio.wait_for(INC.vm_changes(inc), 8)
        except Exception:  # noqa: BLE001
            inc["vm_changes"] = []
        try:                                                  # 관련 KB(자동) — 묶인 이상징후 근거·원문 로그로 문서 합산
            inc["kb"] = await asyncio.wait_for(ENGINE.kblink.for_incident(inc), 8)
        except Exception:  # noqa: BLE001
            inc["kb"] = []
        inc["statuses"] = [{"id": s, "label": STATUS_LABEL[s]} for s in STATUSES]
        return inc

    @r.post("/api/incidents")
    async def incident_create(request: Request):
        b = await body(request)
        title = str(b.get("title") or "").strip()
        sev = str(b.get("severity") or "error")
        if not title or sev not in SEV_RANK:
            raise HTTPException(400, "제목과 심각도(critical·error·warning·info)를 입력하세요")
        ids = [str(x) for x in (b.get("anomaly_ids") or []) if str(x) in ENGINE.anomalies][:200]
        inc = await INC.create_manual(title, sev, who(request)["user"], ids)
        for aid in ids:
            ENGINE.anomalies[aid].incident_id = inc["id"]
        await audit(request, "incident.create_manual", inc["id"], detail={"severity": sev, "anomalies": len(ids)})
        return inc

    @r.post("/api/incidents/{inc_id}/status")
    async def incident_status(inc_id: str, request: Request):
        b = await body(request)
        try:
            inc = await INC.set_status(inc_id, str(b.get("status")), who(request)["user"], str(b.get("note") or "")[:2000])
        except KeyError:
            raise HTTPException(404)
        except ValueError as e:
            raise HTTPException(400, str(e))
        await audit(request, "incident.status", inc_id, detail={"status": b.get("status")})
        return inc

    @r.post("/api/incidents/{inc_id}/assign")
    async def incident_assign(inc_id: str, request: Request):
        b = await body(request)
        assignee = str(b.get("assignee") or "").strip()[:64]
        if assignee and not await AUTH.store.q1("SELECT 1 FROM users WHERE username=? AND disabled=0", (assignee,)):
            raise HTTPException(400, f"사용자 '{assignee}' 없음(또는 비활성)")
        try:
            inc = await INC.assign(inc_id, assignee, who(request)["user"])
        except KeyError:
            raise HTTPException(404)
        await audit(request, "incident.assign", inc_id, detail={"assignee": assignee})
        return inc

    @r.post("/api/incidents/{inc_id}/comment")
    async def incident_comment(inc_id: str, request: Request):
        b = await body(request)
        text = str(b.get("text") or "").strip()
        if not text:
            raise HTTPException(400, "내용을 입력하세요")
        if not await INC.get(inc_id):
            raise HTTPException(404)
        await INC.comment(inc_id, text, who(request)["user"])
        return {"ok": True}

    @r.post("/api/incidents/{inc_id}/rca")
    async def incident_rca(inc_id: str, request: Request):
        """AI 근본원인 분석(인과 사슬 + 4개 검증 기준). 근거 묶음 → Gemma 4 31B."""
        try:
            res = await INC.run_rca(inc_id, who(request)["user"])
        except KeyError:
            raise HTTPException(404)
        except RuntimeError as e:
            raise HTTPException(400, str(e))
        except Exception as e:  # noqa: BLE001
            await audit(request, "incident.rca", inc_id, "fail", {"error": str(e)[:200]})
            raise HTTPException(502, f"AI 분석 실패: {type(e).__name__}: {e}"[:300])
        await audit(request, "incident.rca", inc_id, detail={"complete": res.get("complete"), "confidence": res.get("confidence")})
        return res

    @r.post("/api/incidents/{inc_id}/investigate")
    async def incident_investigate(inc_id: str, request: Request):
        """RCA 입력 근거 묶음 미리보기(이상징후·로그 타임라인·vCenter 조사·지식)"""
        inc = await INC.get(inc_id)
        if not inc:
            raise HTTPException(404)
        bundle = await INC.build_bundle(inc)
        await audit(request, "incident.investigate", inc_id)
        return bundle

    @r.post("/api/incidents/{inc_id}/itsm")
    async def incident_itsm(inc_id: str, request: Request):
        if INC.itsm.kind == "none":
            raise HTTPException(400, "ITSM 연동이 설정되지 않았습니다(설정 → ITSM)")
        try:
            return await INC.itsm_create(inc_id, who(request)["user"])
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"ITSM 등록 실패: {type(e).__name__}: {e}"[:300])

    # ================================================================== 조사(vCenter 읽기 전용)
    @r.get("/api/investigate")
    async def investigate(kind: str, name: str, hours: int = 24):
        if kind not in ("vm", "host", "datastore", "cluster"):
            raise HTTPException(400, "kind = vm | host | datastore | cluster")
        return await ENGINE.investigate(kind, name, max(1, min(hours, 168)))

    @r.get("/api/topology/resolve")
    async def topology_resolve(name: str):
        return ENGINE.resolve(name) or {}

    # ================================================================== 로그 전송 설정 점검
    @r.get("/api/forwarding")
    async def forwarding(request: Request):
        """제품별로 이 서버로 로그를 보내도록 구성됐는지 점검(읽기 전용). 적용은 /api/actions(승인 조치)."""
        res = await ENGINE.forwarding.check_all()
        await audit(request, "forwarding.check", detail=res["summary"])
        return res

    # ================================================================== 조치(승인 게이트)
    @r.get("/api/actions/catalog")
    async def actions_catalog():
        return ACTIONS.catalog()

    @r.get("/api/actions")
    async def actions_list(incident_id: str | None = None, status: str | None = None):
        return await ACTIONS.list(incident_id, status)

    @r.post("/api/actions/preview")
    async def action_preview(request: Request):
        b = await body(request)
        try:
            return await ACTIONS.preview(str(b.get("action")), str(b.get("connector")), b.get("params") or {})
        except (KeyError, ValueError) as e:
            raise HTTPException(400, str(e.args[0] if e.args else e))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"미리보기 실패: {type(e).__name__}: {e}"[:300])

    @r.post("/api/actions")
    async def action_request(request: Request):
        b = await body(request)
        reason = str(b.get("reason") or "").strip()
        if len(reason) < 4:
            raise HTTPException(400, "조치 사유를 입력하세요")
        u = who(request)
        try:
            return await ACTIONS.request(str(b.get("action")), str(b.get("connector")), b.get("params") or {}, reason,
                                         b.get("incident_id") or None, u["user"], u["role"], ip(request))
        except (KeyError, ValueError) as e:
            raise HTTPException(400, str(e.args[0] if e.args else e))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(502, f"요청 실패: {type(e).__name__}: {e}"[:300])

    @r.post("/api/actions/{aid}/approve")
    async def action_approve(aid: int, request: Request):
        u = who(request)
        try:
            return await ACTIONS.approve(aid, u["user"], u["role"], ip(request))
        except KeyError:
            raise HTTPException(404)
        except PermissionError as e:
            raise HTTPException(403, str(e))
        except ValueError as e:
            raise HTTPException(400, str(e))

    @r.post("/api/actions/{aid}/reject")
    async def action_reject(aid: int, request: Request):
        b = await body(request)
        why = str(b.get("reason") or "").strip()
        if not why:
            raise HTTPException(400, "반려 사유를 입력하세요")
        u = who(request)
        try:
            return await ACTIONS.reject(aid, u["user"], u["role"], ip(request), why)
        except KeyError:
            raise HTTPException(404)
        except ValueError as e:
            raise HTTPException(400, str(e))

    # ================================================================== 운영 설정
    def _validate_connectors(defs: Any) -> list[dict]:
        from .connectors import REGISTRY
        if not isinstance(defs, list):
            raise HTTPException(400, "connectors 는 목록이어야 합니다")
        names = set()
        for i, d in enumerate(defs):
            if not isinstance(d, dict):
                raise HTTPException(400, f"#{i + 1} 항목 형식 오류")
            t = str(d.get("type", "")).lower()
            if t not in REGISTRY:
                raise HTTPException(400, f"#{i + 1} 알 수 없는 type '{t}'")
            n = str(d.get("name") or "")
            if not NAME_RX.match(n):
                raise HTTPException(400, f"#{i + 1} 이름은 영문·숫자·._- (1~63자)")
            if n in names:
                raise HTTPException(400, f"이름 중복: {n}")
            names.add(n)
            schema = CONNECTOR_SCHEMA.get("redfish" if t in ("ilo", "idrac") else t, {"fields": []})
            for f in schema["fields"]:
                if f.get("req") and d.get("enabled", True) and d.get(f["f"]) in (None, "", []):
                    raise HTTPException(400, f"{n}: '{f['label']}' 필수")
        return defs

    async def _apply(key: str, value: Any) -> dict:
        """저장된 설정을 실행 중인 구성요소에 즉시 반영"""
        out: dict[str, Any] = {}
        if key == "connectors":
            out = await ENGINE.reload_polling_connectors(value or [])
        elif key == "knowledge":                     # KB·TechDocs 라이브러리 — 원본 폴더·주기·검색 기준
            kl = ENGINE.knowledge
            kl.cfg = value or {}
            kl.enabled = bool(kl.cfg.get("enabled", True))
            kl.k = int(kl.cfg.get("top_k", 4))
            kl.min_rel = float(kl.cfg.get("min_relevance", 0.4))
            kl.home_vendors = set(kl.cfg.get("vendors") or ["vmware"])
            kl.langs = set(kl.cfg.get("languages") or ["en", "ko"])
            lk = ENGINE.kblink
            lk.enabled = bool(kl.cfg.get("auto_link", True))
            lk.interval = float(kl.cfg.get("link_interval", 20))
            lk.min_rel = float(kl.cfg.get("link_min_relevance", 0.6))
            lk.k = int(kl.cfg.get("link_top_k", 3))
            if ENGINE.llm:
                ENGINE.llm.cfg["max_chars_per_lib_ref"] = int(kl.cfg.get("max_chars_per_ref", 2400))
            from .runtime import bg
            bg(kl.refresh())
            out = {"paths": [str(p) for _, p in kl.roots()], "missing": [p for p in kl.cfg.get("paths") or [] if not Path(str(p)).expanduser().is_dir()]}
        elif key == "alerting":
            ENGINE.alerter.cfg = value
        elif key == "siem":
            ENGINE.siem.configure(value or {})
            out = ENGINE.siem.status()
        elif key == "monitoring":
            ENGINE.collection.configure(value or {})
        elif key == "detection":
            ENGINE.detector.configure(value)
        elif key == "incidents":
            INC.cfg = value or {}
        elif key == "itsm":
            INC.itsm = ItsmClient(value or {})
        elif key == "actions":
            ACTIONS.cfg = value or {}
        elif key == "llm":
            out = ENGINE.reconfigure_llm(value or {})
        elif key == "web_search":
            ENGINE.websearch.configure(value or {})
            out = ENGINE.websearch.status()
        return out

    @r.get("/api/settings/schema")
    async def settings_schema():
        from .connectors import REGISTRY
        return {"keys": list(MANAGED_KEYS), "connector_types": CONNECTOR_SCHEMA, "registry": sorted(REGISTRY),
                "restart_required": ["server", "auth", "rag", "syslog", "snmp", "ingest"]}

    @r.get("/api/settings/{key}")
    async def settings_get(key: str):
        if key not in MANAGED_KEYS:
            raise HTTPException(404)
        d = await SETTINGS.get(key)
        if key == "web_search":                              # 빠진 항목은 기본값으로 채워 보여 줌
            from .websearch import DEFAULTS as WSD
            d = {**d, "value": {**WSD, **(d.get("value") or {})}}
        return d

    @r.put("/api/settings/{key}")
    async def settings_put(key: str, request: Request):
        if key not in MANAGED_KEYS:
            raise HTTPException(404)
        b = await body(request)
        value = b.get("value")
        if key == "connectors":
            _validate_connectors(value)
        elif not isinstance(value, dict):
            raise HTTPException(400, "설정 값은 객체여야 합니다")
        try:                                                 # 2.30.0 마스킹된 웹훅 URL·헤더 값('********') → 저장된 값 유지
            value = keep_masked(value, CFG.get(key), key)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if key == "detection":
            try:
                Detector(value)             # 정규식·가중치 사전 검증
            except (ValueError, KeyError, TypeError) as e:
                raise HTTPException(400, str(e))
            for k in ("llm_threshold", "dedupe_window"):
                if k not in value:
                    raise HTTPException(400, f"detection.{k} 필수")
        if key == "knowledge":
            if not isinstance(value.get("paths", []), list) or not all(isinstance(x, str) for x in value.get("paths", [])):
                raise HTTPException(400, "knowledge.paths 는 폴더 경로 목록입니다")
            value["paths"] = [x.strip() for x in value["paths"] if x.strip()][:20]
        if key == "web_search":
            from .websearch import DEFAULTS as WSD
            value = {**WSD, **{k: v for k, v in value.items() if k in WSD}}
            if value.get("provider") not in ("searxng", "brave", "tavily"):
                raise HTTPException(400, "공급자는 searxng·brave·tavily 중 하나")
            if value.get("enabled") and value["provider"] == "searxng" and not str(value.get("url") or "").startswith(("http://", "https://")):
                raise HTTPException(400, "SearXNG 주소(http(s)://…)를 입력하세요")
        if key == "monitoring":
            for e in value.get("expected") or []:
                _regex_ok(str(e.get("match", "")), f"기대 장비 '{e.get('name')}'")
        if key == "incidents" and value.get("min_severity") and value["min_severity"] not in SEV_RANK:
            raise HTTPException(400, "min_severity 오류")
        if key == "llm":                    # 공급자 목록의 마스킹된 키 → 저장된 값(기존 단일 설정 'local' 포함)
            from .llm import PROVIDERS, provider_defs
            olds = {p["name"]: p for p in provider_defs(CFG.get("llm") or {})}
            names = set()
            for pv in value.get("providers") or []:
                if not isinstance(pv, dict) or not pv.get("name"):
                    raise HTTPException(400, "공급자마다 이름이 필요합니다")
                if pv["name"] in names:
                    raise HTTPException(400, f"공급자 이름 중복: {pv['name']}")
                names.add(pv["name"])
                if pv.get("type") not in PROVIDERS:
                    raise HTTPException(400, f"{pv['name']}: 유형은 {', '.join(PROVIDERS)} 중 하나")
                if pv.get("api_key") == "********":
                    pv["api_key"] = (olds.get(pv["name"]) or {}).get("api_key", "")
            for t, n in (value.get("routing") or {}).items():
                if n and n not in names and not (n == "local" and value.get("base_url")):
                    raise HTTPException(400, f"라우팅 '{t}' 의 공급자 '{n}' 이 목록에 없습니다")
        before = CFG.get(key)
        merged = await SETTINGS.put(key, value, who(request)["user"])
        try:
            applied = await _apply(key, merged)
        except Exception as e:  # noqa: BLE001
            await audit(request, "settings.update", key, "apply_fail", {"error": str(e)[:300]})
            raise HTTPException(500, f"저장했지만 적용 실패: {type(e).__name__}: {e}")
        await audit(request, "settings.update", key, detail={"before": redact(before), "after": redact(merged), "applied": applied})
        return {"ok": True, "applied": applied, "value": (await SETTINGS.get(key))["value"]}

    @r.post("/api/settings/{key}/reset")
    async def settings_reset(key: str, request: Request):
        if key not in MANAGED_KEYS:
            raise HTTPException(404)
        val = await SETTINGS.reset(key)
        applied = await _apply(key, val)
        await audit(request, "settings.reset", key, detail={"applied": applied})
        return {"ok": True, "applied": applied}

    def _no_redirect(new: Any, old: Any, what: str) -> None:
        """2.30.0 저장된 비밀('********')을 쓰면서 대상 주소를 바꾼 연결 시험은 거부 — 저장된 자격 증명이 다른 서버로 나가지 않게"""
        f = mask_redirect(new, old, what)
        if f:
            raise HTTPException(400, f"대상 주소({f})가 저장된 값과 다릅니다 — 저장된 비밀값은 다른 주소로 보낼 수 없으니 비밀번호·키를 다시 입력한 뒤 시험하세요")

    @r.post("/api/settings/connectors/test")
    async def settings_connector_test(request: Request):
        """저장 전 연결 시험 — 화면 입력값(마스킹된 비밀은 기존 값으로 대체)으로 임시 커넥터를 만들어 점검"""
        from . import connectors as reg
        b = await body(request)
        d = _validate_connectors([b])[0]
        _no_redirect([d], CFG.get("connectors") or [], "connectors")
        d = _keep_secrets([d], CFG.get("connectors") or [])[0]
        d = {**d, "enabled": True}
        if d.get("hosts"):
            d = {**d, "hosts": d["hosts"][:1]}

        async def _noop(_ev):
            return None
        objs = reg.build({"connectors": [d], "syslog": {"enabled": False}, "snmp": {"enabled": False},
                          "demo": {"enabled": False}}, _noop)
        c = objs[0]
        try:
            res = await asyncio.wait_for(c.test(), timeout=45)
        except asyncio.TimeoutError:
            res = {"ok": False, "error": "시간 초과(45초)"}
        finally:
            if getattr(c, "_http", None):
                await c._http.aclose()
            if hasattr(c, "si") and getattr(c, "si", None):
                try:
                    from pyVim.connect import Disconnect
                    await asyncio.to_thread(Disconnect, c.si)
                except Exception:  # noqa: BLE001
                    pass
        await audit(request, "connector.test_draft", d.get("name", ""), "ok" if res.get("ok") else "fail")
        return res

    @r.post("/api/settings/itsm/test")
    async def settings_itsm_test(request: Request):
        b = await body(request)
        _no_redirect(b.get("value") or {}, CFG.get("itsm") or {}, "itsm")
        try:
            cfg = _keep_secrets(keep_masked(b.get("value") or {}, CFG.get("itsm") or {}, "itsm"), CFG.get("itsm") or {})
        except ValueError as e:
            raise HTTPException(400, str(e))
        try:
            return await asyncio.wait_for(ItsmClient(cfg).test(), timeout=30)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}

    @r.post("/api/settings/siem/test")
    async def settings_siem_test(request: Request):
        """저장 전 설정으로 CEF 테스트 1건 전송(임시 인스턴스)"""
        from .siem import Siem
        b = await body(request)
        _no_redirect(b.get("value") or {}, CFG.get("siem") or {}, "siem")
        cfg = _keep_secrets(b.get("value") or {}, CFG.get("siem") or {})
        try:
            t = Siem(cfg, ENGINE.siem.version, ENGINE.siem.hostname)
            res = await asyncio.wait_for(t.test(), timeout=15)
            t._close()
            await audit(request, "siem.test", cfg.get("host", ""), "ok" if res.get("ok") else "fail")
            return res
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}

    @r.get("/api/settings/siem/status")
    async def settings_siem_status():
        return ENGINE.siem.status()

    # ================================================================== 유지보수 창 · 사일런스
    @r.get("/api/maintenance")
    async def maintenance_list():
        rows = await ENGINE.store.q("SELECT * FROM maintenance ORDER BY id DESC")
        now = time.time()
        for m in rows:
            m["weekly"] = _json(m["weekly"], None)
            m["scope"] = _json(m["scope"], {})
            m["active"] = bool(m["enabled"]) and INC._in_window(m, now)
        return rows

    def _maint_payload(b: dict) -> tuple:
        name = str(b.get("name") or "").strip()[:100]
        if not name:
            raise HTTPException(400, "이름을 입력하세요")
        weekly = b.get("weekly") or None
        start = float(b.get("start") or 0)
        end = float(b.get("end") or 0)
        if weekly:
            if not re.fullmatch(r"\d{2}:\d{2}", str(weekly.get("from", ""))) or not re.fullmatch(r"\d{2}:\d{2}", str(weekly.get("to", ""))):
                raise HTTPException(400, "주간 반복: 시작·종료 시각(HH:MM)")
            weekly = {"days": [int(x) for x in (weekly.get("days") or []) if 0 <= int(x) <= 6], "from": weekly["from"], "to": weekly["to"]}
        elif not (start and end and end > start):
            raise HTTPException(400, "기간(시작<종료) 또는 주간 반복을 지정하세요")
        scope = b.get("scope") or {}
        _regex_ok(scope.get("hosts_regex"), "대상 호스트")
        scope = {"hosts_regex": scope.get("hosts_regex") or "", "clusters": [str(x) for x in scope.get("clusters") or []],
                 "sources": [str(x) for x in scope.get("sources") or []]}
        return name, start, end, json.dumps(weekly) if weekly else None, json.dumps(scope, ensure_ascii=False), int(bool(b.get("enabled", True)))

    @r.post("/api/maintenance")
    async def maintenance_create(request: Request):
        p = _maint_payload(await body(request))
        mid = await ENGINE.store.x("INSERT INTO maintenance(name,start,end,weekly,scope,enabled,created_by,created) VALUES(?,?,?,?,?,?,?,?)",
                                   (*p, who(request)["user"], time.time()))
        await INC.reload_suppression()
        await audit(request, "maintenance.create", p[0], detail={"id": mid, "scope": p[4], "weekly": p[3], "start": p[1], "end": p[2]})
        return {"ok": True, "id": mid}

    @r.put("/api/maintenance/{mid}")
    async def maintenance_update(mid: int, request: Request):
        p = _maint_payload(await body(request))
        await ENGINE.store.x("UPDATE maintenance SET name=?,start=?,end=?,weekly=?,scope=?,enabled=? WHERE id=?", (*p, mid))
        await INC.reload_suppression()
        await audit(request, "maintenance.update", p[0], detail={"id": mid, "enabled": p[5]})
        return {"ok": True}

    @r.delete("/api/maintenance/{mid}")
    async def maintenance_delete(mid: int, request: Request):
        await ENGINE.store.x("DELETE FROM maintenance WHERE id=?", (mid,))
        await INC.reload_suppression()
        await audit(request, "maintenance.delete", str(mid))
        return {"ok": True}

    @r.get("/api/silences")
    async def silences(include_expired: bool = False):
        sql = "SELECT * FROM silences" + ("" if include_expired else " WHERE until > ?") + " ORDER BY id DESC LIMIT 500"
        rows = await ENGINE.store.q(sql, () if include_expired else (time.time(),))
        for s in rows:
            s["match"] = _json(s["match"], {})
            s["active"] = s["until"] > time.time()
        return rows

    @r.post("/api/silences")
    async def silence_create(request: Request):
        b = await body(request)
        mrx, hrx = str(b.get("message_regex") or ""), str(b.get("host_regex") or "")
        if not mrx:
            raise HTTPException(400, "메시지 정규식을 입력하세요")
        _regex_ok(mrx, "메시지")
        _regex_ok(hrx, "호스트")
        reason = str(b.get("reason") or "").strip()
        if not reason:
            raise HTTPException(400, "사유를 입력하세요")
        hours = max(0.25, min(float(b.get("hours", 4)), 24 * 30))
        sid = await ENGINE.store.x("INSERT INTO silences(match,until,reason,created_by,created) VALUES(?,?,?,?,?)",
                                   (json.dumps({"message_regex": mrx, "host_regex": hrx}, ensure_ascii=False),
                                    time.time() + hours * 3600, reason[:200], who(request)["user"], time.time()))
        await INC.reload_suppression()
        await audit(request, "silence.create", str(sid), detail={"message_regex": mrx, "host_regex": hrx, "hours": hours, "reason": reason})
        return {"ok": True, "id": sid}

    @r.delete("/api/silences/{sid}")
    async def silence_expire(sid: int, request: Request):
        await ENGINE.store.x("UPDATE silences SET until=? WHERE id=?", (time.time() - 1, sid))
        await INC.reload_suppression()
        await audit(request, "silence.expire", str(sid))
        return {"ok": True}

    # ================================================================== 감사로그
    @r.get("/api/audit")
    async def audit_query(hours: float = 24, user: str | None = None, action: str | None = None, q: str | None = None,
                          limit: int = 500):
        now = time.time()
        rows = await ENGINE.audit.query(now - hours * 3600, now, user or None, action or None, q or None, limit)
        for x in rows:
            x["detail"] = finite(_json(x["detail"], x["detail"]))      # 예전에 저장된 NaN·Infinity 도 안전하게(2.20)
        return rows

    @r.get("/api/audit/verify")
    async def audit_verify(request: Request):
        res = await ENGINE.audit.verify()
        await audit(request, "audit.verify", result="ok" if res["ok"] else "broken", detail=res)
        return res

    @r.get("/api/audit/export")
    async def audit_export(request: Request, hours: float = 24 * 30):
        now = time.time()
        csv_text = await ENGINE.audit.export_csv(now - hours * 3600, now)
        await audit(request, "audit.export", detail={"hours": hours})
        fn = time.strftime("audit-%Y%m%d-%H%M.csv")
        return Response(csv_text.encode("utf-8"), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": disposition(fn)})

    # ================================================================== 리포트 · 백업
    @r.get("/api/reports")
    async def reports_list():
        rc = CFG.get("reports") or {}
        return {"reports": REPORTER.list(), "schedule": {k: rc.get(k) for k in ("daily", "weekly", "monthly")}}

    @r.post("/api/reports/generate")
    async def reports_generate(request: Request):
        b = await body(request)
        kind = str(b.get("kind") or "daily")
        now = time.time()
        if kind == "daily":
            since, until = now - 86400, now
        elif kind == "weekly":
            since, until = now - 7 * 86400, now
        elif kind == "monthly":
            lt = time.localtime(now)
            first = time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))
            if b.get("previous"):
                pl = time.localtime(first - 1)
                since, until = time.mktime((pl.tm_year, pl.tm_mon, 1, 0, 0, 0, 0, 0, -1)), first
            else:
                since, until = first, now
        else:
            since, until = float(b.get("since") or now - 86400), float(b.get("until") or now)
            if until <= since or until - since > 93 * 86400:
                raise HTTPException(400, "기간 오류(최대 93일)")
            kind = "custom"
        rep = await REPORTER.generate(kind, since, until, who(request)["user"])
        if b.get("email"):
            rcpt = [x for x in (b.get("recipients") or []) if re.fullmatch(r"[^@\s]+@[^@\s]+", str(x))]
            try:
                await REPORTER.email(rep, rcpt)
            except Exception as e:  # noqa: BLE001
                return {"name": rep["name"], "title": rep["title"], "email_error": f"{type(e).__name__}: {e}"[:200]}
        return {"name": rep["name"], "title": rep["title"], "size": rep["size"]}

    @r.get("/api/reports/{name}")
    async def report_get(name: str, request: Request, download: bool = False):
        if not re.fullmatch(r"[a-z]+-\d{8}-\d{4}\.html", name):
            raise HTTPException(400)
        p = REPORTER.dir / name
        if not p.exists():
            raise HTTPException(404)
        headers = {"Content-Disposition": disposition(name)} if download else {}
        return HTMLResponse(p.read_text(encoding="utf-8"), headers=headers)

    @r.get("/api/backup")
    async def backup_list():
        b = CFG.get("backup") or {}
        return {"backups": REPORTER.backups(), "dir": str(Path(b.get("dir", "data/backup")).resolve()),
                "schedule": b.get("time", "02:30"), "keep": b.get("keep", 14), "enabled": b.get("enabled", True)}

    @r.post("/api/backup/run")
    async def backup_run(request: Request):
        try:
            return await REPORTER.backup(who(request)["user"])
        except Exception as e:  # noqa: BLE001
            await audit(request, "backup.run", result="fail", detail={"error": str(e)[:200]})
            raise HTTPException(500, f"백업 실패: {type(e).__name__}: {e}")

    # ================================================================== Prometheus /metrics
    @r.get("/metrics", include_in_schema=False)
    async def metrics(request: Request):
        mc = CFG.get("metrics") or {}
        if not mc.get("enabled", True):
            raise HTTPException(404)
        raw = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        allowed = ip(request) in (mc.get("allow_ips") or [])
        if not allowed and raw:
            allowed = bool(await AUTH.token_user(raw, "metrics", ip(request)))
            legacy = mc.get("token")
            allowed = allowed or bool(legacy and hmac.compare_digest(raw, legacy))
        if not allowed and AUTH.enabled:
            raise HTTPException(401, "metrics 토큰(scope=metrics) 또는 허용 IP 필요")
        return PlainTextResponse(REPORTER.metrics_text(), media_type="text/plain; version=0.0.4; charset=utf-8")

    return r
