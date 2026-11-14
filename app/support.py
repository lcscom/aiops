"""지원 요청(SR, 2.11.0) — 장애 근거를 모아 벤더 SR 양식에 맞춘 보고서·이메일 초안·PDF·로그 묶음·공유 링크

출발점: 인시던트 · 이상징후 · VKS 개체 · 호스트/VM · 직접 작성
수집: 발생 시각(최초·최근·지속 여부) · 환경(제품·버전·빌드) · 영향 개체 · 증상(오류 원문) · 타임라인 · 로그 발췌 ·
      최근 변경(VM 액티비티·VKS 변경 이력) · 확인한 내용(인시던트 기록·RCA·자동 점검) · 관련 KB·TechDocs(제목·번호·URL 만) · 첨부 목록
양식(공개 문서 기준):
  Broadcom  — KB 142884(케이스 생성: Case type·Product·Priority P1~P4·Business Impact), KB 140745(심각도 정의),
              KB 440029(최소 데이터: 증상·영향·첨부·시각·환경 변경·타사 제품·수행한 점검과 참조 KB·연락처·호스트/VM·제품 버전)
  AWS       — Support 사용자 안내서 'Creating support cases'(Service·Category·Severity 5단계·Subject·Description·첨부 3개×5MB·연락 방법)
  Azure     — 'Create an Azure support request'(Issue type·Subscription·Service·Resource·Problem type·시작 시각·Severity A/B/C·진단 정보 동의·연락처)
보안: 보고서·로그는 비밀값 패턴을 가린다. 공유 링크는 무작위 토큰(해시만 저장)·만료·폐기·로그 포함 여부·로그인 요구 선택, 열람은 감사로그.
외부 AI 로 다듬기는 기존 가명화(Masker) 규칙 그대로 — 개체 이름·IP·FQDN 을 가린 뒤 보내고 돌아오면 되돌린다.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import secrets
import time
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape
from pathlib import Path
from typing import Any

from .logexport import LogQuery, build_zip, fmt_ts
from .srlang import act_en, has_ko, rule_en
from .vksobs import mask_log

SCHEMA = """CREATE TABLE IF NOT EXISTS support_requests(id TEXT PRIMARY KEY, created REAL, updated REAL, created_by TEXT, status TEXT,
  vendor TEXT, lang TEXT, title TEXT, severity INTEGER, source_kind TEXT, source_ref TEXT, case_no TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS ix_sr_updated ON support_requests(updated);
CREATE TABLE IF NOT EXISTS support_shares(id TEXT PRIMARY KEY, sr_id TEXT, token_hash TEXT UNIQUE, created REAL, expires REAL, created_by TEXT,
  require_login INTEGER, include_logs INTEGER, revoked INTEGER DEFAULT 0, opened INTEGER DEFAULT 0, last_open REAL);
CREATE TABLE IF NOT EXISTS support_profile(k TEXT PRIMARY KEY, v TEXT);"""
FONT_DIR = Path(__file__).parent / "assets" / "fonts"
STATUSES = {"draft": "초안", "submitted": "접수됨", "waiting": "벤더 회신 대기", "closed": "종료"}
STATUS_EN = {"draft": "Draft", "submitted": "Submitted", "waiting": "Waiting for vendor", "closed": "Closed"}
LANGS = ("both", "ko", "en")

VENDORS: dict[str, dict[str, Any]] = {
    "broadcom": {
        "label": "Broadcom (VMware)", "portal": "https://support.broadcom.com",
        "sev": {1: ("P1", "Critical - P1 (Severity 1)", "운영(프로덕션) 시스템 중단·서비스 대부분 상실 또는 중요 데이터 손실 위험, 즉시 우회책 없음", "Production or mission-critical system down / substantial loss of service, or significant risk of data loss — no workaround immediately available"),
                2: ("P2", "High - P2 (Severity 2)", "주요 기능이 심각하게 손상 — 제한적으로 운영은 계속", "Major functionality severely impaired — operations continue in a restricted fashion"),
                3: ("P3", "Medium - P3 (Severity 3)", "업무에 제한적인 영향", "Limited adverse effect on business operations"),
                4: ("P4", "Low - P4 (Severity 4)", "업무에 영향 없음(문의·경미한 문제)", "Business operations not adversely affected")},
        "fields": [("case_type", "Case type", "Technical"), ("product", "Product", ""), ("version", "Version / Build", ""),
                   ("priority", "Priority", ""), ("business_impact", "Business Impact (P1)", ""), ("production_down", "Production down (P1)", ""),
                   ("site_id", "Site ID", "")],
        "notes": ["포털: My Cases › AI Search 에 증상을 쓰고 'Create Case' (P1 은 Business Impact·Production down 확인 필수)",
                  "로그 번들은 케이스 생성 후 업로드(KB 385549 — 웹·SFTP 등)"],
        "notes_en": ["Portal: My Cases › describe the issue in AI Search › 'Create Case' (P1 requires Business Impact and production-down confirmation)",
                     "Upload log bundles after the case is created (KB 385549 — web, SFTP, etc.)"],
        "refs": ["https://knowledge.broadcom.com/external/article/142884", "https://knowledge.broadcom.com/external/article/140745",
                 "https://knowledge.broadcom.com/external/article/440029"],
    },
    "aws": {
        "label": "AWS Support", "portal": "https://console.aws.amazon.com/support/home",
        "sev": {1: ("urgent", "Production system down (urgent)", "업무에 큰 영향 — 중요한 기능을 쓸 수 없음 (최상위 'Business-critical system down'은 비즈니스 위험 시 선택)", "Business significantly impacted; important functions unavailable"),
                2: ("high", "Production system impaired (high)", "애플리케이션의 중요한 기능이 손상·저하", "Important functions of the application are impaired or degraded"),
                3: ("normal", "System impaired (normal)", "중요하지 않은 기능의 이상", "Non-critical functions are behaving abnormally"),
                4: ("low", "General guidance (low)", "일반 문의·기능 요청", "General guidance question or feature request")},
        "fields": [("case_type", "Case type", "Technical"), ("service", "Service", ""), ("category", "Category", ""), ("severity", "Severity", ""),
                   ("account_id", "AWS account", ""), ("contact_method", "Contact method", "Web")],
        "notes": ["첨부는 최대 3개·각 5MB — 로그 묶음이 크면 공유 링크를 본문에 넣거나 나눠 첨부"],
        "notes_en": ["Up to 3 attachments, 5 MB each — use the share link or split the log bundle if it is larger"],
        "refs": ["https://docs.aws.amazon.com/awssupport/latest/user/case-management-legacy.html"],
    },
    "azure": {
        "label": "Microsoft Azure", "portal": "https://portal.azure.com/#view/Microsoft_Azure_Support/HelpAndSupportBlade",
        "sev": {1: ("A", "Severity A — Critical business impact", "서비스가 크게 손실·저하되어 즉시 대응 필요", "Significant loss or degradation of services requiring immediate attention"),
                2: ("B", "Severity B — Moderate business impact", "서비스가 손실·저하됐지만 제한적으로 업무 계속 가능", "Moderate loss or degradation of services; work can reasonably continue in an impaired manner"),
                3: ("C", "Severity C — Minimum business impact", "경미한 지장 — 업무는 정상", "Functioning with minor impediments of services"),
                4: ("C", "Severity C — Minimum business impact", "경미한 지장 — 업무는 정상", "Functioning with minor impediments of services")},
        "fields": [("issue_type", "Issue type", "Technical"), ("subscription", "Subscription", ""), ("service", "Service", ""),
                   ("resource", "Resource", ""), ("problem_type", "Problem type / subtype", ""), ("severity", "Severity", ""),
                   ("diagnostics", "Advanced diagnostic information", "Yes"), ("contact_method", "Contact method", "Email")],
        "notes": ["파일은 1개(여러 파일은 .zip) 업로드 — 로그 묶음 zip 그대로 첨부"],
        "notes_en": ["One file upload (use a .zip for several files) — attach the log bundle zip as is"],
        "refs": ["https://learn.microsoft.com/en-us/azure/azure-portal/supportability/how-to-create-azure-support-request",
                 "https://azure.microsoft.com/support/plans/response/"],
    },
    "generic": {
        "label": "일반(사내·파트너)", "portal": "",
        "sev": {1: ("S1", "Severity 1 — Service down", "운영 서비스 중단", "Production service down"), 2: ("S2", "Severity 2 — Major impairment", "주요 기능 저하", "Major functionality impaired"),
                3: ("S3", "Severity 3 — Partial impact", "부분·제한적 영향", "Partial / limited impact"), 4: ("S4", "Severity 4 — Question", "영향 없음", "No business impact")},
        "fields": [("product", "Product", ""), ("version", "Version", ""), ("severity", "Severity", "")],
        "notes": [], "refs": [],
    },
}
SEV_OF = {"critical": 1, "error": 2, "warning": 3, "info": 4, "debug": 4}
PRODUCT_OF = {"esxi": "VMware vSphere (ESXi)", "vcenter": "VMware vSphere (vCenter Server)", "vsan": "VMware vSAN", "nsx": "VMware NSX",
              "nsx-edge": "VMware NSX (Edge)", "avi": "VMware Avi Load Balancer", "vks": "vSphere Kubernetes Service (VKS)",
              "vks-supervisor": "vSphere Supervisor", "sddc": "VMware Cloud Foundation (SDDC Manager)", "vcfops": "VCF Operations",
              "vcflogs": "VCF Operations for Logs", "vcfa": "VCF Automation", "srm": "VMware Live Site Recovery", "redfish": "서버 하드웨어(BMC)",
              "vm": "게스트 OS", "baremetal": "물리 서버 OS"}

L = {  # 보고서 문구(한국어·영어)
    "ko": {"summary": "1. 문제 요약", "impact": "2. 심각도·업무 영향", "when": "3. 발생 시각", "env": "4. 환경(제품·버전)", "objects": "5. 영향 받은 개체",
           "symptoms": "6. 증상·오류 메시지(원문)", "changes": "7. 최근 환경 변경", "checked": "8. 확인한 내용(수행한 점검)", "kb": "9. 관련 KB·TechDocs",
           "attach": "10. 첨부·로그", "requests": "11. 요청 사항", "contact": "12. 연락처", "timeline": "부록 A. 타임라인", "logs": "부록 B. 로그 발췌",
           "portal": "포털 입력값", "first": "최초 발생", "last": "최근 발생", "detected": "탐지", "ongoing": "현재 상태", "yes_ongoing": "지속 중",
           "resolved": "해소됨(재발 확인 필요)", "tz": "시간대", "none": "해당 없음", "share": "공유 링크", "generated": "생성",
           "greet": "안녕하세요,\n아래 장애에 대한 기술 지원을 요청드립니다. 상세 보고서와 로그를 첨부합니다.",
           "bye": "확인 부탁드립니다.\n감사합니다.", "req_default": ["원인 분석과 해결 방법(또는 우회책) 안내", "추가로 필요한 로그·명령 출력이 있으면 알려 주십시오",
                                                                   "해당 버전의 알려진 문제·패치 여부 확인"],
           "title_sev": "심각도", "vendor": "제출 대상", "sr": "SR", "status": "상태", "case": "케이스 번호", "role_main": "주 대상", "role_rel": "연관",
           "rca": "근본원인 분석(AI 보조, 검증 필요)", "conf": "확신도", "files": "파일", "rows": "행"},
    "en": {"summary": "1. Problem summary", "impact": "2. Severity & business impact", "when": "3. When it happened", "env": "4. Environment (product / version)",
           "objects": "5. Affected objects", "symptoms": "6. Symptoms & error messages (verbatim)", "changes": "7. Recent environment changes",
           "checked": "8. Troubleshooting performed", "kb": "9. Related KB / TechDocs", "attach": "10. Attachments & logs", "requests": "11. Requests",
           "contact": "12. Contact", "timeline": "Appendix A. Timeline", "logs": "Appendix B. Log excerpt", "portal": "Portal fields",
           "first": "First occurrence", "last": "Last occurrence", "detected": "Detected", "ongoing": "Current state", "yes_ongoing": "Ongoing",
           "resolved": "Resolved (watching for recurrence)", "tz": "Time zone", "none": "None", "share": "Shared link", "generated": "Generated",
           "greet": "Hello,\nWe would like to request technical support for the issue below. The detailed report and logs are attached.",
           "bye": "Thank you for your help.\nBest regards,", "req_default": ["Root cause analysis and a resolution (or workaround)",
                                                                             "Let us know any additional logs or command output you need",
                                                                             "Confirm known issues / patches for this version"],
           "title_sev": "Severity", "vendor": "Submit to", "sr": "SR", "status": "Status", "case": "Case number", "role_main": "Primary", "role_rel": "Related",
           "rca": "Root cause analysis (AI-assisted, needs verification)", "conf": "Confidence", "files": "Files", "rows": "rows"},
}


def _now_tz() -> str:
    return datetime.now().astimezone().strftime("%Z (UTC%z)")


def _clip(s: Any, n: int) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _uniq(xs, key=lambda x: x):
    seen, out = set(), []
    for x in xs:
        k = key(x)
        if k and k not in seen:
            seen.add(k)
            out.append(x)
    return out


class SupportManager:
    def __init__(self, engine, cfg: dict | None = None):
        self.e = engine
        self.cfg = cfg or {}
        self._schema = False
        self._seq_day, self._seq = "", 0

    def _ensure(self) -> None:
        if not self._schema:
            self.e.store.schema(SCHEMA)
            self._schema = True

    # ------------------------------------------------------------------ 기본 정보(연락처·계정 ID)
    PROFILE_DEFAULT = {"company": "", "contact_name": "", "contact_email": "", "contact_phone": "", "secondary_contact": "",
                       "availability": "평일 09:00–18:00(KST), P1 은 24x7", "to": "", "cc": "", "broadcom_site_id": "",
                       "aws_account_id": "", "azure_subscription": "", "default_vendor": "broadcom", "default_lang": "both", "share_days": 7}

    async def profile(self) -> dict[str, Any]:
        self._ensure()
        r = await self.e.store.q1("SELECT v FROM support_profile WHERE k='profile'")
        return {**self.PROFILE_DEFAULT, **(json.loads(r["v"]) if r and r.get("v") else {})}

    async def save_profile(self, p: dict) -> dict[str, Any]:
        self._ensure()
        cur = await self.profile()
        for k, d in self.PROFILE_DEFAULT.items():
            if k in p:
                v = p[k]
                cur[k] = max(1, min(int(v), 90)) if k == "share_days" else _clip(v, 300)
        if cur["default_vendor"] not in VENDORS:
            cur["default_vendor"] = "broadcom"
        if cur["default_lang"] not in LANGS:
            cur["default_lang"] = "both"
        await self.e.store.x("INSERT INTO support_profile(k,v) VALUES('profile',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (json.dumps(cur, ensure_ascii=False),))
        return cur

    # ------------------------------------------------------------------ 저장
    async def _next_id(self) -> str:
        day = datetime.now().strftime("%Y%m%d")
        if day != self._seq_day:
            row = await self.e.store.q1("SELECT COUNT(*) AS n FROM support_requests WHERE id LIKE ?", (f"SR-{day}-%",))
            self._seq_day, self._seq = day, int((row or {}).get("n") or 0)
        self._seq += 1
        return f"SR-{day}-{self._seq:03d}"

    async def get(self, sr_id: str) -> dict | None:
        self._ensure()
        r = await self.e.store.q1("SELECT * FROM support_requests WHERE id=?", (sr_id,))
        if not r:
            return None
        r["data"] = json.loads(r["data"] or "{}")
        return r

    async def _save(self, r: dict) -> None:
        d = r["data"]
        await self.e.store.x("INSERT INTO support_requests(id,created,updated,created_by,status,vendor,lang,title,severity,source_kind,source_ref,case_no,data) "
                             "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated, status=excluded.status, vendor=excluded.vendor, "
                             "lang=excluded.lang, title=excluded.title, severity=excluded.severity, case_no=excluded.case_no, data=excluded.data",
                             (r["id"], r["created"], r["updated"], r["created_by"], r["status"], d["vendor"], d["lang"], d["title"], d["severity"],
                              d["source"]["kind"], d["source"].get("ref", ""), d.get("case_no", ""), json.dumps(d, ensure_ascii=False, default=str)))

    async def list(self, status: str = "", q: str = "", limit: int = 300) -> list[dict]:
        self._ensure()
        sql, p = "SELECT id,created,updated,created_by,status,vendor,lang,title,severity,source_kind,source_ref,case_no FROM support_requests WHERE 1=1", []
        if status:
            sql += " AND status=?"
            p.append(status)
        if q:
            sql += " AND (title LIKE ? OR id LIKE ? OR case_no LIKE ? OR source_ref LIKE ?)"
            p += [f"%{q}%"] * 4
        sql += " ORDER BY updated DESC LIMIT ?"
        p.append(max(1, min(limit, 2000)))
        return await self.e.store.q(sql, p)

    async def delete(self, sr_id: str) -> bool:
        self._ensure()
        if not await self.e.store.q1("SELECT id FROM support_requests WHERE id=?", (sr_id,)):   # x() 는 lastrowid 라 삭제 건수로 못 씀
            return False
        await self.e.store.x("DELETE FROM support_requests WHERE id=?", (sr_id,))
        await self.e.store.x("UPDATE support_shares SET revoked=1 WHERE sr_id=?", (sr_id,))
        return True

    # ------------------------------------------------------------------ 생성
    async def create(self, src: dict, user: dict, opts: dict | None = None) -> dict:
        self._ensure()
        o = opts or {}
        prof = await self.profile()
        vendor = o.get("vendor") if o.get("vendor") in VENDORS else prof["default_vendor"]
        lang = o.get("lang") if o.get("lang") in LANGS else prof["default_lang"]
        data = await self.collect(src)
        data.update(vendor=vendor, lang=lang, created_by=user.get("user", ""), case_no="")
        if o.get("severity") in (1, 2, 3, 4, "1", "2", "3", "4"):
            data["severity"] = int(o["severity"])
        if o.get("title"):
            data["title"] = _clip(o["title"], 200)
        for k in ("impact", "summary", "description"):
            if o.get(k):
                data["impact" if k == "impact" else "summary"] = str(o[k])[:4000]
        data["contact"] = {"name": prof["contact_name"] or user.get("display") or user.get("user", ""), "email": prof["contact_email"] or user.get("email", ""),
                           "phone": prof["contact_phone"], "secondary": prof["secondary_contact"], "availability": prof["availability"],
                           "company": prof["company"], "tz": _now_tz()}
        data["email"] = {"to": prof["to"], "cc": prof["cc"]}
        data["vendor_fields"] = self.default_fields(data, vendor, prof)
        data["requests"] = list(L["en" if lang == "en" else "ko"]["req_default"])
        data["requests_en"] = list(L["en"]["req_default"]) if lang != "ko" else []
        if data["requests_en"]:
            data["en_src"] = {"requests": "\n".join(data["requests"])}
        now = time.time()
        r = {"id": await self._next_id(), "created": now, "updated": now, "created_by": user.get("user", ""), "status": "draft", "data": data}
        if lang != "ko" and getattr(self.e, "llm", None) and o.get("translate", True) is not False and self.en_pending(data):
            try:                                            # 영문 병기 — 사람이 쓴 한국어(제목·기록 등)를 AI 로 번역(가명화), 실패해도 초안은 만든다
                import asyncio
                await asyncio.wait_for(self.translate(r, save=False), 90)
            except Exception as e:  # noqa: BLE001
                data["translate_error"] = f"{type(e).__name__}: {e}"[:200]
        await self._save(r)
        return r

    def default_fields(self, d: dict, vendor: str, prof: dict) -> dict[str, str]:
        v = VENDORS[vendor]
        env = d.get("environment") or []
        prod = d.get("product") or ""
        ver = next((x["value"] for x in env if x.get("product") == prod), "") or (env[0]["value"] if env else "")
        sev = v["sev"][d["severity"]]
        vals = {"product": prod, "version": ver, "priority": sev[1], "severity": sev[1], "business_impact": _clip(d.get("impact"), 300),
                "production_down": "Yes" if d["severity"] == 1 else "No", "site_id": prof.get("broadcom_site_id", ""),
                "account_id": prof.get("aws_account_id", ""), "subscription": prof.get("azure_subscription", ""),
                "service": prod, "resource": ", ".join(o["name"] for o in (d.get("objects") or [])[:3]), "category": d.get("category", ""),
                "problem_type": d.get("category", "")}
        return {k: (vals.get(k) if vals.get(k) not in (None, "") else dflt) for k, _lab, dflt in v["fields"]}

    async def update(self, sr_id: str, patch: dict, user: dict) -> dict:
        r = await self.get(sr_id)
        if not r:
            raise KeyError(sr_id)
        d = r["data"]
        if patch.get("vendor") in VENDORS and patch["vendor"] != d["vendor"]:
            d["vendor"] = patch["vendor"]
            d["vendor_fields"] = self.default_fields(d, d["vendor"], await self.profile())
        if patch.get("lang") in LANGS:
            d["lang"] = patch["lang"]
        if str(patch.get("severity", "")) in ("1", "2", "3", "4"):
            d["severity"] = int(patch["severity"])
            vf = d.get("vendor_fields") or {}
            lab = VENDORS[d["vendor"]]["sev"][d["severity"]][1]
            for k in ("priority", "severity"):
                if k in vf:
                    vf[k] = lab
            if "production_down" in vf:
                vf["production_down"] = "Yes" if d["severity"] == 1 else "No"
        old_imp = d.get("impact") or ""
        for k, n in (("title", 200), ("summary", 6000), ("impact", 3000), ("case_no", 80), ("notes", 6000)):
            if k in patch:
                d[k] = str(patch[k] or "")[:n]
        for k, n in (("title_en", 240), ("summary_en", 8000), ("impact_en", 4000)):      # 영문을 실제로 고쳤을 때만 '이 한국어 기준'으로 기록
            if k in patch and str(patch[k] or "")[:n] != str(d.get(k) or ""):
                d[k] = str(patch[k] or "")[:n]
                d.setdefault("en_src", {})[k[:-3]] = d.get(k[:-3], "")
        for k in ("requests", "checked_extra"):
            if isinstance(patch.get(k), list):
                d[k] = [str(x)[:600] for x in patch[k] if str(x).strip()][:30]
        if isinstance(patch.get("requests_en"), list):
            nv = [str(x)[:600] for x in patch["requests_en"] if str(x).strip()][:30]
            if nv != (d.get("requests_en") or []):
                d["requests_en"] = nv
                d.setdefault("en_src", {})["requests"] = "\n".join(d.get("requests") or [])
        if isinstance(patch.get("vendor_fields"), dict):
            d.setdefault("vendor_fields", {}).update({str(k)[:40]: str(v)[:500] for k, v in patch["vendor_fields"].items()})
        vf = d.setdefault("vendor_fields", {})
        if "impact" in patch and "business_impact" in vf and vf.get("business_impact", "") in ("", _clip(old_imp, 300)):
            vf["business_impact"] = _clip(d.get("impact"), 300)          # 포털 Business Impact 를 직접 고치지 않았으면 함께 갱신
        if isinstance(patch.get("email"), dict):
            d.setdefault("email", {}).update({k: str(patch["email"].get(k, ""))[:500] for k in ("to", "cc", "subject") if k in patch["email"]})
        if isinstance(patch.get("contact"), dict):
            d.setdefault("contact", {}).update({k: str(v)[:300] for k, v in patch["contact"].items() if k in ("name", "email", "phone", "secondary", "availability", "company")})
        if patch.get("status") in STATUSES:
            r["status"] = patch["status"]
        d.setdefault("history", []).append({"ts": time.time(), "user": user.get("user", ""), "fields": sorted(k for k in patch)[:20]})
        d["history"] = d["history"][-50:]
        r["updated"] = time.time()
        await self._save(r)
        return r

    async def refresh(self, sr_id: str) -> dict:
        """근거 다시 모으기(사용자가 고친 제목·요약·영향·요청·포털 값은 유지)"""
        r = await self.get(sr_id)
        if not r:
            raise KeyError(sr_id)
        d = r["data"]
        keep = {k: d.get(k) for k in ("vendor", "lang", "title", "summary", "impact", "severity", "requests", "checked_extra", "vendor_fields",
                                      "email", "contact", "case_no", "notes", "history", "created_by", "refined",
                                      "title_en", "summary_en", "impact_en", "requests_en", "en_src", "tr")}
        nd = await self.collect(d["source"])
        tr_new = nd.get("tr") or {}
        nd.update({k: v for k, v in keep.items() if v is not None})
        nd["tr"] = {**tr_new, **(keep.get("tr") or {})}
        r["data"], r["updated"] = nd, time.time()
        await self._save(r)
        return r

    # ------------------------------------------------------------------ 근거 수집
    async def collect(self, src: dict) -> dict[str, Any]:
        kind = (src or {}).get("kind", "manual")
        fn = {"incident": self._from_incident, "anomaly": self._from_anomaly, "vks": self._from_vks, "host": self._from_entity,
              "vm": self._from_entity, "entity": self._from_entity, "readiness": self._from_readiness}.get(kind, self._from_manual)
        d = await fn(src)
        tr = d.setdefault("tr", {})
        oc = d.get("occurred") or {}
        if d.get("impact") and d["impact"] == _impact_text(d["severity"], d.get("objects") or [], oc.get("ongoing", True)):
            tr[d["impact"]] = _impact_en(d["severity"], d.get("objects") or [], oc.get("ongoing", True))
        for c in d.get("checked") or []:                     # 'AI RCA 수행 — <원인>' 처럼 앞부분만 정해진 문장
            if c.get("en_prefix") and not c.get("text_en") and not has_ko(c.get("en_body", "")):
                c["text_en"] = c["en_prefix"] + c["en_body"]
        d["source"] = {k: src.get(k) for k in ("kind", "ref", "connector", "okind", "ns", "obj", "name", "since", "until", "hosts") if src.get(k) not in (None, "")}
        d["source"]["kind"] = kind
        d.setdefault("objects", [])
        d["objects"] = _uniq(d["objects"], key=lambda o: (o.get("kind"), o.get("name")))[:60]
        d["environment"] = d.get("environment") or self._environment([o["name"] for o in d["objects"]], d.get("sources") or [])
        d.setdefault("kb", [])
        if not d["kb"]:
            d["kb"] = await self._kb(d)
        d["kb"] = d["kb"][:10]
        d.setdefault("checked", [])
        d.setdefault("changes", [])
        d.setdefault("timeline", [])
        d.setdefault("logs_excerpt", [])
        d["timeline"] = sorted(d["timeline"], key=lambda x: x.get("ts") or 0)[-150:]
        d["product"] = d.get("product") or self._product(d.get("sources") or [], d["objects"])
        d["log_stats"] = await self._log_stats(d.get("log_query") or {})
        d["collected"] = time.time()
        d["aiops_version"] = _version()
        return d

    def _product(self, sources: list[str], objects: list[dict]) -> str:
        for s in sources:
            if s in PRODUCT_OF:
                return PRODUCT_OF[s]
        kinds = {o.get("kind") for o in objects}
        if kinds & {"host", "esxi"}:
            return PRODUCT_OF["esxi"]
        if kinds & {"Deployment", "StatefulSet", "Pod", "Service", "Node", "PersistentVolumeClaim"}:
            return PRODUCT_OF["vks"]
        if "vm" in kinds:
            return PRODUCT_OF["vcenter"]
        return "VMware Cloud Foundation"

    def _environment(self, names: list[str], sources: list[str]) -> list[dict]:
        out = []
        short = {n.split(".")[0].lower() for n in names if n}
        for c in getattr(self.e, "connectors", []):
            t = getattr(c, "type", "")
            if t == "vcenter":
                ab = getattr(c, "about", {}) or {}
                if ab.get("version"):
                    out.append({"label": f"vCenter ({c.host})", "product": PRODUCT_OF["vcenter"],
                                "value": f"{ab.get('product', 'vCenter Server')} {ab.get('version')} build {ab.get('build', '')}".strip()})
                snap = (getattr(c, "health_snap", {}) or {}).get("hosts", {})
                topo = getattr(c, "topology", {}) or {}
                for hn, h in snap.items():
                    vms_here = {v for v, vv in (topo.get("vms") or {}).items() if vv.get("host") == hn and v.split(".")[0].lower() in short}
                    if hn.split(".")[0].lower() in short or vms_here:
                        hw = " · ".join(x for x in (h.get("vendor", ""), h.get("model", ""), (f"BIOS {h['bios']}" if h.get("bios") else "")) if x)
                        out.append({"label": f"ESXi {hn}", "product": PRODUCT_OF["esxi"],
                                    "value": f"ESXi {h.get('version', '')} build {h.get('build', '')}".strip() + (f" — {hw}" if hw else "")})
            elif t in ("vks", "kubernetes"):
                ver = str(((getattr(c, "_state", {}) or {}).get("checks") or {}).get("version", "")).replace("ok ", "")
                if ver and ("vks" in sources or c.name in names or getattr(c, "cluster_label", "") in names):
                    out.append({"label": f"Kubernetes {getattr(c, 'cluster_label', c.name)}", "product": PRODUCT_OF["vks"], "value": ver})
        return _uniq(out, key=lambda x: x["label"])[:20]

    async def _kb(self, d: dict) -> list[dict]:
        rag = getattr(self.e, "rag", None)
        if not rag or not getattr(rag, "has_any", lambda: False)():
            return []
        q = " ".join([d.get("title", "")] + [s for s in (d.get("symptoms") or [])[:3]])
        names = [o["name"] for o in d.get("objects") or []]
        for n in names:                                    # 개체 이름은 검색어에서 뺌(엉뚱한 문서 방지)
            if n and len(n) > 2:
                q = q.replace(n, " ")
        q = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", " ", q)
        try:
            hits = await rag.search(_clip(q, 600), source=(d.get("sources") or [None])[0], k=8, intent="rca")
        except Exception:  # noqa: BLE001
            return []
        return [{"kb": h.get("kb", ""), "title": h.get("title", ""), "url": h.get("url", ""), "type": h.get("type", ""),
                 "versions": h.get("versions", "")} for h in hits if h.get("title")]

    async def _log_stats(self, lq: dict) -> dict:
        if not lq:
            return {}
        try:
            from .logexport import count
            q = self._lq(lq)
            n = await count(self.e.store, q)
            return {"rows": n, "since": q.since, "until": q.until}
        except Exception:  # noqa: BLE001
            return {}

    @staticmethod
    def _lq(lq: dict) -> LogQuery:
        return LogQuery(lq.get("since") or time.time() - 3600, lq.get("until") or time.time(), sources=lq.get("sources"), connectors=lq.get("connectors"),
                        hosts=lq.get("hosts"), entities=lq.get("entities"), min_severity=lq.get("min_severity", "debug"), max_rows=lq.get("max_rows", 200_000))

    async def _excerpt(self, lq: dict, limit: int = 60) -> list[dict]:
        q = self._lq(lq)
        where, p = q.where()
        rows = await self.e.store.q(f"SELECT ts,severity,source,host,entity,message FROM logs{where} ORDER BY "
                                    "CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, ts DESC LIMIT ?", [*p, limit])
        for r in rows:
            r["message"] = _clip(mask_log(r["message"]), 500)
        return sorted(rows, key=lambda r: r["ts"])

    # 출발점별 -----------------------------------------------------------
    async def _from_incident(self, src: dict) -> dict:
        inc_mgr = self.e.incidents
        inc = await inc_mgr.get(src.get("ref", ""))
        if not inc:
            raise LookupError(f"인시던트 없음: {src.get('ref')}")
        b = await inc_mgr.build_bundle(inc)
        notes = await inc_mgr.notes(inc["id"])
        an = b.get("anomalies") or []
        first = min([a["time"] for a in an] + [inc["created"]])
        last = max([a["time"] for a in an] + [inc.get("last_anomaly") or inc["created"]])
        ongoing = inc.get("status") not in ("resolved", "closed")
        hosts = [h for h in inc.get("hosts") or [] if h]
        ents = _uniq([a.get("entity") for a in an if a.get("entity")])
        objs = ([{"kind": (b.get("topology_context") or {}).get("kind", "entity"), "name": inc.get("primary_entity"), "role": "main",
                  "detail": inc.get("cluster") or ""}] if inc.get("primary_entity") else [])
        objs += [{"kind": "host", "name": h, "role": "related", "detail": ""} for h in hosts]
        objs += [{"kind": "entity", "name": x, "role": "related", "detail": ""} for x in ents[:20]]
        checked = []
        for n in notes:
            k, t = n.get("kind", ""), _clip(n.get("text"), 400)
            if k in ("comment", "status", "action", "assign", "rca", "itsm", "note", "ack"):
                checked.append({"ts": n.get("ts"), "who": n.get("user", ""), "text": f"[{k}] {t}" if t else f"[{k}]"})
        checked.append({"ts": time.time(), "who": "VCF AIOps", "text": f"묶인 이상징후 {inc.get('anomaly_count') or len(an)}건·관련 로그 {len(b.get('log_timeline') or [])}건 검토",
                        "text_en": f"Reviewed {inc.get('anomaly_count') or len(an)} grouped anomalies and {len(b.get('log_timeline') or [])} related log lines"})
        if b.get("investigation") and not (b["investigation"] or {}).get("error"):
            inv = b["investigation"]
            checked.append({"ts": time.time(), "who": "VCF AIOps", "text": f"vCenter 조사: 알람 {len(inv.get('alarms') or [])}건·이벤트 {len(inv.get('timeline') or [])}건 확인",
                            "text_en": f"vCenter investigation: {len(inv.get('alarms') or [])} alarms and {len(inv.get('timeline') or [])} events reviewed"})
        rca = inc.get("rca") or None
        if isinstance(rca, dict) and rca.get("root_cause"):
            checked.append({"ts": rca.get("_ts") or time.time(), "who": "AI RCA", "text": "근본원인 분석 수행 — " + _clip(rca.get("root_cause"), 300),
                            "en_prefix": "Root cause analysis performed — ", "en_body": _clip(rca.get("root_cause"), 300)})
        tl = [{"ts": a["time"], "source": a["source"], "text": f"[{a['severity']}] {a.get('host') or ''} {_clip(a['message'], 240)}"} for a in an]
        tl += [{"ts": n.get("ts"), "source": "incident", "text": f"{n.get('kind')}: {_clip(n.get('text'), 200)}"} for n in notes]
        changes = [{"text": x} for x in (b.get("vm_changes") or [])[:20]]
        symptoms = _uniq([_clip(a["message"], 400) for a in an if a.get("severity") in ("critical", "error", "warning")] or [_clip(a["message"], 400) for a in an])[:8]
        lq = {"since": first - 1800, "until": (time.time() if ongoing else last + 1800), "hosts": hosts + ents[:30]}
        logs = [{**r, "message": _clip(mask_log(r["message"]), 500)} for r in (b.get("log_timeline") or [])][-60:] or await self._excerpt(lq)
        kb = [{"kb": k.get("kb", ""), "title": k.get("title", ""), "url": k.get("url", ""), "type": k.get("type", ""), "versions": k.get("applies_to") or ""}
              for k in b.get("knowledge") or []]
        sev = SEV_OF.get(inc.get("severity"), 3)
        return {"title": inc["title"], "severity": sev, "category": inc.get("category", ""), "sources": inc.get("sources") or [],
                "summary": inc.get("summary") or (symptoms[0] if symptoms else inc["title"]),
                "impact": _impact_text(sev, objs, ongoing), "occurred": {"first": first, "last": last, "detected": inc["created"], "ongoing": ongoing},
                "objects": objs, "symptoms": symptoms, "timeline": tl, "changes": changes, "checked": checked, "kb": kb, "logs_excerpt": logs,
                "rca": _rca_brief(rca), "log_query": lq, "links": {"incident": inc_mgr.link(inc["id"])}}

    async def _from_anomaly(self, src: dict) -> dict:
        a = self.e.anomalies.get(src.get("ref", ""))
        if not a:
            raise LookupError(f"이상징후 없음: {src.get('ref')}")
        ev = a.event
        ts = ev.get("ts") or a.created
        hosts = _uniq([ev.get("host"), ev.get("entity")])
        objs = [{"kind": "entity", "name": ev.get("entity") or ev.get("host"), "role": "main", "detail": ev.get("source", "")}]
        if ev.get("host") and ev.get("host") != ev.get("entity"):
            objs.append({"kind": "host", "name": ev["host"], "role": "related", "detail": ""})
        lq = {"since": ts - 1800, "until": max(a.last_seen, ts) + 900, "hosts": hosts}
        checked = [{"ts": a.created, "who": "VCF AIOps", "text": f"탐지 근거: {', '.join(a.reasons[:4])} · 재발 {a.count}회",
                    "text_en": f"Detection basis: {', '.join(a.reasons[:4])} · recurred {a.count} time(s)"}]
        if a.ai:
            checked.append({"ts": a.created, "who": "AI", "text": _clip(" — ".join(x for x in (a.ai.get("summary"), a.ai.get("probable_cause")) if x), 500)})
        kb = [{"kb": r.get("kb", ""), "title": r.get("title", ""), "url": r.get("url", ""), "type": r.get("type", "")} for r in (a.refs or []) + (a.related or []) if r.get("title")]
        sev = SEV_OF.get(a.severity, 3)
        return {"title": a.ai.get("title") or a.title, "severity": sev, "category": a.category, "sources": [ev.get("source", "")],
                "summary": _clip(a.ai.get("summary") or ev.get("message"), 1200), "impact": _impact_text(sev, objs, True),
                "occurred": {"first": ts, "last": a.last_seen, "detected": a.created, "ongoing": not a.ack},
                "objects": objs, "symptoms": [_clip(mask_log(ev.get("message", "")), 600)],
                "timeline": [{"ts": ts, "source": ev.get("source", ""), "text": _clip(ev.get("message"), 240)}],
                "checked": checked, "kb": _uniq(kb, key=lambda x: x.get("url") or x.get("title")), "logs_excerpt": await self._excerpt(lq), "log_query": lq,
                "changes": await self._vm_changes(objs, ts)}

    async def _vm_changes(self, objs: list[dict], ts: float) -> list[dict]:
        mv = getattr(self.e, "moves", None)
        if not mv:
            return []
        try:
            names = [o["name"] for o in objs if o.get("name")]
            rows = await mv.related(names, names, (), ts - 6 * 3600, ts + 60, 20)
            return [{"text": x} for x in mv.brief(rows)]
        except Exception:  # noqa: BLE001
            return []

    async def _from_vks(self, src: dict) -> dict:
        name, kind, ns, obj = src.get("connector", ""), src.get("okind", ""), src.get("ns", ""), src.get("obj", "")
        d = await self.e.vksobs.detail(name, kind, ns, obj, hours=24)
        n = d["node"]
        issues = [i["text"] for i in n.get("issues") or []]
        bad = [p for p in d["pods"] if p.get("st") in ("down", "warn")]
        objs = [{"kind": kind, "name": f"{ns}/{obj}" if ns else obj, "role": "main", "detail": f"{d['cluster']} · {n.get('status')}"}]
        objs += [{"kind": "Pod", "name": f"{p.get('ns') or ns}/{p['name']}", "role": "related",
                  "detail": f"{p.get('phase')} {p.get('reason') or ''} · 재시작 {p.get('restarts')} · {p.get('node') or ''}".strip()} for p in bad[:15]]
        objs += [{"kind": "Node", "name": i["node"], "role": "related", "detail": f"VM {i.get('vm_power') or '-'} → ESXi {i.get('esxi') or '-'}"} for i in d["infra"][:8]]
        objs += [{"kind": "host", "name": i["esxi"], "role": "related", "detail": i.get("vsphere_cluster", "")} for i in d["infra"] if i.get("esxi")]
        warn_ev = [e for e in d["events"] if e.get("type") == "Warning"]
        symptoms = _uniq(issues + [f"[{e['reason']}] {e['kind']} {e['name']}: {_clip(e['message'], 300)} (x{e.get('count', 1)})" for e in warn_ev[:6]]
                         + [f"Pod {p['name']}: {p['msg']}" for p in bad if p.get("msg")][:3]
                         + [f"Pod {p['name']}: 직전 종료 {p['last_term']['reason']} (exit {p['last_term'].get('exit')})" for p in bad if (p.get("last_term") or {}).get("reason")][:3])[:12]
        tl = [{"ts": e["ts"], "source": "k8s-event", "text": f"{e['type']} {e['reason']} {e['kind']}/{e['name']}: {_clip(e['message'], 200)}"} for e in d["events"][:60]]
        tl += [{"ts": r["ts"], "source": "vks-activity", "text": f"{r['label']}: {_clip(r['detail'], 200)}"} for r in d["activity"][:60]]
        cut = time.time() - 24 * 3600                       # 최초 발생 = 경고 이벤트 첫 관측 · 이상 진입·재시작 기록 중 가장 이른 것(24시간 안)
        marks = [e.get("first") or e["ts"] for e in warn_ev if (e.get("first") or e["ts"] or 0) >= cut] + \
                [r["ts"] for r in d["activity"] if r["action"] in ("pod_bad", "restart", "rollout", "node") and r["ts"] >= cut]
        first = min(marks) if marks else (min([x["ts"] for x in tl if x.get("ts") and x["ts"] >= cut] or [time.time()]))
        esx = ', '.join(sorted({i['esxi'] for i in d['infra'] if i.get('esxi')}))
        checked = [{"ts": time.time(), "who": "VCF AIOps", "text": t, "text_en": te} for t, te in (
            (f"Kubernetes 이벤트 조회 {len(d['events'])}건(경고 {len(warn_ev)}건, Normal 포함)", f"Queried {len(d['events'])} Kubernetes events ({len(warn_ev)} warnings, Normal included)"),
            (f"관련 파드 {len(d['pods'])}개 상태 확인 — 이상 {len(bad)}개", f"Checked the state of {len(d['pods'])} related pods — {len(bad)} unhealthy"),
            (f"변경 이력(롤아웃·스케일·재시작·파드 교체) 7일 검토 — {len(d['activity'])}건", f"Reviewed 7-day change history (rollouts, scaling, restarts, pod replacement) — {len(d['activity'])} entries"),
            (f"노드 → vSphere VM → ESXi 확인 — {esx or '매칭 없음'}", f"Checked node → vSphere VM → ESXi placement — {esx or 'no match'}"),
            (f"AIOps 수집 경고 {len(d['stored_events'])}건·파드 로그 {len(d['logs'])}줄 검토", f"Reviewed {len(d['stored_events'])} warnings and {len(d['logs'])} pod log lines collected by AIOps"))]
        pod_logs = await self._capture_pod_logs(name, bad[:5], ns)
        if pod_logs:
            checked.append({"ts": time.time(), "who": "VCF AIOps", "text": f"문제 파드 로그 수집(현재·이전 컨테이너) {len(pod_logs)}개 파일 — 첨부 묶음 pod-logs/",
                            "text_en": f"Captured logs of unhealthy pods (current and previous containers) — {len(pod_logs)} files in pod-logs/ of the bundle"})
        ents = [f"{kind}/{ns}/{obj}" if ns else f"{kind}/{obj}"] + [f"Pod/{p.get('ns') or ns}/{p['name']}" for p in d["pods"][:300]]
        lq = {"since": time.time() - 24 * 3600, "until": time.time(), "connectors": [name], "entities": ents,
              "hosts": [i["node"] for i in d["infra"]][:12]}
        logs = [{"ts": r["ts"], "severity": r["severity"], "source": "vks", "host": r["host"], "entity": r["entity"], "message": _clip(r["message"], 500)}
                for r in (d["stored_events"] + d["logs"])][:80]
        sev = 2 if n.get("own") == "down" or n.get("status") == "down" else 3
        return {"title": f"VKS {d['cluster']} {kind} {ns + '/' if ns else ''}{obj} — {issues[0] if issues else n.get('status')}",
                "severity": sev, "category": "Kubernetes", "sources": ["vks"], "summary": "; ".join(issues) or "문제 없음",
                "impact": _impact_text(sev, objs, True), "occurred": {"first": first, "last": time.time(), "detected": first, "ongoing": n.get("status") != "ok"},
                "objects": objs, "symptoms": symptoms, "timeline": tl,
                "changes": [{"text": f"{fmt_ts(r['ts'])} {r['label']} — {_clip(r['detail'], 200)}", "text_en": f"{fmt_ts(r['ts'])} {act_en(r['label'])} — {rule_en(_clip(r['detail'], 200))}"}
                            for r in d["activity"] if r["action"] in ("rollout", "scale", "hpa", "created", "deleted", "network", "storage")][:20],
                "checked": checked, "logs_excerpt": sorted(logs, key=lambda r: r["ts"]), "log_query": lq,
                "incidents": [{"id": i["id"], "title": i.get("title", ""), "status": i.get("status", "")} for i in d["incidents"][:10]],
                "attach_files": pod_logs}

    async def _capture_pod_logs(self, name: str, pods: list[dict], ns: str) -> dict[str, str]:
        c = next((x for x in getattr(self.e, "connectors", []) if x.name == name), None)
        if not c or not hasattr(c, "pod_log"):
            return {}
        import asyncio
        out, total = {}, 0
        for p in pods:
            for cn in (p.get("containers") or [""])[:3]:
                for prev in ((True, False) if p.get("restarts") else (False,)):
                    try:
                        lines = await asyncio.wait_for(c.pod_log(p.get("ns") or ns, p["name"], cn, tail=1000, previous=prev), 15)
                    except Exception as e:  # noqa: BLE001
                        lines = [f"(로그 조회 실패: {type(e).__name__}: {str(e)[:200]})"]
                    txt = "\n".join(mask_log(x) for x in lines) + "\n"
                    total += len(txt)
                    if total > 3_000_000:
                        return out
                    out[f"pod-logs/{p.get('ns') or ns}/{p['name']}/{cn or 'default'}{'.previous' if prev else ''}.log"] = txt
        return out

    async def _from_entity(self, src: dict) -> dict:
        nm = (src.get("name") or src.get("ref") or "").strip()
        if not nm:
            raise LookupError("대상 이름 필요")
        ctx = self.e.resolve(nm) or {}
        hours = max(1, min(int(src.get("hours") or 6), 168))
        until = float(src.get("until") or time.time())
        since = float(src.get("since") or until - hours * 3600)
        lq = {"since": since, "until": until, "hosts": [nm] + ([ctx["host"]] if ctx.get("host") and ctx.get("host") != nm else [])}
        logs = await self._excerpt(lq, 80)
        objs = [{"kind": ctx.get("kind", src.get("kind", "entity")), "name": ctx.get("name") or nm, "role": "main", "detail": ctx.get("cluster", "")}]
        if ctx.get("host") and ctx.get("host") != nm:
            objs.append({"kind": "host", "name": ctx["host"], "role": "related", "detail": ctx.get("cluster", "")})
        checked = [{"ts": time.time(), "who": "VCF AIOps", "text": f"{fmt_ts(since)} ~ {fmt_ts(until)} 로그 검토", "text_en": f"Reviewed logs {fmt_ts(since)} ~ {fmt_ts(until)}"}]
        tl, symptoms = [], []
        if ctx.get("kind") in ("vm", "host", "datastore", "cluster"):
            try:
                inv = await self.e.investigate(ctx["kind"], ctx["name"], hours=hours)
                if not inv.get("error"):
                    tl = [{"ts": x.get("ts"), "source": "vcenter", "text": _clip(x.get("msg") or x.get("message") or x.get("text"), 240)} for x in (inv.get("timeline") or [])[:80]]
                    symptoms += [_clip(f"알람 {x.get('name') or x.get('alarm')}: {x.get('status') or x.get('state') or ''}", 300) for x in (inv.get("alarms") or [])[:5]]
                    checked.append({"ts": time.time(), "who": "VCF AIOps", "text": f"vCenter 조사: 알람 {len(inv.get('alarms') or [])}건·이벤트 {len(inv.get('timeline') or [])}건",
                                    "text_en": f"vCenter investigation: {len(inv.get('alarms') or [])} alarms, {len(inv.get('timeline') or [])} events"})
            except Exception:  # noqa: BLE001
                pass
        symptoms += _uniq([r["message"] for r in logs if r["severity"] in ("critical", "error")])[:6]
        worst = min([SEV_OF.get(r["severity"], 4) for r in logs] + [4])
        sev = max(2, worst)
        return {"title": src.get("title") or f"{nm} — {symptoms[0][:80] if symptoms else '점검 요청'}", "severity": sev, "category": ctx.get("kind", ""),
                "sources": _uniq([r["source"] for r in logs]), "summary": src.get("description") or (symptoms[0] if symptoms else ""),
                "impact": _impact_text(sev, objs, True), "occurred": {"first": logs[0]["ts"] if logs else since, "last": logs[-1]["ts"] if logs else until,
                                                                     "detected": since, "ongoing": True},
                "objects": objs, "symptoms": symptoms, "timeline": tl, "checked": checked, "logs_excerpt": logs, "log_query": lq,
                "changes": await self._vm_changes(objs, until)}

    async def _from_readiness(self, src: dict) -> dict:
        """2.14.0 하드웨어 준비도 스캔 결과(ref='<scan_id>|<target>') → 서버 하드웨어 SR — 실패 점검·SEL·펌웨어·ESXi 연결"""
        sid, _, target = str(src.get("ref") or "").partition("|")
        R = getattr(self.e, "readiness", None)
        h = await R.host(sid, target) if R and sid and target else None
        if not h or not h.get("ok"):
            raise LookupError("준비도 스캔 결과 없음")
        res, host = h["result"], h["host"]
        sm, sysd = res["summary"], host.get("system") or {}
        esx = (h.get("esxi") or {}).get("esxi") or ""
        name = esx or h.get("label") or target
        fails = [c for c in res["checks"] if c["status"] == "fail"]
        warns = [c for c in res["checks"] if c["status"] == "warn"]
        sel = [e for e in host.get("sel") or [] if e.get("severity") in ("critical", "warning")][:20]
        crit = any(e["severity"] == "critical" for e in sel) or any(c["id"] in ("psu", "mem.health") or c["id"].startswith("drv.health") for c in fails)
        sev = int(src.get("severity") or (2 if crit else 3))
        top = (fails or warns or [{"title": "하드웨어 점검", "detail": ""}])[0]
        bmc = f"{sm.get('bmc_model') or 'BMC'} {sm.get('bmc_fw') or ''}".strip()
        env = [{"label": "서버", "product": "", "value": f"{sm.get('vendor', '')} {sm.get('model', '')} (S/N {sm.get('serial', '')})".strip()},
               {"label": "BIOS", "product": "", "value": str(sm.get("bios") or "")}, {"label": "BMC", "product": "", "value": bmc},
               {"label": "CPU", "product": "", "value": f"{sm['cpu'].get('model', '')} × {sm['cpu'].get('sockets', '')}"}]
        env += [{"label": f"펌웨어 {f['name']}"[:60], "product": "", "value": f["version"]} for f in (host.get("firmware") or [])[:8]]
        objs = [{"kind": "host", "name": name, "role": "main", "detail": f"{sm.get('model', '')} · BMC {target.replace('connector:', '')}"}]
        if esx and h.get("label") and h["label"] != esx:
            objs.append({"kind": "bmc", "name": h["label"], "role": "related", "detail": bmc})
        until = time.time()
        lq = {"since": until - 24 * 3600, "until": until, "hosts": [x for x in (esx, h.get("label")) if x]}
        logs = await self._excerpt(lq, 60)
        checked = [{"ts": h["ts"], "who": "VCF AIOps", "text": f"하드웨어 준비도 스캔(Redfish 읽기 전용) {sid} — 판정 {res['verdict_label']}, 실패 {len(fails)}·주의 {len(warns)}",
                    "text_en": f"Hardware readiness scan (read-only Redfish) {sid} — verdict {res['verdict']}, {len(fails)} failed, {len(warns)} warnings"}]
        checked += [{"ts": h["ts"], "who": "VCF AIOps", "text": f"[{c['area']}] {c['title']}: {c['detail']}"[:300]} for c in (fails + warns)[:10]]
        tl = [{"ts": _iso_ts(e.get("ts")), "source": "bmc", "text": _clip(f"{e['severity'].upper()} {e.get('message_id', '')} {e['message']}", 240)} for e in sel]
        return {"title": src.get("title") or f"{name} 하드웨어 — {top['title']}" + (f": {_clip(top['detail'], 80)}" if top.get("detail") else ""), "severity": sev,
                "category": "hardware", "sources": ["redfish"] + _uniq([r["source"] for r in logs]),
                "summary": src.get("description") or "; ".join(f"{c['title']} — {c['detail']}" for c in fails[:4]) or top["title"],
                "impact": _impact_text(sev, objs, True), "occurred": {"first": min([x["ts"] for x in tl if x["ts"]] or [h["ts"]]), "last": h["ts"], "detected": h["ts"], "ongoing": True},
                "objects": objs, "symptoms": [_clip(f"{c['title']}: {c['detail']}", 300) for c in fails[:6]] + [_clip(e["message"], 300) for e in sel[:4]],
                "timeline": tl, "checked": checked, "logs_excerpt": logs, "log_query": lq, "environment": env, "changes": []}

    async def _from_manual(self, src: dict) -> dict:
        hosts = [h.strip() for h in (src.get("hosts") or []) if str(h).strip()][:30]
        until = float(src.get("until") or time.time())
        since = float(src.get("since") or until - 6 * 3600)
        lq = {"since": since, "until": until, "hosts": hosts} if hosts else {}
        logs = await self._excerpt(lq, 60) if hosts else []
        objs = [{"kind": "host", "name": h, "role": "main" if i == 0 else "related", "detail": ""} for i, h in enumerate(hosts)]
        sev = int(src.get("severity") or 3) if str(src.get("severity") or "3") in "1234" else 3
        return {"title": _clip(src.get("title") or "지원 요청", 200), "severity": sev, "category": "", "sources": _uniq([r["source"] for r in logs]),
                "summary": str(src.get("description") or "")[:6000], "impact": _impact_text(sev, objs, True),
                "occurred": {"first": since, "last": until, "detected": since, "ongoing": True}, "objects": objs,
                "symptoms": _uniq([r["message"] for r in logs if r["severity"] in ("critical", "error")])[:6], "timeline": [],
                "checked": ([{"ts": time.time(), "who": "VCF AIOps", "text": f"{', '.join(hosts)} 로그 검토 ({fmt_ts(since)[:16]} ~ {fmt_ts(until)[:16]}) — 오류 {sum(1 for r in logs if r['severity'] in ('critical', 'error'))}건·경고 {sum(1 for r in logs if r['severity'] == 'warning')}건",
                              "text_en": f"Reviewed logs of {', '.join(hosts)} ({fmt_ts(since)[:16]} ~ {fmt_ts(until)[:16]}) — {sum(1 for r in logs if r['severity'] in ('critical', 'error'))} errors, {sum(1 for r in logs if r['severity'] == 'warning')} warnings"}] if hosts else []),
                "logs_excerpt": logs, "log_query": lq, "changes": await self._vm_changes(objs, until) if objs else []}

    # ------------------------------------------------------------------ 출력 — 공통 문서 모델(한국어·영어·병기)
    def langs(self, r: dict) -> list[str]:
        lg = r["data"].get("lang", "both")
        return ["ko", "en"] if lg == "both" else [lg if lg in L else "ko"]

    def en(self, d: dict, s: Any, field: str = "") -> str:
        """영문: 직접 입력 영문 필드 > AI 번역 캐시 > 규칙 영문화 > '(KO) 원문'"""
        if field and str(d.get(field + "_en") or "").strip():
            return str(d[field + "_en"])
        s = str(s or "")
        if not has_ko(s):
            return s
        t = (d.get("tr") or {}).get(s)
        if t:
            return t
        t = rule_en(s)
        return t if not has_ko(t) else f"(KO) {s}"

    def en_pending(self, d: dict) -> list[str]:
        """영문 미번역(규칙·번역·직접 입력 모두 없음) 문구"""
        out = []
        for s in self._ko_strings(d):
            if s not in (d.get("tr") or {}) and has_ko(rule_en(s)):
                out.append(s)
        return out

    def _ko_strings(self, d: dict) -> list[str]:
        xs: list[str] = []
        for f in ("title", "summary", "impact"):
            if not str(d.get(f + "_en") or "").strip():
                xs.append(str(d.get(f) or ""))
        if not d.get("requests_en"):
            xs += [str(x) for x in d.get("requests") or []]
        xs += [c.get("text", "") for c in d.get("checked") or [] if not c.get("text_en")] + list(d.get("checked_extra") or [])
        xs += list(d.get("symptoms") or []) + [c.get("text", "") for c in d.get("changes") or [] if not c.get("text_en")]
        xs += [o.get("detail", "") for o in d.get("objects") or []] + [str((d.get("contact") or {}).get("availability") or "")]
        xs += [str((d.get("vendor_fields") or {}).get(k) or "") for k in (d.get("vendor_fields") or {})]
        if d.get("rca"):
            xs.append(str(d["rca"].get("cause") or ""))
        return [x for x in dict.fromkeys(xs) if x and has_ko(x)][:300]

    def model(self, r: dict) -> dict[str, Any]:
        """언어 쌍(ko, en)으로 된 보고서 구조 — 이메일·HTML·PDF 가 같은 모델을 그린다"""
        d = r["data"]
        v = VENDORS.get(d.get("vendor"), VENDORS["generic"])
        sev = v["sev"].get(int(d.get("severity") or 3))
        o = d.get("occurred") or {}
        E = lambda s, f="": (str(s or ""), self.en(d, s, f))   # noqa: E731
        K, N = L["ko"], L["en"]
        role = lambda ob: (K["role_main"], N["role_main"]) if ob.get("role") == "main" else (K["role_rel"], N["role_rel"])  # noqa: E731
        vf = d.get("vendor_fields") or {}
        reqs_en = d.get("requests_en") or [self.en(d, q) for q in d.get("requests") or []]
        chk = [(f"{fmt_ts(c.get('ts'))[:16]} {c.get('who', '')} — {c.get('text', '')}", f"{fmt_ts(c.get('ts'))[:16]} {c.get('who', '')} — {c.get('text_en') or self.en(d, c.get('text', ''))}")
               for c in d.get("checked") or []] + [E(c) for c in d.get("checked_extra") or []]
        if d.get("rca"):
            cause = d["rca"].get("cause", "")
            chk.append((f"{K['rca']}: {cause} ({K['conf']} {d['rca'].get('confidence', '-')})", f"{N['rca']}: {self.en(d, cause)} ({N['conf']} {d['rca'].get('confidence', '-')})"))
        ls = d.get("log_stats") or {}
        c = d.get("contact") or {}
        cont = [(x, x) for x in (c.get("company"), c.get("name"), c.get("email"), c.get("phone"), (f"2nd: {c['secondary']}" if c.get("secondary") else "")) if x]
        if c.get("availability"):
            cont.append(E(c["availability"]))
        tz = c.get("tz") or _now_tz()
        sec = [
            ("portal", "kv", [((lab, lab), ((vf.get(k) or "-"), _clip(self.en(d, d.get("impact"), "impact"), 300))
                               if k == "business_impact" and vf.get(k) and vf.get(k) == _clip(d.get("impact"), 300) else E(vf.get(k) or "-")) for k, lab, _ in v["fields"]], [(n, ne) for n, ne in zip(v["notes"], v.get("notes_en") or v["notes"])]),
            ("summary", "text", E(d.get("summary") or d.get("title", ""), "summary")),
            ("impact", "text", ((f"{K['title_sev']}: {sev[1]} — {sev[2]}\n" + str(d.get("impact") or "")),
                                (f"{N['title_sev']}: {sev[1]} — {sev[3] if len(sev) > 3 else sev[2]}\n" + self.en(d, d.get("impact") or "", "impact")))),
            ("when", "kv", [((K["first"], N["first"]), (fmt_ts(o.get("first")),) * 2), ((K["last"], N["last"]), (fmt_ts(o.get("last")),) * 2),
                            ((K["detected"], N["detected"]), (fmt_ts(o.get("detected")),) * 2),
                            ((K["ongoing"], N["ongoing"]), (K["yes_ongoing"], N["yes_ongoing"]) if o.get("ongoing") else (K["resolved"], N["resolved"])),
                            ((K["tz"], N["tz"]), (tz, tz))]),
            ("env", "kv", [((e["label"], e["label"]), (e["value"], e["value"])) for e in d.get("environment") or []] + [(("VCF AIOps",) * 2, (d.get("aiops_version", ""),) * 2)]),
            ("objects", "list", [(f"[{role(ob)[0]}] {ob.get('kind', '')} {ob['name']}" + (f" — {ob['detail']}" if ob.get("detail") else ""),
                                  f"[{role(ob)[1]}] {ob.get('kind', '')} {ob['name']}" + (f" — {self.en(d, ob['detail'])}" if ob.get("detail") else "")) for ob in (d.get("objects") or [])[:40]]),
            ("symptoms", "list", [E(s) for s in d.get("symptoms") or []]),
            ("changes", "list", [(ch.get("text", ""), ch.get("text_en") or self.en(d, ch.get("text", ""))) for ch in (d.get("changes") or [])[:20]]),
            ("checked", "list", chk),
            ("kb", "list", [((f"KB {k['kb']} " if k.get("kb") else "") + k["title"] + (f" <{k['url']}>" if k.get("url") else ""),) * 2 for k in d.get("kb") or []]),
            ("attach", "list", [(f"report-{r['id']}.pdf",) * 2,
                                (f"logs-{r['id']}.zip ({ls.get('rows', 0):,} {K['rows']}, {fmt_ts(ls.get('since'))[:16]} ~ {fmt_ts(ls.get('until'))[:16]})",
                                 f"logs-{r['id']}.zip ({ls.get('rows', 0):,} {N['rows']}, {fmt_ts(ls.get('since'))[:16]} ~ {fmt_ts(ls.get('until'))[:16]})")]
             + [(k, k) for k in list((d.get("attach_files") or {}).keys())[:12]]),
            ("requests", "olist", list(zip([str(q) for q in d.get("requests") or []], reqs_en)) if len(reqs_en) == len(d.get("requests") or []) else
             [(q, q2) for q, q2 in zip((d.get("requests") or []) + [""] * 10, reqs_en + [""] * 10) if q or q2]),
            ("contact", "list", cont),
        ]
        return {"vendor": v, "sev": sev, "title": E(d.get("title", ""), "title"), "sections": sec,
                "timeline": [(x.get("ts"), x.get("source", ""), x.get("text", ""), self.en(d, x.get("text", ""))) for x in d.get("timeline") or []],
                "logs": d.get("logs_excerpt") or []}

    # ------------------------------------------------------------------ 출력 — 이메일
    def view(self, r: dict) -> dict[str, Any]:
        d = r["data"]
        lang = d.get("lang", "both")
        v = VENDORS.get(d.get("vendor"), VENDORS["generic"])
        sev = v["sev"].get(int(d.get("severity") or 3))
        return {"id": r["id"], "status": r.get("status", "draft"), "lang": lang, "t": L["ko" if lang != "en" else "en"], "vendor": v, "vendor_id": d.get("vendor"), "sev": sev,
                "severity": int(d.get("severity") or 3), "d": d}

    def subject(self, r: dict) -> str:
        x = self.view(r)
        d = x["d"]
        if (d.get("email") or {}).get("subject"):
            return d["email"]["subject"]
        when = fmt_ts((d.get("occurred") or {}).get("first") or r["created"])[:16]
        main = next((o["name"] for o in d.get("objects") or [] if o.get("role") == "main"), "")
        prod = d.get("product") or ""
        langs = self.langs(r)
        ko, en = d.get("title", ""), self.en(d, d.get("title", ""), "title")
        title = ko if langs == ["ko"] else en if langs == ["en"] else (ko if ko == en or en.startswith("(KO) ") else f"{ko} / {en}")
        return _clip(f"[{x['sev'][0]}] {prod} — {title}{(' / ' + main) if main and main not in title else ''} ({when})", 240)

    def _text_block(self, r: dict, m: dict, lg: str, share_url: str) -> str:
        t = L[lg]
        i = 0 if lg == "ko" else 1
        lines = [t["greet"], ""]
        for key, kind, body, *rest in m["sections"]:
            head = t["portal"] + " — " + m["vendor"]["label"] if key == "portal" else t[key]
            lines.append(f"■ {head}")
            if kind == "text":
                lines.append(_indent(body[i]))
            elif kind == "kv":
                lines += [f"  - {lab[i]}: {val[i] or '-'}" for lab, val in body]
                if key == "env" and not body:
                    lines.append(f"  - {t['none']}")
            elif kind == "olist":
                lines += [f"  {n}. {q[i]}" for n, q in enumerate(body, 1)] or [f"  - {t['none']}"]
            else:
                items = [it[i] for it in body]
                if key == "attach" and share_url:
                    items.append(f"{t['share']}: {share_url}")
                lines += [f"  - {it}" for it in items] or [f"  - {t['none']}"]
            lines.append("")
        d = r["data"]
        if d.get("notes"):
            lines += [_indent(d["notes"] if lg == "ko" else self.en(d, d["notes"])), ""]
        lines += [t["bye"], (d.get("contact") or {}).get("name", "")]
        return "\n".join(lines)

    def email_text(self, r: dict, share_url: str = "") -> str:
        m = self.model(r)
        langs = self.langs(r)
        if langs == ["ko", "en"]:
            return (self._text_block(r, m, "ko", share_url) + "\n\n" + "=" * 24 + " English " + "=" * 24 + "\n\n" + self._text_block(r, m, "en", share_url))
        return self._text_block(r, m, langs[0], share_url)

    def eml(self, r: dict, pdf: bytes | None, logs_zip: bytes | None, share_url: str = "") -> bytes:
        """Outlook 에서 '보내지 않은 초안'으로 열리는 .eml(X-Unsent: 1) — PDF·로그(10MB 이하) 첨부"""
        d = r["data"]
        m = EmailMessage()
        m["Subject"] = self.subject(r)
        if (d.get("email") or {}).get("to"):
            m["To"] = d["email"]["to"]
        if (d.get("email") or {}).get("cc"):
            m["Cc"] = d["email"]["cc"]
        if (d.get("contact") or {}).get("email"):
            m["From"] = d["contact"]["email"]
        m["Date"] = formatdate(localtime=True)
        m["Message-ID"] = make_msgid(domain="vcf-aiops.local")
        m["X-Unsent"] = "1"
        m.set_content(self.email_text(r, share_url))
        if pdf:
            m.add_attachment(pdf, maintype="application", subtype="pdf", filename=f"report-{r['id']}.pdf")
        if logs_zip and len(logs_zip) <= 10 * 2**20:
            m.add_attachment(logs_zip, maintype="application", subtype="zip", filename=f"logs-{r['id']}.zip")
        return bytes(m)

    @staticmethod
    def _heads(key: str, langs: list[str], vendor_label: str) -> str:
        if key == "portal":
            hs = [L[lg]["portal"] for lg in langs]
            return " · ".join(dict.fromkeys(hs)) + " — " + vendor_label
        hs = [L[lg][key] for lg in langs]
        if len(hs) == 1:
            return hs[0]
        return hs[0] + " · " + re.sub(r"^[0-9A-Z]+\. ", "", hs[1])

    # ------------------------------------------------------------------ 출력 — HTML 보고서
    def html(self, r: dict, links: dict[str, str] | None = None, shared: bool = False) -> str:
        m = self.model(r)
        d = r["data"]
        langs = self.langs(r)
        bi = langs == ["ko", "en"]
        idx = [0, 1] if bi else [0 if langs[0] == "ko" else 1]
        t = L[langs[0]]
        v, sev = m["vendor"], m["sev"]
        o = d.get("occurred") or {}
        links = links or {}
        e = escape

        def pair(p, cls=""):
            a = e(p[idx[0]])
            if bi and p[1] and p[1] != p[0]:
                return f"{a}<div class='en{(' ' + cls) if cls else ''}'>{e(p[1])}</div>"
            return a

        def lab(p):
            return e(p[idx[0]]) if not bi or p[0] == p[1] else f"{e(p[0])} <span class='enl'>/ {e(p[1])}</span>"
        body = []
        for key, kind, items, *rest in m["sections"]:
            h = self._heads(key, langs, v["label"])
            if kind == "text":
                inner = "".join(f'<div class="box{" enbox" if i == 1 and bi else ""}">{"<span class=tag>EN</span>" if i == 1 and bi else ""}{e(items[i])}</div>' for i in idx)
            elif kind == "kv":
                inner = "<table>" + "".join(f"<tr><th>{lab(k)}</th><td>{pair(val)}</td></tr>" for k, val in items) + "</table>"
                if rest and rest[0]:
                    inner += "<ul class='muted'>" + "".join(f"<li>{pair(n)}</li>" for n in rest[0]) + "</ul>"
            elif kind == "olist":
                inner = "<ol>" + "".join(f"<li>{pair(q)}</li>" for q in items) + "</ol>" if items else f"<p class='muted'>{e(t['none'])}</p>"
            else:
                its = [pair(it) for it in items]
                if key == "attach":
                    its = []
                    if links.get("pdf"):
                        its.append(f'<a href="{e(links["pdf"])}">report-{e(r["id"])}.pdf</a>')
                    ls = d.get("log_stats") or {}
                    if links.get("logs"):
                        its.append(f'<a href="{e(links["logs"])}">logs-{e(r["id"])}.zip</a> <span class="muted">— {ls.get("rows", 0):,} rows · {e(fmt_ts(ls.get("since"))[:16])} ~ {e(fmt_ts(ls.get("until"))[:16])} · secrets masked</span>')
                    elif not shared:
                        its.append(f'logs-{e(r["id"])}.zip <span class="muted">({ls.get("rows", 0):,} rows)</span>')
                    its += [e(k) for k in list((d.get("attach_files") or {}).keys())[:20]]
                    if links.get("share"):
                        its.append(f'<a href="{e(links["share"])}">{e(links["share"])}</a>')
                if key == "kb":
                    its = [(f"<b>KB {e(k['kb'])}</b> " if k.get("kb") else "") + (f'<a href="{e(k["url"])}" rel="noopener noreferrer" target="_blank">{e(k["title"])}</a>' if k.get("url") else e(k["title"]))
                           + (f" <span class='muted'>{e(k.get('type', ''))}</span>" if k.get("type") else "") for k in d.get("kb") or []]
                cls = " class='mono'" if key == "symptoms" else ""
                inner = "<ul>" + "".join(f"<li{cls}>{x}</li>" for x in its) + "</ul>" if its else f"<p class='muted'>{e(t['none'])}</p>"
            body.append(f"<section><h2>{e(h)}</h2>{inner}</section>")
        tl = "".join(f"<tr><td class='nw'>{e(fmt_ts(ts)[:19])}</td><td>{e(src)}</td><td>{pair((ko, en2))}</td></tr>" for ts, src, ko, en2 in m["timeline"])
        lg = "".join(f"<tr class='sv-{e(x2.get('severity', ''))}'><td class='nw'>{e(fmt_ts(x2.get('ts'))[:19])}</td><td>{e(x2.get('severity', ''))}</td><td>{e(x2.get('host') or '')}</td><td class='msg'>{e(x2.get('message', ''))}</td></tr>"
                     for x2 in m["logs"])
        if tl:
            body.append(f"<section><h2>{e(self._heads('timeline', langs, ''))}</h2><table class='grid'>{tl}</table></section>")
        if lg:
            body.append(f"<section><h2>{e(self._heads('logs', langs, ''))}</h2><table class='grid'>{lg}</table></section>")
        sevc = {1: "#c21d00", 2: "#e8730c", 3: "#e0a800", 4: "#62a420"}[int(d.get("severity") or 3)]
        sdesc = pair((sev[2], sev[3] if len(sev) > 3 else sev[2]))
        st_l = (STATUSES.get(r.get("status", "draft"), ""), STATUS_EN.get(r.get("status", "draft"), ""))
        meta = [f"{e(t['sr'])} <b>{e(r['id'])}</b>", f"{lab((L['ko']['vendor'], L['en']['vendor']))}: {e(v['label'])}", f"{lab((L['ko']['status'], L['en']['status']))}: {e(st_l[idx[0]])}{(' / ' + e(st_l[1])) if bi else ''}"]
        if d.get("case_no"):
            meta.append(f"{lab((L['ko']['case'], L['en']['case']))}: <b>{e(d['case_no'])}</b>")
        meta.append(f"{lab((L['ko']['generated'], L['en']['generated']))}: {e(fmt_ts(time.time())[:16])}")
        title = m["title"]
        return f"""<!doctype html><html lang="{'ko' if idx[0] == 0 else 'en'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><title>{e(r['id'])} — {e(title[idx[0]])}</title>
<style>
:root{{--line:#d8dee4;--muted:#5a6b78;--ink:#1b2a35;--bg:#fff;--soft:#f5f7f9;--en:#2f5d8a}}
@media (prefers-color-scheme:dark){{:root{{--line:#33414d;--muted:#9aa8b4;--ink:#e6edf3;--bg:#11181f;--soft:#18222b;--en:#8cb8e6}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 "Noto Sans KR","Malgun Gothic",system-ui,sans-serif}}
main{{max-width:980px;margin:0 auto;padding:24px 16px 60px}}h1{{font-size:21px;margin:6px 0 2px}}h1 .en{{font-size:16px;font-weight:600}}h2{{font-size:15.5px;border-bottom:2px solid var(--line);padding-bottom:4px;margin:26px 0 8px}}
.meta{{display:flex;flex-wrap:wrap;gap:6px 14px;color:var(--muted);font-size:12.5px}}.pill{{display:inline-block;color:#fff;border-radius:10px;padding:1px 10px;font-weight:700;font-size:12px;background:{sevc}}}
table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}}th{{width:30%;color:var(--muted);font-weight:600}}
.grid th{{width:auto}}.muted{{color:var(--muted)}}.nw{{white-space:nowrap}}.msg,.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all}}
.en{{color:var(--en);font-size:.95em;margin-top:2px}}.enl{{color:var(--en);font-weight:500}}.tag{{display:inline-block;font:700 10px sans-serif;color:#fff;background:var(--en);border-radius:3px;padding:0 5px;margin-right:6px;vertical-align:2px}}
.sv-error td,.sv-critical td{{background:rgba(194,29,0,.06)}}.sv-warning td{{background:rgba(224,168,0,.08)}}ul,ol{{padding-left:20px;margin:6px 0}}li{{margin-bottom:3px}}
.box{{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:10px 14px;white-space:pre-wrap;margin-bottom:6px}}.enbox{{border-left:3px solid var(--en)}}a{{color:#0072a3}}
.bar{{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}}.bar a{{border:1px solid #0072a3;border-radius:4px;padding:4px 12px;text-decoration:none;font-weight:600}}
footer{{margin-top:30px;color:var(--muted);font-size:12px}}@media print{{.bar{{display:none}}main{{max-width:none}}a{{color:inherit}}}}
</style></head><body><main>
<div class="meta">{"".join(f"<span>{x}</span>" for x in meta)}</div>
<h1>{pair(title)}</h1><div><span class="pill">{e(sev[1])}</span> <span class="muted">{sdesc}</span></div>
<div class="bar">{"".join(f'<a href="{e(u)}">{e(lb)}</a>' for lb, u in (("PDF", links.get("pdf")), ("Logs (.zip)", links.get("logs"))) if u)}</div>
{"".join(body)}
<footer>VCF AIOps {e(d.get('aiops_version', ''))} · {e(r['id'])} · 비밀번호·토큰 등 비밀값 패턴은 가려져 있습니다 / secret-like values are masked.</footer>
</main></body></html>"""

    # ------------------------------------------------------------------ 출력 — PDF(한글 글꼴 내장)
    def pdf(self, r: dict, share_url: str = "") -> bytes:
        from fpdf import FPDF
        from fpdf.enums import XPos, YPos
        m = self.model(r)
        d = r["data"]
        langs = self.langs(r)
        bi = langs == ["ko", "en"]
        idx = [0, 1] if bi else [0 if langs[0] == "ko" else 1]
        t = L[langs[0]]
        v, sev = m["vendor"], m["sev"]
        sid = r["id"]

        class P(FPDF):
            def footer(self_):
                self_.set_y(-12)
                self_.set_font("kr", "", 7.5)
                self_.set_text_color(120, 130, 140)
                self_.cell(0, 6, f"VCF AIOps · {sid} · secrets masked · {self_.page_no()}/{{nb}}", align="C")
        pdf = P(format="A4")
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(True, 16)
        pdf.add_font("kr", "", str(FONT_DIR / "NotoSansKR-Regular-sub.otf"))
        pdf.add_font("kr", "B", str(FONT_DIR / "NotoSansKR-Bold-sub.otf"))
        pdf.set_margins(14, 14, 14)
        pdf.add_page()
        W = pdf.w - 28
        ink, enc, mute = (27, 42, 53), (47, 93, 138), (90, 107, 120)

        def mc(w, h, s, size, style="", color=ink):
            pdf.set_font("kr", style, size)
            pdf.set_text_color(*color)
            pdf.multi_cell(w, h, _pdf_safe(s) or "-", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        def h2(s):
            if pdf.get_y() > pdf.h - 40:
                pdf.add_page()
            pdf.ln(3)
            pdf.set_font("kr", "B", 11.5)
            pdf.set_text_color(*ink)
            pdf.multi_cell(W, 6.5, _pdf_safe(s), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
            pdf.set_draw_color(200, 208, 215)
            pdf.line(14, pdf.get_y(), 14 + W, pdf.get_y())
            pdf.ln(1.5)

        def bullets(items, size=9.2, ordered=False):
            if not items:
                mc(W, 5, t["none"], size, color=mute)
                return
            for n, it in enumerate(items, 1):
                pre = f"{n}. " if ordered else ""
                pdf.set_font("kr", "", size)
                pdf.set_text_color(*ink)
                pdf.cell(4, 5, "" if ordered else "•")
                pdf.multi_cell(W - 4, 5, _pdf_safe(pre + it[idx[0]]), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
                if bi and it[1] and it[1] != it[0]:
                    pdf.set_x(18)
                    pdf.set_font("kr", "", size - 0.4)
                    pdf.set_text_color(*enc)
                    pdf.multi_cell(W - 4, 4.8, _pdf_safe(("    " if ordered else "") + it[1]), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")

        def kv(rows, w1=58, size=9.2):
            for k, val in rows:
                kl = k[idx[0]] if not bi or k[0] == k[1] else f"{k[0]} / {k[1]}"
                pdf.set_font("kr", "B", size)
                pdf.set_text_color(*mute)
                y0 = pdf.get_y()
                pdf.multi_cell(w1, 5, _pdf_safe(kl), new_x=XPos.RIGHT, new_y=YPos.TOP, align="L")
                y1 = pdf.get_y()
                pdf.set_xy(14 + w1, y0)
                pdf.set_font("kr", "", size)
                pdf.set_text_color(*ink)
                pdf.multi_cell(W - w1, 5, _pdf_safe(val[idx[0]]) or "-", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
                if bi and val[1] and val[1] != val[0]:
                    pdf.set_x(14 + w1)
                    pdf.set_text_color(*enc)
                    pdf.multi_cell(W - w1, 5, _pdf_safe(val[1]), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="L")
                pdf.set_y(max(pdf.get_y(), y1 if y1 > y0 else pdf.get_y()))

        st_l = (STATUSES.get(r.get("status", "draft"), ""), STATUS_EN.get(r.get("status", "draft"), ""))
        meta = f"SR {sid} · {v['label']} · {st_l[idx[0]]}{(' / ' + st_l[1]) if bi else ''}" + (f" · Case {d['case_no']}" if d.get("case_no") else "") + f" · {fmt_ts(time.time())[:16]}"
        mc(W, 4.5, meta, 8.5, color=mute)
        mc(W, 8, m["title"][idx[0]], 16, "B")
        if bi and m["title"][1] != m["title"][0]:
            mc(W, 6.5, m["title"][1], 12.5, "B", enc)
        sc = {1: (194, 29, 0), 2: (232, 115, 12), 3: (190, 140, 0), 4: (98, 164, 32)}[int(d.get("severity") or 3)]
        mc(W, 6, f"{sev[1]} — {sev[2]}", 10, "B", sc)
        if bi and len(sev) > 3:
            mc(W, 5, sev[3], 9, "", enc)
        for key, kind, items, *rest in m["sections"]:
            h2(self._heads(key, langs, v["label"]))
            if kind == "text":
                for i in idx:
                    if i == 1 and bi:
                        pdf.ln(1)
                        mc(W, 4.5, "EN", 7.5, "B", enc)
                    mc(W, 5, items[i], 9.5, color=enc if (i == 1 and bi) else ink)
            elif kind == "kv":
                kv(items)
                if rest and rest[0]:
                    bullets(rest[0], 8.6)
            elif kind == "olist":
                bullets(items, ordered=True)
            else:
                its = list(items)
                if key == "attach" and share_url:
                    its.append((f"{L['ko']['share']}: {share_url}", f"{L['en']['share']}: {share_url}"))
                bullets(its, 8.8 if key in ("symptoms", "kb") else 9.2)
        if m["timeline"]:
            h2(self._heads("timeline", langs, ""))
            for ts, src, ko, en2 in m["timeline"][-80:]:
                mc(W, 4.4, f"{fmt_ts(ts)[:19]}  [{src}]  {ko if idx[0] == 0 else en2}", 8.2)
                if bi and en2 != ko:
                    mc(W, 4.4, f"                         {en2}", 8.0, color=enc)
        if m["logs"]:
            h2(self._heads("logs", langs, ""))
            for lg in m["logs"][-80:]:
                col = (160, 25, 0) if lg.get("severity") in ("error", "critical") else (140, 100, 0) if lg.get("severity") == "warning" else ink
                mc(W, 4.4, f"{fmt_ts(lg.get('ts'))[:19]}  {str(lg.get('severity', '')).upper()}  {lg.get('host') or ''}  {lg.get('message', '')}", 7.8, color=col)
        return bytes(pdf.output())

    # ------------------------------------------------------------------ 로그 묶음
    async def logs_zip(self, r: dict, with_report: bool = True, share_url: str = "") -> bytes:
        d = r["data"]
        lq = d.get("log_query") or {}
        q = self._lq(lq) if lq else LogQuery(time.time() - 60, time.time(), hosts=["__none__"])
        extra: dict[str, bytes | str] = {}
        extra.update(d.get("attach_files") or {})
        if with_report:
            extra[f"report-{r['id']}.html"] = self.html(r)
            try:
                import asyncio
                extra[f"report-{r['id']}.pdf"] = await asyncio.to_thread(self.pdf, r, share_url)
            except Exception as e:  # noqa: BLE001
                extra["report-pdf-error.txt"] = f"{type(e).__name__}: {e}"
            extra[f"email-{r['id']}.txt"] = f"Subject: {self.subject(r)}\n\n{self.email_text(r, share_url)}"
        extra["summary.json"] = json.dumps({k: d.get(k) for k in ("title", "severity", "vendor", "product", "occurred", "environment", "objects", "symptoms", "kb", "checked", "source")},
                                           ensure_ascii=False, indent=2, default=str)
        if d.get("timeline"):
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["time", "source", "text"])
            for it in d["timeline"]:
                w.writerow([fmt_ts(it.get("ts")), it.get("source", ""), it.get("text", "")])
            extra["timeline.csv"] = "﻿" + buf.getvalue()
        return await build_zip(self.e.store, q, extra, readme=f"{r['id']} — {d.get('title', '')}")

    # ------------------------------------------------------------------ AI 로 다듬기(선택)
    def _names(self, d: dict) -> list[str]:
        out = []
        for o in d.get("objects") or []:
            n = o.get("name") or ""
            if n:
                out += [n] + ([n.split("/")[-1]] if "/" in n else [])
        return out

    async def refine(self, r: dict) -> dict:
        llm = getattr(self.e, "llm", None)
        if not llm:
            raise RuntimeError("AI(LLM) 비활성 — 설정 › AI 에서 공급자를 켜세요")
        d = r["data"]
        lang = d.get("lang", "both")
        brief = {"title": d.get("title"), "product": d.get("product"), "severity": VENDORS[d["vendor"]]["sev"][d["severity"]][1],
                 "occurred": {k: fmt_ts(v) if isinstance(v, (int, float)) else v for k, v in (d.get("occurred") or {}).items()},
                 "objects": [f"{o.get('kind')} {o['name']} {o.get('detail', '')}" for o in (d.get("objects") or [])[:20]], "symptoms": (d.get("symptoms") or [])[:10],
                 "changes": [c["text"] for c in (d.get("changes") or [])[:10]], "checked": [c["text"] for c in (d.get("checked") or [])[:12]],
                 "rca": d.get("rca"), "environment": d.get("environment"), "kb": [f"{k.get('kb', '')} {k.get('title', '')}" for k in (d.get("kb") or [])[:6]]}
        keys = ([("title", "Korean"), ("summary", "Korean"), ("impact", "Korean"), ("requests", "Korean")] if lang != "en" else []) + \
               ([("title_en", "English"), ("summary_en", "English"), ("impact_en", "English"), ("requests_en", "English")] if lang != "ko" else [])
        sysmsg = ("You are a senior VMware/cloud support engineer writing a vendor support request. Using ONLY the facts given, return JSON with keys "
                  + ", ".join(f"'{k}' ({lg})" for k, lg in keys) + ". title: <=120 chars, specific (product, symptom, scope). summary: 3-6 sentences — what failed, since when, "
                  "scope, current state; separate observations from hypotheses. impact: 2-3 sentences on business/service impact consistent with the severity. "
                  "requests: list of 3-5 concrete asks to the vendor. Korean text keeps product names, error messages and commands in English. "
                  "Korean and English versions must say the same thing. Do not invent versions, KB numbers, commands or facts.")
        txt = await llm.complete(sysmsg, json.dumps(brief, ensure_ascii=False, default=str), max_tokens=2000, task="report", names=self._names(d))
        m = re.search(r"\{.*\}", txt, re.S)
        if not m:
            raise RuntimeError("AI 응답 형식 오류")
        j = json.loads(m.group(0))
        out: dict[str, Any] = {}
        for k, _lg in keys:
            v = j.get(k)
            if k.startswith("requests") and isinstance(v, list):
                out[k] = [str(x)[:400] for x in v if str(x).strip()][:6]
            elif isinstance(v, str) and v.strip():
                out[k] = v.strip()
        out["refined"] = {"ts": time.time(), "provider": "llm"}
        return out

    async def translate(self, r: dict, save: bool = True, stale: bool = False) -> dict:
        """영문 병기 — 한국어로만 있는 문구(사람이 쓴 제목·요약·기록, 규칙으로 못 바꾼 문장)를 AI 로 번역(가명화) → data['tr'] 캐시·영문 필드"""
        llm = getattr(self.e, "llm", None)
        if not llm:
            raise RuntimeError("AI(LLM) 비활성 — 설정 › AI 에서 공급자를 켜거나 영문 칸에 직접 입력하세요")
        d = r["data"]
        if stale:
            for f in self.en_stale(d):
                d.pop(f + "_en", None)
                if f == "requests":
                    d.pop("requests_en", None)
        items = self.en_pending(d)[:240]
        n = 0
        sysmsg = ("Translate each Korean string into natural, concise technical English for a VMware/cloud vendor support case. Keep product names, "
                  "Kubernetes/vSphere terms, error messages, commands, numbers, timestamps, hostnames and tokens such as NAME_1, HOST_1, IP_1 exactly as they are. "
                  "Return JSON {\"items\": [...]} with exactly the same number of strings in the same order.")
        tr = d.setdefault("tr", {})
        for i in range(0, len(items), 40):
            chunk = items[i:i + 40]
            txt = await llm.complete(sysmsg, json.dumps({"items": chunk}, ensure_ascii=False), max_tokens=4000, task="report", names=self._names(d))
            m = re.search(r"\{.*\}", txt, re.S)
            outs = (json.loads(m.group(0)) if m else {}).get("items")
            if not isinstance(outs, list) or len(outs) != len(chunk):
                raise RuntimeError("번역 응답 형식 오류(개수 불일치)")
            for a, b2 in zip(chunk, outs):
                if isinstance(b2, str) and b2.strip() and not has_ko(b2):
                    tr[a] = b2.strip()[:4000]
                    n += 1
        for f in ("title", "summary", "impact"):
            if not str(d.get(f + "_en") or "").strip() and d.get(f) in tr:
                d[f + "_en"] = tr[d[f]]
                d.setdefault("en_src", {})[f] = d[f]
        if not d.get("requests_en") and d.get("requests") and all(q in tr or not has_ko(q) for q in d["requests"]):
            d["requests_en"] = [tr.get(q, q) for q in d["requests"]]
            d.setdefault("en_src", {})["requests"] = "\n".join(d["requests"])
        d["translated"] = {"ts": time.time(), "n": n}
        d.pop("translate_error", None)
        if save:
            r["updated"] = time.time()
            await self._save(r)
        return {"translated": n, "pending": len(self.en_pending(d))}

    def en_stale(self, d: dict) -> list[str]:
        """한국어를 고친 뒤 영문이 옛 내용인 필드"""
        src = d.get("en_src") or {}
        out = [f for f in ("title", "summary", "impact") if str(d.get(f + "_en") or "").strip() and f in src and src[f] != d.get(f)]
        if d.get("requests_en") and "requests" in src and src["requests"] != "\n".join(d.get("requests") or []):
            out.append("requests")
        return out

    # ------------------------------------------------------------------ 공유 링크
    async def share_create(self, sr_id: str, user: str, days: float = 7, require_login: bool = False, include_logs: bool = True) -> dict:
        self._ensure()
        tok = secrets.token_urlsafe(32)
        sid = secrets.token_hex(6)
        exp = time.time() + max(1, min(float(days or 7), 90)) * 86400
        await self.e.store.x("INSERT INTO support_shares(id,sr_id,token_hash,created,expires,created_by,require_login,include_logs) VALUES(?,?,?,?,?,?,?,?)",
                             (sid, sr_id, _h(tok), time.time(), exp, user, int(bool(require_login)), int(bool(include_logs))))
        return {"id": sid, "token": tok, "expires": exp, "require_login": bool(require_login), "include_logs": bool(include_logs)}

    async def shares(self, sr_id: str) -> list[dict]:
        self._ensure()
        return await self.e.store.q("SELECT id,created,expires,created_by,require_login,include_logs,revoked,opened,last_open FROM support_shares WHERE sr_id=? ORDER BY created DESC", (sr_id,))

    async def share_revoke(self, sr_id: str, sid: str) -> bool:
        self._ensure()
        return bool(await self.e.store.x("UPDATE support_shares SET revoked=1 WHERE sr_id=? AND id=?", (sr_id, sid)))

    async def share_resolve(self, token: str) -> tuple[dict, dict] | None:
        self._ensure()
        if not re.fullmatch(r"[A-Za-z0-9_-]{30,64}", token or ""):
            return None
        s = await self.e.store.q1("SELECT * FROM support_shares WHERE token_hash=?", (_h(token),))
        if not s or s["revoked"] or s["expires"] < time.time():
            return None
        r = await self.get(s["sr_id"])
        if not r:
            return None
        await self.e.store.x("UPDATE support_shares SET opened=opened+1, last_open=? WHERE id=?", (time.time(), s["id"]))
        return s, r


def _h(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def _indent(s: str) -> str:
    return "\n".join("  " + ln for ln in str(s or "").splitlines()) or "  -"


def _pdf_safe(s: Any) -> str:
    """글꼴에 없는 글자(이모지·한자 등)는 '?' 대신 원문 유지가 안 되므로 공백 대체 — 줄바꿈은 유지"""
    s = str(s or "")
    return re.sub(r"[^\x09\x0a\x20-\x7e\xa0-ſ -⁯←-⇿①-⓿─-➿　-〿㄰-㆏ᄀ-ᇿ가-힣＀-￯]", "·", s)


def _iso_ts(v) -> float | None:
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _impact_text(sev: int, objs: list[dict], ongoing: bool) -> str:
    main = next((o["name"] for o in objs if o.get("role") == "main"), objs[0]["name"] if objs else "")
    n = len(objs)
    base = {1: f"{main} 의 운영 서비스가 중단되었거나 대부분의 기능을 쓸 수 없습니다.",
            2: f"{main} 의 주요 기능이 심각하게 저하되어 제한적으로만 운영 중입니다.",
            3: f"{main} 에 부분적인 영향이 있으며 업무는 제한적으로 계속되고 있습니다.",
            4: f"{main} 관련 문의 — 현재 업무 영향은 없습니다."}[sev]
    return base + (f" 연관 개체 {n - 1}개." if n > 1 else "") + (" 현재도 지속 중입니다." if ongoing else " 현재는 해소된 상태로 재발 여부를 확인 중입니다.")


def _impact_en(sev: int, objs: list[dict], ongoing: bool) -> str:
    main = next((o["name"] for o in objs if o.get("role") == "main"), objs[0]["name"] if objs else "")
    n = len(objs)
    base = {1: f"Production service on {main} is down or most functionality is unavailable.",
            2: f"Major functionality of {main} is severely degraded; operating in a restricted manner.",
            3: f"Partial impact on {main}; business continues in a limited manner.",
            4: f"Question regarding {main} — no current business impact."}[sev]
    return base + (f" {n - 1} related object(s)." if n > 1 else "") + (" The issue is ongoing." if ongoing else " Currently resolved; monitoring for recurrence.")


def _rca_brief(rca: Any) -> dict | None:
    if not isinstance(rca, dict) or not (rca.get("root_cause") or rca.get("cause")):
        return None
    return {"cause": _clip(rca.get("root_cause") or rca.get("cause"), 600), "confidence": rca.get("confidence", ""),
            "chain": [_clip(x, 200) for x in (rca.get("causal_chain") or rca.get("chain") or [])[:6]] if isinstance(rca.get("causal_chain") or rca.get("chain"), list) else []}


def _version() -> str:
    try:
        return (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()
    except OSError:
        return ""
