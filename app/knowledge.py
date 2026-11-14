"""지식 라이브러리 — Broadcom KB · TechDocs 를 파싱한 Markdown 묶음을 색인해 AI 분석·질의·관제의 근거로 쓴다.

입력
  · 설정 knowledge.paths 의 폴더(24시간 수집기가 갱신하는 아카이브 · NFS/SMB 마운트) — 주기적 증분 색인(mtime·크기·해시)
  · 화면에서 올린 zip(md·markdown·txt) → data/knowledge/uploads/<이름>/ 에 풀어 같은 방식으로 색인
파싱(파일 형식이 조금씩 달라도 동작하게)
  · YAML front matter(title·url·kb/article_id·product·version(s)·updated …) 또는 본문 머리의 'Article ID:' 'URL:' 'Products:' 줄
  · 종류: KB(knowledge.broadcom.com · Article ID) / TechDocs(techdocs.broadcom.com · docs.vmware.com) / 일반 문서
  · 제품·버전: front matter → TechDocs URL 경로(…/vsphere/8-0/…) → 본문 키워드(ESXi 8.0 U3, NSX 4.2, VCF 9.0 …)
  · 구역: KB 표준 머리말(Symptoms·Cause·Resolution·Workaround·Environment·Additional Information)을 역할로 표준화,
          TechDocs 는 제목 계층(H1 › H2 › H3)을 경로(crumb)로 보존. 코드 블록(명령)은 자르지 않는다.
  · 식별자(KB 번호·CVE·VMSA·vob.*·esx.problem.*·이벤트 ID SE_DOWN·0x… 코드)는 별도 표로 정확 일치 검색
저장: SQLite(FTS5 BM25) + 선택적 임베딩 벡터(float16 파일, memmap) — 문서 수십만 건도 메모리에 다 올리지 않는다.
검색: BM25 · 식별자 일치 · Dense 를 RRF 로 합치고, 이벤트 소스↔제품, 운영 중인 버전, 의도별 구역(조치=Resolution/Workaround),
      운영자 피드백(도움됨/무관)으로 가중 → 문서 단위로 묶어 증상·원인·해결·우회 구역을 함께 붙여 돌려준다(부모 문서 확장).
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import zipfile
from pathlib import Path
from typing import Any

import numpy as np

from .rag.textutil import ID_PATTERNS, tokenize

KB_URL = "https://knowledge.broadcom.com/external/article/{id}"
MD_EXT = {".md", ".markdown", ".mdx", ".txt"}

# 이벤트 소스 → 관련 제품(검색 가중)
SOURCE_PRODUCTS = {
    "esxi": {"vsphere", "esxi", "vcenter", "vsan", "vcf"}, "vcenter": {"vsphere", "vcenter", "esxi", "vsan", "vcf"},
    "nsx": {"nsx", "vcf"}, "nsx-edge": {"nsx", "vcf"}, "avi": {"avi"}, "sddc": {"vcf"},
    "vcfops": {"vcfops", "vcf"}, "vcflogs": {"vcflogs", "vcf"}, "vcfa": {"vcfa", "vcf"}, "srm": {"srm"},
    "vks": {"vks", "vsphere", "vcf"}, "vks-supervisor": {"vks", "vsphere", "vcf"},
    "redfish": {"hardware", "vsphere"}, "ucs": {"hardware", "vsphere"}, "snmp": {"hardware", "vsphere"},
}
# 문서 제품 → 운영 버전 키(env_versions) — vSAN·VKS 는 vCenter/ESXi 버전을 따른다
DOC_ENV = {"vsphere": ("vsphere",), "esxi": ("esxi", "vsphere"), "vcenter": ("vcenter",), "vsan": ("vsphere",), "vks": ("vsphere",),
           "vcf": ("vcf",), "nsx": ("nsx",), "avi": ("avi",), "hardware": ("hardware",)}
# 제품 판별(제목·URL·본문 앞부분)
PRODUCT_RX = [
    ("avi", r"\bavi\b|advanced load balancer|nsx[- ]alb|service engine|load balancer"),
    ("nsx", r"\bnsx\b|nsx-t|edge node|tier-0|tier-1|transport node"),
    ("vsan", r"\bvsan\b"),
    ("vks", r"\bvks\b|tanzu|supervisor|kubernetes|tkg|vsphere pods?"),
    ("vcfops", r"aria operations(?! for logs)|vrealize operations|vcf operations(?! for logs)|\bvrops\b"),
    ("vcflogs", r"operations for logs|log insight|vrli"),
    ("vcfa", r"aria automation|vrealize automation|vcf automation|\bvra\b"),
    ("srm", r"site recovery|\bsrm\b|live site recovery|vsphere replication"),
    ("vcf", r"cloud foundation|\bvcf\b|sddc manager"),
    ("vcenter", r"vcenter"),
    ("esxi", r"\besxi?\b|vmkernel|hostd|vpxa|psod"),
    ("hardware", r"\bilo\b|idrac|redfish|\bucs\b|cimc|firmware|\bbmc\b"),
]
# 수집기 front matter 의 product 슬러그 → 검색용 제품(이벤트 소스와 연결)
SLUG_PRODUCT = {"vsphere": "vsphere", "vcf": "vcf", "nsx": "nsx", "vsan": "vsan", "hcx": "hcx", "tanzu": "vks", "live-recovery": "srm",
                "cloud-director": "vcd", "avi": "avi", "vdefend": "nsx", "aria": "vcfops", "usage-meter": "usage-meter",
                "private-ai": "private-ai", "vrealize-log-insight-8-x": "vcflogs", "telco-cloud-automation": "tca"}
# 머리말이 빠진 KB 본문(trafilatura 추출)의 구역 추정 단서
PRODUCT_LINE = re.compile(r"^(?:VMware|VCF|vSphere|vCenter|ESXi?|NSX|vSAN|HCX|Tanzu|Avi|Aria|Broadcom|Site Recovery|Live (?:Site )?Recovery|Cloud Director|"
                          r"vDefend|Usage Meter|vRealize|CA |DX |Clarity|Spectrum|Kubernetes|VKS|Supervisor|SDDC|Private AI|Workstation|Fusion|Horizon)"
                          r"[\w .,/()+\-–&:®™]*$", re.I)
CAUSE_CUE = re.compile(r"^(?:\**)(?:cause\b|root cause|this (?:issue|problem|behaviou?r|error|condition) (?:is caused|occurs|happens|can occur|may occur|is due|is seen|is expected)|"
                       r"the (?:issue|problem|error) (?:is caused|occurs|is due)|(?:this|it) (?:is|occurs) (?:due to|because)|caused by|due to |"
                       r"this is (?:a known|expected)|the root cause)", re.I)
RES_CUE = re.compile(r"^(?:\**)(?:resolution\b|solution\b|to resolve|to fix|to remediate|to correct|to address|this (?:issue|problem) (?:is|has been|will be) (?:resolved|fixed|addressed)|"
                     r"(?:the )?(?:issue|problem) is (?:resolved|fixed) in|fixed in|resolved in|upgrade to|update to|apply (?:the )?patch|"
                     r"(?:the )?recommended (?:resolution|fix|solution|action)|perform the following|follow (?:these|the) steps|steps to|"
                     r"broadcom recommends|vmware recommends|option \d|method \d|step \d|to solve|in order to (?:resolve|fix|solve)|the fix\b|fix:|"
                     r"please (?:upgrade|apply|follow|refer|update|contact)|(?:the )?(?:customer|administrator|admin|user)s? (?:has|have|needs?|should|must) to\b|"
                     r"permanent fix|the issue (?:is|was|has been) (?:resolved|fixed|addressed))", re.I)
JA_RES = re.compile(r"(解消されて|修正されて|回避策|回避方法|対処方法|対処策|解決策|解決方法|以下の手順|次の手順|手順は以下)")
STEP_CUE = re.compile(r"^(?:1[.)]\s|```|(?:log ?in|ssh|run|navigate|open|click|restart|reboot|edit|upgrade|apply|download|verify|ensure|use|set|configure|"
                      r"contact|disable|enable|remove|delete|create|add|select|stop|start|power|migrate|place|re-?add|re-?run|re-?try|retry|update|replace|"
                      r"rename|increase|decrease|change|modify|backup|take|connect|go to|follow|refer to|check|review|confirm|perform|re-?install|install|"
                      r"reset|clear|wait|engage|open a|file a|raise|regenerate|renew|replace|re-?deploy|redeploy|shut ?down|log into)\b)", re.I)
WORK_CUE = re.compile(r"^(?:\**)(?:workaround\b|to work ?around|as a workaround|temporary (?:fix|workaround)|a workaround)", re.I)
INFO_CUE = re.compile(r"^(?:\**)(?:additional information|note\b|notes\b|see also|related|for more information|references?\b|impact/risks|impact\b)", re.I)
JUNK_TAIL = re.compile(r"(?:\n\s*(?:Yes|No|Feedback|Was this helpful\??|thumb_up|thumb_down)\s*)+$", re.I)


def _paras(body: str) -> list[str]:
    """빈 줄 기준 문단(코드 블록은 하나로)"""
    out, cur, code = [], [], False
    for ln in body.split("\n"):
        if ln.strip().startswith(("```", "~~~")):
            code = not code
            cur.append(ln)
            if not code:
                out.append("\n".join(cur).strip())
                cur = []
            continue
        if code:
            cur.append(ln)
            continue
        if not ln.strip():
            if cur:
                out.append("\n".join(cur).strip())
                cur = []
        else:
            cur.append(ln)
    if cur:
        out.append("\n".join(cur).strip())
    return [p for p in out if p]


def _is_product_line(p: str, products: list[str]) -> bool:
    if "\n" in p or len(p) > 100 or p.endswith((".", ":", "?")) or p.startswith(("-", "*", "`", ">", "|", "#")):
        return False
    pl = p.lower()
    if any(pl == x.lower() or pl.startswith(x.lower()) for x in products if x):
        return True
    return bool(PRODUCT_LINE.match(p)) and len(p.split()) <= 12


def _is_env_bullets(p: str) -> bool:
    return bool(re.search(r"\*\*(?:products?|versions?|environment|related components?|applies to)\s*:?\*\*", p, re.I))


def kb_segments(body: str, products: list[str]) -> list[dict]:
    """머리말 없는 Broadcom KB 본문 → 증상·환경·원인·해결·우회·추가 정보.
    KB 페이지 순서(Issue/Introduction → Environment → Cause → Resolution → Additional Information)와
    '환경' 자리에 남는 제품명 줄 묶음(또는 **Product:** 목록)을 경계로 쓰고, 문장 단서로 원인·해결·우회를 가른다."""
    ps = _paras(body)
    i = 0
    while i < len(ps) and _is_product_line(ps[i], products):      # 머리의 제품명 줄(제품 메타)
        i += 1
    ps = ps[i:]
    env_s = env_e = None
    for j in range(1, len(ps)):
        if _is_product_line(ps[j], products) or _is_env_bullets(ps[j]):
            env_s = j
            k = j
            while k < len(ps) and (_is_product_line(ps[k], products) or _is_env_bullets(ps[k])):
                k += 1
            env_e = k
            break
    out: list[dict] = []
    if env_s is not None:
        issue, env, rest = ps[:env_s], ps[env_s:env_e], ps[env_e:]
    else:                                                        # 환경 경계 없음 → 원인 단서로만
        c = next((j for j, p in enumerate(ps) if j > 0 and CAUSE_CUE.match(p)), None)
        r = next((j for j, p in enumerate(ps) if j > 0 and (RES_CUE.match(p) or WORK_CUE.match(p))), None)
        cut = c if c is not None else r
        issue, env, rest = (ps[:cut], [], ps[cut:]) if cut else (ps, [], [])
    if issue:
        out.append({"role": "symptom", "crumb": "Issue/Introduction", "paras": issue})
    if env:
        out.append({"role": "env", "crumb": "Environment", "paras": env})
    if rest:
        # 해결 시작: 명시 단서(To resolve·fixed in·Workaround …) 우선 → 없으면 첫 단계·명령(번호 목록·코드·명령형 동사) → 없으면 전부 원인/설명
        r = next((j for j, p in enumerate(rest) if RES_CUE.match(p.lstrip("-* ")) or WORK_CUE.match(p.lstrip("-* ")) or JA_RES.search(p[:80])), None)
        if r is None:          # 첫 문단부터 명령형 동사면 원인 구역이 비어 있는 KB(번호 목록·코드는 원인 설명일 수 있어 둘째 문단부터만)
            r = next((j for j, p in enumerate(rest) if STEP_CUE.match(p.lstrip("*_- ")) and (j > 0 or re.match(r"^[-*]?\s*[A-Za-z]", p))), None)
        if r is None:
            r = len(rest)
        while 0 < r < len(rest) and len(rest[r - 1]) < 200 and rest[r - 1].rstrip("* ").endswith(":"):     # "To remove the old disk group:" 같은 단계 머리말
            r -= 1
        cause, res = rest[:r], rest[r:]
        if cause:
            out.append({"role": "cause", "crumb": "Cause", "paras": cause})
        w = next((j for j, p in enumerate(res) if WORK_CUE.match(p)), None)
        n = next((j for j, p in enumerate(res) if j > 0 and INFO_CUE.match(p) and not p.lstrip().startswith(("1.", "-"))), None)
        if w is not None and (n is None or w < n):
            main, work, info = res[:w], res[w:n] if n and n > w else res[w:], res[n:] if n and n > w else []
        else:
            main, work, info = (res[:n], [], res[n:]) if n is not None else (res, [], [])
        if main:
            out.append({"role": "resolution", "crumb": "Resolution", "paras": main})
        if work:
            out.append({"role": "workaround", "crumb": "Workaround", "paras": work})
        if info:
            out.append({"role": "info", "crumb": "Additional Information", "paras": info})
    return [{"role": x["role"], "crumb": x["crumb"], "text": "\n\n".join(x["paras"])} for x in out]


def clean_body(body: str, title: str) -> str:
    """수집기 본문 정리 — 제목·메타 인용줄·'Yes/No' 피드백 꼬리·TechDocs 목차·내부 링크 주소 제거"""
    b = body.strip()
    b = re.sub(r"^#\s+.+\n+", "", b, count=1) if b.startswith("# ") else b
    b = re.sub(r"^>\s*Product:.*\n+", "", b, count=1)
    b = JUNK_TAIL.sub("", b).rstrip()
    b = re.sub(r"(?m)^CHANGE VERSION\s*$\n?", "", b)
    b = re.sub(r"This document contains the following sections\s*\n+(?:\s*[-*] \[[^\]]*\]\([^)]*\)\s*\n?)+", "", b)
    b = re.sub(r"\[([^\]]+)\]\((?!https?://)[^)]*\.md(?:#[^)]*)?\)", r"\1", b)          # 아카이브 내부 링크는 글자만
    return b.strip()


SECTION_ROLES = [
    ("symptom", r"^(symptoms?|issue|issue/introduction|introduction|problem|증상|문제)\b"),
    ("env", r"^(environment|products?|applies to|환경|적용 대상)\b"),
    ("cause", r"^(cause|root cause|원인)\b"),
    ("resolution", r"^(resolution|solution|fix|remediation|해결|조치)\b"),
    ("workaround", r"^(workaround|우회)\b"),
    ("info", r"^(additional information|notes?|related|references|참고|추가 정보)\b"),
]
ROLE_KO = {"symptom": "증상", "env": "환경", "cause": "원인", "resolution": "해결", "workaround": "우회", "info": "추가 정보"}
VER_RX = re.compile(r"\b(?:ESXi?|vCenter(?: Server)?|vSphere|vSAN|NSX(?:-T)?|VCF|Cloud Foundation|Avi(?: Load Balancer)?|NSX ALB|"
                    r"SDDC Manager|Aria Operations|VCF Operations|SRM|Site Recovery Manager)\s*(?:Server\s*)?v?(\d{1,2}(?:\.\d{1,2}){0,2})(?:\s*(?:U|Update\s*)(\d))?",
                    re.I)
EXTRA_IDS = [re.compile(r"\b[A-Z][A-Z0-9]{1,}(?:_[A-Z0-9]{2,}){1,5}\b"),                # Avi·NSX 이벤트 ID: SE_DOWN, VS_HEALTH_DEGRADED
             re.compile(r"\b[a-z0-9]+_[a-z0-9_]+\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\b"),        # NSX 알람: edge_health.edge_datapath_cpu_high
             re.compile(r"(?:article/|KB\s?#?|Article ID[:\s]*)(\d{5,7})", re.I)]
# 한국어 질문·제목 → 영문 KB 검색어(임베딩 없이도 영문 KB 가 걸리도록). 긴 표현부터 맞춘다.
KO_EN = [
    ("응답 없음", "not responding"), ("응답없음", "not responding"), ("연결 끊김", "disconnected"), ("연결이 끊", "disconnected"), ("연결 안", "cannot connect"),
    ("접속 안", "cannot connect"), ("접속 불가", "cannot connect"), ("핑크 스크린", "purple screen psod"), ("퍼플 스크린", "purple screen psod"),
    ("인증서", "certificate"), ("만료", "expired"), ("갱신", "renew"), ("업그레이드", "upgrade"), ("업데이트", "update"), ("패치", "patch"),
    ("사전 점검", "precheck"), ("사전점검", "precheck"), ("호환성", "compatibility"), ("설치", "install"), ("배포", "deploy"),
    ("느림", "slow latency"), ("느려", "slow latency"), ("지연", "latency"), ("성능", "performance"), ("메모리 부족", "out of memory"), ("메모리", "memory"),
    ("디스크", "disk"), ("스토리지", "storage"), ("데이터스토어", "datastore"), ("경로", "path"), ("다운", "down"), ("장애", "failure"),
    ("실패", "fails"), ("오류", "error"), ("에러", "error"), ("경고", "alarm warning"), ("알람", "alarm"), ("크래시", "crash"), ("충돌", "crash"),
    ("코어 덤프", "core dump"), ("재부팅", "reboot"), ("재시작", "restart"), ("멈춤", "hang"), ("멈춰", "hang"), ("중단", "stopped"),
    ("네트워크", "network"), ("스위치", "switch"), ("포트그룹", "portgroup"), ("가상 머신", "virtual machine vm"), ("가상머신", "virtual machine vm"),
    ("호스트", "esxi host"), ("클러스터", "cluster"), ("스냅샷", "snapshot"), ("백업", "backup"), ("복제", "replication"), ("마이그레이션", "migration vmotion"),
    ("이중화", "high availability ha"), ("페일오버", "failover"), ("라이선스", "license"), ("로그인", "login"), ("인증", "authentication"),
    ("권한", "permission"), ("암호", "password"), ("비밀번호", "password"), ("계정", "account"), ("잠김", "locked"), ("서비스", "service"),
    ("로그", "log"), ("용량", "capacity full"), ("가득", "full"), ("부족", "insufficient"), ("시간 동기화", "ntp time sync"), ("시간", "time"),
    ("방화벽", "firewall"), ("로드밸런서", "load balancer"), ("가상 서비스", "virtual service vs"), ("서비스 엔진", "service engine"),
    ("엣지", "edge"), ("에지", "edge"), ("터널", "tunnel"), ("파드", "pod"), ("노드", "node"), ("슈퍼바이저", "supervisor"), ("하트비트", "heartbeat"),
]
# 영문 운영 표현 — 불용어로 흩어지지 않게 구(phrase)로도 검색
PHRASES = ("not responding", "lost access", "core dump", "out of memory", "purple screen", "dead path", "all paths down",
           "permanent device loss", "certificate expired", "disconnected from", "cannot connect", "failed to connect", "no space left",
           "heartbeat failure", "high cpu", "high memory", "datastore full", "time out", "timed out")


def kb_query_of(ev: dict, reasons: list[str] | None = None) -> str:
    """이상징후 → 지식 검색어: 원문 메시지 + 개체·앱 + 규칙 이름(한국어 사유 문구는 검색 잡음이라 규칙 이름만)"""
    rules = [r.split(":", 1)[1] for r in (reasons or []) if str(r).startswith("규칙:")]
    attrs = ev.get("attrs") or {}
    return " ".join(x for x in [str(ev.get("message", ""))[:600], str(ev.get("entity", "") or ""), str(attrs.get("app", "") or ""),
                                str(attrs.get("event_type", "") or attrs.get("eventTypeId", "") or ""), " ".join(rules)] if x)


def expand_query(q: str) -> str:
    """한국어 운영 용어를 영문 검색어로 덧붙인다(원문은 그대로 둠 — 한국어 문서도 계속 걸림)"""
    if not re.search(r"[가-힣]", q or ""):
        return q
    add = []
    for ko, en in KO_EN:
        if ko in q and en not in add:
            add.append(en)
    return f"{q} {' '.join(add)}" if add else q


_HOSTNAME_RX = re.compile(r"\b(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
                          r"\.(?:lab|local|corp|internal|intra|lan|vcf|home|site)\b", re.I)
STOPQ = {"error", "failed", "failure", "warning", "info", "host", "server", "the", "and", "for", "with", "from", "this", "that", "not",
         "down", "status", "state", "high", "low", "alarm", "event", "log", "check", "issue", "problem", "value", "time", "new", "use",
         "message", "detected", "changed", "unknown", "true", "false", "none", "null", "issues", "problems", "errors"}


VMW_OTHER = {"converter", "remote-console", "operations-manager", "saltstack-entitlement-to-vmware", "workstation", "fusion", "vmware"}   # vendor=other 중 VMware 제품
TITLE_STOP = {"the", "and", "for", "with", "from", "this", "that", "not", "are", "was", "has", "have", "into", "when", "after", "due"}


def _ids(text: str) -> set[str]:
    out: set[str] = set()
    for rx in ID_PATTERNS[:6]:
        out |= {m.lower().replace(" ", "").replace("#", "") for m in rx.findall(text or "")}
    out |= {m for m in EXTRA_IDS[0].findall(text or "") if len(m) >= 6}
    out |= {m.lower() for m in EXTRA_IDS[1].findall(text or "")}
    out |= {f"kb{m}" for m in EXTRA_IDS[2].findall(text or "")}
    return {i for i in out if 4 <= len(i) <= 120}


def _norm_ver(major: str, minor: str | None = None) -> str:
    return f"{int(major)}.{int(minor)}" if minor is not None and minor != "" else f"{int(major)}.x"


def versions_in(text: str) -> list[str]:
    vs: set[str] = set()
    for m in re.finditer(r"(?:prior to|before|earlier than|lower than|below|older than|up to|through)\s+(?:[A-Za-z][\w.-]*\s+){0,4}?v?(\d{1,2})\.(\d{1,2})", text or "", re.I):
        vs.add(_norm_ver(m.group(1), m.group(2)))
    for m in VER_RX.finditer(text or ""):
        p = m.group(1).split(".")
        if not p[0].isdigit() or int(p[0]) > 40:
            continue
        vs.add(_norm_ver(p[0], p[1] if len(p) > 1 else None))
    for m in re.finditer(r"(?<![\d.])(\d{1,2})\.x\b", text or ""):
        vs.add(f"{int(m.group(1))}.x")
    return sorted(vs)[:20]


def _front_matter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    raw, body = text[3:end], text[end + 4:].lstrip("\n")
    try:
        import yaml
        fm = yaml.safe_load(raw) or {}
        return (fm if isinstance(fm, dict) else {}), body
    except Exception:  # noqa: BLE001        # YAML 이 깨진 경우(따옴표 중첩 등) — 줄 단위로 최대한 읽기(목록 '- 값' 포함)
        fm: dict = {}
        key = ""
        for ln in raw.splitlines():
            m = re.match(r"^([A-Za-z_][\w -]{0,40}):\s*(.*)$", ln)
            if m:
                key, v = m.group(1).strip().lower(), m.group(2).strip()
                fm[key] = _unq(v) if v else []
            elif key and re.match(r"^\s*-\s+", ln):
                if not isinstance(fm.get(key), list):
                    fm[key] = [] if fm.get(key) in ("", None) else [fm[key]]
                fm[key].append(_unq(re.sub(r"^\s*-\s+", "", ln)))
        return fm, body


def _unq(v: str) -> str:
    v = v.strip()
    return v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'" else v


def _fm(fm: dict, *keys) -> str:
    low = {str(k).lower().replace(" ", "_"): v for k, v in fm.items()}
    for k in keys:
        v = low.get(k)
        if v not in (None, "", []):
            return ", ".join(map(str, v)) if isinstance(v, list) else str(v)
    return ""


def _head_field(body: str, *names) -> str:
    """본문 머리(앞 60줄)의 '**Article ID:** 123', 'URL: https://…' 같은 줄"""
    for ln in body.splitlines()[:60]:
        s = re.sub(r"[*_`>|]", "", ln).strip()
        for n in names:
            m = re.match(rf"{n}\s*[:：]\s*(.+)$", s, re.I)
            if m:
                return m.group(1).strip()
    return ""


def techdocs_meta(url: str) -> tuple[str, str]:
    """TechDocs URL 경로 → (제품, 버전) 예) …/vmware-cis/vsphere/vsphere/8-0/… → (vsphere, 8.0)"""
    u = (url or "").lower()
    prod = ""
    for k, rx in (("avi", r"avi-load-balancer|load-balancing"), ("nsx", r"/nsx/"), ("vsan", r"/vsan/"), ("vcf", r"/vcf/|cloud-foundation"),
                  ("vks", r"vsphere-supervisor|/tanzu|vks"), ("vcfops", r"aria-operations|vcf-operations"), ("srm", r"site-recovery"),
                  ("vsphere", r"/vsphere/")):
        if re.search(rx, u):
            prod = k
            break
    m = re.search(r"/(\d{1,2})-(\d{1,2})(?:-\d+)?(?:-and-later)?/", u)
    return prod, (_norm_ver(m.group(1), m.group(2)) if m else "")


def detect_product(title: str, url: str, head: str) -> str:
    p, _ = techdocs_meta(url)
    if p:
        return p
    blob = f"{title}\n{url}\n{head[:2500]}".lower()
    for k, rx in PRODUCT_RX:
        if re.search(rx, blob):
            return k
    return "general"


def section_role(heading: str) -> str:
    h = re.sub(r"[#*_`:]", "", heading or "").strip().lower()
    for role, rx in SECTION_ROLES:
        if re.match(rx, h, re.I):
            return role
    return ""


def doc_lang(t: str) -> str:
    """번역본 구분 — 가나가 있으면 ja, 한글이면 ko, 한자만 많으면 zh, 그 외 en"""
    if re.search(r"[\u3040-\u30ff]", t):
        return "ja"
    if re.search(r"[\uac00-\ud7a3]", t):
        return "ko"
    if len(re.findall(r"[\u4e00-\u9fff]", t)) > 8:
        return "zh"
    return "en"


def parse_markdown(text: str, path: str = "") -> dict[str, Any]:
    """md 한 파일 → {title, url, kind, kb, product, versions, updated, sections:[{role, crumb, text}]}"""
    fm, body = _front_matter(text.replace("\r\n", "\n"))
    title = _fm(fm, "title", "name", "subject")
    m = re.search(r"^#\s+(.+)$", body, re.M)
    if not title:
        title = m.group(1).strip() if m else Path(path).stem.replace("_", " ").replace("-", " ")
    url = _fm(fm, "url", "source_url", "source", "link", "canonical", "permalink") or _head_field(body, "url", "source", "link", "원문")
    um = re.search(r"https?://\S+", url)
    url = um.group(0).rstrip(").,>]") if um else ""
    kb = _fm(fm, "kb", "kb_id", "article_id", "articleid", "article", "id", "number")
    kb = kb or _head_field(body, "article id", "article number", "kb", "kb number", "문서 번호")
    km = re.fullmatch(r"\s*(?:kb[-_ ]?)?(\d{3,7})\s*", kb or "", re.I) or re.search(r"\d{5,7}", kb or "") or re.search(r"/article/(\d{5,7})", url) or re.search(r"(?:^|[^\d])(?:kb|article)[_-]?(\d{5,7})", Path(path).name, re.I)
    kb = (km.group(1) if km and km.re.groups else km.group(0)) if km else ""
    if "techdocs.broadcom.com" in url or "docs.vmware.com" in url or "techdocs" in path.lower():
        kind = "techdoc"
    elif kb or "knowledge.broadcom.com" in url or re.search(r"(^|/)kb[s]?(/|_|-)", path.lower()):
        kind = "kb"
    else:
        kind = "doc"
    if kind == "kb" and kb and not url:
        url = KB_URL.format(id=kb)
    src = str(fm.get("source") or "").lower()
    if src == "techdocs":
        kind = "techdoc"
    elif src == "kb" and kb:
        kind = "kb"
    products = [str(x) for x in (fm.get("products") or [])] if isinstance(fm.get("products"), list) else ([str(fm["products"])] if fm.get("products") else [])
    doc_type = str(fm.get("doc_type") or "")
    summary = str(fm.get("summary") or "").strip()
    sigs = [re.sub(r"^[\"']+|[\"']+$", "", str(x).replace("`", "")).strip() for x in (fm.get("error_signatures") or []) if str(x).strip()][:20]
    body = clean_body(body, title)
    head = body[:4000]
    slug = str(fm.get("product") or "").lower()
    prod = next((k for k, rx in PRODUCT_RX if re.search(rx, " ".join(products))), "") if products else ""
    if slug in SLUG_PRODUCT and not (prod and (SLUG_PRODUCT[slug] in ("vsphere", "vcf") or prod == SLUG_PRODUCT[slug])):
        prod = SLUG_PRODUCT[slug]
    if not prod:
        prod = (_fm(fm, "product", "category") or "").lower()
        prod = next((k for k, rx in PRODUCT_RX if re.search(rx, prod)), "") if prod else ""
    prod = prod or (SLUG_PRODUCT.get(slug) or slug or detect_product(title, url, head))
    vers = set()
    fv = _fm(fm, "version", "versions", "applies_to", "product_version", "release")
    if fv:
        for x in re.findall(r"\d{1,2}(?:\.\d{1,2})?(?:\.x)?", fv):
            p = x.split(".")
            vers.add(_norm_ver(p[0], p[1] if len(p) > 1 and p[1] != "x" else None))
    _, tv = techdocs_meta(url)
    if tv:
        vers.add(tv)
    updated = _fm(fm, "updated", "last_updated", "updated_on", "date", "modified", "published") or _head_field(body, "updated on", "last updated", "updated", "published")
    # 구역 나누기 — 제목 계층 보존, 코드 블록 안의 # 은 무시
    sections, stack, cur, in_code = [], [], [], False     # stack = [(레벨, 제목)]
    role = ""

    def flush():
        t = "\n".join(cur).strip()
        if t:
            sections.append({"role": role, "crumb": " › ".join(h for _, h in stack), "text": t})

    for ln in body.split("\n"):
        if ln.strip().startswith("```") or ln.strip().startswith("~~~"):
            in_code = not in_code
            cur.append(ln)
            continue
        hm = None if in_code else re.match(r"^(#{1,4})\s+(.+?)\s*#*$", ln)
        bm = None if in_code or hm else re.match(r"^\*\*([A-Za-z가-힣 /]{3,40})\*\*\s*:?\s*$", ln.strip())   # **Resolution** 형태
        if hm or (bm and section_role(bm.group(1))):
            flush()
            cur = []
            lvl, h = (len(hm.group(1)), hm.group(2).strip()) if hm else (2, bm.group(1).strip())
            if lvl == 1 and h == title and not stack:
                stack = [(1, h)]
                role = ""
                continue
            parent_role = role
            while stack and stack[-1][0] >= lvl:
                stack.pop()
            stack.append((lvl, h))
            r = section_role(h)
            role = r or (parent_role if len(stack) > 1 and any(section_role(x) for _, x in stack[:-1]) else "")
            continue
        cur.append(ln)
    flush()
    seg = "headings"
    if kind == "kb" and not any(x["role"] for x in sections):        # 머리말 없는 KB(수집기 본문) → 구역 추정
        guess = kb_segments(body, products)
        if any(x["role"] in ("cause", "resolution", "workaround") for x in guess):
            sections, seg = guess, "inferred"
    if summary and not any(x["role"] == "symptom" for x in sections):
        sections.insert(0, {"role": "symptom", "crumb": "Summary", "text": summary})
    env_txt = " ".join(s["text"] for s in sections if s["role"] == "env")[:3000]
    vers |= set(versions_in(env_txt or head[:2500] + " " + title))
    return {"title": title.strip()[:300], "url": url, "kind": kind, "kb": kb, "product": prod, "versions": sorted(vers)[:20],
            "updated": str(updated)[:40], "sections": sections, "doc_type": doc_type, "summary": summary[:600], "signatures": sigs,
            "products": products[:10], "segmentation": seg, "vendor": str(fm.get("vendor") or "").lower()[:40],
            "lang": doc_lang(title + " " + summary + " " + body[:400])}


def chunk_sections(doc: dict, size: int = 1600, overlap: int = 150) -> list[dict]:
    """구역 → 청크(문단 경계, 코드 블록 보존). 각 청크 = {role, crumb, text}"""
    out = []
    for s in doc["sections"]:
        paras, buf, in_code, blk = [], [], False, []
        for ln in s["text"].split("\n"):
            if ln.strip().startswith(("```", "~~~")):
                if not in_code and buf:                  # 코드 블록 앞 문장(예: "1. 경로 확인:")을 먼저 — 순서 보존
                    paras.append("\n".join(buf))
                    buf = []
                in_code = not in_code
                blk.append(ln)
                if not in_code:
                    paras.append("\n".join(blk))
                    blk = []
                continue
            if in_code:
                blk.append(ln)
                continue
            if not ln.strip():
                if buf:
                    paras.append("\n".join(buf))
                    buf = []
            else:
                buf.append(ln)
        if blk:
            paras.append("\n".join(blk))
        if buf:
            paras.append("\n".join(buf))
        cur = ""
        for p in paras:
            while len(p) > size * 2 and not p.lstrip().startswith("```"):
                if cur:
                    out.append({**s, "text": cur})
                    cur = ""
                out.append({**s, "text": p[:size]})
                p = p[size - overlap:]
            if cur and len(cur) + len(p) + 2 > size:
                out.append({**s, "text": cur})
                cur = _tail(cur, overlap) + "\n\n" + p if overlap and not cur.rstrip().endswith("```") else p
            else:
                cur = f"{cur}\n\n{p}" if cur else p
        if cur.strip():
            out.append({**s, "text": cur})
    return out


def _tail(t: str, n: int) -> str:
    """겹침 꼬리 — 단어·줄 경계에서 시작(단어 중간 'Xi using …' 처럼 잘리지 않게)"""
    x = t[-n:]
    if len(t) > n and not t[-n - 1].isspace():
        m = re.search(r"\s", x)
        x = x[m.end():] if m else x
    return x.lstrip()


def _join_overlap(a: str, b: str) -> str:
    """같은 구역의 이웃 청크 이어 붙이기 — 청크 겹침(overlap)으로 반복된 앞부분을 뺀다"""
    for k in range(min(len(a), len(b), 600), 15, -1):
        if a.endswith(b[:k]):
            return a + b[k:]
    return a + "\n" + b


def _merge_chunks(ch) -> list[dict]:
    out: list[dict] = []
    for c in ch:
        role = ROLE_KO.get(c["role"] or "", "")
        if out and out[-1]["role"] == role and out[-1]["crumb"] == c["crumb"]:
            out[-1]["text"] = _join_overlap(out[-1]["text"], c["text"])
        else:
            out.append({"role": role, "crumb": c["crumb"], "text": c["text"]})
    return out


def env_versions(engine) -> dict[str, set[str]]:
    """운영 중인 제품 버전(major.minor) — vCenter about, ESXi config.product, NSX node, Avi 로그인 응답, UCSM"""
    out: dict[str, set[str]] = {}

    def add(prod, v):
        m = re.match(r"(\d{1,2})\.(\d{1,2})", str(v or ""))
        if m:
            out.setdefault(prod, set()).update({f"{int(m.group(1))}.{int(m.group(2))}", f"{int(m.group(1))}.x"})
    for c in getattr(engine, "connectors", []) or []:
        t = getattr(c, "type", "")
        if t == "vcenter":
            add("vcenter", (getattr(c, "about", {}) or {}).get("version"))
            add("vsphere", (getattr(c, "about", {}) or {}).get("version"))
            for h in ((getattr(c, "topology", {}) or {}).get("hosts", {}) or {}).values():
                add("esxi", h.get("esx_version") or h.get("version"))
                add("vsphere", h.get("esx_version") or h.get("version"))
        elif t in ("nsx", "avi", "nsx-alb"):
            add("nsx" if t == "nsx" else "avi", getattr(c, "version", ""))
        elif t == "ucsm":
            add("hardware", ((getattr(c, "ucs", {}) or {}).get("system") or {}).get("version"))
    if "vcenter" in out:                      # VCF 9.x 는 vCenter 9.x 와 번호가 같다(5.x 이하는 대응이 달라 추정하지 않음)
        out.setdefault("vcf", set()).update(v for v in out["vcenter"] if re.match(r"(9|1\d)\.", v))
    return out


class KnowledgeLibrary:
    def __init__(self, cfg: dict, data_dir: str, embedder=None):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.root = Path(data_dir) / "knowledge"
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "uploads").mkdir(exist_ok=True)
        self.db_path = self.root / "knowledge.db"
        self.vec_path = self.root / "vectors.f16"
        self.embedder = embedder
        self.use_vectors = bool(self.cfg.get("embed", True))
        self.size = int(self.cfg.get("chunk_size", 1600))
        self.overlap = int(self.cfg.get("chunk_overlap", 150))
        self.max_file = int(float(self.cfg.get("max_file_mb", 8)) * 2**20)
        self.k = int(self.cfg.get("top_k", 5))
        self.min_rel = float(self.cfg.get("min_relevance", 0.4))
        self.lock = threading.RLock()
        self.job: dict[str, Any] = {"state": "idle"}
        self._vec: np.ndarray | None = None
        self._vec_dim = 0
        self._stop = False
        self._db = self._open()
        self._cnt = (0.0, 0)
        self._sig_cache = None
        self._gen: int | None = None
        self.changed_at = 0.0
        self.home_vendors = set(self.cfg.get("vendors") or ["vmware"])
        self.langs = set(self.cfg.get("languages") or ["en", "ko"])

    def has_chunks(self) -> bool:
        if time.time() - self._cnt[0] > 60:
            with self.lock:
                n = self._db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
            self._cnt = (time.time(), int(n))
        return self._cnt[1] > 0

    # ------------------------------------------------------------------ 저장소
    SCHEMA_VER = "3"

    def _open(self) -> sqlite3.Connection:
        db = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
        db.row_factory = sqlite3.Row
        try:                                             # 스키마가 바뀌면(1.11: 오류 문구·요약·문서 유형) 다시 색인
            ver = db.execute("SELECT v FROM meta WHERE k='schema'").fetchone()
            if ver is None or ver[0] != self.SCHEMA_VER:
                db.executescript("DROP TABLE IF EXISTS docs; DROP TABLE IF EXISTS chunks; DROP TABLE IF EXISTS chunks_fts; DROP TABLE IF EXISTS ids;")
                self.vec_path.unlink(missing_ok=True)
                db.execute("DELETE FROM meta WHERE k IN ('vec_dim','vec_model','last_scan')")
        except sqlite3.OperationalError:
            pass
        db.executescript("""
PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, path TEXT UNIQUE, root TEXT, sha TEXT, mtime REAL, size INTEGER,
  kind TEXT, kb TEXT, title TEXT, url TEXT, product TEXT, versions TEXT, updated TEXT, roles TEXT, indexed REAL,
  doc_type TEXT, summary TEXT, sigs TEXT, products TEXT, seg TEXT, vendor TEXT, lang TEXT);
CREATE INDEX IF NOT EXISTS ix_docs_kb ON docs(kb);
CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, doc INTEGER, ord INTEGER, role TEXT, crumb TEXT, text TEXT, vrow INTEGER);
CREATE INDEX IF NOT EXISTS ix_chunks_doc ON chunks(doc);
CREATE INDEX IF NOT EXISTS ix_chunks_vrow ON chunks(vrow);
CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(title, crumb, text, sig, tokenize='unicode61 remove_diacritics 2');
CREATE TABLE IF NOT EXISTS ids(token TEXT, chunk INTEGER);
CREATE INDEX IF NOT EXISTS ix_ids_tok ON ids(token);
CREATE TABLE IF NOT EXISTS feedback(sig TEXT, doc INTEGER, vote INTEGER, user TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_fb_sig ON feedback(sig);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
""")
        db.execute("INSERT OR REPLACE INTO meta VALUES('schema', ?)", (self.SCHEMA_VER,))
        db.commit()
        return db

    @property
    def gen(self) -> int:
        """지식 세대 — 문서가 추가·변경·삭제될 때마다 1 증가. 분석 재사용·자동 연결이 '그 뒤로 지식이 바뀌었는지' 판단에 쓴다"""
        if self._gen is None:
            try:
                self._gen = int(self._meta("gen") or 0)
            except ValueError:
                self._gen = 0
        return self._gen

    def bump(self) -> int:
        self._gen = self.gen + 1
        self._meta("gen", str(self._gen))
        self.changed_at = time.time()
        return self._gen

    def _meta(self, k: str, v: str | None = None) -> str:
        with self.lock:
            if v is None:
                r = self._db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
                return r["v"] if r else ""
            self._db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))
            self._db.commit()
            return v

    def roots(self) -> list[tuple[str, Path]]:
        out = []
        for p in self.cfg.get("paths") or []:
            pp = Path(str(p)).expanduser()
            if pp.is_dir():
                out.append((pp.name or str(pp), pp))
        for d in sorted((self.root / "uploads").iterdir()):
            if d.is_dir():
                out.append((f"upload:{d.name}", d))
        return out

    # ------------------------------------------------------------------ 색인(증분)
    def _index_file(self, root: str, p: Path, st: os.stat_result) -> int:
        raw = p.read_bytes()
        sha = hashlib.sha1(raw).hexdigest()
        with self.lock:
            old = self._db.execute("SELECT id, sha FROM docs WHERE path=?", (str(p),)).fetchone()
        if old and old["sha"] == sha:
            with self.lock:
                self._db.execute("UPDATE docs SET mtime=?, size=? WHERE id=?", (st.st_mtime, st.st_size, old["id"]))
            return 0
        doc = parse_markdown(raw.decode("utf-8", errors="replace"), str(p))
        chunks = chunk_sections(doc, self.size, self.overlap)
        if not chunks:
            return 0
        roles = sorted({c["role"] for c in chunks if c["role"]})
        with self.lock:
            if old:
                self._drop_doc(old["id"])
            sigs = doc.get("signatures") or []
            cur = self._db.execute(
                "INSERT INTO docs(path,root,sha,mtime,size,kind,kb,title,url,product,versions,updated,roles,indexed,doc_type,summary,sigs,products,seg,vendor,lang) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(p), root, sha, st.st_mtime, st.st_size, doc["kind"], doc["kb"], doc["title"], doc["url"], doc["product"],
                 json.dumps(doc["versions"]), doc["updated"], json.dumps(roles), time.time(), doc.get("doc_type", ""), doc.get("summary", ""),
                 json.dumps(sigs), json.dumps(doc.get("products") or []), doc.get("segmentation", ""), doc.get("vendor", ""), doc.get("lang", "en")))
            did = cur.lastrowid
            doc_ids = _ids(doc["title"] + " " + " ".join(sigs)) | ({f"kb{doc['kb']}"} if doc["kb"] else set())
            sig_txt = " ".join(sigs + [doc.get("summary", "")])
            for i, c in enumerate(chunks):
                cc = self._db.execute("INSERT INTO chunks(doc,ord,role,crumb,text) VALUES(?,?,?,?,?)", (did, i, c["role"], c["crumb"][:400], c["text"]))
                cid = cc.lastrowid
                self._db.execute("INSERT INTO chunks_fts(rowid,title,crumb,text,sig) VALUES(?,?,?,?,?)",
                                 (cid, doc["title"], c["crumb"], c["text"], sig_txt if i == 0 else ""))
                for t in (_ids(c["text"]) | (doc_ids if i == 0 else set())):
                    self._db.execute("INSERT INTO ids VALUES(?,?)", (t, cid))
        return len(chunks)

    def _drop_doc(self, did: int) -> None:
        rows = [r["id"] for r in self._db.execute("SELECT id FROM chunks WHERE doc=?", (did,))]
        for i in range(0, len(rows), 500):
            part = rows[i:i + 500]
            q = ",".join("?" * len(part))
            self._db.execute(f"DELETE FROM chunks_fts WHERE rowid IN ({q})", part)
            self._db.execute(f"DELETE FROM ids WHERE chunk IN ({q})", part)
        self._db.execute("DELETE FROM chunks WHERE doc=?", (did,))
        self._db.execute("DELETE FROM docs WHERE id=?", (did,))

    def scan(self, full: bool = False) -> dict[str, Any]:
        """폴더 증분 색인(스레드에서 실행). 바뀐 파일만 다시 파싱, 사라진 파일은 삭제."""
        t0 = time.time()
        files: list[tuple[str, Path]] = []
        skip = set(self.cfg.get("skip_dirs") or []) 
        for name, root in self.roots():
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if not d.startswith((".", "_")) and d not in skip]     # _catalog·_changes·_rag(수집기 메타) 제외
                for f in fn:
                    if dp == str(root) and f.lower() in ("readme.md", "index.md", "catalog.md"):   # 아카이브 맨 위 안내 파일
                        continue
                    if Path(f).suffix.lower() in MD_EXT and not f.startswith("."):
                        files.append((name, Path(dp) / f))
        self.job = {"state": "indexing", "done": 0, "total": len(files), "changed": 0, "chunks": 0, "errors": 0, "started": t0, "last_error": ""}
        with self.lock:
            known = {r["path"]: (r["mtime"], r["size"]) for r in self._db.execute("SELECT path, mtime, size FROM docs")}
        seen = set()
        for i, (name, p) in enumerate(files, 1):
            if self._stop:
                break
            sp = str(p)
            seen.add(sp)
            try:
                st = p.stat()
                if st.st_size > self.max_file or st.st_size < 40:
                    continue
                if not full and sp in known and known[sp] == (st.st_mtime, st.st_size):
                    continue
                n = self._index_file(name, p, st)
                if n:
                    self.job["changed"] += 1
                    self.job["chunks"] += n
            except Exception as e:  # noqa: BLE001
                self.job["errors"] += 1
                self.job["last_error"] = f"{p.name}: {type(e).__name__}: {e}"[:200]
            if i % 200 == 0:
                with self.lock:
                    self._db.commit()
            self.job["done"] = i
        removed = 0
        with self.lock:
            for sp in set(known) - seen:
                r = self._db.execute("SELECT id FROM docs WHERE path=?", (sp,)).fetchone()
                if r:
                    self._drop_doc(r["id"])
                    removed += 1
            self._db.commit()
        self.job.update(state="done", removed=removed, seconds=round(time.time() - t0, 1), finished=time.time())
        if self.job.get("changed") or removed:
            self.bump()
        self._cnt = (0.0, 0)
        self._sig_cache = None
        self._sigs()                                   # 오류 문구 캐시 미리 구성(첫 검색 지연 방지)
        self._meta("last_scan", str(time.time()))
        return dict(self.job)

    # ------------------------------------------------------------------ 임베딩(백그라운드, 증분)
    def _load_vectors(self) -> None:
        dim = int(self._meta("vec_dim") or 0)
        if not dim or not self.vec_path.exists():
            self._vec, self._vec_dim = None, 0
            return
        n = self.vec_path.stat().st_size // (2 * dim)
        self._vec = np.memmap(self.vec_path, dtype=np.float16, mode="r", shape=(n, dim)) if n else None
        self._vec_dim = dim

    async def embed_pending(self, batch: int = 64) -> int:
        if not (self.use_vectors and self.embedder and getattr(self.embedder, "enabled", False)):
            return 0
        model = self.embedder.model
        if self._meta("vec_model") and self._meta("vec_model") != model:          # 모델이 바뀌면 전부 다시
            with self.lock:
                self._db.execute("UPDATE chunks SET vrow=NULL")
                self._db.commit()
            self._vec = None
            self.vec_path.unlink(missing_ok=True)
            self._meta("vec_dim", "0")
        self._meta("vec_model", model)
        done = 0
        while not self._stop:
            with self.lock:
                rows = self._db.execute("SELECT c.id, c.text, c.crumb, d.title FROM chunks c JOIN docs d ON d.id=c.doc WHERE c.vrow IS NULL LIMIT ?",
                                        (batch,)).fetchall()
            if not rows:
                break
            v = await self.embedder.embed([f"{r['title']} › {r['crumb']}\n{r['text']}"[:6000] for r in rows])
            v = v.astype(np.float16)
            dim = int(self._meta("vec_dim") or 0)
            if dim and dim != v.shape[1]:
                raise RuntimeError(f"임베딩 차원 불일치 {dim}≠{v.shape[1]}")
            self._meta("vec_dim", str(v.shape[1]))
            start = self.vec_path.stat().st_size // (2 * v.shape[1]) if self.vec_path.exists() else 0
            with open(self.vec_path, "ab") as f:
                f.write(v.tobytes())
            with self.lock:
                self._db.executemany("UPDATE chunks SET vrow=? WHERE id=?", [(start + i, r["id"]) for i, r in enumerate(rows)])
                self._db.commit()
            done += len(rows)
            self.job["embedded"] = self.job.get("embedded", 0) + len(rows)
        self._load_vectors()
        return done

    async def refresh(self, full: bool = False) -> dict:
        """색인 → 임베딩. 화면 '지금 색인'·주기 작업·업로드 후 호출"""
        if self.job.get("state") in ("indexing", "embedding"):
            return self.job
        r = await asyncio.to_thread(self.scan, full)
        try:
            self.job["state"] = "embedding"
            await self.embed_pending()
            self.job["state"] = "done"
        except Exception as e:  # noqa: BLE001
            self.job.update(state="done", embed_error=f"{type(e).__name__}: {e}"[:200])
        return r

    async def loop(self) -> None:
        self._load_vectors()
        await asyncio.sleep(15)
        every = max(300.0, float(self.cfg.get("scan_interval", 21600)))
        while not self._stop:
            try:
                if self.roots():
                    await self.refresh()
            except Exception as e:  # noqa: BLE001
                self.job = {"state": "error", "last_error": f"{type(e).__name__}: {e}"[:200]}
            await asyncio.sleep(every)

    def import_zip(self, data: "bytes | str | Path", name: str) -> dict:
        """zip(md 묶음) → uploads/<이름>/ (md·txt 만, 경로 정규화 — zip slip 방지). data = 바이트 또는 디스크의 zip 경로"""
        safe = re.sub(r"[^A-Za-z0-9가-힣._-]+", "_", Path(name).stem)[:60] or "upload"
        dest = self.root / "uploads" / safe
        tmp = self.root / "uploads" / f".{safe}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        n = skipped = 0
        with zipfile.ZipFile(io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else str(data)) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                rel = Path(*[re.sub(r"[^\w가-힣.\- ]+", "_", x) for x in Path(info.filename).parts if x not in ("..", ".", "", "/")])
                if rel.suffix.lower() not in MD_EXT or info.file_size > self.max_file or not rel.parts:
                    skipped += 1
                    continue
                out = (tmp / rel).resolve()
                if not str(out).startswith(str(tmp.resolve())):
                    skipped += 1
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                n += 1
        if not n:
            shutil.rmtree(tmp, ignore_errors=True)
            raise ValueError("zip 안에 md/txt 파일이 없습니다")
        shutil.rmtree(dest, ignore_errors=True)
        tmp.rename(dest)
        return {"name": f"upload:{safe}", "files": n, "skipped": skipped}

    def save_file(self, data: bytes, filename: str, relpath: str = "", collection: str = "manual") -> dict:
        """md 파일 한 개 직접 올리기 → uploads/<묶음>/<상대 경로> 저장 후 바로 색인(파싱 결과를 돌려줌).
        같은 묶음·같은 경로면 덮어씀(KB 갱신). zip 과 달리 묶음 전체를 바꾸지 않는다."""
        coll = re.sub(r"[^A-Za-z0-9가-힣._-]+", "_", collection or "manual").strip("._")[:60] or "manual"
        raw = [x for x in Path((relpath or filename).replace("\\", "/")).parts if x not in ("..", ".", "", "/")]
        if any(x.startswith(("_", ".")) for x in raw[:-1]) or (raw and raw[-1].startswith(".")):
            raise ValueError("수집기 메타 폴더(_catalog 등)·숨김 파일은 색인하지 않습니다")
        parts = [re.sub(r"[^\w가-힣.\- ]+", "_", x) for x in raw]
        if not parts:
            raise ValueError("파일 이름이 비어 있습니다")
        rel = Path(*parts)
        if rel.suffix.lower() not in MD_EXT:
            raise ValueError("md·markdown·txt 파일만 올릴 수 있습니다")
        if len(data) > self.max_file:
            raise ValueError(f"파일이 너무 큽니다(최대 {self.max_file // 2**20}MB)")
        if len(data) < 40:
            raise ValueError("내용이 너무 짧습니다")
        base = (self.root / "uploads" / coll).resolve()
        out = (base / rel).resolve()
        if not str(out).startswith(str(base) + os.sep):
            raise ValueError("경로 거부")
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(f".{out.name}.part")
        tmp.write_bytes(data)
        tmp.replace(out)
        n = self._index_file(f"upload:{coll}", out, out.stat())
        with self.lock:
            self._db.commit()
            r = self._db.execute("SELECT id, kind, kb, title, product, versions, roles, seg, doc_type FROM docs WHERE path=?", (str(out),)).fetchone()
        self._cnt = (0.0, 0)
        self._sig_cache = None
        if n:
            self.bump()
        if not r:
            return {"saved": str(rel), "collection": coll, "indexed": False, "chunks": 0}
        return {"saved": str(rel), "collection": coll, "indexed": True, "changed": bool(n), "doc_id": f"lib:{r['id']}",
                "kind": r["kind"], "kb": r["kb"] or "", "title": r["title"], "product": r["product"],
                "versions": json.loads(r["versions"] or "[]"), "sections": [ROLE_KO[x] for x in ("symptom", "env", "cause", "resolution", "workaround", "info") if x in json.loads(r["roles"] or "[]")],
                "segmentation": r["seg"] or "", "doc_type": r["doc_type"] or ""}

    def remove_upload(self, name: str) -> None:
        nm = str(name or "").replace("upload:", "", 1)
        if not re.fullmatch(r"[A-Za-z0-9가-힣._-]{1,80}", nm) or not nm.strip("."):      # 2.30.0 '..'·경로 구분자 차단(지식 루트 삭제 방지)
            raise ValueError("업로드 묶음 이름이 올바르지 않습니다")
        base = (self.root / "uploads").resolve()
        d = (base / nm).resolve()
        if d.parent == base and d != base and d.is_dir():
            shutil.rmtree(d)

    # ------------------------------------------------------------------ 피드백
    def feedback(self, sig: str, doc: int, vote: int, user: str = "") -> None:
        with self.lock:
            self._db.execute("DELETE FROM feedback WHERE sig=? AND doc=? AND user=?", (sig, doc, user))
            if vote:
                self._db.execute("INSERT INTO feedback VALUES(?,?,?,?,?)", (sig, doc, 1 if vote > 0 else -1, user, time.time()))
            self._db.commit()

    def _votes(self, sig: str | None) -> dict[int, float]:
        if not sig:
            return {}
        with self.lock:
            return {r["doc"]: float(r["s"]) for r in self._db.execute("SELECT doc, SUM(vote) s FROM feedback WHERE sig=? GROUP BY doc", (sig,))}

    # ------------------------------------------------------------------ 검색
    @staticmethod
    def query_terms(q: str, limit: int = 24) -> tuple[list[str], set[str]]:
        """로그·질문 → (FTS 단어, 식별자). 숫자·IP·UUID 같은 변동 토큰은 버리고 식별자는 정확 일치로"""
        ids = _ids(q)
        words = []
        q = _HOSTNAME_RX.sub(" ", q or "")                 # 2.6.1 호스트 FQDN(esx08.rangers.lab)의 도메인 조각(rangers·lab)이 무관한 문서와 맞지 않게
        for t in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}|[가-힣]{2,}", q):
            tl = t.lower()
            if tl in STOPQ or len(tl) > 40 or re.fullmatch(r"[0-9a-f]{8,}", tl):
                continue
            if tl not in words:
                words.append(tl)
        return words[:limit], ids

    def _fts(self, words: list[str], limit: int) -> list[tuple[int, float, int]]:
        if not words:
            return []
        q = " OR ".join(f'"{w}"' for w in words)
        with self.lock:
            rows = self._db.execute("SELECT rowid, bm25(chunks_fts, 4.0, 2.0, 1.0, 6.0) s FROM chunks_fts WHERE chunks_fts MATCH ? ORDER BY s LIMIT ?",
                                    (q, limit)).fetchall()
        return [(r["rowid"], -float(r["s"]), 0) for r in rows]

    def _id_hits(self, ids: set[str]) -> dict[int, int]:
        if not ids:
            return {}
        out: dict[int, int] = {}
        with self.lock:
            ql = list(ids)[:30]
            for r in self._db.execute(f"SELECT chunk, COUNT(*) n FROM ids WHERE token IN ({','.join('?' * len(ql))}) GROUP BY chunk LIMIT 400", ql):
                out[r["chunk"]] = int(r["n"])
        return out

    @staticmethod
    def _sig_norm(t: str) -> str:
        t = str(t or "").lower()
        t = re.sub(r"<[^>]{1,60}>|\\[<>]|\*[^*]{1,40}\*", " ", t)                       # <timedatestamp>·*placeholder* 자리 표시
        t = re.sub(r"[`\"'\\\[\]]", " ", t)
        t = re.sub(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b|\d+", "#", t)
        return re.sub(r"\s+", " ", t).strip()

    def _sigs(self) -> list[tuple[int, list[list[str]]]]:
        """오류 문구(front matter error_signatures) → 고정 구간 목록(숫자·자리 표시를 뺀 8자 이상 조각) — 메모리 캐시"""
        if self._sig_cache is None:
            out = []
            with self.lock:
                rows = self._db.execute("SELECT id, sigs FROM docs WHERE sigs IS NOT NULL AND sigs != '[]'").fetchall()
            for r in rows:
                fl = []
                for sg in json.loads(r["sigs"] or "[]"):
                    frags = [x.strip(" #:;,.()=-") for x in self._sig_norm(sg).split("#")]
                    frags = [x for x in frags if len(x) >= 8]
                    if sum(len(x) for x in frags) >= 16:
                        fl.append(frags)
                if fl:
                    out.append((int(r["id"]), fl))
            self._sig_cache = out
        return self._sig_cache

    def _sig_hits(self, query: str) -> set[int]:
        qn = self._sig_norm(query)
        if len(qn) < 16:
            return set()
        return {did for did, fl in self._sigs() if any(all(f in qn for f in frags) for frags in fl)}

    def _dense(self, qv: np.ndarray, limit: int) -> list[tuple[int, float]]:
        if self._vec is None or qv is None or self._vec_dim != qv.shape[0]:
            return []
        sims = np.asarray(self._vec @ qv.astype(np.float16), dtype=np.float32)
        top = np.argpartition(-sims, min(limit, len(sims) - 1))[:limit]
        top = top[np.argsort(-sims[top])]
        rows = [int(x) for x in top]
        with self.lock:
            m = {r["vrow"]: r["id"] for r in self._db.execute(f"SELECT id, vrow FROM chunks WHERE vrow IN ({','.join('?' * len(rows))})", rows)}
        return [(m[r], float(sims[r])) for r in rows if r in m]

    def search_sync(self, query: str, source: str | None = None, k: int | None = None, intent: str = "analyze",
                    sig: str | None = None, env: dict[str, set[str]] | None = None, qv: np.ndarray | None = None) -> list[dict]:
        k = k or self.k
        query = expand_query(query)
        words, ids = self.query_terms(query, limit=40)
        words = ([w for w in words if not re.search(r"[가-힣]", w)][:24] + [w for w in words if re.search(r"[가-힣]", w)])[:32]   # 영문(확장어 포함) 먼저
        ql = query.lower()
        words = [f"{p}" for p in PHRASES if p in ql] + words          # 구는 앞에(검색어 상한에 잘리지 않게)
        tw = list(dict.fromkeys(w for w in re.findall(r"[a-z][a-z0-9_.-]{2,}", query[:600].lower()) if w not in TITLE_STOP))[:12]
        lat_words = [w for w in words if not re.search(r"[가-힣]", w)]
        fts = self._fts(words, 150)
        idh = self._id_hits(ids)
        den = self._dense(qv, 150) if qv is not None else []
        sig_docs = self._sig_hits(query)                  # 로그 원문 ↔ KB 오류 문구 정확 일치
        if sig_docs:
            with self.lock:
                for r in self._db.execute(f"SELECT id FROM chunks WHERE ord=0 AND doc IN ({','.join('?' * len(sig_docs))})", list(sig_docs)):
                    idh[r["id"]] = idh.get(r["id"], 0) + 5
        if not fts and not idh and not den:
            return []
        rank: dict[int, float] = {}
        for lst in (fts, [(c, s, 0) for c, s in den]):
            for r, (cid, _s, _x) in enumerate(lst):
                rank[cid] = rank.get(cid, 0.0) + 1.0 / (60 + r)
        for cid, n in idh.items():
            rank[cid] = rank.get(cid, 0.0) + 0.02 * n
        cand = sorted(rank, key=lambda c: -rank[c])[:240]
        with self.lock:
            rows = {r["id"]: r for r in self._db.execute(
                f"SELECT c.id, c.doc, c.role, c.crumb, c.text, d.kind, d.kb, d.title, d.url, d.product, d.versions, d.updated, d.doc_type, d.summary, d.vendor, d.lang "
                f"FROM chunks c JOIN docs d ON d.id=c.doc WHERE c.id IN ({','.join('?' * len(cand))})", cand)}
        dmap = dict((c, s) for c, s in den)
        prods = SOURCE_PRODUCTS.get(source or "", set())
        envv = env or {}
        votes = self._votes(sig)
        intent_roles = {"analyze": {"cause": 1.1, "resolution": 1.25, "workaround": 1.2, "symptom": 1.1},
                        "chat": {"resolution": 1.2, "workaround": 1.15, "cause": 1.1},
                        "rca": {"cause": 1.25, "symptom": 1.1, "resolution": 1.1}}.get(intent, {})
        scored = []
        for cid in cand:
            r = rows.get(cid)
            if not r:
                continue
            low = (r["title"] + " " + r["crumb"] + " " + r["text"]).lower()
            ww = words if (r["lang"] or "en") == "ko" else lat_words      # 영문 문서는 한국어 낱말(번역 못 한 말)을 분모에서 뺀다
            matched = sum(1 for w in ww if w in low)
            bm_rel = matched / max(1, min(6, len(ww))) if ww else 0.0
            rel = max(min(1.0, bm_rel), dmap.get(cid, 0.0), 1.0 if idh.get(cid) else 0.0)
            if rel < self.min_rel:
                continue
            s = 0.65 * rel + 12 * rank[cid]
            tl = r["title"].lower()
            if tw:                                      # 제목이 질의를 많이 덮을수록 — KB 제목은 증상 요약이다(down·failure 같은 일반어 포함)
                s *= 1 + 0.35 * sum(1 for w in tw if w in tl) / max(1, min(7, len(tw)))
            s *= intent_roles.get(r["role"] or "", 1.0)
            if prods:
                s *= 1.2 if r["product"] in prods else (0.95 if r["product"] == "general" else 0.75)
            dv = set(json.loads(r["versions"] or "[]"))
            pv = set().union(*[envv.get(p, set()) for p in (prods or envv.keys())]) if envv else set()
            if dv and pv:
                s *= 1.15 if dv & pv else 0.85
            if r["doc"] in votes:
                s *= max(0.2, 1 + 0.25 * votes[r["doc"]]) if votes[r["doc"]] > 0 else max(0.2, 1 + 0.4 * votes[r["doc"]])
            if r["kind"] == "kb":
                s *= 1.05
            if r["doc"] in sig_docs:
                s *= 1.6
                rel = 1.0
            dt = r["doc_type"] or ""
            if intent in ("analyze", "rca") and "troubleshooting" in dt:
                s *= 1.1
            elif intent in ("analyze", "rca") and dt in ("release-notes", "landing", "concept"):
                s *= 0.85
            if (r["vendor"] or "vmware") not in self.home_vendors and r["product"] not in VMW_OTHER:   # CA·Symantec·메인프레임 등 다른 Broadcom 사업부
                s *= 0.7
            if (r["lang"] or "en") not in self.langs:                  # 같은 KB의 일본어·중국어 번역본은 뒤로
                s *= 0.8
            scored.append((s, rel, r))
        scored.sort(key=lambda x: -x[0])
        out, seen = [], set()
        for s, rel, r in scored:
            if r["doc"] in seen:
                continue
            seen.add(r["doc"])
            out.append(self._compose(r, s, rel, words, intent))
            if len(out) >= k:
                break
        return out

    def _compose(self, r, score: float, rel: float, words: list[str], intent: str) -> dict:
        """문서 단위 근거 — 맞은 청크 + 같은 문서의 증상·원인·해결·우회 구역(부모 문서 확장)"""
        with self.lock:
            secs = self._db.execute("SELECT role, crumb, text FROM chunks WHERE doc=? AND role IN ('symptom','cause','resolution','workaround','env') "
                                    "ORDER BY ord", (r["doc"],)).fetchall()
        by: dict[str, str] = {}
        for x in secs:
            if x["role"] not in by:
                by[x["role"]] = x["text"]
            elif len(by[x["role"]]) < 1800:
                by[x["role"]] = _join_overlap(by[x["role"]], x["text"])
        hit = r["text"]
        parts = []
        if r["role"] in ("", None, "info") or r["kind"] != "kb":
            parts.append(f"(일치 구역: {r['crumb'] or r['title']})\n{hit[:1800]}")
        order = ("symptom", "cause", "resolution", "workaround") if intent != "rca" else ("symptom", "cause", "resolution")
        for role in order:
            if role in by:
                parts.append(f"[{ROLE_KO[role]}]\n{by[role][:1600]}")
        if "env" in by:
            parts.append(f"[{ROLE_KO['env']}] {by['env'][:300]}")
        text = "\n\n".join(parts) or hit
        kb = r["kb"]
        title = r["title"] if not kb or kb in r["title"] else f"KB {kb} · {r['title']}"
        return {"pack": "library", "pack_name": "KB·TechDocs 라이브러리", "score": round(float(score), 3), "relevance": round(float(rel), 2),
                "title": title[:300], "url": r["url"] or "", "type": r["kind"] or "doc", "doc_id": f"lib:{r['doc']}", "kb": kb or "",
                "product": r["product"], "versions": json.loads(r["versions"] or "[]"), "updated": r["updated"] or "",
                "section": ROLE_KO.get(r["role"] or "", r["crumb"] or ""), "sections": [ROLE_KO[x] for x in ("symptom", "cause", "resolution", "workaround") if x in by],
                "text": text[:6000], "mode": "library", "doc_type": r["doc_type"] or "", "summary": (r["summary"] or "")[:400],
                "lang": r["lang"] or "en"}

    def doc(self, did: int) -> dict | None:
        with self.lock:
            d = self._db.execute("SELECT * FROM docs WHERE id=?", (did,)).fetchone()
            if not d:
                return None
            ch = self._db.execute("SELECT role, crumb, text FROM chunks WHERE doc=? ORDER BY ord", (did,)).fetchall()
        return {"id": did, "title": d["title"], "url": d["url"], "kind": d["kind"], "kb": d["kb"], "product": d["product"],
                "versions": json.loads(d["versions"] or "[]"), "updated": d["updated"], "path": d["path"],
                "doc_type": d["doc_type"] or "", "summary": d["summary"] or "", "signatures": json.loads(d["sigs"] or "[]"),
                "products": json.loads(d["products"] or "[]"), "segmentation": d["seg"] or "", "vendor": d["vendor"] or "", "lang": d["lang"] or "",
                "sections": _merge_chunks(ch)}

    def recent(self, days: float = 14, limit: int = 40, env: dict[str, set[str]] | None = None, mine: bool = False) -> list[dict]:
        """최근 갱신 KB·문서(front matter updated 기준) — 운영 중인 제품·버전에 해당하는 문서를 표시·우선(수집기 _changes 와 같은 시야)"""
        since = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))
        with self.lock:
            rows = self._db.execute("SELECT id, kind, kb, title, url, product, versions, updated, doc_type, summary, vendor, lang, sigs FROM docs "
                                    "WHERE updated >= ? ORDER BY updated DESC, id DESC LIMIT 3000", (since,)).fetchall()
        envv = env or {}
        out = []
        for r in rows:
            if (r["vendor"] or "vmware") not in self.home_vendors and r["product"] not in VMW_OTHER:
                continue
            if (r["lang"] or "en") not in self.langs:
                continue
            dv = set(json.loads(r["versions"] or "[]"))
            pv = set().union(*[envv[p] for p in DOC_ENV.get(r["product"], (r["product"],)) if p in envv]) if envv else set()
            hit = bool(pv) and (bool(dv & pv) if dv or r["kind"] != "kb" else True)     # TechDocs 는 버전이 맞아야, 버전 없는 KB 는 제품만 맞아도
            if mine and not hit:
                continue
            out.append({"doc_id": f"lib:{r['id']}", "kb": r["kb"] or "", "title": r["title"], "url": r["url"] or "", "type": r["kind"], "product": r["product"],
                        "versions": sorted(dv), "updated": r["updated"] or "", "doc_type": r["doc_type"] or "", "summary": (r["summary"] or "")[:300],
                        "signatures": len(json.loads(r["sigs"] or "[]")), "applies": hit, "matched": sorted(dv & pv) if hit and dv else []})
        out.sort(key=lambda x: (x["applies"] and bool(x["matched"]), x["applies"], x["updated"]), reverse=True)    # 버전 일치 → 제품 일치 → 나머지
        return out[:limit]

    def stats(self) -> dict:
        with self.lock:
            d = self._db.execute("SELECT COUNT(*) n, SUM(kind='kb') kb, SUM(kind='techdoc') td FROM docs").fetchone()
            c = self._db.execute("SELECT COUNT(*) n, SUM(vrow IS NOT NULL) v FROM chunks").fetchone()
            prods = {r["product"]: r["n"] for r in self._db.execute("SELECT product, COUNT(*) n FROM docs GROUP BY product ORDER BY n DESC LIMIT 20")}
            roots = {r["root"]: r["n"] for r in self._db.execute("SELECT root, COUNT(*) n FROM docs GROUP BY root")}
            fb = self._db.execute("SELECT COUNT(*) n FROM feedback").fetchone()["n"]
        return {"enabled": self.enabled, "docs": d["n"] or 0, "kb": d["kb"] or 0, "techdoc": d["td"] or 0, "chunks": c["n"] or 0,
                "embedded": c["v"] or 0, "vector_model": self._meta("vec_model"), "products": prods, "roots": roots,
                "paths": [str(p) for _, p in self.roots()], "configured_paths": list(self.cfg.get("paths") or []),
                "last_scan": float(self._meta("last_scan") or 0), "job": self.job, "feedback": fb, "gen": self.gen,
                "db_mb": round(sum(f.stat().st_size for f in self.root.glob("knowledge.db*")) / 2**20, 1),
                "vec_mb": round(self.vec_path.stat().st_size / 2**20, 1) if self.vec_path.exists() else 0}

    def close(self) -> None:
        self._stop = True


# ---------------------------------------------------------------- 답변 검증
KB_REF_RX = re.compile(r"\bKB\s?#?(\d{5,7})\b|knowledge\.broadcom\.com/external/article/(\d{5,7})|\bArticle(?: ID)?\s?#?(\d{5,7})\b", re.I)


def guard_kb_numbers(result: dict, refs: list[dict]) -> list[str]:
    """AI 답변에 근거 문서에 없는 KB 번호가 있으면 '(근거 없음)'으로 표시하고 목록을 돌려준다(환각 방지)"""
    allowed = set()
    for r in refs or []:
        if r.get("kb"):
            allowed.add(str(r["kb"]))
        for m in KB_REF_RX.finditer(f"{r.get('title', '')} {r.get('url', '')} {r.get('text', '')[:4000]}"):
            allowed.add(next(g for g in m.groups() if g))
    bad: list[str] = []

    def fix(s: str) -> str:
        def rep(m):
            n = next(g for g in m.groups() if g)
            if n in allowed:
                return m.group(0)
            bad.append(n)
            return f"{m.group(0)}(근거 문서 없음 — 확인 필요)"
        return KB_REF_RX.sub(rep, s)
    for k in ("summary", "probable_cause", "impact", "title"):
        if isinstance(result.get(k), str):
            result[k] = fix(result[k])
    if isinstance(result.get("actions"), list):
        result["actions"] = [fix(a) if isinstance(a, str) else a for a in result["actions"]]
    return sorted(set(bad))


def doc_sig(event: dict) -> str:
    """피드백 키 — 같은 로그 패턴(템플릿)이면 같은 키"""
    base = event.get("pattern") or event.get("template") or re.sub(r"\d+", "#", str(event.get("message", ""))[:200])
    return hashlib.sha1(f"{event.get('source', '')}|{base}".encode()).hexdigest()[:20]


def rrf_merge(*lists: list[dict], k: int = 6) -> list[dict]:
    """팩 결과 + 라이브러리 결과 — 순위 기반 병합(점수 척도가 달라도 공정하게)"""
    sc: dict[tuple, float] = {}
    keep: dict[tuple, dict] = {}
    for lst in lists:
        for i, r in enumerate(lst):
            key = (r.get("pack"), r.get("doc_id") or r.get("title"))
            sc[key] = sc.get(key, 0.0) + 1.0 / (10 + i) + (0.02 if r.get("kb") else 0.0)
            keep.setdefault(key, r)
    return [keep[x] for x in sorted(sc, key=lambda x: -sc[x])][:k]


def _cli(argv=None) -> None:
    """md 형식 점검: python -m app.knowledge inspect <파일|폴더> [--n 10]
       파일마다 종류·KB·제품·적용 버전·구역 역할·청크 수를 보여 준다(사내 수집기 형식이 잘 읽히는지 미리 확인)."""
    import argparse
    ap = argparse.ArgumentParser(prog="python -m app.knowledge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("inspect")
    i.add_argument("path")
    i.add_argument("--n", type=int, default=10)
    i.add_argument("--chunks", action="store_true", help="첫 파일의 청크 본문 출력")
    a = ap.parse_args(argv)
    root = Path(a.path)
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.suffix.lower() in MD_EXT
                                                  and not any(x.startswith((".", "_")) for x in p.relative_to(root).parts[:-1]))
    stat = {"kb": 0, "techdoc": 0, "doc": 0, "no_role": 0, "no_version": 0, "inferred": 0, "sigs": 0, "ja": 0}
    roles_n: dict[str, int] = {}
    for n, p in enumerate(files):
        d = parse_markdown(p.read_text(encoding="utf-8", errors="replace"), str(p))
        ch = chunk_sections(d)
        stat[d["kind"]] += 1
        stat["no_role"] += not any(s["role"] for s in d["sections"])
        stat["no_version"] += not d["versions"]
        stat["inferred"] += d.get("segmentation") == "inferred"
        stat["sigs"] += bool(d.get("signatures"))
        stat["ja"] += d.get("lang") == "ja"
        for r_ in {s_["role"] for s_ in d["sections"] if s_["role"]}:
            roles_n[r_] = roles_n.get(r_, 0) + 1
        if n < a.n:
            roles = [ROLE_KO.get(s["role"], s["role"]) for s in d["sections"] if s["role"]]
            print(f"· {p.name}  [{d.get('segmentation')}·{d.get('doc_type') or '-'}·{d.get('lang')}]\n  종류={d['kind']} KB={d['kb'] or '-'} 제품={d['product']} 버전={','.join(d['versions']) or '-'} 갱신={d['updated'] or '-'}"
                  f"\n  제목={d['title'][:90]}\n  URL={d['url'] or '-'}\n  구역={' / '.join(dict.fromkeys(roles)) or '(역할 없음 — 제목 계층만)'} · 청크 {len(ch)}")
            if a.chunks and n == 0:
                for c in ch[:6]:
                    print(f"  ── [{c['role'] or '-'}] {c['crumb'][:80]}\n{c['text'][:600]}\n")
    print(f"\n파일 {len(files)} · KB {stat['kb']} · TechDocs {stat['techdoc']} · 기타 {stat['doc']} · 구역 역할 없음 {stat['no_role']} · 버전 미검출 {stat['no_version']}"
          f"\n머리말 없는 KB 구역 추정 {stat['inferred']} · 오류 문구(error_signatures) 보유 {stat['sigs']} · 일본어 번역본 {stat['ja']}"
          f"\n구역 보유 문서: " + " · ".join(f"{ROLE_KO.get(k, k)} {v}" for k, v in sorted(roles_n.items(), key=lambda x: -x[1])))


if __name__ == "__main__":
    _cli()
