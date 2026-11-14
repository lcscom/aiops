"""LLM 클라이언트 — 여러 공급자(provider)를 같은 인터페이스로.

  openai    : VMware Private AI Services(PAIS)·vLLM·Ollama·OpenAI 등 OpenAI 호환 /chat/completions (기본: 사내 Gemma 4 31B)
  anthropic : Claude API  POST https://api.anthropic.com/v1/messages  (x-api-key, anthropic-version: 2023-06-01)
  gemini    : Gemini API  POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent (x-goog-api-key)

작업(task)별 라우팅: analyze(이상징후 판정) · rca(인시던트 근본원인) · chat(AI 질의) · brief(관제 브리핑) · report(리포트 요약).
기본 공급자가 실패하면 fallback 순서대로 다음 공급자 사용. 외부(인터넷) 공급자로 보낼 때는 IP·FQDN·호스트명을
가명(IP_1, HOST_1 …)으로 바꿔 보내고 응답에서 되돌린다(external_mask, 기본 켜짐 — 망분리·개인정보 보호).
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx

from .sanitize import GUARD, clean, strip_markers, wrap

SYSTEM_PROMPT = """너는 VMware Cloud Foundation(VCF 9.x) 운영 SRE이자 장애 분석가다.
대상 스택: vSphere(ESX/vCenter), vSAN, NSX, VCF Operations, VCF Operations for logs, VCF Automation,
SDDC Manager, Site Recovery Manager(VMware Live Site Recovery), Avi Load Balancer, 서버 BMC(iLO/iDRAC/Redfish).

입력으로 1차 탐지기가 걸러낸 '이상 후보' 로그와 같은 호스트/소스의 직전 로그(context)가 주어진다.
각 후보를 판정해 반드시 JSON 하나만 출력한다(마크다운·설명 금지).

스키마:
{"results":[{"id":"<후보 id>","is_anomaly":true|false,"severity":"critical|error|warning|info",
"category":"host|storage|network|cluster|vm|security|hardware|service|operation|dr|lb|capacity|general",
"title":"한 줄 제목(한국어, 40자 이내)","summary":"무슨 일이 일어났는지(한국어 2문장 이내)",
"probable_cause":"가장 가능성 높은 원인(한국어)","impact":"서비스/업무 영향(한국어)",
"actions":["즉시 확인·조치 단계(한국어, 구체 명령/메뉴/KB 키워드 포함)", "..."],
"references":["R1","R3"],"confidence":0.0~1.0}]}

판정 기준:
- 단발성 정보성 로그, 정상 작업 완료, 예정된 유지보수는 is_anomaly=false.
- 데이터 손실·서비스 중단·이중화 상실 가능성이 있으면 critical/error.
- 모르는 사실은 지어내지 말고 confidence를 낮춘다. 로그에 없는 호스트명/버전을 만들지 않는다.

참고 지식(knowledge):
- 후보마다 활성화된 RAG 팩(KB·VMSA·CVE·가이드)에서 검색한 문서가 knowledge[{ref,title,type,url,text}]로 주어질 수 있다.
- 로그 증상과 실제로 맞는 문서만 근거로 쓰고, 사용한 문서의 ref를 references에 넣는다. 관련 없으면 references=[].
- KB 번호·CVE·VMSA·패치 버전은 knowledge에 있는 것만 인용한다. knowledge에 없는 번호를 만들어내지 않는다.
- 취약점(CVE/VMSA) 문서가 맞으면 영향 버전·수정 버전·우회책을 actions에 반영한다.
- KB·TechDocs 문서는 [증상]·[원인]·[해결]·[우회] 구역으로 정리되어 온다. 로그가 [증상]과 맞으면:
  · probable_cause 는 [원인]을 근거로 쓰고 끝에 "(KB 번호 또는 문서 제목, Rn)"을 붙인다.
  · actions 는 [해결]·[우회]의 단계·명령(esxcli·vsish·nsxcli·API 경로·메뉴 경로)을 순서대로 구체적으로 옮긴다.
    문서의 명령은 그대로 쓰고, 영향이 큰 단계(재부팅·서비스 재시작·설정 변경)는 앞에 "[변경]"을 붙인다.
  · applies_to(적용 버전)가 로그·호스트 버전과 다르면 actions 첫 줄에 "적용 버전 확인 필요: …"를 쓴다.
  · 증상이 일부만 맞으면 confidence 를 낮추고 summary 에 "유사 사례"라고 밝힌다.

최근 변경(recent_vm_changes):
- 이상 직전 2시간 안에 대상 VM·같은 호스트에서 있었던 VM 변경(구성·전원·스냅샷·생성·삭제·이동·HA, 사용자·변경 내용 포함)이 주어질 수 있다.
- 시간·대상이 맞고 증상과 인과가 그럴듯하면 probable_cause 에 "직전 변경: …(시각, 사용자)"로 밝히고, 되돌리기·확인 단계를 actions 에 넣는다.
- 시간만 겹치고 인과 근거가 없으면 원인으로 단정하지 않는다(관련 가능성으로만 언급).

데이터 충실성:
- 입력에 없는 객체·수치·관계를 만들지 않는다. 관찰(로그에 있는 사실)과 해석(추정)을 구분해 쓴다.
- 상태·심각도 값은 원문 그대로 인용한다(번역·정규화 금지).
"""
SYSTEM_PROMPT += "\n" + GUARD


RCA_PROMPT = """너는 VMware Cloud Foundation 장애 분석가다. 인시던트 번들(묶인 이상징후, 로그 타임라인, vCenter 조사 번들,
토폴로지, RAG 근거 문서, vm_changes = 인시던트 전후 VM 변경 이력(구성·전원·스냅샷·생성·삭제·이동·HA·사용자·변경 창 여부))을 받아 근본원인을 분석한다.
변경과 증상의 시간 순서·대상이 맞으면 변경을 근본원인 후보로 검토하고, 근거(변경 시각·사용자·내용)를 criteria 에 인용한다. 아래 프로토콜(인과 사슬 + 4대 완결성 기준)을 반드시 따른다.

인과 사슬: 근본원인(root) → 전파(propagation) → 증폭(amplification, 없으면 빈 문자열) → 영향(impact)
완결성 기준 — 각각 근거(지표명·로그 원문·이벤트·문서 ref)를 제시하고, 근거가 부족하면 satisfied=false 와 필요한 추가 증거를 쓴다:
 1) falsifiability(반증 가능성): 독립적으로 측정·검증 가능한가
 2) sufficiency(충분성): 원인을 제거하면 증상이 사라지는가(반사실 근거)
 3) necessity(필요성): 원인이 있을 때마다 증상이 나타나는가(동일 조건의 정상 피어와 비교)
 4) mechanism(메커니즘): 전파 경로를 설명하는가
하나라도 충족되지 않으면 complete=false — 불완전한 결론을 완전한 것처럼 말하지 않는다. "재시작해보라"류 진단 생략 금지.
번들에 없는 객체·수치·KB 번호를 만들지 않는다. 조치는 영향이 적은 확인 단계부터, 쓰기 조치는 승인 필요 표시.

JSON 하나만 출력:
{"summary":"한국어 2~3문장","root_cause":"","propagation":"","amplification":"","impact":"",
 "criteria":{"falsifiability":{"satisfied":true,"evidence":""},"sufficiency":{"satisfied":true,"evidence":""},
             "necessity":{"satisfied":true,"evidence":""},"mechanism":{"satisfied":true,"evidence":""}},
 "complete":true,"missing_evidence":[""],"confidence":0.0,
 "next_checks":["추가 확인(읽기) 단계"],"remediation":[{"step":"","risk":"low|medium|high","requires_approval":false}],
 "references":["R1"],"related_entities":["호스트/VM/데이터스토어 이름"]}
"""


def _extract_json(text: str) -> dict[str, Any]:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            return json.loads(m.group(0))
        raise


TASKS = ("analyze", "rca", "chat", "brief", "report")
TYPES = {"openai": "OpenAI 호환(PAIS·vLLM·Ollama·OpenAI)", "pais_agent": "PAIS Agent Builder 에이전트(OpenAI 호환)", "anthropic": "Claude API(Anthropic)",
         "gemini": "Gemini API(Google)"}
PAIS_AGENT_PATH = "/api/v1/compatibility/openai/v1/agents/"
DEFAULT_URL = {"openai": "http://127.0.0.1:8000/v1", "pais_agent": "https://<pais>/api/v1/compatibility/openai/v1/agents/<agent-id>", "anthropic": "https://api.anthropic.com", "gemini": "https://generativelanguage.googleapis.com/v1beta"}
DEFAULT_MODEL = {"openai": "google/gemma-4-31B-it", "pais_agent": "agent", "anthropic": "claude-haiku-5-5", "gemini": "gemini-3.5-flash-lite"}

_IP = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
_FQDN = re.compile(r"\b(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.(?:lab|local|corp|internal|intra|lan|com|net|org|kr|io|co|biz|info|cloud|vcf|vmware|home|site|xyz)\b", re.I)


class Masker:
    """외부 공급자 전송용 가명화 — 같은 값은 같은 가명(IP_1, HOST_1), 응답에서 원래 값으로 복원"""

    def __init__(self, extra: list[str] | None = None):
        self.fwd: dict[str, str] = {}
        self.rev: dict[str, str] = {}
        self.extra = sorted({x for x in (extra or []) if x and len(x) >= 3}, key=len, reverse=True)

    def _tok(self, val: str, kind: str) -> str:
        t = self.fwd.get(val)
        if not t:
            t = f"{kind}_{sum(1 for v in self.fwd.values() if v.startswith(kind + '_')) + 1}"
            self.fwd[val] = t
            self.rev[t] = val
        return t

    def mask(self, text: str) -> str:
        text = _IP.sub(lambda m: self._tok(m.group(0), "IP"), text)
        text = _FQDN.sub(lambda m: self._tok(m.group(0), "HOST"), text)
        for x in self.extra:                                  # 호스트·개체 이름(짧은 이름 포함)
            if x in text and not x.startswith(("IP_", "HOST_", "NAME_")):
                text = re.sub(rf"(?<![\w.-]){re.escape(x)}(?![\w-])", self._tok(x, "NAME"), text)
        return text

    def unmask(self, obj: Any) -> Any:
        if not self.rev:
            return obj
        if isinstance(obj, str):
            return re.sub(r"\b(?:IP|HOST|NAME)_\d+\b", lambda m: self.rev.get(m.group(0), m.group(0)), obj)
        if isinstance(obj, list):
            return [self.unmask(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.unmask(v) for k, v in obj.items()}
        return obj


INTERNAL_SUFFIXES = (".local", ".lab", ".internal")


def host_internal(base_url: str, extra: Any = None) -> bool:
    """2.30.0 base_url 의 호스트가 사내인지 — 사설·루프백·링크로컬 IP, 점 없는 이름, .local/.lab/.internal, 설정한 접미사(llm.internal_suffixes).
    그 밖(공인 IP·일반 도메인·해석 불가)은 외부로 본다"""
    try:
        h = (urlsplit(base_url if "://" in base_url else "//" + base_url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not h:
        return False
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    if "." not in h:
        return True
    sfx = INTERNAL_SUFFIXES + tuple("." + str(x).strip().lower().strip(".") for x in (extra or []) if str(x).strip().strip("."))
    return h.endswith(sfx)


PUBLIC_AI = ("api.openai.com", "openai.azure.com", "api.anthropic.com", "generativelanguage.googleapis.com", "aiplatform.googleapis.com",
             "api.mistral.ai", "api.groq.com", "api.together.xyz", "openrouter.ai", "api.deepseek.com", "api.cohere.com", "api.cohere.ai",
             "api.perplexity.ai", "api.x.ai", "api.fireworks.ai", "bedrock-runtime", "inference.ai.azure.com", "api.upstage.ai", "clovastudio")


def _public_ai(url: str) -> bool:
    from urllib.parse import urlparse
    h = (urlparse(url if "//" in url else "https://" + url).hostname or "").lower()
    return any(h == x or h.endswith("." + x) or x in h for x in PUBLIC_AI)


class Provider:
    type = "openai"

    def __init__(self, pc: dict, common: dict):
        self.pc = pc
        self.name = str(pc.get("name") or self.type)
        self.model = str(pc.get("model") or DEFAULT_MODEL[self.type])
        self.base = str(pc.get("base_url") or DEFAULT_URL[self.type]).rstrip("/")
        self.key = str(pc.get("api_key") or "")
        self.enabled = pc.get("enabled", True) is not False
        # 외부 여부: 명시 설정(external)이 있으면 그 값. 없으면 Claude·Gemini 유형은 외부, OpenAI 호환은 주소로 판단(2.30.0 — api.openai.com 등 공인 주소는 외부·가명화)
        self.host_internal = host_internal(self.base, common.get("internal_suffixes"))
        self.external = bool(pc["external"]) if pc.get("external") is not None else (self.type != "openai" or not self.host_internal)
        # 2.36.0 — '사내(external:false)'로 저장했어도 주소가 알려진 공용 AI 서비스면 외부로 보고 가명화한다(설정 실수로 원문 유출 방지).
        #          사설 IP·내부 도메인이 아닌 그 밖의 주소는 고객 사내 도메인일 수 있어 화면 경고만(internal_suffixes 에 넣으면 사라짐).
        #          공용 서비스에 정말 가명화 없이 보내야 하면 allow_unmasked: true 를 명시
        self.forced_external = False
        if not self.external and not self.host_internal and _public_ai(self.base) and not pc.get("allow_unmasked"):
            self.external = self.forced_external = True
        self.max_tokens = int(pc.get("max_tokens") or common.get("max_tokens", 1200))
        self.temperature = float(pc.get("temperature", common.get("temperature", 0.1)))
        self.timeout = float(pc.get("timeout") or common.get("timeout", 120))
        self.tasks = set(pc.get("tasks") or TASKS)
        verify = pc["verify_tls"] if pc.get("verify_tls") is not None else (True if self.external else common.get("verify_tls", False))   # 외부는 기본 검증(공통 설정이 꺼져 있어도)
        self.http = httpx.AsyncClient(headers=self.headers(), verify=bool(verify),
                                      timeout=httpx.Timeout(self.timeout, connect=10))
        self.status: dict[str, Any] = {"name": self.name, "type": self.type, "model": self.model, "state": "unknown", "latency_ms": None,
                                       "last_error": "", "calls": 0, "failures": 0, "last_ok": None, "tokens": 0, "external": self.external,
                                       "host_internal": self.host_internal, "forced_external": self.forced_external}

    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.key:
            h["Authorization"] = f"Bearer {self.key}"
        return h

    def _ok(self, t0: float, tokens: int = 0) -> None:
        self.status.update(state="ok", latency_ms=int((time.perf_counter() - t0) * 1000), last_ok=time.time(), last_error="")
        self.status["tokens"] += int(tokens or 0)

    def _fail(self, e: Exception) -> None:
        self.status["failures"] += 1
        msg = f"{type(e).__name__}: {e}"
        if isinstance(e, httpx.HTTPStatusError):
            msg = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        self.status.update(state="down" if isinstance(e, httpx.TransportError) else "degraded", last_error=msg[:300])

    async def close(self) -> None:
        try:
            await self.http.aclose()
        except Exception:  # noqa: BLE001
            pass

    # ---- OpenAI 호환
    async def chat(self, system: str, messages: list[dict], json_mode: bool = False, max_tokens: int | None = None) -> str:
        body = {"model": self.model, "messages": [{"role": "system", "content": system}] + messages,
                "temperature": self.temperature, "max_tokens": int(max_tokens or self.max_tokens), "stream": False}
        if json_mode and self.pc.get("json_mode", True):
            body["response_format"] = {"type": "json_object"}
        body.update(self.pc.get("extra_body") or {})
        t0 = time.perf_counter()
        self.status["calls"] += 1
        try:
            r = await self.http.post(f"{self.base}/chat/completions", json=body)
            if r.status_code == 400 and "response_format" in r.text:
                self.pc["json_mode"] = False                  # JSON 모드 미지원 엔드포인트 → 자동 해제 후 재시도
                body.pop("response_format", None)
                r = await self.http.post(f"{self.base}/chat/completions", json=body)
            r.raise_for_status()
            j = r.json()
            self._ok(t0, (j.get("usage") or {}).get("total_tokens", 0))
            return j["choices"][0]["message"]["content"] or ""
        except Exception as e:
            self._fail(e)
            raise

    async def stream(self, system: str, messages: list[dict]) -> AsyncIterator[str]:
        body = {"model": self.model, "messages": [{"role": "system", "content": system}] + messages,
                "temperature": self.temperature, "max_tokens": self.max_tokens, "stream": True, **(self.pc.get("extra_body") or {})}
        self.status["calls"] += 1
        async with self.http.stream("POST", f"{self.base}/chat/completions", json=body) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    delta = json.loads(data)["choices"][0]["delta"].get("content")
                except Exception:  # noqa: BLE001
                    continue
                if delta:
                    yield delta

    async def health(self) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            r = await self.http.get(f"{self.base}/models")
            r.raise_for_status()
            ids = [m.get("id") for m in r.json().get("data", [])]
            ok = self.model in ids or not ids
            self.status.update(state="ok" if ok else "degraded", latency_ms=int((time.perf_counter() - t) * 1000), served_models=ids[:20],
                               last_error="" if ok else f"모델 '{self.model}' 미서빙 (가용: {', '.join(ids[:10])})")
        except Exception as e:  # noqa: BLE001
            self._fail(e)
        return self.status


class PaisAgentProvider(Provider):
    """PAIS Agent Builder 에이전트 — OpenAI 호환 엔드포인트 {PAIS}/api/v1/compatibility/openai/v1/agents/{agent_id} 의 /chat/completions.
    · 주소: PAIS 화면의 'base_url_for_agents' 를 그대로 붙여 넣거나, PAIS 주소 + agent_id(pc.agent_id)
    · model 값은 API 가 쓰지 않음(OpenAI 형식상 필요해 'agent' 기본) · 사내 공급자(가명화·외부 표시 없음)
    · 에이전트는 자체 지시문·지식을 가지므로 JSON 모드(response_format)는 보내지 않고, system 역할을 거부하면 사용자 메시지 앞에 붙여 재시도
    · 스트리밍을 지원하지 않으면(SSE 아님·4xx) 일반 응답으로 받아 한 번에 전달
    · 기본 작업: AI 질의(chat)·요약(brief)·리포트(report) — JSON 판정이 필요한 자동 분석·RCA 는 tasks 로 명시할 때만"""
    type = "pais_agent"

    def __init__(self, pc: dict, common: dict):
        pc = dict(pc)
        pc.setdefault("external", False)
        pc.setdefault("json_mode", False)
        pc.setdefault("tasks", ["chat", "brief", "report"])
        base = str(pc.get("base_url") or "").strip().rstrip("/")
        if base.endswith("/chat/completions"):
            base = base[: -len("/chat/completions")]
        if pc.get("agent_id") and "/agents/" not in base:
            base = base.split("/api/")[0] + PAIS_AGENT_PATH + str(pc["agent_id"]).strip()
        pc["base_url"] = base
        super().__init__(pc, common)
        self.system_mode = str(pc.get("system_mode") or "system")      # system | user(사용자 메시지 앞에 붙임)

    def _msgs(self, system: str, messages: list[dict]) -> list[dict]:
        if self.system_mode == "user" and messages:
            first = dict(messages[0])
            first["content"] = f"{system}\n\n---\n{first.get('content', '')}"
            return [first] + messages[1:]
        return [{"role": "system", "content": system}] + messages

    async def _post(self, body: dict) -> httpx.Response:
        r = await self.http.post(f"{self.base}/chat/completions", json=body)
        if r.status_code in (400, 422) and self.system_mode == "system" and ("system" in r.text.lower() or "role" in r.text.lower()):
            self.system_mode = "user"                                    # system 역할 미지원 → 사용자 메시지에 합쳐 재시도(이후 계속)
            sysmsg = body["messages"][0]["content"] if body["messages"] and body["messages"][0]["role"] == "system" else ""
            body = {**body, "messages": self._msgs(sysmsg, body["messages"][1:] if sysmsg else body["messages"])}
            r = await self.http.post(f"{self.base}/chat/completions", json=body)
        return r

    async def chat(self, system: str, messages: list[dict], json_mode: bool = False, max_tokens: int | None = None) -> str:
        body = {"model": self.model, "messages": self._msgs(system, messages), "temperature": self.temperature,
                "max_tokens": int(max_tokens or self.max_tokens), "stream": False, **(self.pc.get("extra_body") or {})}
        t0 = time.perf_counter()
        self.status["calls"] += 1
        try:
            r = await self._post(body)
            r.raise_for_status()
            j = r.json()
            self._ok(t0, (j.get("usage") or {}).get("total_tokens", 0))
            ch = (j.get("choices") or [{}])[0]
            return (ch.get("message") or {}).get("content") or ch.get("text") or ""
        except Exception as e:
            self._fail(e)
            raise

    async def stream(self, system: str, messages: list[dict]) -> AsyncIterator[str]:
        if self.pc.get("stream", True) is False or self.pc.get("_no_stream"):
            yield await self.chat(system, messages)
            return
        body = {"model": self.model, "messages": self._msgs(system, messages), "temperature": self.temperature,
                "max_tokens": self.max_tokens, "stream": True, **(self.pc.get("extra_body") or {})}
        self.status["calls"] += 1
        t0 = time.perf_counter()
        async with self.http.stream("POST", f"{self.base}/chat/completions", json=body) as r:
            if r.status_code >= 400 or "event-stream" not in r.headers.get("content-type", ""):
                raw = (await r.aread()).decode("utf-8", "replace")
                if r.status_code < 400:                                  # 스트리밍 무시하고 JSON 으로 응답한 경우
                    try:
                        j = json.loads(raw)
                        ch = (j.get("choices") or [{}])[0]
                        self._ok(t0)
                        yield (ch.get("message") or {}).get("content") or ch.get("text") or ""
                        return
                    except Exception:  # noqa: BLE001
                        pass
                self.pc["_no_stream"] = True                             # 이후엔 일반 호출
                self.status["calls"] -= 1
                yield await self.chat(system, messages)
                return
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                try:
                    ch = json.loads(data)["choices"][0]
                    delta = (ch.get("delta") or {}).get("content") or ch.get("text")
                except Exception:  # noqa: BLE001
                    continue
                if delta:
                    yield delta
            self._ok(t0)

    async def health(self) -> dict[str, Any]:
        """에이전트 엔드포인트는 /models 가 없을 수 있음 — 404·405 면 '호출 시 확인'(마지막 호출 성공이면 ok)"""
        t = time.perf_counter()
        try:
            r = await self.http.get(f"{self.base}/models")
            if r.status_code in (404, 405):
                self.status.update(state="ok" if self.status.get("last_ok") else "unknown", latency_ms=int((time.perf_counter() - t) * 1000),
                                   last_error="" if self.status.get("last_ok") else "에이전트 엔드포인트 — 연결 시험(짧은 생성)으로 확인")
                return self.status
            r.raise_for_status()
            self.status.update(state="ok", latency_ms=int((time.perf_counter() - t) * 1000), last_error="")
        except Exception as e:  # noqa: BLE001
            self._fail(e)
        return self.status


class AnthropicProvider(Provider):
    type = "anthropic"

    def headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "x-api-key": self.key, "anthropic-version": str(self.pc.get("api_version") or "2023-06-01")}

    def _body(self, system, messages, max_tokens, stream=False) -> dict:
        b = {"model": self.model, "system": system, "messages": messages, "max_tokens": int(max_tokens or self.max_tokens),
             "temperature": self.temperature}
        if stream:
            b["stream"] = True
        b.update(self.pc.get("extra_body") or {})
        return b

    async def chat(self, system, messages, json_mode=False, max_tokens=None) -> str:
        if json_mode:
            system += "\n\n반드시 JSON 객체 하나만 출력한다(앞뒤 설명·마크다운 금지)."
        t0 = time.perf_counter()
        self.status["calls"] += 1
        try:
            r = await self.http.post(f"{self.base}/v1/messages", json=self._body(system, messages, max_tokens))
            r.raise_for_status()
            j = r.json()
            u = j.get("usage") or {}
            self._ok(t0, (u.get("input_tokens") or 0) + (u.get("output_tokens") or 0))
            return "".join(b.get("text", "") for b in j.get("content") or [] if b.get("type") == "text")
        except Exception as e:
            self._fail(e)
            raise

    async def stream(self, system, messages) -> AsyncIterator[str]:
        self.status["calls"] += 1
        async with self.http.stream("POST", f"{self.base}/v1/messages", json=self._body(system, messages, None, True)) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                try:
                    j = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if j.get("type") == "content_block_delta" and (j.get("delta") or {}).get("type") == "text_delta":
                    yield j["delta"].get("text", "")

    async def health(self) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            if not self.key:
                raise ValueError("API 키 없음")
            r = await self.http.get(f"{self.base}/v1/models")
            r.raise_for_status()
            ids = [m.get("id") for m in r.json().get("data", [])]
            ok = not ids or self.model in ids or any(self.model in (i or "") for i in ids)
            self.status.update(state="ok" if ok else "degraded", latency_ms=int((time.perf_counter() - t) * 1000), served_models=ids[:20],
                               last_error="" if ok else f"모델 '{self.model}' 이 목록에 없음")
        except Exception as e:  # noqa: BLE001
            self._fail(e)
        return self.status


class GeminiProvider(Provider):
    type = "gemini"

    def headers(self) -> dict[str, str]:
        return {"Content-Type": "application/json", "x-goog-api-key": self.key}

    def _body(self, system, messages, max_tokens, json_mode=False) -> dict:
        gc = {"temperature": self.temperature, "maxOutputTokens": int(max_tokens or self.max_tokens)}
        if json_mode:
            gc["responseMimeType"] = "application/json"
        b = {"systemInstruction": {"parts": [{"text": system}]},
             "contents": [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]} for m in messages],
             "generationConfig": gc}
        b.update(self.pc.get("extra_body") or {})
        return b

    @staticmethod
    def _text(j: dict) -> str:
        out = []
        for c in j.get("candidates") or []:
            for p in (c.get("content") or {}).get("parts") or []:
                if p.get("text") and not p.get("thought"):
                    out.append(p["text"])
        return "".join(out)

    async def chat(self, system, messages, json_mode=False, max_tokens=None) -> str:
        t0 = time.perf_counter()
        self.status["calls"] += 1
        try:
            r = await self.http.post(f"{self.base}/models/{self.model}:generateContent", json=self._body(system, messages, max_tokens, json_mode))
            r.raise_for_status()
            j = r.json()
            self._ok(t0, (j.get("usageMetadata") or {}).get("totalTokenCount", 0))
            return self._text(j)
        except Exception as e:
            self._fail(e)
            raise

    async def stream(self, system, messages) -> AsyncIterator[str]:
        self.status["calls"] += 1
        async with self.http.stream("POST", f"{self.base}/models/{self.model}:streamGenerateContent", params={"alt": "sse"},
                                    json=self._body(system, messages, None)) as r:
            r.raise_for_status()
            async for line in r.aiter_lines():
                if not line.startswith("data:"):
                    continue
                try:
                    t = self._text(json.loads(line[5:].strip()))
                except ValueError:
                    continue
                if t:
                    yield t

    async def health(self) -> dict[str, Any]:
        t = time.perf_counter()
        try:
            if not self.key:
                raise ValueError("API 키 없음")
            r = await self.http.get(f"{self.base}/models/{self.model}")
            r.raise_for_status()
            self.status.update(state="ok", latency_ms=int((time.perf_counter() - t) * 1000), last_error="")
        except Exception as e:  # noqa: BLE001
            self._fail(e)
        return self.status


PROVIDERS = {"openai": Provider, "pais_agent": PaisAgentProvider, "anthropic": AnthropicProvider, "gemini": GeminiProvider}


def provider_defs(cfg: dict) -> list[dict]:
    """설정 → 공급자 목록. 기존(1.4 이하) 단일 설정(base_url·model·api_key)은 'local' 공급자로 자동 변환."""
    defs = [dict(p) for p in (cfg.get("providers") or []) if isinstance(p, dict) and p.get("name")]
    if cfg.get("base_url") and not any(p["name"] == "local" for p in defs):
        defs.insert(0, {"name": "local", "type": "openai", "base_url": cfg["base_url"], "api_key": cfg.get("api_key", ""),
                        "model": cfg.get("model"), "json_mode": cfg.get("json_mode", True), "extra_body": cfg.get("extra_body") or {},
                        "verify_tls": cfg.get("verify_tls", False), "external": False})
    for p in defs:
        p["type"] = p.get("type") if p.get("type") in PROVIDERS else "openai"
    return defs


class LLMClient:
    def __init__(self, cfg: dict):
        self.providers: dict[str, Provider] = {}
        self.gov = None                                       # aigov.Governor — 엔진이 주입
        self.configure(cfg)

    def configure(self, cfg: dict) -> None:
        old = self.providers
        self.cfg = cfg
        self.providers = {}
        for d in provider_defs(cfg):
            self.providers[d["name"]] = PROVIDERS[d["type"]](d, cfg)
        for p in old.values():                                # 이전 HTTP 연결 정리
            try:
                import asyncio
                asyncio.get_running_loop().create_task(p.close())
            except RuntimeError:
                pass
        self.routing = {t: (cfg.get("routing") or {}).get(t) for t in TASKS}
        self.fallback = cfg.get("fallback", True) is not False
        self.mask_external = cfg.get("external_mask", True) is not False
        self.last_used: dict[str, str] = {}

    # ---- 라우팅
    def order(self, task: str) -> list[Provider]:
        en = [p for p in self.providers.values() if p.enabled and task in p.tasks]
        first = self.providers.get(self.routing.get(task) or cfg_first(self.cfg) or "")
        out = [first] if first and first.enabled else []
        if self.fallback or not out:
            out += [p for p in en if p not in out]
        return out

    def primary(self, task: str = "analyze") -> Provider | None:
        o = self.order(task)
        return o[0] if o else None

    @property
    def status(self) -> dict[str, Any]:
        p = self.primary("analyze")
        base = dict(p.status) if p else {"state": "disabled", "model": "", "last_error": "공급자 없음"}
        base["provider"] = p.name if p else ""
        base["providers"] = {n: x.status for n, x in self.providers.items()}
        base["routing"] = {t: (self.primary(t).name if self.primary(t) else "") for t in TASKS}
        return base

    async def health(self) -> dict[str, Any]:
        for p in self.providers.values():
            if p.enabled:
                await p.health()
        return self.status

    def _sys(self, system: str, lang: str | None) -> str:
        lang = (lang or self.cfg.get("language") or "ko").lower()
        if lang.startswith("en"):
            return system.replace("한국어", "English") + "\n\nIMPORTANT: Write every human-readable value in English. Keep JSON keys exactly as specified."
        return system

    async def _run(self, task: str, system: str, user: str, json_mode: bool = False, max_tokens: int | None = None,
                   lang: str | None = None, names: list[str] | None = None, only: str | None = None,
                   interactive: bool = False, governed: bool = True) -> tuple[str, Provider, Masker | None]:
        order = [self.providers[only]] if only and only in self.providers else self.order(task)
        if not order:
            raise RuntimeError("사용 가능한 LLM 공급자가 없습니다")
        err: Exception | None = None
        for p in order:
            mk = Masker(names) if p.external and self.mask_external else None
            u = mk.mask(user) if mk else user
            try:
                if self.gov and (governed or p is not order[0]):
                    await self.gov.acquire(p, interactive)
                text = await p.chat(self._sys(system, lang), [{"role": "user", "content": u}], json_mode=json_mode, max_tokens=max_tokens)
                self.last_used[task] = f"{p.name}:{p.model}"
                return text, p, mk
            except Exception as e:  # noqa: BLE001
                err = e
                continue
        raise err or RuntimeError("LLM 호출 실패")

    # ---- 작업
    async def analyze(self, candidates: list[dict[str, Any]], only: str | None = None, interactive: bool = False,
                      governed: bool = True) -> dict[str, dict[str, Any]]:
        """candidates: [{id, event, context, refs}] → {id: result}  (result['_provider'], ['_model'] 포함)"""
        payload, names = [], []
        for c in candidates:
            e = c["event"]
            names += [e.get("host") or "", e.get("entity") or ""] + list(c.get("change_names") or [])
            payload.append({
                "id": c["id"],
                "source": e["source"], "connector": e["connector"], "kind": e["kind"],
                "severity_raw": e["severity"],
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])),
                "message": wrap(e["message"], 1500),
                "host": clean(e["host"], 200), "entity": clean(e["entity"], 200),
                "detector_reasons": c.get("reasons", []),
                "knowledge": [{"ref": r["ref"], "title": r["title"], "type": r["type"], "url": r["url"],
                               **({"kb": r["kb"]} if r.get("kb") else {}),
                               **({"applies_to": r["versions"]} if r.get("versions") else {}),
                               **({"sections": r["sections"]} if r.get("sections") else {}),
                               "text": wrap(r["text"], int(self.cfg.get("max_chars_per_lib_ref", 2400) if r.get("pack") == "library"
                                                           else self.cfg.get("max_chars_per_ref", 1200)), "UNTRUSTED_DOC")}
                              for r in c.get("refs", [])],
                "context": [f"{time.strftime('%H:%M:%S', time.localtime(x['ts']))} [{x['severity']}] {wrap(x['message'], 300)}"
                            for x in c.get("context", [])],
                **({"recent_vm_changes": [wrap(x, 300) for x in c["changes"]]} if c.get("changes") else {}),
            })
        text, p, mk = await self._run("analyze", SYSTEM_PROMPT, "이상 후보:\n" + json.dumps(payload, ensure_ascii=False),
                                      json_mode=True, names=names, only=only, interactive=interactive, governed=governed)
        try:
            data = _extract_json(text)
        except Exception as e:
            p._fail(ValueError(f"JSON 해석 실패: {e}"))
            raise
        out = {}
        for x in data.get("results", []):
            if isinstance(x, dict):
                x = strip_markers(mk.unmask(x) if mk else x)
                x["_provider"], x["_model"] = p.name, p.model
                out[str(x.get("id"))] = x
        return out

    async def rca(self, bundle: dict[str, Any], interactive: bool = True) -> dict[str, Any]:
        """인시던트 근본원인 분석 — VMware-AIops investigation-protocol(인과 사슬 + 4대 완결성 기준) 적용"""
        t = time.perf_counter()
        bundle = dict(bundle)
        names = list(bundle.pop("mask_names", None) or [])          # 외부 AI 가명화 대상(번들에는 싣지 않음)
        inc = bundle.get("incident") or {}
        names += list(inc.get("hosts") or []) + [inc.get("primary_entity") or "", inc.get("cluster") or ""]
        names += [x for a in bundle.get("anomalies") or [] for x in (a.get("host") or "", a.get("entity") or "")]
        raw = json.dumps(bundle, ensure_ascii=False, default=str)[:60000]
        text, p, mk = await self._run("rca", RCA_PROMPT + "\n" + GUARD, raw, json_mode=True,
                                      max_tokens=int(self.cfg.get("rca_max_tokens", 2500)), interactive=interactive, names=names)
        data = strip_markers(_extract_json(text))
        data = mk.unmask(data) if mk else data
        data["_latency_ms"] = int((time.perf_counter() - t) * 1000)
        data["_model"] = p.model
        data["_provider"] = p.name
        return data

    async def complete(self, system: str, user: str, max_tokens: int = 800, task: str = "brief", names: list[str] | None = None) -> str:
        text, p, mk = await self._run(task, system + "\n" + GUARD, user, max_tokens=max_tokens, names=names)
        text = strip_markers(re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip())
        return mk.unmask(text) if mk else text

    async def chat_stream(self, question: str, context: str, lang: str | None = None, names: list[str] | None = None,
                          system: str | None = None) -> AsyncIterator[str]:
        """system 을 주면 기본 SRE 답변 형식 대신 그 지시를 쓴다(RVTools 분석 Q&A 등). names = 외부 공급자일 때 추가 가명화 대상"""
        order = self.order("chat")
        if not order:
            raise RuntimeError("사용 가능한 LLM 공급자가 없습니다")
        p = order[0]
        if self.gov:
            await self.gov.acquire(p, interactive=True, max_wait=30)
        mk = Masker(names) if p.external and self.mask_external else None
        system = (system + "\n" + GUARD + "\n\n" + (mk.mask(context) if mk else context)) if system else ("너는 VMware VCF(vSphere·vSAN·NSX·Avi·VKS) 운영 SRE다. 아래 컨텍스트(질문 대상·이상징후·로그·성능 SLI)와 근거 문서만 써서 한국어로 답한다.\n"
                  "근거 우선순위: ① '질문 대상' 절의 실제 상태·로그 ② 사내 KB·TechDocs [R#] ③ 웹 검색 [W#](공식 Broadcom/VMware 문서 > 커뮤니티·블로그) ④ Isvara [I1].\n"
                  "답변 형식(근거가 없는 항목은 쓰지 말고 건너뛴다 — '없습니다'로 칸을 채우지 않는다):\n"
                  "**결론** — 지금 무슨 상태이고 무엇이 문제(또는 문제 없음)인지 1~2문장.\n"
                  "**근거** — 판단에 쓴 로그 원문·상태 값·수치를 시각과 함께 2~5개(관찰과 추정을 구분).\n"
                  "**원인** — 문서 근거가 있으면 [R#]/[W#] 인용, 없으면 '추정'이라고 밝힌다.\n"
                  "**조치** — 번호 목록. 먼저 읽기 전용 확인(UI 메뉴 경로·esxcli/vsish/esxtop·로그 위치), 다음 해결. 문서에 있는 명령은 그대로, 영향 큰 단계(재부팅·서비스 재시작·설정 변경)는 앞에 [변경].\n"
                  "**참고** — 실제로 인용한 문서만 KB 번호·제목·URL.\n"
                  "규칙: '질문 대상' 절이 있으면 그 개체 근거를 최우선으로 쓰고 다른 개체의 로그와 섞지 않는다. "
                  "상태 값은 원문 그대로 해석한다 — Green·Normal·OK·정상·connected 는 정상이며 경고로 해석하지 않는다(Yellow·Red·Unknown 만 문제). "
                  "질문 증상과 맞지 않는 문서는 인용하지 않는다. 웹 근거는 내용·적용 버전이 질문과 맞을 때만 쓰고, 출처 URL 을 함께 쓴다. "
                  "문서·웹 근거 어디에도 없는 KB 번호·CVE·명령 옵션은 만들지 않는다. 확신이 낮으면 무엇을 더 확인하면 되는지 말한다. "
                  + GUARD + "\n\n" + (mk.mask(context) if mk else context))
        buf = ""
        async for tok in p.stream(self._sys(system, lang), [{"role": "user", "content": mk.mask(question) if mk else question}]):
            if not mk:
                yield tok
                continue
            buf += tok                                         # 가명 토큰이 조각나 오지 않게 단어 경계까지 모아서 복원
            cut = max(buf.rfind(" "), buf.rfind("\n"))
            if cut > 0:
                yield mk.unmask(buf[:cut + 1])
                buf = buf[cut + 1:]
        if buf:
            yield mk.unmask(buf) if mk else buf
        p.status["last_ok"] = time.time()

    async def test(self, name: str) -> dict[str, Any]:
        """설정 화면 '연결 시험' — 상태 조회 + 짧은 생성 1회"""
        p = self.providers.get(name)
        if not p:
            return {"ok": False, "error": "공급자 없음"}
        st = await p.health()
        t0 = time.perf_counter()
        try:
            txt = await p.chat("짧게 답한다.", [{"role": "user", "content": "Reply with the single word: OK"}], max_tokens=200)
            return {"ok": True, "state": st.get("state"), "reply": txt.strip()[:60], "latency_ms": int((time.perf_counter() - t0) * 1000),
                    "model": p.model, "warning": st.get("last_error", "")}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": p.status.get("last_error") or f"{type(e).__name__}: {e}"[:300], "model": p.model}


def cfg_first(cfg: dict) -> str:
    """작업 라우팅이 비어 있을 때 기본 공급자 — llm.provider, 없으면 첫 번째"""
    if cfg.get("provider"):
        return str(cfg["provider"])
    d = provider_defs(cfg)
    return d[0]["name"] if d else ""
