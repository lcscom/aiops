"""RVTools 분석 내보내기 — xlsx(점검·KISA·VMSA·VCF9·호스트·VM·데이터스토어) · 단독 HTML 보고서"""
from __future__ import annotations

import html
import time

from ..readiness.export import xlsx as _xlsx
from .analyze import SEV_KO

ST_KO = {"PASS": "적합", "FAIL": "부적합", "WARN": "주의", "MANUAL": "현장 확인", "N/A": "해당 없음"}
VD_KO = {"ready": "준비됨", "actions": "조치 필요", "not_ready": "준비 안 됨", "unknown": "확인 필요"}


def _ts(t) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if t else ""


def sheets(meta: dict, inv: dict, res: dict) -> list[tuple[str, list[list]]]:
    sm = res["summary"]
    c, cp, s = sm["counts"], sm["compute"], sm["storage"]
    summ = [["항목", "값"], ["파일", meta.get("name", "")], ["vCenter", ", ".join(f"{v['name']} ({v.get('fullname') or v.get('version', '')})" for v in sm["vcenters"])],
            ["RVTools 내보낸 시각", _ts(inv["meta"].get("exported"))], ["종합 점수", res["score"]], ["KISA 적합률(%)", res["hardening"]["score"]],
            ["클러스터·호스트·VM(켜짐/전체)", f"{c['clusters']} · {c['hosts']} · {c['vms_on']}/{c['vms']}"], ["템플릿", c["templates"]],
            ["물리 코어 · vCPU(켜짐) · 비율", f"{cp['cores']} · {cp['vcpu_on']} · {cp['ratio']}:1"], ["물리 메모리 GB · 할당(켜짐) GB", f"{cp['mem_gb']} · {cp['vram_on_gb']}"],
            ["데이터스토어 용량 TB · 여유 TB · 사용률", f"{s['cap_tb']} · {s['free_tb']} · {s['used_pct']}%"], ["VM 프로비전 TB · 사용 TB", f"{s['vm_prov_tb']} · {s['vm_used_tb']}"],
            ["점검 결과", ", ".join(f"{SEV_KO.get(k, k)} {v}" for k, v in res["counts"].items())],
            ["VCF 9 판정", ", ".join(f"{VD_KO.get(k, k)} {v}" for k, v in res["vcf9"]["verdicts"].items())],
            ["VCF 라이선스 코어(CPU당 최소 16)", res["vcf9"]["licensed_cores"]]]
    fnd = [["등급", "출처", "점검", "영역", "대상", "내용", "상세", "조치", "근거"]] + [
        [SEV_KO.get(f["severity"], f["severity"]), f.get("source", ""), f["id"], f["area"], f["entity"], f["title"], str(f.get("detail", "")), f.get("fix", ""), f.get("ref", "")]
        for f in res["findings"]]
    kisa = [["vCenter", "ID", "KISA", "항목", "결과", "대상", "현재", "기대값", "조치"]] + [
        [r.get("vcenter", ""), r.get("id", ""), r.get("kisa", ""), r.get("title", ""), ST_KO.get(r.get("status"), r.get("status")), r.get("target", ""),
         str(r.get("current", ""))[:300], str(r.get("expected", ""))[:300], str(r.get("fix", ""))[:500]] for r in res["hardening"]["rows"]]
    vmsa = [["대상", "제품", "버전", "빌드", "권고", "심각도", "CVSS", "CVE", "판정", "판단 근거", "URL"]] + [
        [r.get("target", ""), r.get("product", ""), r.get("version", ""), r.get("build", ""), r.get("vmsa", ""), r.get("severity", ""), r.get("cvss", ""),
         ", ".join(r.get("cves") or [])[:300], r.get("verdict", ""), r.get("why", ""), r.get("url", "")] for r in res["vmsa"]["rows"]]
    v9 = [["호스트", "클러스터", "제조사", "모델", "CPU", "CPU 계열", "VCF 9 CPU 등급", "ESXi", "최대 NIC Gb", "코어", "소켓", "라이선스 코어", "판정"]] + [
        [h["host"], h["cluster"], h["vendor"], h["model"], h["cpu"], h["cpu_family"], h["cpu_tier"], h["esx"], h["nic_gbps"], h["cores"], h["sockets"], h["licensed_cores"],
         VD_KO.get(h["verdict"], h["verdict"])] for h in res["vcf9"]["hosts"]]
    hosts = [["호스트", "클러스터", "제조사", "모델", "CPU", "소켓×코어", "메모리 GB", "CPU %", "메모리 %", "VM", "vCPU", "ESXi", "BIOS", "시리얼", "NTP", "EVC", "전원 정책", "인증서 만료"]] + [
        [hn, h["cluster"], h["vendor"], h["model"], h["cpu_model"], f"{h['sockets']}×{h['cores_per_cpu']}", round((h["mem_mb"] or 0) / 1024), h["cpu_pct"], h["mem_pct"], h["vms"],
         h["vcpus"], h["esx"], h["bios"], h["serial"], ", ".join(h["ntp"]), h["evc"], h["power_policy"], _ts(h["cert_expiry"])] for hn, h in inv["hosts"].items()]
    vms = [["VM", "전원", "템플릿", "vCPU", "메모리 GB", "프로비전 GB", "사용 GB", "OS", "HW", "Tools", "호스트", "클러스터", "IP", "네트워크", "CPU 준비 %"]] + [
        [v["name"], v["power"], "예" if v["template"] else "", v["vcpu"], round((v["mem_mb"] or 0) / 1024, 1), round((v["prov_mib"] or 0) / 1024, 1),
         round((v["used_mib"] or 0) / 1024, 1), v["os_tools"] or v["os_cfg"], v["hw"], v["tools"], v["host"], v["cluster"], v["ip"], ", ".join(v["networks"]), v["cpu_ready"]]
        for v in inv["vms"].values()]
    ds = [["데이터스토어", "유형", "용량 GB", "여유 GB", "여유 %", "프로비전 GB", "VM", "호스트 수"]] + [
        [dn, d["type"], round(d["cap_mib"] / 1024), round(d["free_mib"] / 1024), d["free_pct"], round(d["prov_mib"] / 1024), d["vms"], len(d["hosts"])]
        for dn, d in inv["datastores"].items()]
    cl = [["클러스터", "호스트", "코어", "켜진 VM", "vCPU", "vCPU:코어", "메모리 GB", "VM 메모리 GB", "메모리 사용 %", "N+1 메모리 %", "HA", "DRS"]] + [
        [x["name"], x["hosts"], x["cores"], x["vms_on"], x["vcpu"], x["ratio"], x["mem_gb"], x["vram_gb"], x["mem_used_pct"], x["n1_mem_pct"], "켬" if x["ha"] else "끔",
         f"{'켬' if x['drs'] else '끔'} {x['drs_behavior'] or ''}"] for x in sm["clusters"]]
    return [("요약", summ), ("점검 결과", fnd), ("KISA", kisa), ("VMSA", vmsa), ("VCF 9", v9), ("클러스터", cl), ("호스트", hosts), ("VM", vms), ("데이터스토어", ds)]


def xlsx(meta: dict, inv: dict, res: dict) -> bytes:
    return _xlsx(sheets(meta, inv, res))


def _tbl(rows: list[list]) -> str:
    if not rows:
        return ""
    h = "".join(f"<th>{html.escape(str(x))}</th>" for x in rows[0])
    b = "".join("<tr>" + "".join(f"<td>{html.escape('' if x is None else str(x))}</td>" for x in r) + "</tr>" for r in rows[1:])
    return f"<table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table>"


def _md(t: str) -> str:
    """AI 보고서(마크다운 일부: 제목·표·목록·굵게)를 안전한 HTML 로"""
    import re
    out, tbl = [], []

    def flush():
        if tbl:
            rows = [[c.strip() for c in r.strip().strip("|").split("|")] for r in tbl if not re.fullmatch(r"\s*\|?[\s:\-|]+\|?\s*", r)]
            out.append(_tbl(rows))
            tbl.clear()
    for ln in (t or "").splitlines():
        if ln.strip().startswith("|"):
            tbl.append(ln)
            continue
        flush()
        e = html.escape(ln)
        e = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", e)
        if ln.startswith("### "):
            out.append(f"<h4>{e[4:]}</h4>")
        elif ln.startswith("## "):
            out.append(f"<h3>{e[3:]}</h3>")
        elif ln.startswith("# "):
            out.append(f"<h3>{e[2:]}</h3>")
        elif re.match(r"\s*[-*] ", ln):
            out.append("<li>" + re.sub(r"^\s*[-*] ", "", e) + "</li>")
        elif e.strip():
            out.append(f"<p>{e}</p>")
    flush()
    return "\n".join(out)


def report_html(meta: dict, inv: dict, res: dict) -> str:
    sh = dict(sheets(meta, inv, res))
    ai = (meta.get("ai") or {}).get("report")
    css = ("body{font-family:'Pretendard','Malgun Gothic',system-ui,sans-serif;margin:24px;color:#1b2430;background:#fff}h1{font-size:22px}h2{font-size:17px;margin-top:28px;"
           "border-bottom:2px solid #1b2430;padding-bottom:4px}table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}th,td{border:1px solid #c9d1db;padding:4px 6px;"
           "text-align:left;vertical-align:top}th{background:#eef2f6}.m{color:#5b6775;font-size:12px}@media print{h2{page-break-before:auto}}")
    parts = [f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><title>RVTools 분석 — {html.escape(meta.get('name', ''))}</title><style>{css}</style></head><body>",
             f"<h1>RVTools 분석 보고서</h1><p class='m'>{html.escape(meta.get('name', ''))} · 기준 시각(RVTools 내보낸 시각) {_ts(res.get('evaluated'))} · 생성 {_ts(time.time())} · VCF AIOps</p>",
             "<h2>요약</h2>" + _tbl(sh["요약"])]
    if ai:
        parts.append("<h2>AI 진단(설정된 LLM)</h2>" + _md(ai) + f"<p class='m'>{html.escape((meta.get('ai') or {}).get('provider', ''))} · {_ts((meta.get('ai') or {}).get('at'))}</p>")
    parts += ["<h2>클러스터 용량</h2>" + _tbl(sh["클러스터"]), "<h2>점검 결과</h2>" + _tbl([r[:8] for r in sh["점검 결과"]]),
              "<h2>VCF 9 준비도</h2>" + _tbl(sh["VCF 9"]), "<h2>KISA 하이퍼바이저 보안</h2><p class='m'>" + html.escape(res["hardening"]["note"]) + "</p>" + _tbl(sh["KISA"]),
              "<h2>데이터스토어</h2>" + _tbl(sh["데이터스토어"]), "<h2>호스트</h2>" + _tbl(sh["호스트"]),
              "<p class='m'>근거: Broadcom KB 428874(ESX 9 CPU 지원), KB 418259(9.x 업그레이드 경로 — 상호운용성 매트릭스), KB 457561(빌드 출시일 기준 업그레이드 경로). "
              "RVTools 는 내보낸 시점의 스냅숏이며 ESXi 고급 설정·서비스·방화벽은 포함하지 않습니다.</p></body></html>"]
    return "\n".join(parts)
