"""제3자 소프트웨어 고지 생성기 — THIRD_PARTY_LICENSES.txt(라이선스 원문 모음)를 다시 만든다.

  python3 -m venv /tmp/rt && /tmp/rt/bin/pip install -r requirements.txt
  /tmp/rt/bin/python scripts/third_party.py > THIRD_PARTY_LICENSES.txt

배포물(OVA·패치·Ubuntu 설치)에 들어가는 런타임 Python 패키지는 requirements.txt 를 깨끗한 가상환경에 설치한 결과와 같다.
이 스크립트는 그 가상환경의 각 패키지 dist-info 에 들어 있는 라이선스 파일 원문을 그대로 모으고,
저장소에 동봉한 바이너리·폰트(govc 는 OVA 빌드 때 내려받음, WinSW, Pretendard)의 라이선스 원문을 덧붙인다.
의존성이 바뀌면 다시 실행하고 THIRD_PARTY_NOTICES.md 의 표도 함께 갱신한다.
"""
from __future__ import annotations

import importlib.metadata as md
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {"pip", "setuptools", "wheel"}
LIC_RX = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE)[^/]*$", re.I)
BUNDLED = [
    ("WinSW v2.12.0 (scripts/windows/bin/WinSW.NET461.exe)", ROOT / "scripts/windows/bin/WinSW-LICENSE.txt"),
    ("Pretendard Variable (app/static/fonts, extras/streamlit/static/fonts)", ROOT / "app/static/fonts/OFL.txt"),
    ("Noto Sans CJK KR subset (app/assets/fonts — SR PDF 보고서)", ROOT / "app/assets/fonts/OFL.txt"),
    ("BCG CPU Series data from vmware/vcf-readiness (app/assets/bcg_cpu_series.json — 하드웨어 준비도)", ROOT / "app/assets/LICENSE-vcf-readiness.txt"),
]


def license_of(m) -> str:
    lic = m.get("License-Expression") or ""
    if not lic:
        cls = [c.split(" :: ")[-1] for c in (m.get_all("Classifier") or []) if c.startswith("License ::")]
        lic = "; ".join(cls) or ((m.get("License") or "").splitlines() or [""])[0][:80]
    return lic


def main() -> None:
    out = ["VCF AIops — 제3자 소프트웨어 라이선스 원문(THIRD_PARTY_LICENSES.txt)",
           "생성: scripts/third_party.py · 목록과 설명은 THIRD_PARTY_NOTICES.md", ""]
    dists = sorted((d for d in md.distributions() if d.metadata["Name"].lower() not in SKIP),
                   key=lambda d: d.metadata["Name"].lower())
    for d in dists:
        m = d.metadata
        files = [f for f in (d.files or []) if LIC_RX.search(str(f))]
        out += ["=" * 78, f"{m['Name']} {d.version}  —  {license_of(m)}", "=" * 78]
        if not files:
            out += ["(패키지에 라이선스 파일이 들어 있지 않음 — 위 라이선스 표기와 프로젝트 저장소 참조)", ""]
            continue
        for f in files:
            try:
                txt = Path(d.locate_file(f)).read_text(encoding="utf-8", errors="replace").rstrip()
            except OSError:
                continue
            out += [f"--- {f}", txt, ""]
    for name, path in BUNDLED:
        out += ["=" * 78, name, "=" * 78, path.read_text(encoding="utf-8").rstrip(), ""]
    import os
    gov = Path(os.environ.get("GOVC_LICENSE", "/opt/vcf-aiops/licenses/govc-LICENSE.txt"))   # govc_Linux_x86_64.tar.gz 의 LICENSE.txt
    out += ["=" * 78, "govc v0.46.3 (VMware govmomi) — Apache-2.0 — OVA·Ubuntu 설치 시 /opt/vcf-aiops/bin/govc", "=" * 78,
            gov.read_text(encoding="utf-8").rstrip() if gov.exists() else
            "Apache License 2.0 — 원문은 이 저장소의 LICENSE 와 같다(https://github.com/vmware/govmomi/blob/main/LICENSE.txt).", ""]
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
