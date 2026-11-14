# 제3자 소프트웨어 고지(Third-Party Notices)

VCF AIops 는 [Apache License 2.0](LICENSE) 으로 배포되며, 아래 오픈소스 소프트웨어를 사용합니다. 각 구성요소는 **그 구성요소의 라이선스**를 따르고, 이 저장소의 라이선스가 그 조건을 바꾸지 않습니다.
라이선스 원문은 [THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt)(각 패키지에 동봉된 원문을 그대로 모음, `scripts/third_party.py` 로 생성)에 있습니다.

기준: 2.11.0(2.11.0 에서 fpdf2·fonttools·Pillow·defusedxml 추가 — 지원 요청 PDF 보고서, 2.4.1 에서 asyncssh 추가 — eAPI 를 못 쓰는 스위치 SSH 수집) · requirements.txt 를 Python 3.12 깨끗한 가상환경에 설치한 결과와 OVA 이미지(`/opt/vcf-aiops/venv`)를 대조해 일치함을 확인.

## 1. 배포물에 포함되는 구성요소

배포물 = OVA 어플라이언스, 서명 패치(`.tgz`), Ubuntu·Windows 설치본, Docker 이미지. 소스 저장소 자체에는 아래 2)·3)의 바이너리·폰트만 들어 있고, 1)·4)는 설치·빌드 때 내려받습니다.

### 1) Python 런타임 패키지(38개, 전이 의존성 포함)

| 패키지 | 버전 | 라이선스 | 용도 |
|---|---|---|---|
| [annotated-doc](https://github.com/fastapi/annotated-doc) | 0.0.5 | MIT | FastAPI 하위 |
| [annotated-types](https://github.com/annotated-types/annotated-types) | 0.8.0 | MIT | pydantic 하위 |
| [anyio](https://github.com/agronholm/anyio) | 4.15.1 | MIT | 비동기 I/O(httpx·starlette) |
| [beautifulsoup4](https://www.crummy.com/software/BeautifulSoup/bs4/) | 4.15.0 | MIT | RAG 빌더 HTML 정제 |
| [asyncssh](https://github.com/ronf/asyncssh) | 2.24.1 | EPL-2.0 OR GPL-2.0-or-later | 스위치 SSH CLI 수집(2.4.1, 수정 없이 사용 — EPL-2.0 선택) |
| [certifi](https://github.com/certifi/python-certifi) | 2026.7.22 | MPL-2.0 | CA 번들(httpx) |
| [cffi](https://github.com/python-cffi/cffi) | 2.1.1 | MIT-0 | cryptography 하위 |
| [click](https://github.com/pallets/click/) | 8.5.0 | BSD-3-Clause | uvicorn CLI |
| [cryptography](https://github.com/pyca/cryptography) | 50.0.2 | Apache-2.0 OR BSD-3-Clause | 설정 암호화(Fernet)·SNMPv3·인증서 |
| [defusedxml](https://github.com/tiran/defusedxml) | 0.7.1 | PSF-2.0 | fpdf2 하위(안전한 XML 파싱) |
| [fastapi](https://github.com/fastapi/fastapi) | 0.143.0 | MIT | 웹 프레임워크·REST API |
| [fonttools](https://github.com/fonttools/fonttools) | 4.67.0 | MIT | fpdf2 하위(PDF 글꼴 서브셋) |
| [fpdf2](https://github.com/py-pdf/fpdf2) | 2.8.9 | LGPL-3.0-only | 지원 요청(SR) PDF 보고서(2.11.0) |
| [h11](https://github.com/python-hyper/h11) | 0.16.0 | MIT | HTTP/1.1(httpcore·uvicorn) |
| [httpcore](https://www.encode.io/httpcore/) | 1.0.9 | BSD-3-Clause | httpx 하위 |
| [httptools](https://github.com/MagicStack/httptools) | 0.9.0 | MIT | HTTP 파서(uvicorn) |
| [httpx](https://github.com/encode/httpx) | 0.28.1 | BSD-3-Clause | REST 커넥터·LLM·웹훅 HTTP 클라이언트 |
| [idna](https://github.com/kjd/idna) | 3.20 | BSD-3-Clause | 국제화 도메인(httpx) |
| [ldap3](https://github.com/cannatag/ldap3) | 2.9.1 | LGPL-3.0 | AD/LDAP 로그인 |
| [numpy](https://numpy.org) | 2.5.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | 임베딩 벡터·통계 |
| [opentelemetry-api](https://github.com/open-telemetry/opentelemetry-python/tree/main/opentelemetry-api) | 1.45.1 | Apache-2.0 | FastAPI 하위(추적 API, 이 프로젝트는 계측하지 않음) |
| [Pillow](https://github.com/python-pillow/Pillow) | 13.0.0 | MIT-CMU | fpdf2 하위(이미지) |
| [pyasn1](https://github.com/pyasn1/pyasn1) | 0.6.4 | BSD-2-Clause | ASN.1(pysnmp·ldap3) |
| [pycparser](https://github.com/eliben/pycparser) | 3.11 | BSD-3-Clause | cffi 하위 |
| [pydantic](https://github.com/pydantic/pydantic) | 2.14.1 | MIT | 요청·설정 모델(FastAPI) |
| [pydantic_core](https://github.com/pydantic) | 2.50.1 | MIT | pydantic 하위 |
| [pypdf](https://github.com/py-pdf/pypdf) | 6.20.0 | BSD-3-Clause | RAG 빌더 PDF |
| [pysnmp](https://pysnmp.com) | 7.1.30 | BSD-2-Clause | SNMP 트랩 수신(v1/v2c/v3) · 네트워크 장비 SNMP 폴링(2.2) |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | 1.2.4 | BSD-3-Clause | .env 읽기(uvicorn[standard]) |
| [pyvmomi](https://developer.broadcom.com/sdks/pyvmomi/latest) | 9.1.1.0 | Apache-2.0 | vCenter SOAP(이벤트·알람·인벤토리) |
| [PyYAML](https://github.com/yaml/pyyaml) | 6.0.3 | MIT | config.yaml |
| [segno](https://github.com/heuer/segno) | 1.6.6 | BSD-3-Clause | MFA 등록 QR 코드(SVG) |
| [soupsieve](https://github.com/facelessuser/soupsieve) | 3.0.2 | MIT | beautifulsoup4 하위 |
| [starlette](https://github.com/Kludex/starlette) | 1.7.0 | BSD-3-Clause | ASGI 기반(FastAPI 하위) |
| [typing-inspection](https://github.com/pydantic/typing-inspection) | 0.4.4 | MIT | pydantic 하위 |
| [typing_extensions](https://github.com/python/typing_extensions) | 4.16.0 | PSF-2.0 | 타입 보조 |
| [uvicorn](https://uvicorn.dev/) | 0.54.0 | BSD-3-Clause | ASGI 서버 |
| [uvloop](https://github.com/MagicStack/uvloop) | 0.23.0 | Apache-2.0 OR MIT | 이벤트 루프(Linux) |
| [watchfiles](https://github.com/samuelcolvin/watchfiles) | 1.3.0 | MIT | 파일 감시(uvicorn[standard], 운영 미사용) |
| [websockets](https://github.com/python-websockets/websockets) | 17.2 | BSD-3-Clause | WebSocket(uvicorn) |

라이선스 표기(SPDX)는 각 패키지 메타데이터 기준이며, 표기가 없는 pysnmp 는 동봉 원문(BSD 2조항)으로 판단했습니다.

**LGPL 고지 — ldap3**: ldap3(LGPL-3.0)는 수정 없이 별도 Python 패키지로 동적으로 불러 씁니다. 사용자는 `/opt/vcf-aiops/venv` 의 ldap3 를 다른 버전(같은 인터페이스)으로 교체할 수 있으며, 원본 소스는 <https://github.com/cannatag/ldap3> · PyPI 에서 받을 수 있습니다. 라이선스 원문(COPYING.txt·COPYING.LESSER.txt)은 THIRD_PARTY_LICENSES.txt 에 있습니다.

**LGPL 고지 — fpdf2**: fpdf2(LGPL-3.0)는 수정 없이 별도 Python 패키지로 동적으로 불러 씁니다(지원 요청 PDF). 사용자는 `/opt/vcf-aiops/venv` 의 fpdf2 를 같은 인터페이스의 다른 버전으로 교체할 수 있으며, 원본 소스는 <https://github.com/py-pdf/fpdf2> · PyPI 에서 받을 수 있습니다. 라이선스 원문은 THIRD_PARTY_LICENSES.txt 에 있습니다.

**MPL-2.0 고지 — certifi**: 수정 없이 사용합니다. 소스: <https://github.com/certifi/python-certifi>.

### 2) 동봉 바이너리·실행 파일

| 구성요소 | 버전 | 라이선스 | 위치·용도 |
|---|---|---|---|
| [govc (VMware govmomi)](https://github.com/vmware/govmomi) | v0.46.3 | Apache-2.0 | OVA·Ubuntu 설치 시 내려받아 SHA-256 확인 후 `/opt/vcf-aiops/bin/govc` — '수집 전용 계정 만들기'의 vCenter SSO 사용자 생성. 라이선스 원문 `/opt/vcf-aiops/licenses/govc-LICENSE.txt` |
| [WinSW](https://github.com/winsw/winsw) | v2.12.0 | MIT | `scripts/windows/bin/WinSW.NET461.exe` — Windows 서비스 래퍼. 원문 `scripts/windows/bin/WinSW-LICENSE.txt` |

### 3) 글꼴

| 구성요소 | 라이선스 | 위치 |
|---|---|---|
| [Pretendard Variable](https://github.com/orioncactus/pretendard) — Copyright (c) 2021 Kil Hyung-jin (RFN 'Pretendard'); 포함 글리프 Copyright 2014-2021 Adobe (RFN 'Source'), Copyright (c) 2016 The Inter Project Authors (RFN 'Inter'), Copyright 2021 The M+ FONTS Project Authors (RFN 'M PLUS 1') | SIL Open Font License 1.1 | `app/static/fonts/PretendardVariable.woff2`(원문 `OFL.txt`), `extras/streamlit/static/fonts/` |
| [Noto Sans CJK KR](https://github.com/notofonts/noto-cjk) Regular·Bold — © 2014-2021 Adobe, Noto 는 Google LLC 의 상표 — Latin·한글 음절/자모·기본 기호만 남긴 서브셋(2.11.0, 지원 요청 PDF 에 내장) | SIL Open Font License 1.1 | `app/assets/fonts/NotoSansKR-*-sub.otf`(원문 `app/assets/fonts/OFL.txt`) |

### 3-1) 데이터

| 구성요소 | 라이선스 | 위치 |
|---|---|---|
| Broadcom Compatibility Guide CPU Series 목록(ESXi 9.1, 2026-07-22 내보내기) — [vmware/vcf-readiness](https://github.com/vmware/vcf-readiness) `hcl/CPU Series_07-22-2026.csv` 에서 CPUID·시리즈 이름만 JSON 으로 변환(2.14.0 하드웨어 준비도) | CA, Inc. Software License Agreement(CA 제품과 함께 사용하는 조건으로 사용·복제·수정·배포 허용, 저작권 고지 포함) | `app/assets/bcg_cpu_series.json`(원문 `app/assets/LICENSE-vcf-readiness.txt`) |

하드웨어 준비도(`app/readiness/`)는 vcf-readiness 를 설계 참고로만 삼아 새로 작성했으며 그 코드를 복사하지 않았습니다.

라이선스 관리(`app/license/`, `app/static/license.js`, 2.16.0)는 [postout7979/VCF-Lic-MGMT](https://github.com/postout7979/VCF-Lic-MGMT)(MIT License, Copyright (c) 2026 postout7979)의 기능·데이터 형식(공급자·CSP 엑셀 열 이름, CSP 'Quantity' 분해, vCenter costUnit 구분, VCF Operations 사용량 보고서 해석)을 참고해 이 제품 구조에 맞게 새로 작성했습니다. MIT 고지 원문: `app/assets/LICENSE-VCF-Lic-MGMT.txt`.

화면은 이 외에 외부 CDN·JavaScript 라이브러리를 쓰지 않습니다(정적 파일은 모두 이 저장소에서 작성).

### 4) OVA 어플라이언스 운영체제 — Ubuntu 24.04 LTS

OVA 에는 Ubuntu 24.04 LTS 패키지 262개(소스 패키지 176개)가 들어 있습니다 — 커널 linux 6.8(GPL-2.0), systemd(LGPL-2.1+), GRUB 2·shim(GPL-3.0+/BSD), OpenSSH, OpenSSL(Apache-2.0), Python 3.12(PSF-2.0), SQLite(public domain), chrony·ufw·open-vm-tools(GPL/LGPL) 등.
전체 목록·버전·라이선스와 **대응 소스 코드 제공 안내**는 [docs/OSS-APPLIANCE-PACKAGES.md](docs/OSS-APPLIANCE-PACKAGES.md), 패키지별 정본 고지는 어플라이언스의 `/usr/share/doc/<패키지>/copyright` 입니다. Ubuntu 는 Canonical Ltd. 의 상표입니다.

### 5) Docker 이미지

`Dockerfile` 은 공식 `python:3.12-slim`(Debian 기반, Python PSF-2.0) 위에 1)의 패키지를 설치합니다. 기반 이미지 구성요소의 라이선스는 그 이미지의 `/usr/share/doc/*/copyright` 를 따릅니다.

## 2. 설치 중 대상 서버가 직접 내려받는 소프트웨어(이 프로젝트가 배포하지 않음)

| 구성요소 | 라이선스 | 어디서·언제 |
|---|---|---|
| [Fluent Bit](https://github.com/fluent/fluent-bit) | Apache-2.0 | VM·서버 에이전트 설치 스크립트가 packages.fluentbit.io 에서 설치(Linux 패키지·Windows zip) |
| rsyslog | GPL-3.0+ / LGPL-3.0+ / Apache-2.0(일부) | 에이전트 rsyslog 모드 — 대상 OS 배포판 패키지를 설정만 추가 |
| [Miniforge](https://github.com/conda-forge/miniforge) | BSD-3-Clause | Windows 설치 `setup.ps1 -InstallMiniforge` 선택 시 |
| Python·pip 패키지 | 1.1) 참조 | Ubuntu 설치 `install.sh` 가 PyPI(또는 사내 미러·오프라인 휠)에서 설치 |

## 3. 개발·시험 전용(배포물에 포함되지 않음)

| 패키지 | 버전 | 라이선스 |
|---|---|---|
| [hypothesis](https://hypothesis.works) | 6.169.0 | MPL-2.0 |
| [iniconfig](https://github.com/pytest-dev/iniconfig) | 2.3.1 | MIT |
| [packaging](https://github.com/pypa/packaging) | 26.3 | Apache-2.0 OR BSD-2-Clause |
| [pluggy](https://pypi.org/project/pluggy) | 1.6.0 | MIT |
| [Pygments](https://pygments.org) | 2.21.0 | BSD-2-Clause |
| [pytest](https://docs.pytest.org/en/latest/) | 9.1.1 | MIT |
| [sortedcontainers](http://www.grantjenks.com/docs/sortedcontainers/) | 2.4.0 | Apache-2.0 |
| [vcsim (govmomi vCenter 시뮬레이터)](https://github.com/vmware/govmomi/tree/main/vcsim) | — | Apache-2.0 |
| GitHub Actions(`actions/checkout`·`actions/setup-python`) | v4·v5 | MIT |

## 4. 외부 서비스·데이터

| 대상 | 고지 |
|---|---|
| Broadcom vSAN HCL JSON(`vvs.broadcom.com/service/vsan/all.json.gz`) | 하드웨어 준비도에서 관리자가 '최신 HCL 받기'를 누르거나 파일을 올릴 때만 사용·저장(배포물에 포함하지 않음) |
| NVD CVE API 2.0 (RAG 팩 빌더 `type: nvd` · 보안 판독 VMSA/CVE 동기화, 기본 꺼짐) | This product uses the NVD API but is not endorsed or certified by the NVD. |
| Broadcom KB·TechDocs | 저장소·배포물에 KB·TechDocs 원문을 포함하지 않습니다. 사용자가 직접 수집한 Markdown 을 색인할 뿐이며, 그 내용의 권리는 Broadcom Inc. 에 있습니다. `ragpacks/` 는 수집 방법(레시피)과 KB 번호 목록만 담습니다 |
| LLM 공급자(Private AI Services·vLLM, Anthropic Claude, Google Gemini), Isvara iO, ServiceNow | 사용자가 설정할 때만 호출하며, 각 서비스의 이용 약관을 따릅니다 |

## 5. 상표

VMware, VMware Cloud Foundation, vSphere, vCenter, ESXi, vSAN, NSX, Avi, VKS 는 Broadcom Inc. 또는 그 계열사의 상표입니다. Cisco UCS 는 Cisco Systems, Inc., FortiGate 는 Fortinet, Inc., HPE iLO 는 Hewlett Packard Enterprise, iDRAC 은 Dell Inc., ServiceNow 는 ServiceNow, Inc., Ubuntu 는 Canonical Ltd., Claude 는 Anthropic PBC, Gemini 는 Google LLC 의 상표입니다. 이 프로젝트는 이들 회사의 공식 제품이 아니며 보증·지원을 받지 않습니다.
