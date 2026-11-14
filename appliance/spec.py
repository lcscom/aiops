"""VCF AIops 어플라이언스 — OVF 배포 속성(vApp Properties)·배포 크기 정의.

make-ovf.py(OVF 생성)와 provision.py(첫 부팅 구성)가 함께 쓰는 단일 정의입니다.
키를 바꾸면 이미 배포된 VM 의 재구성 동작도 바뀌므로 키는 유지하고 라벨·설명만 고치세요.
"""

PRODUCT = "VCF AIops"
VENDOR = "Broadcom Korea FSI SA"
OS_USER = "aiopsadmin"

# 배포 크기 — docs/INSTALL-UBUNTU.md B(사양 산정) 표와 동일
SIZES = {
    "small": dict(cpu=4, mem_gb=8, data_gb=60,
                  label="소(Small) — 4 vCPU · 8GB · 데이터 60GB",
                  desc="PoC·관리 도메인, 평균 ~100 EPS, 보존 7일"),
    "medium": dict(cpu=8, mem_gb=16, data_gb=250, default=True,
                   label="중(Medium) — 8 vCPU · 16GB · 데이터 250GB",
                   desc="VI 도메인 1~2개, 평균 ~500 EPS, 보존 7일"),
    "large": dict(cpu=8, mem_gb=32, data_gb=700,
                  label="대(Large) — 8 vCPU · 32GB · 데이터 700GB",
                  desc="다수 도메인·VM 에이전트, 평균 ~1,500 EPS, 보존 7일"),
}
OS_DISK_GB = 40

NET, SYS, APP = "1. 네트워크", "2. 시스템", "3. AIOps"

# type: string|int|boolean   password: 비밀값(배포 마법사에서 가림, 로그·show 에서 가림)
PROPS = [
    # ---------------------------------------------------------------- 네트워크
    dict(key="net.hostname", cat=NET, type="string", default="", qualifiers="MinLen(1),MaxLen(253)",
         label="호스트 이름(FQDN)",
         desc="예: aiops.corp.example — 인증서 SAN·장비 syslog 대상·에이전트/BMC 접속 주소. DNS A·PTR 레코드를 먼저 등록하세요."),
    dict(key="net.ip", cat=NET, type="string", default="",
         label="IPv4 주소", desc="고정 IP(예: 10.10.20.50). 비우면 DHCP — 운영은 고정 IP 권장."),
    dict(key="net.prefix", cat=NET, type="int", default="24", qualifiers="MinValue(1),MaxValue(32)",
         label="서브넷 접두 길이", desc="예: 24 (= 255.255.255.0). DHCP 이면 무시."),
    dict(key="net.gateway", cat=NET, type="string", default="",
         label="기본 게이트웨이", desc="예: 10.10.20.1. DHCP 이면 무시."),
    dict(key="net.dns", cat=NET, type="string", default="",
         label="DNS 서버", desc="쉼표 구분, 예: 10.10.0.11,10.10.0.12"),
    dict(key="net.search", cat=NET, type="string", default="",
         label="DNS 검색 도메인", desc="쉼표 구분, 예: corp.example"),
    dict(key="net.ntp", cat=NET, type="string", default="",
         label="NTP 서버", desc="쉼표 구분 — ESXi·vCenter·NSX 와 같은 NTP 를 쓰세요(로그 시각 상관 분석에 필수)."),
    # ---------------------------------------------------------------- 시스템
    dict(key="sys.password", cat=SYS, type="string", password=True, default="", qualifiers="MinLen(12),MaxLen(128)",
         label=f"OS 관리자({OS_USER}) 비밀번호",
         desc=f"콘솔·SSH 로그인 계정 {OS_USER}(sudo). 12자 이상. 최초 로그인 시 변경이 강제됩니다. root 로그인은 막혀 있습니다."),
    dict(key="sys.ssh_key", cat=SYS, type="string", default="",
         label="SSH 공개 키(선택)", desc=f"{OS_USER} 의 authorized_keys 에 넣을 한 줄(ssh-ed25519 … / ssh-rsa …)."),
    dict(key="sys.ssh", cat=SYS, type="boolean", default="true",
         label="SSH 사용", desc="끄면 SSH 서비스를 비활성화합니다(콘솔만 사용)."),
    dict(key="sys.timezone", cat=SYS, type="string", default="Asia/Seoul",
         label="시간대", desc="IANA 이름(예: Asia/Seoul, UTC)."),
    dict(key="sys.firewall", cat=SYS, type="boolean", default="true",
         label="OS 방화벽(ufw) 사용", desc="22/tcp, 웹 포트, 514/udp·tcp, 6514/tcp, 162/udp 만 허용."),
    # ---------------------------------------------------------------- AIOps
    dict(key="app.admin_password", cat=APP, type="string", password=True, default="",
         qualifiers="MinLen(12),MaxLen(128)",
         label="웹 콘솔 admin 초기 비밀번호",
         desc="웹 콘솔 로컬 관리자 admin 의 초기 비밀번호. 12자 이상. 최초 로그인 시 변경이 강제됩니다."),
    dict(key="app.port", cat=APP, type="int", default="8630", qualifiers="MinValue(1024),MaxValue(65535)",
         label="웹·API 포트", desc="콘솔·관제 화면·에이전트(HTTPS)·Redfish push 수신 포트."),
    dict(key="app.pais_url", cat=APP, type="string", default="",
         label="Private AI(PAIS) 주소", desc="OpenAI 호환 엔드포인트, 예: https://pais.corp.example/v1 — 비우면 규칙 탐지만 동작(나중에 설정 가능)."),
    dict(key="app.pais_key", cat=APP, type="string", password=True, default="",
         label="PAIS API 키", desc="PAIS 에서 발급한 키. 나중에 /etc/vcf-aiops/.env 에서 바꿀 수 있습니다."),
    dict(key="app.llm_model", cat=APP, type="string", default="google/gemma-4-31B-it",
         label="LLM 모델 id", desc="PAIS GET /v1/models 의 id 와 정확히 일치해야 합니다."),
    dict(key="app.retention_days", cat=APP, type="int", default="7", qualifiers="MinValue(1),MaxValue(90)",
         label="원본 로그 보존(일)", desc="데이터 디스크 크기에 비례 — 배포 크기 표는 7일 기준."),
    dict(key="app.snmp_community", cat=APP, type="string", default="public",
         label="SNMP 트랩 커뮤니티", desc="운영 전 사내 값으로 변경하세요(v3 는 설치 후 config.yaml)."),
    dict(key="app.cert_pem", cat=APP, type="string", default="",
         label="서버 인증서(PEM, base64·선택)",
         desc="사내 CA 발급 인증서(체인 포함 가능) PEM 파일을 base64 한 줄로(base64 -w0 aiops.crt). 비우면 자체 서명 인증서를 만듭니다."),
    dict(key="app.key_pem", cat=APP, type="string", password=True, default="",
         label="서버 개인 키(PEM, base64·선택)", desc="위 인증서의 개인 키(base64 -w0 aiops.key). 인증서와 함께 넣으세요."),
]

PASSWORD_KEYS = {p["key"] for p in PROPS if p.get("password")}
DEFAULTS = {p["key"]: p["default"] for p in PROPS}
