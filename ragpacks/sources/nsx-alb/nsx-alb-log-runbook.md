# NSX ALB(Avi) 로그 수집·분석 런북 (VCF AIops)

## 수집 경로
- 이벤트 로그 API: GET https://<Controller>/api/analytics/logs?type=2&duration=<초>&page_size=<최대 10000> — start/end(YYYY-MM-DDTHH:MM:SS) 지정 가능. AIOps Avi 커넥터가 주기적으로 조회.
- 알람: GET /api/alert, 상태: /api/virtualservice-inventory, /api/serviceengine-inventory(oper_status).
- Syslog: Operations > Notifications 에서 Syslog 알림(서버·포트) 생성 → Alert Actions(Syslog-Audit-Persistence 템플릿)에 연결 → Alert Config 에서 조건과 Action 연결. UI 기본 UDP, TCP 는 alertsyslogconfig 의 syslog_servers 항목에서 udp 해제.

## 대표 증상 → 우선 확인
- VS OPER_DOWN / Pool all servers down: 헬스 모니터 결과, 백엔드 서버 상태, 네트워크(SE ↔ 서버) 경로.
- SE down / heartbeat failure: SE VM 상태(vCenter), 관리 네트워크, Controller ↔ SE 연결.
- Controller 클러스터 노드 down / quorum: 3노드 클러스터 상태, 디스크 사용률.
- Health score 급락: 성능(지연·오류율), 리소스(SE CPU), 보안(WAF·DDoS) 구성요소 분해.
