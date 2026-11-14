# NSX Manager · Edge 로그 수집·분석 런북 (VCF AIops)

## 수집 경로
- Syslog exporter(노드별): POST /api/v1/node/services/syslog/exporters (접속한 Manager 노드),
  /api/v1/cluster/{cluster-node-id}/node/services/syslog/exporters (각 Manager 노드),
  /api/v1/transport-nodes/{transport-node-id}/node/services/syslog/exporters (Edge 등 전송 노드).
  본문: exporter_name, server, port(기본 TCP/TLS/UDP 514), protocol(TCP·TLS·UDP·LI·LI-TLS), level(EMERG~DEBUG), TLS 는 tls_ca_pem 등.
- NSX syslog(RFC5424)의 구조화 데이터 [nsx@6876 comp="nsx-edge" subcomp="datapathd" ...] 로 구성요소 구분 — AIOps 는 comp 로 nsx-edge / nsx 를 분리.
- API: 알람 GET /api/v1/alarms?status=OPEN, Manager 클러스터 GET /api/v1/cluster/status, Edge 상태 GET /api/v1/transport-nodes/{id}/status.

## 대표 증상 → 우선 확인
- BFD/BGP down(Hold Timer Expired): 물리 라우터 측 상태, Edge uplink(fp-eth) 링크, MTU, 경로.
- Datapath(datapathd) 재시작·코어덤프·high CPU: Edge 폼팩터·vCPU, 패킷 처리량, 서비스(LB·NAT·VPN) 부하.
- T0/T1 SR HA 전환·split-brain: Edge 간 BFD(관리·오버레이), Edge 클러스터 멤버 상태.
- TEP 터널 down: 오버레이 VLAN·MTU(1600+), TEP IP 풀, 호스트 측 vmk10/11.
