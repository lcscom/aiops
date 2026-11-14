# VKS · Supervisor 로그 수집·분석 런북 (VCF AIops)

## 수집 경로
- Supervisor 컨트롤 플레인 VM: vCenter 어플라이언스 관리(5480)에 설정한 원격 syslog 를 Workload Control Plane 서비스가 5분 주기로 모든 컨트롤 플레인 VM 에 반영한다. 활성화·업그레이드 중 부트스트랩 로그는 rsyslog 로, 이후에는 Fluent Bit 가 기본 전달자.
- Supervisor Fluent Bit: vmware-system-logging 네임스페이스의 ConfigMap fluentbit-config-custom 의 outputs-custom.conf 에 [OUTPUT] Name syslog / Match system* / Host / Port / Mode tcp / Syslog_Format rfc5424 를 추가. TLS 는 Tls on, Tls.verify, Tls.ca_file.
- 워크로드(VKS) 클러스터: Fluent Bit 표준 패키지(fluent-bit.tanzu.vmware.com) 설치 후 data-values 의 fluent_bit.config.outputs 에 syslog 출력.
- Kubernetes API: 이벤트(Warning)·노드 상태·파드 상태·Cluster API(Machine/Cluster)를 AIOps VKS 커넥터가 직접 조회. Supervisor 토큰은 POST https://<Supervisor>/wcp/login (Basic, vSphere SSO) 응답 session_id, 기본 10시간 유효. 워크로드 클러스터는 본문 guest_cluster_name.

## 대표 증상 → 우선 확인
- NodeNotReady / Ready=False(KubeletNotReady, NetworkReady=false): 노드 VM 상태(vCenter), CNI(Antrea/Calico) 파드, kubelet 로그.
- DiskPressure / Evicted: 노드 ephemeral-storage(컨테이너 이미지·로그) 사용률, 이미지 GC 실패 이벤트.
- ImagePullBackOff / ErrImagePull: 레지스트리(Harbor) 접근·인증서(x509 unknown authority)·이미지 태그.
- CrashLoopBackOff / OOMKilled: 컨테이너 종료 코드·메모리 limit, 직전 로그.
- FailedMount / FailedAttachVolume / CnsFault: vSphere CSI·CNS, 데이터스토어 접근, 스토리지 정책.
- FailedScheduling(Insufficient cpu/memory, untolerated taint): 노드 용량·taint, VM Class.
- etcdserver: request timed out / apply request took too long / leader changed: 컨트롤 플레인 VM 디스크 지연(데이터스토어 레이턴시), CPU 경합.
- VKS Machine Failed / 장시간 Provisioning: vSphere 네임스페이스 리소스 한도, 존(zone) 용량, VM Operator·이미지(컨텐츠 라이브러리), IP 풀.
- kubectl/로그인 401: STS 인증서 갱신 후 게스트 클러스터 로그인 실패 사례가 있음(KB 443970), 401 오류(KB 444592).
