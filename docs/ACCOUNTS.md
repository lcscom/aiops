# 수집 전용(읽기 전용) 계정 자동 생성

커넥터 추가·편집 화면의 **관리자 계정으로 수집 전용 계정 만들기**에서 관리자 계정을 한 번 입력하면, 그 자리에서 제품 API 로 읽기 전용 계정을 만들고 커넥터의 계정·비밀번호 칸에 채웁니다. 관리자 비밀번호는 저장하지 않으며, 감사 로그에는 대상·결과·단계만 남습니다(`connector.provision_account`).

| 제품 | 만드는 것 | 쓰기 불가 보장 | 비고 |
|---|---|---|---|
| vCenter | SSO 사용자(`readonly@vsphere.local` 기본) · 역할 `VCF-AIops-ReadOnly-Collector`(System.Anonymous·View·Read + Global.Diagnostics) · vCenter 루트 권한(하위 전파) · vSphere 네임스페이스 VIEW · VKS 워크로드 클러스터 ClusterRole `vcf-aiops-reader`(get·list·watch) | 유효 권한 조회(그룹·상속 포함)에서 허용 목록 밖 권한이나 대표 쓰기 권한 16종 중 하나라도 잡히면 **방금 준 권한을 회수**하고 실패로 멈춤 · SSO 관리 그룹 소속이면 중단 | SSO 사용자 생성은 govc(VMware govmomi, Apache-2.0, 어플라이언스 `/opt/vcf-aiops/bin/govc`) 사용 |
| NSX 4.1+ | 로컬 사용자 생성 → 활성화 → 비밀번호 만료 해제 | 기본 Auditor 역할만 보유하는지 확인, 다른 역할이면 중단 | 4.0 이하: 내장 `audit`(10002) 활성화 · 3노드 반영에 수 분 |
| VCF Operations | 로컬 사용자 + `ReadOnly` 역할(모든 개체) | 역할 지정 | 기존 사용자는 역할만 맞춤(비밀번호는 Ops 에서) |
| Operations for logs | 로컬 사용자 + `View Only Admin` 역할 | 역할 지정 | 메일 등록 없이 비밀번호 직접 설정(email 필드 생략) |
| SDDC Manager | 이미 있는 SSO 사용자에 `VIEWER` 역할 | 역할 지정 | SDDC Manager 는 로컬 계정이 없음 → 관리 도메인 vCenter 에서 먼저 생성 |

이 계정으로 되지 않는 것(의도): 알람 확인·유지보수 모드·VM 조치·ESXi syslog 대상 변경 등 쓰기 조치, vCenter 어플라이언스 헬스 REST(관리 그룹 필요). 화면에서 해당 항목만 비활성으로 표시됩니다.

## 1차 자료
- NSX: [CreateNodeUser 4.1](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.1.0/method_CreateNodeUser.html) · [ActivateNodeUser](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_ActivateNodeUser.html) · [UpdateNodeUser](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_UpdateNodeUser.html) · [CreateRoleBinding](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/4.2/method_CreateRoleBinding.html)
- VCF Operations: [user](https://developer.broadcom.com/xapis/vcf-operations-api/latest/data-structures/user/) · [role-permission](https://developer.broadcom.com/xapis/vmware-vrealize-operations-api/8.6.3/data-structures/role-permission)
- Operations for logs: [POST /api/v2/users](https://developer.broadcom.com/xapis/vrealize-log-insight-api/latest/api/v2/users/post/) · [KB 382067(비밀번호 지정 시 email 생략)](https://knowledge.broadcom.com/external/article/382067)
- SDDC Manager: [POST /v1/users](https://developer.broadcom.com/xapis/vmware-cloud-foundation-api/5.1.0/v1/users/post/)
- vSphere 네임스페이스 권한: [POST .../namespaces/instances/{namespace}/access/{domain}/{subject}](https://developer.broadcom.com/xapis/vsphere-automation-api/8.0.3/vcenter/api/vcenter/namespaces/instances/namespace/access/domain/subject/post/)
- Supervisor 엔드포인트: [GET .../namespace-management/clusters/{cluster}](https://developer.broadcom.com/xapis/vsphere-automation-api/8.0.3/vcenter/api/vcenter/namespace-management/clusters/cluster/get/)
- govc: [govmomi releases](https://github.com/vmware/govmomi/releases) (`sso.user.create`)

## 시험 범위
vCenter 흐름은 vcsim(govmomi 시뮬레이터)+govc 로 SSO 사용자·역할·권한 단계까지 확인했습니다(vcsim 의 유효 권한 조회는 항상 Admin 을 돌려주므로 검증 단계가 실패·회수하는 것까지 확인). NSX·Ops·Logs·SDDC 는 1차 문서의 요청·응답 형식을 따른 모의 서버로 시험했습니다. 실제 장비에서 처음 쓸 때 단계 결과(✓/!/✗)를 확인하세요.
