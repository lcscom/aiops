"""SR 보고서 영문화(2.12.0) — 이 제품이 스스로 만든 한국어 문구는 규칙으로 영어로 바꾸고(오프라인),
사람이 쓴 글(제목·요약·인시던트 기록 등)은 AI 번역 결과(data['tr'] 캐시) 또는 직접 입력한 영문 필드를 쓴다.
번역이 없으면 원문 앞에 '(KO)'를 붙여 미번역임을 드러낸다 — 지어내지 않는다.
"""
from __future__ import annotations

import re

HANGUL = re.compile(r"[ᄀ-ᇿ㄰-㆏가-힣]")

VM_TYPES_EN = {"vMotion": "vMotion", "DRS 자동 이동": "DRS migration", "Storage vMotion": "Storage vMotion", "콜드 이전": "cold relocate",
               "HA 재시작": "HA restart", "HA 재시작 실패": "HA restart failed", "HA VM 리셋": "HA VM reset", "HA 리셋 실패": "HA reset failed",
               "호스트 장애(HA)": "host failure (HA)", "호스트 격리(HA)": "host isolation (HA)", "이동 실패": "migration failed",
               "위치 변경 감지": "placement change detected", "VM 생성": "VM created", "VM 복제": "VM cloned", "템플릿 배포": "deployed from template",
               "VM 등록": "VM registered", "VM 삭제·등록 해제": "VM removed/unregistered", "VM 이름 변경": "VM renamed", "생성 실패": "create failed",
               "새 VM 감지": "new VM detected", "VM 사라짐 감지": "VM disappeared", "전원 켬": "powered on", "전원 끔": "powered off",
               "일시 중단": "suspended", "리셋": "reset", "게스트 종료": "guest shutdown", "게스트 재시작": "guest reboot", "구성 변경": "reconfigured",
               "스냅샷 생성": "snapshot created", "스냅샷 삭제": "snapshot removed", "스냅샷 모두 삭제": "all snapshots removed", "스냅샷 되돌림": "snapshot reverted"}
VM_FLAGS_EN = {"업무 외": "off-hours", "대량 삭제": "bulk delete", "대량 전원 끔": "bulk power-off", "보호 VM": "protected VM", "단명 VM": "short-lived VM",
               "변경 창 밖": "outside change window", "변경 창 안": "inside change window", "반복 이동": "repeated moves"}
ACT_EN = {"생성": "Created", "삭제": "Deleted", "롤아웃": "Rollout", "스케일": "Scale", "준비 상태": "Readiness", "파드 교체": "Pod replacement",
          "재시작": "Restart", "파드 이상": "Pod failure", "파드 회복": "Pod recovery", "노드": "Node", "네트워크": "Network", "스토리지": "Storage",
          "자동 스케일": "Autoscale"}

# (정규식, 바꿀 문자열) — 순서대로 적용. 앞쪽은 긴 문구.
RULES: list[tuple[re.Pattern, str]] = [(re.compile(a), b) for a, b in [
    # VKS 구성도 문제(vksmap._health)
    (r"준비된 파드 없음 \((\d+)/(\d+)\)", r"No ready pods (\1/\2)"),
    (r"롤아웃 진행 중 — 새 버전 (\d+)/(\d+)", r"Rollout in progress — new version \1/\2"),
    (r"롤아웃 실패 — ", "Rollout failed — "),
    (r"롤아웃 일시 중지\(paused\)", "Rollout paused"),
    (r"레플리카 0 \(중지됨\)", "0 replicas (stopped)"),
    (r"실행 중인 파드 없음", "No running pods"),
    (r"HPA 최대 레플리카 도달 \(", "HPA at max replicas ("),
    (r"\(현재 (\d+)\)", r"(current \1)"),
    (r"마지막 Job (\S+) 실패 (\d+)회", r"Last Job \1 failed \2 time(s)"),
    (r"CronJob 일시 중지\(suspend\)", "CronJob suspended"),
    (r"최근 1시간 컨테이너 재시작 \+(\d+)", r"Container restarts in the last hour +\1"),
    (r"외부 IP 할당 대기\(LoadBalancer Pending\)", "Waiting for external IP (LoadBalancer pending)"),
    (r"셀렉터와 일치하는 파드 없음 — 엔드포인트 0", "No pods match the selector — 0 endpoints"),
    (r"백엔드 Service 없음: ", "Backend Service missing: "),
    (r"주소\(VIP\) 미할당", "No address (VIP) assigned"),
    (r"Avi 가상 서비스 ", "Avi virtual service "),
    (r"PVC Lost — 볼륨 유실", "PVC Lost — volume lost"),
    (r"PVC (\S+) — 바인딩 대기", r"PVC \1 — waiting for binding"),
    (r"PV Released\(회수 대기\)", "PV Released (awaiting reclaim)"),
    (r"모든 백엔드 장애 → 요청 실패 가능", "All backends down → requests may fail"),
    (r"볼륨 문제: ", "Volume problem: "),
    (r"백엔드 (\d+)/(\d+) 저하: ", r"Backends degraded \1/\2: "),
    (r"스케줄 불가\(cordon\)", "Unschedulable (cordon)"),
    (r"vSphere VM 전원 ", "vSphere VM power "),
    (r"(\b[A-Za-z][\w]+) (\d+)개 — ", r"\1 ×\2 — "),
    (r"(?<![\w/])준비 (\d+)/(\d+)", r"Ready \1/\2"),
    (r"문제 없음", "No issues"),
    (r"(?<![\w])재시작 (\d+)\b", r"restarts \1"),
    (r"매칭 없음", "no match"),
    # 파드·변경 이력(vksobs)
    (r"직전 종료 (\S+) \(exit ([^)]*)\)", r"last terminated \1 (exit \2)"),
    (r"파드 (\S+) 재시작 \+(\d+) \(누적 (\d+)\)", r"Pod \1 restarted +\2 (total \3)"),
    (r"파드 (\S+) 정상화 \((.*?) 해소\)", r"Pod \1 recovered (\2 cleared)"),
    (r"파드 (\S+) 노드 (\S+) → (\S+)", r"Pod \1 moved from node \2 to \3"),
    (r"파드 생성 (\d+) · 삭제 (\d+)", r"Pods created \1 · deleted \2"),
    (r"파드 생성 (\d+)", r"Pods created \1"),
    (r"파드 삭제 (\d+)", r"Pods deleted \1"),
    (r"Job 파드 (\S+) 실패", r"Job pod \1 failed"),
    (r"독립 파드 생성", "Standalone pod created"),
    (r"독립 파드 삭제", "Standalone pod deleted"),
    (r"리비전 (\S+) → (\S+) \(파드 템플릿 변경 — 환경변수·설정·리소스 등\)", r"Revision \1 → \2 (pod template change — env/config/resources)"),
    (r"\(리비전 (\S+) → (\S+)\)", r"(revision \1 → \2)"),
    (r"(?<![\w])이미지 ", "Image "),
    (r"레플리카 (\S+) → (\S+)", r"Replicas \1 → \2"),
    (r"참조 ConfigMap·Secret 이름 변경", "Referenced ConfigMap/Secret names changed"),
    (r"롤아웃 재개", "Rollout resumed"),
    (r"HPA (\S+) 레플리카 (\S+) → (\S+) \(범위 ([^)]*)\)", r"HPA \1 replicas \2 → \3 (range \4)"),
    (r"HPA 범위 ", "HPA range "),
    (r"유형 (\S+) → (\S+)", r"Type \1 → \2"),
    (r"외부 IP (.*?) → (.*)", r"External IP \1 → \2"),
    (r"셀렉터 ", "Selector "),
    (r"포트 ", "Ports "),
    (r"규칙 변경 — 호스트 (.*?) · 백엔드 (.*)", r"Rules changed — hosts \1 · backends \2"),
    (r"주소 (.*?) → (.*)", r"Address \1 → \2"),
    (r"단계 (\S+) → (\S+)", r"Phase \1 → \2"),
    (r"크기 (\S+) → (\S+) \(확장\)", r"Size \1 → \2 (expanded)"),
    (r"(\w+) 생성 — 레플리카 (\d+) · ", r"\1 created — replicas \2 · "),
    (r"(\w+) 생성 — ", r"\1 created — "),
    (r"(\b[A-Z]\w+) 생성\b", r"\1 created"),
    (r"(\b[A-Z]\w+) 삭제\b", r"\1 deleted"),
    (r"레플리카 (\d+)", r"replicas \1"),
    (r"노드 추가 \(", "Node added ("),
    (r"노드 삭제\(클러스터에서 제거\)", "Node deleted (removed from cluster)"),
    (r"uncordon\(스케줄 재개\)", "uncordon (scheduling resumed)"),
    (r"cordon\(스케줄 불가\)", "cordon (unschedulable)"),
    (r"압박 (.*?) → (.*)", r"Pressure \1 → \2"),
    (r"없음", "none"),
    (r"일시 중지\(suspend\)", "suspended"),
    (r"(?<![\w])재개\b", "resumed"),
    # VM 액티비티 요약(vmmoves.brief)
    (r"\[대상 VM\]", "[target VM]"), (r"\[같은 호스트\]", "[same host]"), (r"\[같은 클러스터\]", "[same cluster]"),
    (r"메모리 ([\d.]+) → ([\d.]+) GB", r"memory \1 → \2 GB"), (r"메모리 ([\d.]+) GB", r"memory \1 GB"), (r"메모 변경", "notes changed"),
    (r"디스크 ", "disk "), (r"(?<![\w])추가\b", "added"), (r"(?<![\w])제거\b", "removed"), (r"(?<![\w])변경\b", "changed"),
    # 기본 연락 가능 시간·자동 업무 영향 문장
    (r"평일 09:00–18:00\(KST\), P1 은 24x7", "Weekdays 09:00–18:00 (KST), 24x7 for P1"),
    # 시각·공통
    (r"분 전", " min before"), (r"시간 전", " h before"),
]]


def has_ko(s: str) -> bool:
    return bool(HANGUL.search(str(s or "")))


def rule_en(s: str) -> str:
    """규칙 기반 영문화 — 한글이 남으면 그대로 반환(호출 측이 판단)"""
    t = str(s or "")
    if not has_ko(t):
        return t
    for k, v in sorted(VM_TYPES_EN.items(), key=lambda x: -len(x[0])):
        if k in t and has_ko(k):
            t = t.replace(k, v)
    for k, v in VM_FLAGS_EN.items():
        t = t.replace(k, v)
    for rx, rep in RULES:
        t = rx.sub(rep, t)
        if not has_ko(t):
            break
    return t


def act_en(label: str) -> str:
    return ACT_EN.get(label, label)
