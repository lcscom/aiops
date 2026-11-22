# 릴리스 산출물 — 2.52.0

| 파일 | 용도 |
|---|---|
| `2.52.0/vcf-aiops-patch-2.52.0.tgz.part00~` | 서명된 패치 번들 조각 — 합친 뒤 웹 콘솔 › 시스템·패치 또는 `sudo vcf-aiopsctl patch` |
| `2.52.0/Merge-Patch.ps1` | Windows 에서 조각 합치기·SHA-256 확인 |
| `2.52.0/SHA256SUMS` | 무결성 값(합친 번들 포함) |
| `2.52.0/vcf-aiops-2.52.0.apk` | 안드로이드 앱(운영자용) |
| `2.52.0/vcf-aiops-sensor-2.52.0.apk` | 현장 센서 앱 — 안 쓰는 안드로이드 폰을 감시 소스로(포털 › 수집·연동 › 현장 센서) |

Linux 에서 합치기: `cat vcf-aiops-patch-2.52.0.tgz.part* > vcf-aiops-patch-2.52.0.tgz && grep "vcf-aiops-patch-2.52.0.tgz$" SHA256SUMS | sha256sum -c`

새 서버 설치는 `dist/vcf-aiops-ubuntu.zip`(docs/DEPLOY-UBUNTU.md). 최신 버전 하나만 두며 이전 버전은 커밋 기록에 남습니다.
