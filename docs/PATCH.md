# 패치 — 기존 설치본을 새 버전으로 (설정·데이터 유지)

OVA 를 다시 배포하지 않고, 이미 운영 중인 VCF AIops(OVA·`install.sh` 설치본, 1.0 이상)를 새 버전으로 바꿉니다. 설정(`/etc/vcf-aiops`)·데이터(`/var/lib/vcf-aiops`)·인증서·계정·커넥터는 그대로입니다.

> **2.29.0 이하에서 2.30.0 이상으로 올릴 때는 먼저 [서명 키 교체](#서명-키-교체-2300--2290-이하에서-한-번)를 한 번 해야 합니다.** 하지 않으면 "서명 검증 실패"로 거부됩니다.

## 번들
`vcf-aiops-patch-<버전>.tgz` (+ `.sha256`)

| 파일 | 내용 |
|---|---|
| `manifest.json` | `product`(=`vcf-aiops`)·버전·만든 시각·`payload_sha256`·`apply_sha256`·`files`(그 밖의 모든 파일의 SHA-256)·`python_tag`(wheel 대상, 예 `cp312`)·`notes` |
| `manifest.sig` | Ed25519 서명(manifest.json) |
| `payload.tar.gz` | 프로그램(app·scripts·deploy·ragpacks·docs·tests·appliance·requirements·VERSION). Android 앱(APK)은 `app/static/app/` 에 포함, `mobile/`(Android 소스)은 싣지 않음 |
| `apply.sh` | 적용기 |
| `patch-signing.pub` | 이 번들을 서명한 키의 공개 키(참고용 — 적용 때 신뢰 근거로 쓰지 않음) |
| `wheelhouse/` | (선택) 의존 패키지가 바뀐 패치를 망분리 환경에 적용할 때 |

서명은 `manifest.json` 만 덮습니다. 그래서 **번들 안의 모든 파일은 manifest 에 SHA-256 이 있어야 하고**, 목록에 없는 파일이 하나라도 있으면 거부합니다(서명된 번들에 `apply.sh`·wheel 을 바꿔 넣는 공격 차단).

## 적용 방법

| 현재 버전 | 방법 |
|---|---|
| 1.3 이상 | 웹 콘솔 › **시스템·패치** › 번들 끌어 놓기 → 검사 결과 확인 → **적용** (관리자) |
| 1.3 이상 | `sudo vcf-aiopsctl patch vcf-aiops-patch-<버전>.tgz` |
| 1.2 이하 | `tar xzf vcf-aiops-patch-<버전>.tgz && sudo bash vcf-aiops-patch-<버전>/apply.sh` — 신뢰 키가 아직 없으므로 표시되는 SHA-256 을 배포처 값과 비교 후 진행. 적용 후부터는 위 두 방법 사용 |

## 서명 키 교체 (2.30.0 — 2.29.0 이하에서 한 번)
2.29.0 까지 쓰던 서명 키는 폐기되었고, 2.30.0 부터는 새 키로 서명합니다. 2.29.0 이하 설치본은 옛 키만 믿으므로, **2.30.0 번들을 올리기 전에 새 공개 키를 신뢰 목록에 한 번 넣어야** 합니다.

새 키 지문(공개 키 DER 의 SHA-256):

```
6c1aa79dc69d1b4a770f39f738734f6dfe0f96f5a7c8c49c42d49c64e9fb0ecc
```

2.29.0 이하 서버에서(`trust-key` 명령은 2.30.0 부터 있으므로 직접 설치):

```bash
# 1) 새 공개 키 준비 — 배포처가 준 vcf-aiops-2026.pub. 번들에서 꺼내도 됩니다:
tar -xzOf vcf-aiops-patch-2.30.0.tgz vcf-aiops-patch-2.30.0/patch-signing.pub > vcf-aiops-2026.pub

# 2) 지문 확인 — 출력이 위 값(6c1aa79d…fb0ecc)과 한 글자도 다르지 않아야 합니다. 다르면 중단
openssl pkey -pubin -in vcf-aiops-2026.pub -outform DER | sha256sum

# 3) 신뢰 목록에 설치(root 소유 0644, 폴더 0755 — 웹 서비스 계정도 읽어야 함)
sudo install -d -m 0755 -o root -g root /etc/vcf-aiops/patch-trust
sudo install -m 0644 -o root -g root vcf-aiops-2026.pub /etc/vcf-aiops/patch-trust/vcf-aiops-2026.pub

# 4) 적용(웹 콘솔 업로드도 이때부터 통과)
sudo vcf-aiopsctl patch vcf-aiops-patch-2.30.0.tgz
```

- 지문은 반드시 **번들과 다른 경로**(이 문서·릴리스 노트·담당자)로 받은 값과 비교하세요. 번들 안의 키 파일만으로는 아무것도 증명하지 못합니다.
- 서비스 재시작은 필요 없습니다. 2.30.0 이 설치되면 설치본 키(`/opt/vcf-aiops/appliance/patch/patch-signing.pub`)가 새 키로 바뀝니다.
- **3)에서 넣은 `/etc/vcf-aiops/patch-trust/vcf-aiops-2026.pub` 는 지우지 마세요.** 2.29.0 이하로 롤백하면 설치본 키가 옛 키로 되돌아가므로, 이 파일이 없으면 2.30.0 이상을 다시 올릴 수 없습니다.

2.30.0 이상에서 키 관리:

```bash
vcf-aiopsctl trust-key list                                   # 이름 + 지문(설치본 키 · 추가 키)
sudo vcf-aiopsctl trust-key add 새키.pub [--name 이름] [--yes] # Ed25519 PEM 인지 확인 → 지문 표시 → yes 입력 → /etc/vcf-aiops/patch-trust/<이름>.pub
sudo vcf-aiopsctl trust-key remove <이름> [--yes]              # 추가 키만(설치본 키는 지울 수 없음)
```
이름은 영문·숫자·`.`·`_`·`-` 만. 추가·삭제는 `patch-history` 에 `trust_add`/`trust_remove` 로 남습니다. root 소유가 아니거나 다른 계정이 쓸 수 있는 키 파일은 무시합니다.

## 적용 순서(apply.sh)
0. 잠금: `/etc/vcf-aiops/patch-state/lock`(root 전용) — CLI·웹 요청·롤백이 겹치면 뒤에 온 쪽이 바로 끝남
1. 무결성: `product`·payload·apply.sh·그 밖의 모든 파일 SHA-256 = manifest 값(`apply_sha256` 필수)
2. 서명: 설치된 신뢰 공개 키(`/opt/vcf-aiops/appliance/patch/patch-signing.pub`, 추가 키 `/etc/vcf-aiops/patch-trust/*.pub`)로 검증 — 1.3 이상에서는 필수
3. 사전 점검(서비스 중지 전): 파일시스템별 여유 — `/opt/vcf-aiops`(새 프로그램 + 100MB)·스테이징 `/var/tmp`(새 프로그램 + 50MB)·`/var/lib/vcf-aiops`(프로그램 백업 + DB + 100MB). 같은 파일시스템이면 합산
4. 백업: 프로그램(tar) + DB 온라인 백업(sqlite `.backup`) + `pip freeze` → `/var/lib/vcf-aiops/patches/backup/`(**root 전용 0700**)
5. 의존 패키지: `requirements.txt` 가 바뀐 경우만(번들 wheelhouse 우선, 없으면 PyPI). wheelhouse 의 `python_tag` 가 서버 venv 의 Python 과 다르면 중지 전에 거부
6. 새 트리를 `/opt/vcf-aiops/.patch-new.*` 에 준비 → 서비스 중지 → 폴더 단위 rename 교체(옛 것은 `.patch-old.*` 로 옮겼다가 성공 뒤 삭제) → `VERSION`(rename) → 서비스 기동
7. 확인: `/readyz` 정상(최대 180초, 설정의 `server.host` 가 특정 주소면 그 주소로) + 설치된 `VERSION` = 대상 버전 + 준비 뒤 10초 동안 서비스가 내려가거나 재시작하지 않음
8. 성공 뒤: `/opt/vcf-aiops/release.json`(`version`·`from`·`applied_at`·`notes`) 기록, 기록(`history.jsonl`)에 대상 버전·`notes`, 백업 정리(최근 3개 + **설치한 버전과 다른 가장 최근 백업은 항상 보관**)

**6의 서비스 중지부터 7의 확인까지는 무엇이 실패해도 자동 롤백**합니다 — `/readyz` 무응답뿐 아니라 교체 중 예상 못 한 오류, 중단 신호(SIGTERM·Ctrl-C), 웹 적용 유닛의 시간 초과까지. 롤백은 프로그램을 백업에서 되돌리고, 새 버전이 한 번이라도 기동했다면 DB 도 백업 시점으로 되돌리며, 의존 패키지를 바꿨다면 `pip freeze` 기록으로 venv 를 되돌립니다(최선 노력 — 망분리 환경에서 이전 wheel 을 구할 수 없으면 실패하고, 수동 명령을 화면·기록에 남깁니다). 각 단계가 실패해도 계속 진행해 마지막에 서비스 기동을 시도하고, 완전하지 않으면 상태가 `failed` 로 남습니다.

서비스 중단은 보통 1~3분입니다. 백업 시점 이후 중지 전까지 들어온 몇 초 분량의 이벤트는 롤백 시 DB 와 함께 되돌아갑니다(장비 쪽 syslog 재전송 여부에 따름).

## 웹 콘솔 적용 경로와 권한
서비스 계정(`aiops`)은 `/opt/vcf-aiops` 에 쓸 수 없습니다(systemd `ProtectSystem=strict`). 웹에서 적용하면:

1. 서비스가 업로드를 `/var/lib/vcf-aiops/patches/incoming/` 에 저장하고 서명·무결성·버전을 검사(관리자 권한, 감사 로그 `system.patch_upload`)
2. **적용**을 누르면 `patches/request.json` 만 만듭니다(`system.patch_apply`)
3. `vcf-aiops-patch.path` → root 서비스 `vcf-aiops-patch.service` 가 `vcf-aiopsctl patch-request` 실행. root 쪽은 서비스 계정이 쓴 것을 믿지 않고 다시 확인합니다(2.30.0):
   - `request.json` 형식(허용 필드 `action`·`file`·`by`·`force`·`ts`, 파일은 `incoming/<숫자>-<이름>.tgz` 만)
   - 번들을 **root 전용(0700) 임시 폴더로 복사한 뒤** 그 사본에서 서명 → `product` → `apply.sh`·payload·모든 파일 SHA-256 확인, 실행도 그 사본에서(검사 뒤 바꿔치기 방지)
   - 현재 버전보다 새 버전이 아니면 요청에 `force: true` 가 있어야 함(웹 계층과 같은 규칙)
4. 화면은 진행 단계(`patches/status.json`)를 보여 주고, 재기동 후 자동으로 다시 연결합니다

앱이 침해되더라도 신뢰 키로 서명되지 않은 번들·서명 뒤에 바뀐 파일은 root 가 실행하지 않습니다.

| 경로 | 소유·권한 | 용도 |
|---|---|---|
| `/var/lib/vcf-aiops/patches/` | root:aiops 0770 | 요청·상태·기록·업로드(서비스 계정이 씀 — root 는 여기 내용을 신뢰하지 않음) |
| `/var/lib/vcf-aiops/patches/backup/` | root:root 0700 | 백업(서비스 계정은 읽지 못함) |
| `/var/lib/vcf-aiops/patches/backups.json` | root:aiops 0640 | 백업 색인 **사본** — 웹 콘솔 표시용 |
| `/etc/vcf-aiops/patch-state/` | root:root 0700 | 잠금, 백업 색인 **원본**(각 백업의 SHA-256) |
| `/etc/vcf-aiops/patch-trust/` | root:root 0755, 키 0644 | 추가 신뢰 키 |

## 되돌리기
- 웹 콘솔 › 시스템·패치 › **이전 버전으로 되돌리기**
- `sudo vcf-aiopsctl rollback` (최신 백업) · `sudo vcf-aiopsctl rollback --list` · `sudo vcf-aiopsctl rollback <백업명> [--no-db]`
- 기록: `sudo vcf-aiopsctl patch-history`

롤백은 `/usr/local/bin/vcf-aiopsctl` 까지 백업본으로 바꾸므로, 복원 전에 백업을 확인합니다(2.30.0): 백업 폴더와 그 상위가 root 전용(0700)인지, `code.tar.gz`·`vcf-aiopsctl`·`aiops.db` 의 SHA-256 이 root 전용 색인 원본과 같은지. 다르면 복원하지 않습니다.

- **2.30 이전에 만든 백업**: 2.30.0 을 적용할 때 root 소유·쓰기 금지 상태인 백업만 색인에 넣고(`legacy`) 권한을 0700 으로 바꿉니다. 그렇지 않은 것은 `untrusted.<이름>` 으로 옮기고 색인에서 뺍니다(자동 정리 대상도 아님 — 확인 후 직접 삭제).
- 색인에 없는 백업을 꼭 써야 하면 내용을 직접 확인한 뒤 CLI 에서만: `sudo vcf-aiopsctl rollback <백업명> --no-verify`
- **2.29.0 이하로 롤백하면** ① 설치본 키가 옛 키로 되돌아갑니다 — `/etc/vcf-aiops/patch-trust/` 의 새 키를 지우지 않았다면 2.30.0 이상을 그대로 다시 올릴 수 있습니다. ② `vcf-aiopsctl` 도 옛 것이 되어 `trust-key`·백업 확인이 없습니다. ③ 옛 웹 콘솔은 root 전용이 된 백업 폴더를 읽지 못해 백업 목록이 비어 보입니다 — CLI(`sudo vcf-aiopsctl rollback --list`)를 쓰세요.
- 수동 롤백은 venv 를 건드리지 않습니다. 패치가 의존 패키지를 바꿨다면 백업의 기록으로 되돌립니다: `sudo /opt/vcf-aiops/venv/bin/python -m pip install --no-deps -r /var/lib/vcf-aiops/patches/backup/<백업명>/pip-freeze.txt`

## 패치 번들 만들기(배포처)
```bash
bash appliance/patch/build-patch.sh --version 2.30.1 --out ./out --notes "변경 요약"
#   서명 키: ~/.vcf-aiops/patch-signing.key (없으면 --genkey, 공개 키는 appliance/patch/patch-signing.pub)
#   의존 패키지가 바뀐 패치를 망분리 환경에 줄 때: --wheels (cp312 · manylinux x86_64 — manifest python_tag)
```
- `app/static/app/vcf-aiops.apk` 가 있으면 `app.json` 의 `sha256`·`size` 가 APK 와 같아야 합니다. 다르면 빌드가 실패합니다.
- 최상위에 payload 목록에 없는 폴더(`*.py` 포함)·파일이 있으면 경고합니다. 싣는 목록은 네 군데(`build-patch.sh` `PAY_DIRS`/`PAY_FILES`, `apply.sh` `CODE_DIRS`/`CODE_FILES`, `vcf-aiopsctl` `_rollback`, `scripts/linux/install.sh`)를 같이 고칩니다. `mobile/` 은 의도적으로 제외.
- 번들에 파일을 더 넣으려면 manifest 를 쓰기 전에 넣으세요(`files` 에 해시가 없으면 적용 쪽이 거부).

서명 키는 오프라인 보관하고 사본을 둡니다(잃어버리면 모든 설치본에서 위 키 교체 절차가 필요). 키를 바꿀 때는 새 공개 키의 지문을 별도 경로로 알리고 `trust-key add` 로 먼저 배포하거나, 옛 키가 남아 있다면 새 키가 들어 있는 버전을 옛 키로 서명해 한 번 패치합니다.

## 시험 결과
- qemu(Secure Boot, OVA 1.2.0 배포본): 1.2.0 → 1.3.0(CLI, 레거시 경로) · 1.3.0 → 1.3.1(웹 업로드 → root 유닛) · 웹 롤백 1.3.1 → 1.3.0 · 기동 실패 번들(1.3.2) → 자동 롤백 후 1.3.0 정상.
- 단위 시험(`tests/test_patching.py`): 번들 변조(payload·apply.sh·manifest)·`apply_sha256` 누락·manifest 밖 파일·서명 불일치 거부, 지문·백업 색인, `vcf-aiopsctl` 사본으로 변조 번들 거부·키 추가 전 거부/후 통과·잘못된 키 파일 거부.
- 2.30.0 의 apply.sh·vcf-aiopsctl 변경은 가짜 경로 + `systemctl`·`curl`·`pip` 대역으로만 확인했습니다(성공, `/readyz` 무응답·기동 실패·교체 중 오류·SIGTERM → 롤백, 디스크 부족 거부, 잠금, 2.29.0 `vcf-aiopsctl` 이 새 apply.sh 를 부르는 경로). **실제 어플라이언스(systemd·실제 venv)에서의 2.29.0 → 2.30.0 적용·롤백은 출시 전에 따로 확인해야 합니다.**
