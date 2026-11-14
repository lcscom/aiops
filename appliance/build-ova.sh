#!/usr/bin/env bash
# =============================================================================================
#  VCF AIops — 어플라이언스 OVA 빌드 (Ubuntu 24.04 LTS 기반, 첫 부팅 자동 구성)
#
#  빌드 PC: Ubuntu 24.04 LTS(권장)·22.04, root, 여유 디스크 15GB, Ubuntu 저장소·PyPI 접근
#           (사내 미러: --mirror http://mirror.corp/ubuntu · PIP_INDEX_URL=https://pypi.corp/simple)
#  사용   : sudo bash appliance/build-ova.sh [--version 1.0.0] [--out ./out] [--mirror URL]
#                                         [--wheelhouse DIR] [--keep-raw]
#  결과   : out/vcf-aiops-<버전>.ova  (+ .ovf · .mf · -disk1.vmdk · SHA256SUMS)
#
#  이미지 구성
#    - GPT: ESP(FAT32 512MB) + root(ext4, 40GB 가상 / 실사용 약 2.5GB)
#    - 부팅: UEFI + 보안 부팅(Canonical 서명 shim·grub·커널) — vSphere 'EFI + 보안 부팅'
#    - 드라이버: PVSCSI·VMXNET3(커널 기본 모듈, initramfs 포함), open-vm-tools
#    - 앱: /opt/vcf-aiops + venv 사전 설치(인터넷 없이 첫 부팅 구성), 서비스는 첫 부팅 구성 후 기동
#    - 비밀값 없음: SSH 호스트 키·machine-id·설정 암호화 키·인증서는 VM 마다 첫 부팅에 생성
# =============================================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$(cd "$HERE/.." && pwd)"
VERSION="$(date +%Y.%m.%d)"; OUT="$SRC/out"; MIRROR="http://archive.ubuntu.com/ubuntu"
SUITE=noble; WHEELHOUSE=""; KEEP_RAW=0; NAME=vcf-aiops
OS_DISK_GB="$(python3 -c "import sys;sys.path.insert(0,'$HERE');import spec;print(spec.OS_DISK_GB)")"
OS_USER="$(python3 -c "import sys;sys.path.insert(0,'$HERE');import spec;print(spec.OS_USER)")"

die()  { echo -e "\e[31m✖ $*\e[0m" >&2; exit 1; }
ok()   { echo -e "  \e[32m✔\e[0m $*"; }
step() { echo -e "\n\e[36m▶ $*\e[0m"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --mirror) MIRROR="$2"; shift 2 ;;
    --wheelhouse) WHEELHOUSE="$(cd "$2" && pwd)"; shift 2 ;;
    --keep-raw) KEEP_RAW=1; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "알 수 없는 옵션: $1" ;;
  esac
done
[[ $EUID -eq 0 ]] || die "root(sudo)로 실행하세요(루프 디바이스·chroot)."
[[ "$VERSION" =~ ^[0-9A-Za-z._-]+$ ]] || die "--version 형식 오류"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/aiops-ova.XXXXXX")"; MNT="$WORK/root"; RAW="$WORK/disk.raw"
LOOP_ESP=""; LOOP_ROOT=""
BASE="$NAME-$VERSION"; VMDK="$OUT/$BASE-disk1.vmdk"

cleanup() {
  set +e
  for m in boot/efi run sys/firmware/efi/efivars sys proc dev/pts dev; do
    mountpoint -q "$MNT/$m" 2>/dev/null && umount -lf "$MNT/$m"
  done
  mountpoint -q "$MNT" 2>/dev/null && umount -lf "$MNT"
  [[ -n "$LOOP_ESP" ]] && losetup -d "$LOOP_ESP" 2>/dev/null
  [[ -n "$LOOP_ROOT" ]] && losetup -d "$LOOP_ROOT" 2>/dev/null
  if [[ $KEEP_RAW -eq 1 && -f "$RAW" ]]; then mv "$RAW" "$OUT/$BASE.raw" && echo "  raw 보존: $OUT/$BASE.raw"; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# ------------------------------------------------------------------------------- 0. 빌드 도구
step "0. 빌드 도구"
NEED=(debootstrap qemu-img sgdisk losetup mkfs.vfat mkfs.ext4 blkid fstrim mcopy python3)
miss=(); for c in "${NEED[@]}"; do command -v "$c" >/dev/null || miss+=("$c"); done
if [[ ${#miss[@]} -gt 0 ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq debootstrap qemu-utils gdisk util-linux dosfstools mtools e2fsprogs zerofree python3 >/dev/null
fi
for c in "${NEED[@]}"; do command -v "$c" >/dev/null || die "$c 없음"; done
command -v zerofree >/dev/null || { apt-get install -y -qq zerofree >/dev/null 2>&1 || echo "  ! zerofree 없음 — OVA 가 커질 수 있음"; }
avail=$(df -BG --output=avail "$WORK" | tail -1 | tr -dc 0-9); [[ $avail -ge 12 ]] || die "$WORK 여유 공간 ${avail}GB < 12GB"
ok "작업 폴더 $WORK · 출력 $OUT · 버전 $VERSION · 미러 $MIRROR"

# ------------------------------------------------------------------------------- 1. 디스크
step "1. 디스크(GPT: ESP 512MB + root ext4) — ${OS_DISK_GB}GB 가상"
truncate -s "${OS_DISK_GB}G" "$RAW"
sgdisk -Z "$RAW" >/dev/null 2>&1
sgdisk -n 1:1MiB:+512MiB -t 1:ef00 -c 1:"EFI System" -n 2:0:0 -t 2:8300 -c 2:"aiops-root" "$RAW" >/dev/null
pinfo() { local f l; f=$(sgdisk -i "$1" "$RAW" | sed -n 's/^First sector: \([0-9]*\).*/\1/p'); l=$(sgdisk -i "$1" "$RAW" | sed -n 's/^Last sector: \([0-9]*\).*/\1/p'); echo "$f $((l-f+1))"; }
read -r P1S P1N < <(pinfo 1)
read -r P2S P2N < <(pinfo 2)
[[ "$P1S" -gt 0 && "$P2N" -gt 0 ]] || die "파티션 정보 읽기 실패"
LOOP_ESP="$(losetup -f --show -o $((P1S*512)) --sizelimit $((P1N*512)) "$RAW")"
LOOP_ROOT="$(losetup -f --show -o $((P2S*512)) --sizelimit $((P2N*512)) "$RAW")"
mkfs.vfat -F 32 -n EFI "$LOOP_ESP" >/dev/null
mkfs.ext4 -q -L aiops-root -O ^orphan_file "$LOOP_ROOT" 2>/dev/null || mkfs.ext4 -q -L aiops-root "$LOOP_ROOT"
ROOT_UUID="$(blkid -s UUID -o value "$LOOP_ROOT")"; ESP_UUID="$(blkid -s UUID -o value "$LOOP_ESP")"
mkdir -p "$MNT"; mount "$LOOP_ROOT" "$MNT"
ok "root UUID=$ROOT_UUID · ESP UUID=$ESP_UUID"

# ------------------------------------------------------------------------------- 2. 기본 OS
step "2. Ubuntu $SUITE 기본 시스템(debootstrap)"
debootstrap --arch=amd64 --variant=minbase --components=main,restricted,universe \
  --include=ca-certificates,gpg "$SUITE" "$MNT" "$MIRROR" > "$WORK/debootstrap.log" 2>&1 \
  || { tail -30 "$WORK/debootstrap.log"; die "debootstrap 실패"; }
mkdir -p "$MNT/boot/efi"     # ESP 는 마운트하지 않고 7단계에서 mtools 로 기록(vfat 커널 모듈 불필요)
for m in dev dev/pts proc sys; do mount --bind "/$m" "$MNT/$m"; done
mount -t tmpfs tmpfs "$MNT/run"; mkdir -p "$MNT/run/systemd/resolve"
cp -L /etc/resolv.conf "$MNT/run/systemd/resolve/stub-resolv.conf"
rm -f "$MNT/etc/resolv.conf"; cp -L /etc/resolv.conf "$MNT/etc/resolv.conf"
printf '#!/bin/sh\nexit 101\n' > "$MNT/usr/sbin/policy-rc.d"; chmod 0755 "$MNT/usr/sbin/policy-rc.d"
cat > "$MNT/etc/apt/sources.list.d/ubuntu.sources" <<EOF
Types: deb
URIs: $MIRROR
Suites: $SUITE $SUITE-updates $SUITE-security
Components: main restricted universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
: > "$MNT/etc/apt/sources.list"
# 빌드 중 프록시·사내 CA(있으면) 전달 — 이미지에는 남기지 않음
CHENV=(DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin)
for v in http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_TRUSTED_HOST; do
  [[ -n "${!v:-}" ]] && CHENV+=("$v=${!v}")
done
for v in PIP_CERT SSL_CERT_FILE REQUESTS_CA_BUNDLE; do
  if [[ -n "${!v:-}" && -f "${!v}" ]]; then cp "${!v}" "$MNT/tmp/build-ca.crt"; CHENV+=("$v=/tmp/build-ca.crt"); fi
done
ch() { chroot "$MNT" /usr/bin/env -i "${CHENV[@]}" "$@"; }
ok "debootstrap $(ch cat /etc/lsb-release | sed -n 's/DISTRIB_DESCRIPTION=//p' | tr -d '"')"

# ------------------------------------------------------------------------------- 3. 패키지
step "3. 커널·부트로더·VMware 도구·운영 패키지"
# 어플라이언스 크기 축소: 문서·man·번역 제외(저작권 고지는 유지) — Ubuntu minimal 이미지와 같은 방식
cat > "$MNT/etc/dpkg/dpkg.cfg.d/01-vcf-aiops-nodoc" <<'EOF'
path-exclude=/usr/share/doc/*
path-include=/usr/share/doc/*/copyright
path-exclude=/usr/share/man/*
path-exclude=/usr/share/info/*
path-exclude=/usr/share/locale/*
path-include=/usr/share/locale/ko/*
path-include=/usr/share/locale/en*/*
path-include=/usr/share/locale/locale.alias
EOF
find "$MNT/usr/share/doc" -type f ! -name copyright -delete 2>/dev/null || true
rm -rf "$MNT"/usr/share/man/* "$MNT"/usr/share/info/*
mkdir -p "$MNT/etc/initramfs-tools/conf.d"; echo "RESUME=none" > "$MNT/etc/initramfs-tools/conf.d/vcf-aiops"
cat > "$MNT/etc/fstab" <<EOF
# VCF AIops 어플라이언스
UUID=$ROOT_UUID  /          ext4  defaults,errors=remount-ro  0 1
UUID=$ESP_UUID   /boot/efi  vfat  umask=0077                  0 1
EOF
echo "aiops" > "$MNT/etc/hostname"
ch apt-get update -qq
PKGS=(linux-image-virtual initramfs-tools systemd-sysv systemd-resolved udev kmod dbus netplan.io iproute2
      openssh-server open-vm-tools sudo curl openssl chrony ufw sqlite3 python3 python3-venv python3-pip logrotate
      cloud-guest-utils xfsprogs e2fsprogs dosfstools gdisk less vim-tiny nano iputils-ping bind9-dnsutils tcpdump
      lsof tzdata bash-completion apt-utils util-linux shim-signed grub-efi-amd64-signed efibootmgr)
ch apt-get install -y -qq --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
   "${PKGS[@]}" > "$WORK/apt.log" 2>&1 || { tail -40 "$WORK/apt.log"; die "패키지 설치 실패"; }
KVER="$(ls "$MNT/lib/modules" | sort -V | tail -1)"
for mod in vmw_pvscsi vmxnet3 vmw_vmci vmw_vsock_vmci_transport; do
  [[ -n "$(find "$MNT/lib/modules/$KVER" -name "${mod}.ko*" -print -quit)" ]] || die "커널 모듈 없음: $mod"
done
ok "커널 $KVER (vmw_pvscsi·vmxnet3·vmci 모듈 확인) · 패키지 ${#PKGS[@]}개"

# ------------------------------------------------------------------------------- 4. 부팅(UEFI·보안 부팅)
step "4. UEFI 부팅(shim → grub → 커널, Canonical 서명)"
first() { local f; for f in "$@"; do [[ -f "$f" ]] && { echo "$f"; return 0; }; done; echo ""; }
SHIM="$(first "$MNT"/usr/lib/shim/shimx64.efi.signed.latest "$MNT"/usr/lib/shim/shimx64.efi.signed)"
MM="$(first "$MNT"/usr/lib/shim/mmx64.efi.signed "$MNT"/usr/lib/shim/mmx64.efi)"
GRUB="$MNT/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed"
[[ -f "$SHIM" && -f "$GRUB" ]] || die "서명된 shim/grub 없음"
for d in BOOT ubuntu; do
  mkdir -p "$MNT/boot/efi/EFI/$d"
  cat > "$MNT/boot/efi/EFI/$d/grub.cfg" <<EOF
search.fs_uuid $ROOT_UUID root
set prefix=(\$root)'/boot/grub'
configfile \$prefix/grub.cfg
EOF
  cp "$GRUB" "$MNT/boot/efi/EFI/$d/grubx64.efi"
  [[ -n "$MM" ]] && cp "$MM" "$MNT/boot/efi/EFI/$d/mmx64.efi"
done
cp "$SHIM" "$MNT/boot/efi/EFI/BOOT/BOOTX64.EFI"; cp "$SHIM" "$MNT/boot/efi/EFI/ubuntu/shimx64.efi"
mkdir -p "$MNT/boot/grub"
CMDLINE="root=UUID=$ROOT_UUID ro console=ttyS0,115200n8 console=tty0 quiet"
cat > "$MNT/boot/grub/grub.cfg" <<EOF
# VCF AIops 어플라이언스 — 커널 업데이트 시 update-grub 가 다시 생성합니다
set timeout=3
set default=0
search --no-floppy --fs-uuid --set=root $ROOT_UUID
menuentry "VCF AIops Appliance (Ubuntu 24.04 LTS)" {
  linux /boot/vmlinuz $CMDLINE
  initrd /boot/initrd.img
}
menuentry "VCF AIops Appliance (recovery mode)" {
  linux /boot/vmlinuz root=UUID=$ROOT_UUID ro single nomodeset console=tty0
  initrd /boot/initrd.img
}
EOF
# update-grub 가 쓰는 기본값(설치 후 커널 업데이트 대비)
mkdir -p "$MNT/etc/default/grub.d"
cat > "$MNT/etc/default/grub.d/90-vcf-aiops.cfg" <<'EOF'
GRUB_TIMEOUT=3
GRUB_TIMEOUT_STYLE=menu
GRUB_CMDLINE_LINUX_DEFAULT="quiet"
GRUB_CMDLINE_LINUX="console=ttyS0,115200n8 console=tty0"
GRUB_TERMINAL=console
EOF
[[ -e "$MNT/boot/vmlinuz" && -e "$MNT/boot/initrd.img" ]] || { ch ln -sf "vmlinuz-$KVER" /boot/vmlinuz; ch ln -sf "initrd.img-$KVER" /boot/initrd.img; }
ch update-initramfs -u -k all >/dev/null 2>&1
INITRD_LIST="$(ch lsinitramfs "/boot/initrd.img-$KVER")"
for mod in vmw_pvscsi vmxnet3; do grep -qE "/${mod}\.ko" <<<"$INITRD_LIST" || die "initramfs 에 $mod 없음"; done
ok "ESP: /EFI/BOOT/BOOTX64.EFI(shim) · /EFI/ubuntu · initramfs(pvscsi 포함)"

# ------------------------------------------------------------------------------- 5. OS 설정
step "5. OS 설정(계정·SSH·네트워크·시간·저널)"
ch useradd -m -s /bin/bash -G sudo,adm,systemd-journal -c "VCF AIops admin" "$OS_USER"
ch passwd -l "$OS_USER" >/dev/null; ch passwd -l root >/dev/null
echo "$OS_USER ALL=(ALL:ALL) ALL" > "$MNT/etc/sudoers.d/90-$OS_USER"; chmod 0440 "$MNT/etc/sudoers.d/90-$OS_USER"
mkdir -p "$MNT/etc/ssh/sshd_config.d"
cat > "$MNT/etc/ssh/sshd_config.d/10-vcf-aiops.conf" <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
EOF
rm -f "$MNT"/etc/ssh/ssh_host_*                         # VM 마다 첫 부팅에 생성
ln -sf ../run/systemd/resolve/stub-resolv.conf "$MNT/etc/resolv.conf.final"
mkdir -p "$MNT/etc/netplan"; chmod 0755 "$MNT/etc/netplan"
cat > "$MNT/etc/netplan/50-vcf-aiops.yaml" <<'EOF'
# 첫 부팅 전 기본값(DHCP) — vcf-aiops-provision-early 가 vApp 속성으로 다시 씁니다
network:
  version: 2
  renderer: networkd
  ethernets:
    nic0:
      match: {name: "en*"}
      dhcp4: true
      dhcp-identifier: mac
EOF
chmod 0600 "$MNT/etc/netplan/50-vcf-aiops.yaml"
mkdir -p "$MNT/etc/systemd/system/systemd-networkd-wait-online.service.d"
cat > "$MNT/etc/systemd/system/systemd-networkd-wait-online.service.d/10-vcf-aiops.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --timeout=90
EOF
mkdir -p "$MNT/var/log/journal" "$MNT/etc/issue.d"
echo 'LANG=C.UTF-8' > "$MNT/etc/default/locale"
cat > "$MNT/etc/motd" <<'EOF'

  VCF AIops Appliance - vcf-aiopsctl status | logs | health | ovf | provision-log | support
  config /etc/vcf-aiops  data /var/lib/vcf-aiops  docs /opt/vcf-aiops/docs/OVA.md

EOF
: > "$MNT/etc/legal" 2>/dev/null || true
rm -f "$MNT"/etc/update-motd.d/10-help-text "$MNT"/etc/update-motd.d/50-motd-news 2>/dev/null || true
ch systemctl enable systemd-networkd systemd-resolved ssh.socket open-vm-tools chrony >/dev/null 2>&1 || true
ch systemctl disable ssh.service >/dev/null 2>&1 || true
ch systemctl mask systemd-networkd-wait-online@.service >/dev/null 2>&1 || true
ok "계정 $OS_USER(잠금 — 첫 부팅에 vApp 속성 비밀번호) · root 잠금 · SSH 호스트 키 제거"

# ------------------------------------------------------------------------------- 6. VCF AIops
step "6. VCF AIops 프로그램·파이썬 패키지(이미지 단계)"
STAGE_SRC="$MNT/root/vcf-aiops-src"; mkdir -p "$STAGE_SRC"
tar -C "$SRC" --exclude='./out' --exclude='./.git' --exclude='__pycache__' --exclude='./data' --exclude='./.hypothesis' --exclude='./docs/images' --exclude='./.github' \
    --exclude='./.pytest_cache' --exclude='*.ova' --exclude='*.vmdk' --exclude='*.raw' -cf - . | tar -C "$STAGE_SRC" -xf -
OFFL=(); if [[ -n "$WHEELHOUSE" ]]; then mkdir -p "$MNT/root/offline"; cp -a "$WHEELHOUSE" "$MNT/root/offline/wheelhouse"; OFFL=(--offline /root/offline); fi
ch bash /root/vcf-aiops-src/scripts/linux/install.sh --stage image "${OFFL[@]}" > "$WORK/install.log" 2>&1 \
  || { tail -40 "$WORK/install.log"; die "install.sh --stage image 실패"; }
sed 's/\x1b\[[0-9;]*m//g' "$WORK/install.log" | grep -E '✔|!' | sed 's/^/   /'
# 서비스는 python -O 로 실행 → 최적화 바이트코드(.opt-1.pyc)만 남기고 일반 .pyc 제거(크기 축소)
find "$MNT/opt/vcf-aiops/venv" -path '*/__pycache__/*.pyc' ! -name '*.opt-1.pyc' -delete
# govc(VMware govmomi, Apache-2.0) — 커넥터 화면의 '수집 전용 계정 만들기'에서 vCenter SSO 사용자 생성에 사용
GOVC_VER="${GOVC_VERSION:-v0.46.3}"; GOVC_SHA="${GOVC_SHA256:-91f96c35a48cdde8c5e661c6c219bdf1303fbefbedcf13eb078b64a194e56d4a}"
if [[ -n "${GOVC_TGZ:-}" && -f "$GOVC_TGZ" ]]; then cp "$GOVC_TGZ" "$WORK/govc.tgz"
else curl -fsSL -o "$WORK/govc.tgz" "https://github.com/vmware/govmomi/releases/download/${GOVC_VER}/govc_Linux_x86_64.tar.gz" || true; fi
if [[ -f "$WORK/govc.tgz" ]] && echo "$GOVC_SHA  $WORK/govc.tgz" | sha256sum -c --quiet - 2>/dev/null; then
  mkdir -p "$MNT/opt/vcf-aiops/bin" "$MNT/opt/vcf-aiops/licenses"
  tar -xzf "$WORK/govc.tgz" -C "$MNT/opt/vcf-aiops/bin" govc && chmod 0755 "$MNT/opt/vcf-aiops/bin/govc"
  tar -xzf "$WORK/govc.tgz" -C "$MNT/opt/vcf-aiops/licenses" LICENSE.txt 2>/dev/null && mv "$MNT/opt/vcf-aiops/licenses/LICENSE.txt" "$MNT/opt/vcf-aiops/licenses/govc-LICENSE.txt" || true
  ok "govc ${GOVC_VER} (SHA256 확인) → /opt/vcf-aiops/bin/govc"
else
  echo "  ! govc 다운로드/검증 실패 — vCenter 수집 전용 계정 자동 생성 불가(GOVC_TGZ=<파일> 로 지정 가능)"
fi
install -m 0644 "$HERE/systemd/vcf-aiops-provision-early.service" "$MNT/etc/systemd/system/"
install -m 0644 "$HERE/systemd/vcf-aiops-provision.service" "$MNT/etc/systemd/system/"
mkdir -p "$MNT/etc/systemd/system/vcf-aiops.service.d"
cat > "$MNT/etc/systemd/system/vcf-aiops.service.d/20-appliance.conf" <<'EOF'
# 어플라이언스: 첫 기동 때만 존재하는 1회용 환경 파일(웹 콘솔 admin 초기 비밀번호) — 구성 직후 파기
[Service]
EnvironmentFile=-/etc/vcf-aiops/firstboot.env
EOF
ch systemctl enable vcf-aiops-provision-early.service vcf-aiops-provision.service >/dev/null 2>&1
ch systemctl disable vcf-aiops.service >/dev/null 2>&1 || true   # 첫 부팅 구성(install.sh --stage configure)이 활성화
# 이미지에는 비밀·인증서·데이터 없음(첫 부팅에 VM 마다 생성)
rm -rf "$MNT/etc/vcf-aiops/"{secret.key,.env,config.yaml,firstboot.env} "$MNT/etc/vcf-aiops/certs/"* "$MNT/var/lib/vcf-aiops/"*
install -d -m 0750 -o 0 -g "$(ch getent group aiops | cut -d: -f3)" "$MNT/etc/vcf-aiops/certs"
echo "$VERSION" > "$MNT/opt/vcf-aiops/VERSION"; chmod 0644 "$MNT/opt/vcf-aiops/VERSION"
cat > "$MNT/etc/vcf-aiops-appliance-release" <<EOF
VCF AIops Appliance $VERSION (Ubuntu 24.04 LTS, kernel $KVER)
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
VERSION=$VERSION
EOF
ok "/opt/vcf-aiops $(du -sh "$MNT/opt/vcf-aiops" | cut -f1) · 프로비저닝 유닛 활성"

# ------------------------------------------------------------------------------- 7. 정리
step "7. 정리(machine-id·로그·캐시·빈 공간 회수)"
ch apt-get clean
rm -rf "$MNT/var/lib/apt/lists/"* "$MNT/root/vcf-aiops-src" "$MNT/root/offline" "$MNT/tmp/"* "$MNT/var/tmp/"* \
       "$MNT/root/.cache" "$MNT/root/.bash_history" "$MNT/var/cache/debconf/"*-old "$MNT/usr/sbin/policy-rc.d"
find "$MNT/var/log" -type f \( -name '*.log' -o -name '*.gz' -o -name '*.[0-9]' \) -delete
: > "$MNT/etc/machine-id"; rm -f "$MNT/var/lib/dbus/machine-id"; ln -sf /etc/machine-id "$MNT/var/lib/dbus/machine-id"
rm -f "$MNT/var/lib/systemd/random-seed" "$MNT/var/lib/systemd/credential.secret"
rm -f "$MNT/etc/resolv.conf"; mv "$MNT/etc/resolv.conf.final" "$MNT/etc/resolv.conf"
USED="$(df -B1 --output=used "$MNT" | tail -1 | tr -dc 0-9)"
for m in run sys proc dev/pts dev; do umount -l "$MNT/$m"; done
MTOOLS_SKIP_CHECK=1 mcopy -s -o -i "$LOOP_ESP" "$MNT"/boot/efi/* ::/ 2>/dev/null
MTOOLS_SKIP_CHECK=1 mdir -/ -b -i "$LOOP_ESP" ::/EFI 2>/dev/null | sed 's/^/   ESP /'
rm -rf "$MNT"/boot/efi/*
fstrim "$MNT" >/dev/null 2>&1 || true
umount "$MNT"; e2fsck -fy "$LOOP_ROOT" >/dev/null 2>&1 || true
# 삭제된 파일(.deb·pip 캐시)이 남긴 블록을 0 으로 — fstrim 이 루프 백엔드까지 전달되지 않는 환경 대비, VMDK 가 0 블록은 생략
command -v zerofree >/dev/null && zerofree "$LOOP_ROOT" && ok "빈 블록 0 채움(zerofree)"
losetup -d "$LOOP_ESP" "$LOOP_ROOT"; LOOP_ESP=""; LOOP_ROOT=""
ok "root 실사용 $((USED/1024/1024)) MiB"

# ------------------------------------------------------------------------------- 8. VMDK · OVF · OVA
step "8. VMDK(streamOptimized) · OVF · OVA"
rm -f "$VMDK"
qemu-img convert -p -f raw -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic,compat6 "$RAW" "$VMDK" >/dev/null
python3 "$HERE/make-ovf.py" --vmdk "$VMDK" --version "$VERSION" --name "$NAME" --out "$OUT" --populated "$USED"
( cd "$OUT" && sha256sum "$BASE.ova" "$BASE.ovf" "$BASE.mf" "$(basename "$VMDK")" > "$BASE.SHA256SUMS" )
ok "$(ls -lh "$OUT/$BASE.ova" | awk '{print $5}')  $OUT/$BASE.ova"
echo
echo "  배포: vSphere Client › 클러스터 › OVF 템플릿 배포 › $BASE.ova › 배포 크기 선택 › vApp 속성 입력 › 전원 켜기"
echo "  CLI : ovftool --acceptAllEulas --powerOn --deploymentOption=medium --prop:net.hostname=aiops.corp.example ... $BASE.ova vi://..."
