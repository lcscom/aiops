#!/usr/bin/env python3
"""VCF AIops 어플라이언스 — 첫 부팅 자동 구성(OVF vApp 속성 → OS·네트워크·디스크·앱).

  provision.py early   부팅 초기, 네트워크 기동 전(매 부팅): SSH 호스트 키 · 호스트 이름 · netplan · OS 디스크 확장 · 데이터 디스크
  provision.py late    네트워크 이후(매 부팅): 최초 1회 계정·SSH·시간대·인증서·앱 구성/기동, 이후 변경분(FQDN·NTP·시간대·SSH) 반영 · 콘솔 배너
  provision.py show    현재 속성(비밀값 가림)과 상태
  provision.py banner  콘솔 배너만 갱신

속성 출처(앞에서 찾으면 사용):
  1) /etc/vcf-aiops/ovf-env.xml       수동 재구성·시험용
  2) VMware guestinfo.ovfEnv          vCenter 배포(vApp 옵션, OVF 전송 'VMware Tools')
  3) ISO 전송                         레이블 'OVF ENV' CD-ROM 의 ovf-env.xml (vCenter ISO 전송·KVM 시험)
비밀값(비밀번호·키)은 최초 구성에만 쓰고 파일에 남기지 않습니다. vApp 속성 값 자체는 vCenter 에 남으므로
배포 후 비밀번호는 반드시 변경하세요(OS·웹 콘솔 모두 최초 로그인 시 변경 강제).
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from spec import DEFAULTS, OS_USER, PASSWORD_KEYS  # noqa: E402

PREFIX = Path("/opt/vcf-aiops")
ETC = Path("/etc/vcf-aiops")
DATA = Path("/var/lib/vcf-aiops")
STATE_DIR = Path("/var/lib/vcf-aiops-appliance")
STATE = STATE_DIR / "state.json"
RUN = Path("/run/vcf-aiops-appliance")
LOG = Path("/var/log/vcf-aiops-provision.log")
NETPLAN = Path("/etc/netplan/50-vcf-aiops.yaml")
ISSUE = Path("/etc/issue.d/50-vcf-aiops.issue")
RELEASE = Path("/etc/vcf-aiops-appliance-release")
OVF_NS = "http://schemas.dmtf.org/ovf/environment/1"
DATA_LABEL = "aiops-data"


# ============================================================================ 공통
def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(msg, flush=True)
    try:
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        os.chmod(LOG, 0o600)
    except OSError:
        pass


def run(cmd: list[str], check: bool = True, input: str | None = None, timeout: int = 900,
        quiet: bool = False) -> subprocess.CompletedProcess:
    shown = " ".join(cmd)
    if not quiet:
        log(f"  $ {shown}")
    p = subprocess.run(cmd, input=input, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"명령 실패({p.returncode}): {shown}\n{(p.stdout or '')[-2000:]}{(p.stderr or '')[-2000:]}")
    return p


def write(path: Path, text: str, mode: int = 0o644, owner: str | None = None) -> bool:
    """내용이 바뀐 경우에만 기록 — 바뀌었으면 True."""
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == text:
        return False
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    if owner:
        shutil.chown(tmp, *owner.split(":"))
    os.replace(tmp, path)
    return True


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(st: dict) -> None:
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    write(STATE, json.dumps(st, ensure_ascii=False, indent=1), 0o600)


def digest(*vals: object) -> str:
    return hashlib.sha256(json.dumps(vals, sort_keys=True).encode()).hexdigest()[:16]


# ============================================================================ OVF 환경
def virt() -> str:
    p = subprocess.run(["systemd-detect-virt"], text=True, capture_output=True)
    return (p.stdout or "").strip()


def _from_guestinfo() -> str | None:
    if virt() != "vmware":
        return None
    for cmd in (["vmtoolsd", "--cmd", "info-get guestinfo.ovfEnv"], ["vmware-rpctool", "info-get guestinfo.ovfEnv"]):
        if shutil.which(cmd[0]):
            p = subprocess.run(cmd, text=True, capture_output=True, timeout=30)
            if p.returncode == 0 and "<" in (p.stdout or ""):
                return p.stdout
    return None


def _from_iso() -> str | None:
    devs: list[str] = []
    p = subprocess.run(["blkid", "-t", "LABEL=OVF ENV", "-o", "device"], text=True, capture_output=True)
    devs += [d for d in (p.stdout or "").split() if d]
    devs += [str(d) for d in sorted(Path("/dev").glob("sr[0-9]*"))]
    for dev in dict.fromkeys(devs):
        with tempfile.TemporaryDirectory() as mnt:
            if subprocess.run(["mount", "-o", "ro", dev, mnt], capture_output=True).returncode != 0:
                continue
            try:
                for name in ("ovf-env.xml", "OVF-ENV.XML", "ovf_env.xml"):
                    f = Path(mnt) / name
                    if f.exists():
                        return f.read_text(encoding="utf-8")
            finally:
                subprocess.run(["umount", mnt], capture_output=True)
    return None


def read_env() -> tuple[str | None, str]:
    """(ovf-env XML, 출처). 찾은 XML 은 /run(tmpfs, 0600) 에 캐시 — late 단계·show 에서 재사용."""
    cache = RUN / "ovf-env.xml"
    override = ETC / "ovf-env.xml"
    if override.exists():
        return override.read_text(encoding="utf-8"), str(override)
    for src, fn in (("guestinfo.ovfEnv", _from_guestinfo), ("ISO 'OVF ENV'", _from_iso)):
        try:
            xml = fn()
        except Exception as e:  # noqa: BLE001
            log(f"  ! {src} 읽기 실패: {e}")
            xml = None
        if xml:
            RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
            write(cache, xml, 0o600)
            write(RUN / "source", src, 0o600)
            return xml, src
    if cache.exists():
        src = (RUN / "source").read_text(encoding="utf-8") if (RUN / "source").exists() else "cache"
        return cache.read_text(encoding="utf-8"), src + " (캐시)"
    return None, "없음"


def parse_env(xml: str) -> dict[str, str]:
    root = ET.fromstring(xml)
    out: dict[str, str] = {}
    for el in root.iter():
        if el.tag.endswith("}Property") or el.tag == "Property":
            k = el.get(f"{{{OVF_NS}}}key") or el.get("key")
            v = el.get(f"{{{OVF_NS}}}value")
            if v is None:
                v = el.get("value", "")
            if k:
                out[k] = v
    return out


class Props:
    def __init__(self, raw: dict[str, str], source: str):
        self.raw = raw
        self.source = source
        self.v = {k: (raw.get(k) if raw.get(k) is not None else d) for k, d in DEFAULTS.items()}
        for k, val in raw.items():
            self.v.setdefault(k, val)

    def s(self, k: str) -> str:
        return (self.v.get(k) or "").strip()

    def b(self, k: str) -> bool:
        return self.s(k).lower() in ("true", "1", "yes", "y", "on")

    def i(self, k: str, lo: int, hi: int) -> int:
        try:
            n = int(self.s(k) or DEFAULTS[k])
        except ValueError:
            n = int(DEFAULTS[k])
        return min(max(n, lo), hi)

    def lst(self, k: str) -> list[str]:
        return [x for x in re.split(r"[,\s;]+", self.s(k)) if x]

    def redacted(self) -> dict[str, str]:
        return {k: ("********" if k in PASSWORD_KEYS and v else
                    (v[:24] + "…(base64)" if k.endswith("_pem") and v else v))
                for k, v in sorted(self.v.items())}


def load_props() -> Props:
    xml, src = read_env()
    if not xml:
        return Props({}, "없음")
    try:
        return Props(parse_env(xml), src)
    except ET.ParseError as e:
        log(f"  ! OVF 환경 XML 해석 실패({src}): {e} — 기본값 사용")
        return Props({}, src + " (해석 실패)")


# ============================================================================ 검증
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def net_settings(p: Props) -> dict:
    fqdn = p.s("net.hostname").rstrip(".").lower() or "aiops"
    if not HOST_RE.match(fqdn):
        log(f"  ! 호스트 이름 형식 오류 '{fqdn}' → 'aiops' 사용")
        fqdn = "aiops"
    ip = p.s("net.ip")
    cfg = {"fqdn": fqdn, "short": fqdn.split(".")[0], "dhcp": True, "ip": "", "prefix": 24, "gateway": "",
           "dns": [], "search": [], "ntp": []}
    for d in p.lst("net.dns"):
        try:
            cfg["dns"].append(str(ipaddress.ip_address(d)))
        except ValueError:
            log(f"  ! DNS 주소 무시: {d}")
    cfg["search"] = [d for d in p.lst("net.search") if HOST_RE.match(d)]
    cfg["ntp"] = [n for n in p.lst("net.ntp") if HOST_RE.match(n) or _is_ip(n)]
    if ip:
        try:
            pre = p.i("net.prefix", 1, 32)
            iface = ipaddress.ip_interface(f"{ip}/{pre}")
            cfg.update(dhcp=False, ip=str(iface.ip), prefix=pre)
            gw = p.s("net.gateway")
            if gw:
                g = ipaddress.ip_address(gw)
                if g not in iface.network:
                    log(f"  ! 게이트웨이 {g} 가 {iface.network} 밖에 있습니다(on-link 로 설정)")
                cfg["gateway"] = str(g)
        except ValueError as e:
            log(f"  ! IP 설정 오류({e}) → DHCP 사용")
    return cfg


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ============================================================================ early
def ssh_host_keys() -> None:
    if not list(Path("/etc/ssh").glob("ssh_host_*_key")):
        run(["ssh-keygen", "-A"])
        log("✔ SSH 호스트 키 생성(이 VM 고유)")


def apply_hostname(n: dict) -> None:
    changed = write(Path("/etc/hostname"), n["short"] + "\n")
    hosts_ip = n["ip"] or "127.0.1.1"
    names = f"{n['fqdn']} {n['short']}" if n["fqdn"] != n["short"] else n["short"]
    hosts = Path("/etc/hosts").read_text(encoding="utf-8") if Path("/etc/hosts").exists() else ""
    kept = [ln for ln in hosts.splitlines() if "# vcf-aiops" not in ln and not ln.startswith("127.0.1.1")]
    if not any(ln.startswith("127.0.0.1") for ln in kept):
        kept.insert(0, "127.0.0.1 localhost")
    if not any(ln.startswith("::1") for ln in kept):
        kept.append("::1 localhost ip6-localhost ip6-loopback")
    kept.insert(1, f"{hosts_ip} {names} # vcf-aiops")
    write(Path("/etc/hosts"), "\n".join(kept) + "\n")
    subprocess.run(["hostname", n["short"]], capture_output=True)
    if changed:
        log(f"✔ 호스트 이름 {n['fqdn']}")


def apply_netplan(n: dict) -> None:
    nic: dict = {"match": {"name": "en*"}}       # vmxnet3 → ens160/ens192 등, NIC 1개 기준
    if n["dhcp"]:
        nic.update({"dhcp4": True, "dhcp6": False, "dhcp-identifier": "mac"})
        if n["dns"] or n["search"]:
            nic["dhcp4-overrides"] = {"use-dns": not n["dns"]}
    else:
        nic.update({"dhcp4": False, "dhcp6": False, "addresses": [f"{n['ip']}/{n['prefix']}"]})
        if n["gateway"]:
            route = {"to": "default", "via": n["gateway"]}
            if not ipaddress.ip_address(n["gateway"]) in ipaddress.ip_interface(f"{n['ip']}/{n['prefix']}").network:
                route["on-link"] = True
            nic["routes"] = [route]
    if n["dns"] or n["search"]:
        nic["nameservers"] = {k: v for k, v in (("addresses", n["dns"]), ("search", n["search"])) if v}
    doc = {"network": {"version": 2, "renderer": "networkd", "ethernets": {"nic0": nic}}}
    text = "# VCF AIops 어플라이언스 — vApp 속성에서 생성(직접 수정하면 다음 부팅 때 덮어씀; 고정하려면 /etc/vcf-aiops/ovf-env.xml)\n" \
           + _yaml(doc)
    for f in Path("/etc/netplan").glob("*.yaml"):
        if f != NETPLAN:
            f.rename(f.with_suffix(".yaml.disabled"))
            log(f"  기존 netplan 비활성: {f}")
    if write(NETPLAN, text, 0o600):
        log(f"✔ netplan {'DHCP' if n['dhcp'] else n['ip'] + '/' + str(n['prefix']) + ' gw ' + (n['gateway'] or '-')}"
            f" dns {','.join(n['dns']) or '-'}")
    run(["netplan", "generate"], quiet=True)


def _yaml(o, ind: int = 0) -> str:
    """netplan 용 최소 YAML 직렬화(문자열은 JSON 인용 — YAML 의 부분집합)."""
    pad = "  " * ind
    out = ""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, (dict, list)) and v:
                out += f"{pad}{k}:\n{_yaml(v, ind + 1)}"
            else:
                out += f"{pad}{k}: {_scalar(v)}\n"
    elif isinstance(o, list):
        for v in o:
            if isinstance(v, dict):
                first = True
                for k, vv in v.items():
                    lead = f"{pad}- " if first else f"{pad}  "
                    first = False
                    if isinstance(vv, (dict, list)) and vv:
                        out += f"{lead}{k}:\n{_yaml(vv, ind + 2)}"
                    else:
                        out += f"{lead}{k}: {_scalar(vv)}\n"
            else:
                out += f"{pad}- {_scalar(v)}\n"
    return out


def _scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (list, dict)):
        return "[]" if isinstance(v, list) else "{}"
    return json.dumps(str(v))


def grow_root() -> None:
    src = run(["findmnt", "-no", "SOURCE", "/"], quiet=True).stdout.strip()
    disk = run(["lsblk", "-no", "PKNAME", src], quiet=True, check=False).stdout.strip()
    m = re.search(r"(\d+)$", src)
    if not disk or not m or not shutil.which("growpart"):
        return
    p = subprocess.run(["growpart", f"/dev/{disk}", m.group(1)], text=True, capture_output=True)
    if p.returncode == 0:
        run(["resize2fs", src])
        log(f"✔ OS 디스크 확장: {src}")


def root_disk() -> str:
    src = run(["findmnt", "-no", "SOURCE", "/"], quiet=True).stdout.strip()
    return "/dev/" + run(["lsblk", "-no", "PKNAME", src], quiet=True, check=False).stdout.strip()


def prepare_data_disk() -> None:
    """빈 두 번째 디스크 → XFS(LABEL=aiops-data) → /var/lib/vcf-aiops. 이미 있으면 마운트만."""
    if shutil.which("udevadm"):
        subprocess.run(["udevadm", "settle", "-t", "30"], capture_output=True)
    fstab = Path("/etc/fstab")
    line = f"LABEL={DATA_LABEL} {DATA} xfs defaults,noatime,nofail,x-systemd.device-timeout=30s 0 2"
    if subprocess.run(["mountpoint", "-q", str(DATA)]).returncode == 0:
        return
    dev = subprocess.run(["blkid", "-L", DATA_LABEL], text=True, capture_output=True).stdout.strip()
    if not dev:
        rd = root_disk()
        out = run(["lsblk", "-dpnbo", "NAME,TYPE,SIZE,RO,RM"], quiet=True).stdout.split("\n")
        for ln in out:
            f = ln.split()
            if len(f) < 5 or f[1] != "disk" or f[0] == rd or f[3] == "1" or f[4] == "1" or int(f[2]) < (4 << 30):
                continue
            kids = run(["lsblk", "-no", "NAME", f[0]], quiet=True).stdout.split()
            sig = subprocess.run(["blkid", "-p", f[0]], capture_output=True).returncode  # 2 = 서명 없음
            if len(kids) == 1 and sig == 2:
                dev = f[0]
                break
        if not dev:
            log("  데이터 디스크 없음 — OS 디스크의 /var/lib/vcf-aiops 사용(운영은 두 번째 디스크 권장)")
            return
        run(["mkfs.xfs", "-q", "-L", DATA_LABEL, dev])
        log(f"✔ 데이터 디스크 포맷: {dev} → XFS LABEL={DATA_LABEL}")
        migrate_existing(dev)
    text = fstab.read_text(encoding="utf-8") if fstab.exists() else ""
    if f"LABEL={DATA_LABEL}" not in text:
        write(fstab, text.rstrip("\n") + "\n" + line + "\n")
    DATA.mkdir(parents=True, exist_ok=True)
    run(["mount", str(DATA)])
    for d in (DATA, DATA / "backup"):
        d.mkdir(exist_ok=True)
        subprocess.run(["chown", "aiops:aiops", str(d)], capture_output=True)
        os.chmod(d, 0o750)
    log(f"✔ 데이터 디스크 마운트: {DATA}")


def migrate_existing(dev: str) -> None:
    """나중에 데이터 디스크를 추가한 경우: OS 디스크의 기존 데이터를 새 디스크로 옮긴 뒤 마운트(서비스 기동 전 단계)."""
    if not DATA.is_dir() or not any(DATA.iterdir()):
        return
    tmp = Path("/run/vcf-aiops-data-migrate")
    tmp.mkdir(parents=True, exist_ok=True)
    run(["mount", dev, str(tmp)])
    try:
        run(["cp", "-a", f"{DATA}/.", str(tmp)])
        src_n = sum(1 for _ in DATA.rglob("*"))
        dst_n = sum(1 for _ in tmp.rglob("*"))
        if dst_n < src_n:
            raise RuntimeError(f"복사 검증 실패({dst_n}/{src_n})")
    finally:
        run(["umount", str(tmp)], check=False)
    for c in DATA.iterdir():
        shutil.rmtree(c) if c.is_dir() and not c.is_symlink() else c.unlink()
    log(f"✔ 기존 데이터 {src_n}개 항목을 새 데이터 디스크로 이전")


def early() -> int:
    log("━━ VCF AIops 프로비저닝(early)")
    p = load_props()
    log(f"  속성 출처: {p.source} · 속성 {len(p.raw)}개")
    n = net_settings(p)
    steps = (("SSH 호스트 키", ssh_host_keys), ("호스트 이름", lambda: apply_hostname(n)),
             ("네트워크", lambda: apply_netplan(n)), ("OS 디스크", grow_root), ("데이터 디스크", prepare_data_disk))
    rc = 0
    for name, fn in steps:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — 한 단계 실패가 부팅을 막지 않게
            rc = 1
            log(f"✖ {name}: {e}")
    return rc


# ============================================================================ late
def apply_timezone(tz: str) -> None:
    if not tz or not Path("/usr/share/zoneinfo", tz).is_file() or ".." in tz:
        log(f"  ! 시간대 '{tz}' 없음 — 유지")
        return
    cur = os.path.realpath("/etc/localtime")
    if cur.endswith("/" + tz):
        return
    if subprocess.run(["timedatectl", "set-timezone", tz], capture_output=True).returncode != 0:
        Path("/etc/localtime").unlink(missing_ok=True)
        os.symlink(f"/usr/share/zoneinfo/{tz}", "/etc/localtime")
        write(Path("/etc/timezone"), tz + "\n")
    log(f"✔ 시간대 {tz}")


def gen_password(n: int = 16) -> str:
    al = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        pw = "".join(secrets.choice(al) for _ in range(n))
        if all(any(c in s for c in pw) for s in (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#%^*-_=+")):
            return pw


def apply_os_account(p: Props, st: dict) -> None:
    pw = p.s("sys.password")
    key = p.s("sys.ssh_key")
    if not pw:
        pw = gen_password()
        st["generated_os_password"] = pw     # 콘솔 배너에만 표시, 최초 변경 후 상태 파일에서 삭제
        log("  ! sys.password 미입력 — 임시 비밀번호 생성(콘솔 배너 표시, 최초 로그인 시 변경)")
    if "\n" in pw:
        raise ValueError("비밀번호에 줄바꿈은 넣을 수 없습니다")
    run(["chpasswd"], input=f"{OS_USER}:{pw}\n", quiet=True)
    run(["chage", "-d", "0", OS_USER], quiet=True)     # 최초 로그인 시 변경 강제
    log(f"✔ OS 계정 {OS_USER} 비밀번호 설정(최초 로그인 시 변경)")
    if key:
        if not re.match(r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp\d+|sk-\S+) [A-Za-z0-9+/=]+( .*)?$", key):
            log("  ! SSH 공개 키 형식 오류 — 무시")
        else:
            home = Path(f"/home/{OS_USER}")
            write(home / ".ssh/authorized_keys", key + "\n", 0o600, f"{OS_USER}:{OS_USER}")
            os.chmod(home / ".ssh", 0o700)
            shutil.chown(home / ".ssh", OS_USER, OS_USER)
            log("✔ SSH 공개 키 등록")


def apply_ssh(enabled: bool) -> None:
    units = ["ssh.socket", "ssh.service"]
    if enabled:
        subprocess.run(["systemctl", "enable", "--now", "ssh.socket"], capture_output=True)
    else:
        subprocess.run(["systemctl", "disable", "--now", *units], capture_output=True)
        log("✔ SSH 비활성")


def apply_ntp(servers: list[str]) -> None:
    f = Path("/etc/chrony/sources.d/vcf-aiops.sources")
    text = "".join(f"server {s} iburst\n" for s in servers)
    if write(f, text):
        subprocess.run(["chronyc", "reload", "sources"], capture_output=True)
        log(f"✔ NTP {','.join(servers) or '(없음 — 기본 풀)'}")


def app_port(p: Props) -> int:
    port = p.i("app.port", 1024, 65535)
    if port == 6514:                       # syslog TLS 와 충돌
        log("  ! 웹 포트 6514 는 syslog TLS 와 겹칩니다 — 8630 사용")
        port = 8630
    return port


def wait_ready(port: int, secs: int = 180) -> bool:
    for _ in range(secs // 2):
        for scheme in ("https", "http"):
            if subprocess.run(["curl", "-fsk", "--max-time", "2", f"{scheme}://127.0.0.1:{port}/readyz"],
                              capture_output=True).returncode == 0:
                return True
        time.sleep(2)
    return False


def configure_app(p: Props, n: dict) -> None:
    port = app_port(p)
    cmd = ["bash", str(PREFIX / "scripts/linux/install.sh"), "--stage", "configure", "--fqdn", n["fqdn"],
           "--port", str(port), "--llm-model", p.s("app.llm_model") or DEFAULTS["app.llm_model"],
           "--retention-days", str(p.i("app.retention_days", 1, 90))]
    comm = p.s("app.snmp_community") or "public"
    if re.match(r"^[A-Za-z0-9._@:-]{1,64}$", comm):
        cmd += ["--snmp-community", comm]
    else:
        log("  ! SNMP 커뮤니티 형식 오류 — public 사용")
    if n["ntp"]:
        cmd += ["--ntp", ",".join(n["ntp"])]
    url = p.s("app.pais_url")
    if url:
        if re.match(r"^https?://[^\s#'\"]+$", url):
            cmd += ["--pais-url", url]
        else:
            log("  ! PAIS 주소 형식 오류 — 무시")
    key = p.s("app.pais_key")
    if key:
        if re.match(r"^[^\s#'\"&\\]+$", key):
            cmd += ["--pais-key", key]
        else:
            log("  ! PAIS 키에 공백·#·따옴표·&·\\ 는 넣을 수 없습니다 — 설치 후 /etc/vcf-aiops/.env 에 직접 입력")
    if p.b("sys.firewall"):
        cmd += ["--enable-firewall"]
    RUN.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp: list[Path] = []
    cp, kp = p.s("app.cert_pem"), p.s("app.key_pem")
    if cp and kp:
        try:
            c, k = base64.b64decode(cp, validate=False), base64.b64decode(kp, validate=False)
            if b"BEGIN CERTIFICATE" not in c or b"PRIVATE KEY" not in k:
                raise ValueError("PEM 아님")
            cf, kf = RUN / "aiops.crt", RUN / "aiops.key"
            cf.write_bytes(c)
            kf.write_bytes(k)
            os.chmod(cf, 0o600)
            os.chmod(kf, 0o600)
            mod_c = run(["openssl", "x509", "-noout", "-pubkey", "-in", str(cf)], quiet=True).stdout
            mod_k = run(["openssl", "pkey", "-pubout", "-in", str(kf)], quiet=True).stdout
            if mod_c.strip() != mod_k.strip():
                raise ValueError("인증서와 개인 키가 짝이 아닙니다")
            tmp += [cf, kf]
            cmd += ["--cert", str(cf), "--key", str(kf)]
            log("  사내 CA 인증서 사용")
        except Exception as e:  # noqa: BLE001
            log(f"  ! 인증서 속성 사용 불가({e}) — 자체 서명 인증서 생성")
    elif cp or kp:
        log("  ! 인증서와 개인 키는 함께 입력해야 합니다 — 자체 서명 인증서 생성")
    # 웹 콘솔 admin 초기 비밀번호: 1회용 환경 파일(서비스 첫 기동 때만 사용) → 준비 확인 후 파기
    fb = ETC / "firstboot.env"
    apw = p.s("app.admin_password")
    if apw and "\n" not in apw:
        ETC.mkdir(parents=True, exist_ok=True)
        write(fb, f"AIOPS_ADMIN_PASSWORD={apw}\n", 0o640, "root:aiops")
    else:
        log("  ! app.admin_password 미입력 — 초기 비밀번호를 /var/lib/vcf-aiops/initial-admin.txt 에 생성")
    try:
        p2 = subprocess.run(cmd, text=True, capture_output=True, timeout=1500)
        for ln in (p2.stdout + p2.stderr).splitlines():
            ln = re.sub(r"\x1b\[[0-9;]*m", "", ln).rstrip()
            if ln:
                log("  │ " + ln)
        if p2.returncode != 0:
            raise RuntimeError(f"install.sh --stage configure 실패({p2.returncode})")
    finally:
        for f in [fb, *tmp]:
            if f.exists():
                subprocess.run(["shred", "-u", str(f)], capture_output=True)
                f.unlink(missing_ok=True)


def refresh_fqdn(old: str, n: dict, port: int) -> None:
    """vApp 속성에서 FQDN 이 바뀐 경우: config.yaml 의 접속 주소 · 자체 서명 인증서 갱신 후 재시작."""
    cfg = ETC / "config.yaml"
    if cfg.exists():
        t = cfg.read_text(encoding="utf-8")
        # 이전 FQDN(또는 비어 있는 값)을 가리키는 주소만 갱신 — Cloudflare Tunnel 등 외부 공개 이름(2.21.2)은 유지
        def same(h: str) -> bool:
            return old in ("", "?") or h.lower() == old.lower()
        t2 = re.sub(r"(public_url: https?://)([^:/\s]+)", lambda m: m.group(1) + (n["fqdn"] if same(m.group(2)) else m.group(2)), t)
        t2 = re.sub(r"(advertise_host: )(\S+)", lambda m: m.group(1) + (n["fqdn"] if same(m.group(2)) else m.group(2)), t2)
        write(cfg, t2, 0o640, "root:aiops")
    crt = ETC / "certs/aiops.crt"
    if crt.exists():
        subj = run(["openssl", "x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253", "-in", str(crt)], quiet=True).stdout
        lines = [ln.split("=", 1)[1].strip() for ln in subj.splitlines() if "=" in ln]
        if len(lines) == 2 and lines[0] == lines[1]:      # 자체 서명만 교체(사내 CA 인증서는 유지)
            run(["bash", str(PREFIX / "scripts/linux/make-cert.sh"), "--fqdn", n["fqdn"], "--out", str(ETC / "certs")], check=False)
            subprocess.run(["chown", "root:aiops", str(ETC / "certs/aiops.key")], capture_output=True)
            os.chmod(ETC / "certs/aiops.key", 0o640)
        else:
            log("  ! 사내 CA 인증서는 유지 — 새 FQDN 이 SAN 에 없으면 재발급하세요")
    subprocess.run(["systemctl", "restart", "vcf-aiops"], capture_output=True)
    log(f"✔ FQDN 변경 반영 {old} → {n['fqdn']}")


def grow_data() -> None:
    if subprocess.run(["mountpoint", "-q", str(DATA)]).returncode == 0:
        subprocess.run(["xfs_growfs", "-d", str(DATA)], capture_output=True)


def late() -> int:
    log("━━ VCF AIops 프로비저닝(late)")
    st = load_state()
    p = load_props()
    n = net_settings(p)
    port = app_port(p)
    st["status"] = "configuring"
    save_state(st)
    banner(st, n, port)
    rc = 0
    try:
        apply_timezone(p.s("sys.timezone") or "Asia/Seoul")
        grow_data()
        if not st.get("configured"):
            apply_os_account(p, st)
            apply_ssh(p.b("sys.ssh"))
            configure_app(p, n)
            if not wait_ready(port, 240):
                raise RuntimeError("서비스 준비 확인 실패 — journalctl -u vcf-aiops")
            st.update(configured=time.time(), fqdn=n["fqdn"], ntp=n["ntp"], ssh=p.b("sys.ssh"), port=port)
            log(f"✔ 최초 구성 완료 — https://{n['fqdn']}:{port}/")
        else:
            if n["fqdn"] != st.get("fqdn"):
                refresh_fqdn(st.get("fqdn", "?"), n, st.get("port", port))
                st["fqdn"] = n["fqdn"]
            if n["ntp"] != st.get("ntp"):
                apply_ntp(n["ntp"])
                st["ntp"] = n["ntp"]
            if p.b("sys.ssh") != st.get("ssh"):
                apply_ssh(p.b("sys.ssh"))
                st["ssh"] = p.b("sys.ssh")
            if port != st.get("port"):
                log(f"  ! 웹 포트 변경({st.get('port')}→{port})은 자동 반영하지 않습니다 — config.yaml server.port 수정 후 재시작")
        # 생성된 임시 OS 비밀번호는 사용자가 바꾼 뒤 상태에서 삭제
        if st.get("generated_os_password"):
            ch = subprocess.run(["chage", "-l", OS_USER], text=True, capture_output=True,
                                env={**os.environ, "LC_ALL": "C"}).stdout
            if "password must be changed" not in ch.split("\n")[0]:
                st.pop("generated_os_password", None)
        st["status"] = "ready"
    except Exception as e:  # noqa: BLE001
        rc = 1
        st["status"] = "failed"
        st["error"] = str(e)[:500]
        log(f"✖ 구성 실패: {e}")
    else:
        st.pop("error", None)
    save_state(st)
    banner(st, n, port)
    # 비밀값이 든 OVF 환경 캐시 제거(필요하면 show 가 원천에서 다시 읽음)
    for f in (RUN / "ovf-env.xml", RUN / "source"):
        f.unlink(missing_ok=True)
    return rc


# ============================================================================ 배너 · show
def primary_ip() -> str:
    p = subprocess.run(["ip", "-4", "-o", "route", "get", "1.1.1.1"], text=True, capture_output=True)
    m = re.search(r"\bsrc (\S+)", p.stdout or "")
    if m:
        return m.group(1)
    p = subprocess.run(["hostname", "-I"], text=True, capture_output=True)
    return (p.stdout or "").split()[0] if (p.stdout or "").split() else "-"


def banner(st: dict | None = None, n: dict | None = None, port: int | None = None) -> None:
    """콘솔(tty) 배너 — VGA 콘솔은 한글 글꼴이 없어 영문으로 표기."""
    st = st if st is not None else load_state()
    if n is None or port is None:
        p = load_props()
        n = n or net_settings(p)
        port = port or st.get("port") or p.i("app.port", 1024, 65535)
    ip = primary_ip()
    host = n["fqdn"] if "." in n["fqdn"] else ip          # FQDN 미입력(DHCP 기본값)이면 IP 로 안내
    ver = RELEASE.read_text(encoding="utf-8").strip().splitlines()[0] if RELEASE.exists() else "VCF AIops Appliance"
    status = {"ready": "READY", "configuring": "CONFIGURING (first boot can take a few minutes)",
              "failed": "FAILED - run: sudo journalctl -u vcf-aiops-provision"}.get(st.get("status", ""), "STARTING")
    rows = [
        "",
        f"  {ver}",
        "  " + "-" * 64,
        f"  Web console : https://{host}:{port}/      (IP {ip})",
        f"  NOC wall    : https://{host}:{port}/noc",
        f"  Status      : {status}",
        f"  OS login    : {OS_USER}  (ssh {OS_USER}@{ip})",
    ]
    if st.get("generated_os_password"):
        rows.append(f"  Temp OS pw  : {st['generated_os_password']}   (must change at first login)")
    rows += ["  Help        : vcf-aiopsctl status | ovf | provision-log | support", "", ""]
    if write(ISSUE, "\n".join(rows), 0o644):
        subprocess.run(["agetty", "--reload"], capture_output=True)


def show() -> int:
    p = load_props()
    st = load_state()
    st.pop("generated_os_password", None)
    print(f"속성 출처: {p.source}")
    for k, v in p.redacted().items():
        print(f"  {k:22s} = {v}")
    n = net_settings(p)
    print(f"\n해석된 네트워크: {json.dumps(n, ensure_ascii=False)}")
    print(f"상태: {json.dumps(st, ensure_ascii=False, default=str)}")
    return 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "show"
    if cmd in ("early", "late", "banner") and os.geteuid() != 0:
        print("root 로 실행하세요", file=sys.stderr)
        return 2
    if cmd == "early":
        return early()
    if cmd == "late":
        return late()
    if cmd == "banner":
        banner()
        return 0
    if cmd == "show":
        return show()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
