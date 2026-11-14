#!/bin/sh
# =============================================================================================
#  VCF AIops — 서버 사양 수집(가정 분석용). 추가하려는 서버에서 한 번 실행하고, 나온 JSON 을 포털에 올린다.
#    포털: 성능·용량 › 용량·적정화 › 가정 분석 › 서버 사양 › 'JSON 올리기'
#  사용:  sh collect-server-spec.sh > spec.json          (Linux 또는 ESXi 셸 — 읽기만, 아무것도 바꾸지 않음)
#  수집:  제조사·모델, CPU 모델·소켓·코어·속도, 메모리, 디스크(크기·종류), NIC 속도
#  보내지 않음: 호스트 이름·IP·MAC·시리얼 번호(이름은 포털에 올릴 때 직접 붙인다)
#  dmidecode 가 없거나 root 가 아니면 제조사·모델만 비고, 나머지는 채워진다.
# =============================================================================================
LC_ALL=C; export LC_ALL
j() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }
num() { case "$1" in ''|*[!0-9.]*) printf '0' ;; *) printf '%s' "$1" ;; esac; }

if command -v esxcli >/dev/null 2>&1; then
  OS="esxi $(esxcli system version get 2>/dev/null | sed -n 's/^ *Version: //p')"
  VENDOR=$(esxcli hardware platform get 2>/dev/null | sed -n 's/^ *Vendor Name: //p')
  MODEL=$(esxcli hardware platform get 2>/dev/null | sed -n 's/^ *Product Name: //p')
  SOCKETS=$(esxcli hardware cpu global get 2>/dev/null | sed -n 's/^ *CPU Packages: //p')
  CORES=$(esxcli hardware cpu global get 2>/dev/null | sed -n 's/^ *CPU Cores: //p')
  THREADS=$(esxcli hardware cpu global get 2>/dev/null | sed -n 's/^ *CPU Threads: //p')
  CPUMODEL=$(vsish -e get /hardware/cpu/cpuModelName 2>/dev/null | tr -s ' ')
  [ -n "$CPUMODEL" ] || CPUMODEL=$(esxcli hardware cpu list 2>/dev/null | sed -n 's/^ *Brand: //p' | head -1 | tr -s ' ')
  HZ=$(esxcli hardware cpu list 2>/dev/null | sed -n 's/^ *Core Speed: //p' | head -1)
  GHZ=$(awk -v h="$(num "$HZ")" 'BEGIN{printf "%.2f", h/1000000000}')
  MEMB=$(esxcli hardware memory get 2>/dev/null | sed -n 's/^ *Physical Memory: \([0-9]*\).*/\1/p')
  MEMGB=$(awk -v b="$(num "$MEMB")" 'BEGIN{printf "%.0f", b/1073741824}')
  DISKS=$(esxcli storage core device list 2>/dev/null | awk '
    /^[^ ]/ {if (sz>0 && !usb) printf "%s{\"gb\":%.0f,\"type\":\"%s\"}", (n++?",":""), sz/1024, (ssd?"ssd":"hdd"); sz=0; ssd=0; usb=0}
    /^ *Size: /{sz=$2} /^ *Is SSD: true/{ssd=1} /^ *Is USB: true/{usb=1} /^ *Is Boot Device: true/{usb=1}
    END{if (sz>0 && !usb) printf "%s{\"gb\":%.0f,\"type\":\"%s\"}", (n++?",":""), sz/1024, (ssd?"ssd":"hdd")}')
  NICS=$(esxcli network nic list 2>/dev/null | awk 'NR>2 && $5=="Up" {printf "%s{\"gbps\":%.0f}", (n++?",":""), $6/1000}')
else
  OS="linux $(uname -r)"
  VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null); MODEL=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
  CPUMODEL=$(sed -n 's/^model name[^:]*: //p' /proc/cpuinfo | head -1 | tr -s ' ')
  SOCKETS=$(sed -n 's/^physical id[^:]*: //p' /proc/cpuinfo | sort -u | wc -l | tr -d ' '); [ "$SOCKETS" -gt 0 ] 2>/dev/null || SOCKETS=1
  CORES=$(awk -F: '/^physical id/{p=$2} /^core id/{c[p":"$2]=1} END{n=0; for(k in c) n++; print n}' /proc/cpuinfo); [ "$CORES" -gt 0 ] 2>/dev/null || CORES=$(grep -c '^processor' /proc/cpuinfo)
  THREADS=$(grep -c '^processor' /proc/cpuinfo)
  GHZ=$(printf '%s' "$CPUMODEL" | sed -n 's/.*@ *\([0-9.]*\) *GHz.*/\1/p')
  [ -n "$GHZ" ] || GHZ=$(awk -v m="$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)" 'BEGIN{printf "%.2f", m/1000000}')
  MEMGB=$(awk '/^MemTotal:/{g=$2/1048576; s=1; while (s<g*0.97) s*=2; if (g>s*0.75 && s<=g*1.1) printf "%.0f", s; else printf "%.0f", g}' /proc/meminfo)   # 커널이 뺀 만큼 보정(64·128·… 근처면 그 값)
  DISKS=""; n=0
  for d in /sys/block/sd* /sys/block/nvme*n* /sys/block/vd*; do
    [ -r "$d/size" ] || continue
    [ "$(cat "$d/removable" 2>/dev/null)" = "1" ] && continue
    gb=$(awk -v s="$(cat "$d/size")" 'BEGIN{printf "%.0f", s*512/1000000000}'); [ "$gb" -gt 0 ] 2>/dev/null || continue
    case "$d" in */nvme*) t=nvme ;; *) [ "$(cat "$d/queue/rotational" 2>/dev/null)" = "0" ] && t=ssd || t=hdd ;; esac
    DISKS="$DISKS$([ $n -gt 0 ] && printf ',')$(printf '{"gb":%s,"type":"%s"}' "$gb" "$t")"; n=$((n+1))
  done
  NICS=""; n=0
  for i in /sys/class/net/*; do
    [ -e "$i/device" ] || continue
    sp=$(cat "$i/speed" 2>/dev/null); [ "$sp" -gt 0 ] 2>/dev/null || continue
    NICS="$NICS$([ $n -gt 0 ] && printf ',')$(awk -v s="$sp" 'BEGIN{printf "{\"gbps\":%.0f}", s/1000}')"; n=$((n+1))
  done
fi
printf '{"schema":"vcf-aiops-server-spec/1","os":"%s","vendor":"%s","model":"%s","cpu_model":"%s","sockets":%s,"cores":%s,"threads":%s,"core_ghz":%s,"mem_gb":%s,"disks":[%s],"nics":[%s]}\n' \
  "$(j "$OS")" "$(j "$VENDOR")" "$(j "$MODEL")" "$(j "$CPUMODEL")" "$(num "$SOCKETS")" "$(num "$CORES")" "$(num "$THREADS")" "$(num "$GHZ")" "$(num "$MEMGB")" "$DISKS" "$NICS"
