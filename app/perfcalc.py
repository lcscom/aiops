"""호스트·VM 성능 상세(2.23.0) — vCenter 성능 카운터 원자료 → 화면 지표(순수 계산, pyVmomi 의존 없음).

입력  raw: [(카운터 키 "그룹.이름.롤업", 인스턴스, [값…])], ts: [초], interval: 초, kind: "vm"|"host", vcpu: VM vCPU 수
출력  {"ts", "interval", "series": {"cpu.usage_pct": [...], ...}, "instances": {"disk": [...], "net": [...]}, "missing": [...]}

단위 변환(vSphere 성능 카운터 문서 기준)
  percent 카운터(cpu.usage·mem.usage·mem.latency) 는 1/100 % 정수 → ÷100
  cpu.ready·cpu.costop.summation 은 수집 간격 동안의 ms 합 → ÷(간격 초×1000)×100 = %, VM 은 vCPU 수로 나눠 vCPU 평균
  mem.* (active·consumed·vmmemctl·swapped·compressed) KB → MB
  virtualDisk/disk read·write·usage KBps → B/s, net received·transmitted·usage KBps → bit/s
  packetsRx/Tx·droppedRx/Tx.summation 은 간격 합계 → packets 는 ÷간격(초당), dropped 는 간격당 개수 그대로
  지연(ms)은 인스턴스(가상 디스크·장치) 중 최댓값, 처리량·IOPS 는 합
"""
from __future__ import annotations

from typing import Any

VM_COUNTERS = ("cpu.usage.average", "cpu.usagemhz.average", "cpu.ready.summation", "cpu.costop.summation",
               "mem.usage.average", "mem.active.average", "mem.consumed.average", "mem.vmmemctl.average", "mem.swapped.average",
               "mem.compressed.average", "mem.latency.average",
               "virtualDisk.numberReadAveraged.average", "virtualDisk.numberWriteAveraged.average", "virtualDisk.read.average",
               "virtualDisk.write.average", "virtualDisk.totalReadLatency.average", "virtualDisk.totalWriteLatency.average",
               "disk.usage.average", "disk.maxTotalLatency.latest",
               "net.usage.average", "net.received.average", "net.transmitted.average", "net.packetsRx.summation", "net.packetsTx.summation",
               "net.droppedRx.summation", "net.droppedTx.summation")
HOST_COUNTERS = ("cpu.usage.average", "cpu.usagemhz.average",
                 "mem.usage.average", "mem.active.average", "mem.consumed.average", "mem.vmmemctl.average", "mem.swapinRate.average",
                 "mem.swapoutRate.average",
                 "disk.numberReadAveraged.average", "disk.numberWriteAveraged.average", "disk.read.average", "disk.write.average",
                 "disk.totalReadLatency.average", "disk.totalWriteLatency.average", "disk.deviceLatency.average", "disk.kernelLatency.average",
                 "disk.usage.average", "disk.maxTotalLatency.latest",
                 "net.usage.average", "net.received.average", "net.transmitted.average", "net.packetsRx.summation", "net.packetsTx.summation",
                 "net.droppedRx.summation", "net.droppedTx.summation")
LATEST_COMMON = ("cpu.usage.average", "mem.usage.average", "disk.usage.average", "disk.maxTotalLatency.latest", "net.usage.average")
LATEST_COUNTERS = {"vm": LATEST_COMMON + ("virtualDisk.numberReadAveraged.average", "virtualDisk.numberWriteAveraged.average", "cpu.ready.summation"),
                   "host": LATEST_COMMON + ("disk.numberReadAveraged.average", "disk.numberWriteAveraged.average")}     # VM 에 disk.* 를 섞으면 LUN 값이 더해져 2배

# 카운터 → (출력 지표, 변환, 인스턴스 집계 sum|max|avg, 인스턴스 표 분류·열)
SPEC: dict[str, tuple[str, str, str, tuple[str, str] | None]] = {
    "cpu.usage.average": ("cpu.usage_pct", "pct", "avg", None),
    "cpu.usagemhz.average": ("cpu.usage_mhz", "x1", "sum", None),
    "cpu.ready.summation": ("cpu.ready_pct", "ready", "sum", None),
    "cpu.costop.summation": ("cpu.costop_pct", "ready", "sum", None),
    "mem.usage.average": ("mem.usage_pct", "pct", "avg", None),
    "mem.active.average": ("mem.active_mb", "kb2mb", "sum", None),
    "mem.consumed.average": ("mem.consumed_mb", "kb2mb", "sum", None),
    "mem.vmmemctl.average": ("mem.balloon_mb", "kb2mb", "sum", None),
    "mem.swapped.average": ("mem.swapped_mb", "kb2mb", "sum", None),
    "mem.compressed.average": ("mem.compressed_mb", "kb2mb", "sum", None),
    "mem.latency.average": ("mem.latency_pct", "pct", "avg", None),
    "mem.swapinRate.average": ("mem.swapin_Bps", "kbps2B", "sum", None),
    "mem.swapoutRate.average": ("mem.swapout_Bps", "kbps2B", "sum", None),
    "virtualDisk.numberReadAveraged.average": ("disk.read_iops", "x1", "sum", ("disk", "read_iops")),
    "virtualDisk.numberWriteAveraged.average": ("disk.write_iops", "x1", "sum", ("disk", "write_iops")),
    "virtualDisk.read.average": ("disk.read_Bps", "kbps2B", "sum", ("disk", "read_Bps")),
    "virtualDisk.write.average": ("disk.write_Bps", "kbps2B", "sum", ("disk", "write_Bps")),
    "virtualDisk.totalReadLatency.average": ("disk.read_lat_ms", "x1", "max", ("disk", "read_lat_ms")),
    "virtualDisk.totalWriteLatency.average": ("disk.write_lat_ms", "x1", "max", ("disk", "write_lat_ms")),
    "disk.numberReadAveraged.average": ("disk.read_iops", "x1", "sum", ("disk", "read_iops")),
    "disk.numberWriteAveraged.average": ("disk.write_iops", "x1", "sum", ("disk", "write_iops")),
    "disk.read.average": ("disk.read_Bps", "kbps2B", "sum", ("disk", "read_Bps")),
    "disk.write.average": ("disk.write_Bps", "kbps2B", "sum", ("disk", "write_Bps")),
    "disk.totalReadLatency.average": ("disk.read_lat_ms", "x1", "max", ("disk", "read_lat_ms")),
    "disk.totalWriteLatency.average": ("disk.write_lat_ms", "x1", "max", ("disk", "write_lat_ms")),
    "disk.deviceLatency.average": ("disk.device_lat_ms", "x1", "max", ("disk", "device_lat_ms")),
    "disk.kernelLatency.average": ("disk.kernel_lat_ms", "x1", "max", ("disk", "kernel_lat_ms")),
    "disk.usage.average": ("disk.usage_Bps", "kbps2B", "sum", None),
    "disk.maxTotalLatency.latest": ("disk.max_lat_ms", "x1", "max", None),
    "net.usage.average": ("net.usage_bps", "kbps2bit", "sum", ("net", "usage_bps")),
    "net.received.average": ("net.rx_bps", "kbps2bit", "sum", ("net", "rx_bps")),
    "net.transmitted.average": ("net.tx_bps", "kbps2bit", "sum", ("net", "tx_bps")),
    "net.packetsRx.summation": ("net.rx_pps", "per_s", "sum", ("net", "rx_pps")),
    "net.packetsTx.summation": ("net.tx_pps", "per_s", "sum", ("net", "tx_pps")),
    "net.droppedRx.summation": ("net.drop_rx", "x1", "sum", ("net", "drop_rx")),
    "net.droppedTx.summation": ("net.drop_tx", "x1", "sum", ("net", "drop_tx")),
}


def conv(how: str, v: float | None, interval: int, vcpu: int = 1) -> float | None:
    if v is None or v < 0:                      # vCenter 는 표본 없음을 -1 로 줌
        return None
    if how == "pct":
        return v / 100.0
    if how == "ready":
        return v / (max(1, interval) * 1000.0) * 100.0 / max(1, vcpu)
    if how == "kb2mb":
        return v / 1024.0
    if how == "kbps2B":
        return v * 1024.0
    if how == "kbps2bit":
        return v * 8 * 1024.0
    if how == "per_s":
        return v / max(1, interval)
    return float(v)


def _agg(vals: list[float | None], how: str) -> float | None:
    xs = [x for x in vals if x is not None]
    if not xs:
        return None
    return max(xs) if how == "max" else sum(xs) / len(xs) if how == "avg" else sum(xs)


def build(raw: list[tuple[str, str, list]], ts: list[float], interval: int, kind: str = "vm", vcpu: int = 1,
          labels: dict[str, str] | None = None) -> dict[str, Any]:
    labels = labels or {}
    order = sorted(range(len(ts)), key=ts.__getitem__)          # 시간 오름차순
    ts2 = [ts[i] for i in order]
    n = len(ts2)
    per: dict[str, dict[str, list]] = {}                        # 지표 → 인스턴스 → 값
    seen = set()
    for key, inst, vals in raw:
        sp = SPEC.get(key)
        if not sp or not vals:
            continue
        seen.add(key)
        how = sp[1]
        vv = [conv(how, float(vals[i]) if i < len(vals) and vals[i] is not None else None, interval,
                   vcpu if (kind == "vm" and how == "ready") else 1) for i in order]
        per.setdefault(sp[0], {}).setdefault(inst or "", vv)
    series: dict[str, list] = {}
    for key, sp in SPEC.items():
        name = sp[0]
        if name in series or name not in per:
            continue
        d = per[name]
        if "" in d and any(x is not None for x in d[""]):
            series[name] = d[""]
        else:
            insts = [v for k, v in d.items() if k != ""]
            series[name] = [_agg([s[i] if i < len(s) else None for s in insts], sp[2]) for i in range(n)] if insts else []
    inst_rows: dict[str, dict[str, dict]] = {"disk": {}, "net": {}}
    for key, sp in SPEC.items():
        if not sp[3] or sp[0] not in per:
            continue
        grp, col = sp[3]
        for inst, vals in per[sp[0]].items():
            if inst == "":
                continue
            xs = [x for x in vals if x is not None]
            r = inst_rows[grp].setdefault(inst, {"id": inst, "label": labels.get(f"{grp}:{inst}", "")})
            r[col] = xs[-1] if xs else None
            r[col + "_avg"] = sum(xs) / len(xs) if xs else None
            r[col + "_max"] = max(xs) if xs else None
    want = VM_COUNTERS if kind == "vm" else HOST_COUNTERS
    return {"ts": ts2, "interval": interval, "series": series,
            "instances": {g: sorted(v.values(), key=lambda r: r["id"]) for g, v in inst_rows.items()},
            "missing": [k for k in want if k not in seen]}


def summarize(series: dict[str, list]) -> dict[str, dict]:
    """지표별 최근·평균·최대(화면 요약 칸)"""
    out = {}
    for k, vals in series.items():
        xs = [x for x in vals if x is not None]
        if xs:
            out[k] = {"last": xs[-1], "avg": sum(xs) / len(xs), "max": max(xs), "min": min(xs)}
    return out


def latest(raw: list[tuple[str, str, list]], interval: int, kind: str = "vm", vcpu: int = 1) -> dict[str, float | None]:
    """순위표용 — 최근 표본 평균: cpu_pct · mem_pct · iops · disk_lat_ms · net_bps · ready_pct"""
    b = build(raw, list(range(max((len(v) for _, _, v in raw), default=0))), interval, kind, vcpu)
    s = summarize(b["series"])
    g = lambda k: s.get(k, {}).get("avg")  # noqa: E731
    iops = None if g("disk.read_iops") is None and g("disk.write_iops") is None else (g("disk.read_iops") or 0) + (g("disk.write_iops") or 0)
    return {"cpu_pct": g("cpu.usage_pct"), "mem_pct": g("mem.usage_pct"), "iops": iops, "disk_lat_ms": g("disk.max_lat_ms"),
            "disk_Bps": g("disk.usage_Bps"), "net_bps": g("net.usage_bps"), "ready_pct": g("cpu.ready_pct") if kind == "vm" else None}
