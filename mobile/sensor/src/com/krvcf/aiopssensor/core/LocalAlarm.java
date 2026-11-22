package com.krvcf.aiopssensor.core;

import java.util.HashMap;
import java.util.Map;

/** 폰 자체 경보(안드로이드 의존 없음 — JVM 에서 단위 시험). 서버가 내려준 기준값으로 위험(crit) 여부를 폰에서도 판정해
 *  통신이 끊겨도 현장에서 알 수 있게. 상태가 바뀔 때만 결과를 낸다(같은 위험을 반복해 울리지 않음) */
public final class LocalAlarm {
    private final Map<String, Boolean> crit = new HashMap<>();

    /** th: {metric: {crit_hi, crit_lo}}, v: 이번 값 → 새로 위험이 된 측정값 이름들(쉼표), 없으면 "" */
    public String check(Map<String, double[]> th, Map<String, Double> v) {
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, double[]> e : th.entrySet()) {
            Double x = v.get(e.getKey());
            if (x == null) continue;
            double hi = e.getValue()[0], lo = e.getValue()[1];
            boolean c = (!Double.isNaN(hi) && x >= hi) || (!Double.isNaN(lo) && x <= lo);
            Boolean was = crit.put(e.getKey(), c);
            if (c && (was == null || !was)) { if (out.length() > 0) out.append(','); out.append(e.getKey()); }
        }
        return out.toString();
    }

    public boolean any() { for (Boolean b : crit.values()) if (b) return true; return false; }
}
