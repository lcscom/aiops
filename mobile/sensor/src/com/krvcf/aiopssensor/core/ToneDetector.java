package com.krvcf.aiopssensor.core;

/** 경보음 판정(안드로이드 의존 없음 — JVM 에서 단위 시험). SoundMeter 가 100ms(1600표본) 구간마다 tonal() 을 부르고,
 *  구간 결과를 Window 에 모아 verdict() 로 경보음 여부를 낸다. */
public final class ToneDetector {
    private ToneDetector() { }
    public static final int RATE = 16000;
    public static final int SEG = 160;              // 10ms — Goertzel 분해능 100Hz
    public static final double RATIO = 0.3;         // 한 주파수 에너지 비율이 이 이상이면 순음

    public static double goertzel(short[] x, int off, int n, int hz) {
        double w = 2 * Math.PI * hz / RATE, c = 2 * Math.cos(w), s1 = 0, s2 = 0;
        for (int i = off; i < off + n; i++) { double s0 = x[i] + c * s1 - s2; s2 = s1; s1 = s0; }
        return s1 * s1 + s2 * s2 - c * s1 * s2;
    }

    /** 이 구간이 순음(1.5~4.5kHz)이면 주파수(Hz), 아니면 0. dbfs 가 -50 미만이면 판단하지 않음 */
    public static int tonal(short[] buf, int got, double dbfs) {
        if (dbfs <= -50) return 0;
        int segs = got / SEG;
        if (segs == 0) return 0;
        double best = 0;
        int bestHz = 0;
        for (int hz = 1500; hz <= 4500; hz += 100) {
            double p = 0;
            for (int k = 0; k < segs; k++) p += goertzel(buf, k * SEG, SEG, hz);
            if (p > best) { best = p; bestHz = hz; }
        }
        double total = 0;
        for (int i = 0; i < segs * SEG; i++) total += (double) buf[i] * buf[i];
        total = total * SEG / 2.0;
        return total > 0 && best / total > RATIO ? bestHz : 0;
    }

    /** 구간 결과 누적 → {경보음 구간 비율 %, 평균 주파수, 경보음 0/1} */
    public static final class Window {
        int used, tonal, flips;
        long hzSum;
        boolean prev, first = true;

        public void add(int hz) {
            boolean t = hz > 0;
            used++;
            if (t) { tonal++; hzSum += hz; }
            if (!first && t != prev) flips++;
            prev = t;
            first = false;
        }

        public double[] verdict() {
            double pct = used == 0 ? 0 : tonal * 100.0 / used;
            boolean alarm = pct >= 80 || (pct >= 30 && flips >= 2);
            return new double[]{Math.round(pct), tonal == 0 ? 0 : Math.round((double) hzSum / tonal), alarm ? 1 : 0};
        }
    }
}
