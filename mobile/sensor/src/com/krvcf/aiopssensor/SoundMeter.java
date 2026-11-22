package com.krvcf.aiopssensor;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;

/** 마이크 음량·경보음 감지 — 소리는 저장·전송하지 않고 숫자만 낸다.
 *  결과 {평균 dBFS, 최대 dBFS(100ms 구간), 경보음 구간 비율(%), 경보음 주파수(Hz), 경보음 여부(0/1)} 또는 null
 *  경보음: UPS·화재·항온항습기 경보는 대개 2~4kHz 순음을 '삐-삐' 반복하거나 계속 낸다.
 *  100ms 구간마다 Goertzel 로 1.5~4.5kHz 를 100Hz 간격으로 보고, 한 주파수에 에너지가 몰려 있으면(순음) '경보음 구간'.
 *  구간 비율 30% 이상 + 켜짐/꺼짐 2번 이상(반복음) 또는 80% 이상(지속음)이면 경보음. */
final class SoundMeter {
    private SoundMeter() { }
    private static final int RATE = 16000;

    static double[] measure(int seconds, boolean tone) {
        int min = AudioRecord.getMinBufferSize(RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
        if (min <= 0) return null;
        AudioRecord r = null;
        try {
            r = new AudioRecord(MediaRecorder.AudioSource.MIC, RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, Math.max(min, RATE / 5));
            if (r.getState() != AudioRecord.STATE_INITIALIZED) return null;
            r.startRecording();
            short[] buf = new short[RATE / 10];                     // 100ms
            int blocks = Math.max(1, seconds * 10);
            double sumSq = 0, peakDb = -120;
            long n = 0;
            int tonal = 0, used = 0, flips = 0;
            boolean prev = false;
            double hzSum = 0;
            for (int b = 0; b < blocks; b++) {
                int got = r.read(buf, 0, buf.length);
                if (got <= 0) continue;
                double s = 0;
                for (int i = 0; i < got; i++) s += (double) buf[i] * buf[i];
                sumSq += s;
                n += got;
                double rms = Math.sqrt(s / got);
                double db = 20 * Math.log10(rms / 32768.0 + 1e-9);
                if (db > peakDb) peakDb = db;
                if (!tone) continue;
                used++;
                boolean t = false;
                if (db > -50) {                                       // 너무 조용한 구간은 판단하지 않음
                    // 10ms(160표본) 조각마다 Goertzel(분해능 100Hz) → 조각 합. 100Hz 간격이면 어느 주파수든 최악 0.4배 이상 잡힘
                    final int seg = 160;
                    int segs = got / seg;
                    double best = 0, bestHz = 0;
                    for (int hz = 1500; hz <= 4500; hz += 100) {
                        double p = 0;
                        for (int k = 0; k < segs; k++) p += goertzel(buf, k * seg, seg, hz);
                        if (p > best) { best = p; bestHz = hz; }
                    }
                    double total = 0;                                     // 같은 척도의 총 에너지(순음이면 비율 ≈ 1, 잡음 ≈ 0.02)
                    for (int i = 0; i < segs * seg; i++) total += (double) buf[i] * buf[i];
                    total = total * seg / 2.0;
                    if (total > 0 && best / total > 0.3) { t = true; hzSum += bestHz; }
                }
                if (t) tonal++;
                if (b > 0 && t != prev) flips++;
                prev = t;
            }
            if (n == 0) return null;
            double avg = 20 * Math.log10(Math.sqrt(sumSq / n) / 32768.0 + 1e-9);
            double pct = used == 0 ? 0 : tonal * 100.0 / used;
            boolean alarm = tone && (pct >= 80 || (pct >= 30 && flips >= 2));
            return new double[]{avg, peakDb, Math.round(pct), tonal == 0 ? 0 : Math.round(hzSum / tonal), alarm ? 1 : 0};
        } catch (Throwable e) {
            return null;
        } finally {
            if (r != null) { try { r.stop(); } catch (Throwable ignored) { } r.release(); }
        }
    }

    /** 한 주파수의 전력(Goertzel) */
    static double goertzel(short[] x, int off, int n, int hz) {
        double w = 2 * Math.PI * hz / RATE, c = 2 * Math.cos(w), s1 = 0, s2 = 0;
        for (int i = off; i < off + n; i++) { double s0 = x[i] + c * s1 - s2; s2 = s1; s1 = s0; }
        return s1 * s1 + s2 * s2 - c * s1 * s2;
    }
}
