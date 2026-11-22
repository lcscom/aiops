package com.krvcf.aiopssensor;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;

/** 마이크 음량만 측정(dBFS) — 소리는 저장·전송하지 않는다. 결과 {평균, 최대(100ms 구간)} 또는 null */
final class SoundMeter {
    private SoundMeter() { }

    static double[] measure(int seconds) {
        final int rate = 16000;
        int min = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
        if (min <= 0) return null;
        AudioRecord r = null;
        try {
            r = new AudioRecord(MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, Math.max(min, rate / 5));
            if (r.getState() != AudioRecord.STATE_INITIALIZED) return null;
            r.startRecording();
            short[] buf = new short[rate / 10];                     // 100ms
            int blocks = Math.max(1, seconds * 10);
            double sumSq = 0, peakDb = -120;
            long n = 0;
            for (int b = 0; b < blocks; b++) {
                int got = r.read(buf, 0, buf.length);
                if (got <= 0) continue;
                double s = 0;
                for (int i = 0; i < got; i++) s += (double) buf[i] * buf[i];
                sumSq += s;
                n += got;
                double db = 20 * Math.log10(Math.sqrt(s / got) / 32768.0 + 1e-9);
                if (db > peakDb) peakDb = db;
            }
            if (n == 0) return null;
            double avg = 20 * Math.log10(Math.sqrt(sumSq / n) / 32768.0 + 1e-9);
            return new double[]{avg, peakDb};
        } catch (Throwable e) {
            return null;
        } finally {
            if (r != null) { try { r.stop(); } catch (Throwable ignored) { } r.release(); }
        }
    }
}
