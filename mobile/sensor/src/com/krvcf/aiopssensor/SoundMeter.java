package com.krvcf.aiopssensor;

import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;

import com.krvcf.aiopssensor.core.ToneDetector;

/** 마이크 음량·경보음 — 소리는 저장·전송하지 않고 숫자만 낸다.
 *  결과 {평균 dBFS, 최대 dBFS(100ms), 경보음 구간 %, 경보음 주파수 Hz, 경보음 0/1} 또는 null(마이크를 못 쓸 때 — 다른 앱이 쓰는 중 등) */
final class SoundMeter {
    private SoundMeter() { }

    static double[] measure(int seconds, boolean tone) {
        final int rate = ToneDetector.RATE;
        int min = AudioRecord.getMinBufferSize(rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
        if (min <= 0) return null;
        AudioRecord r = null;
        try {
            r = new AudioRecord(MediaRecorder.AudioSource.MIC, rate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, Math.max(min, rate / 5));
            if (r.getState() != AudioRecord.STATE_INITIALIZED) return null;
            r.startRecording();
            if (r.getRecordingState() != AudioRecord.RECORDSTATE_RECORDING) return null;
            short[] buf = new short[rate / 10];
            int blocks = Math.max(1, seconds * 10);
            double sumSq = 0, peakDb = -120;
            long n = 0;
            ToneDetector.Window w = new ToneDetector.Window();
            for (int b = 0; b < blocks; b++) {
                int got = r.read(buf, 0, buf.length);
                if (got <= 0) continue;
                double s = 0;
                for (int i = 0; i < got; i++) s += (double) buf[i] * buf[i];
                sumSq += s;
                n += got;
                double db = 20 * Math.log10(Math.sqrt(s / got) / 32768.0 + 1e-9);
                if (db > peakDb) peakDb = db;
                if (tone) w.add(ToneDetector.tonal(buf, got, db));
            }
            if (n == 0) return null;
            double avg = 20 * Math.log10(Math.sqrt(sumSq / n) / 32768.0 + 1e-9);
            double[] v = tone ? w.verdict() : new double[]{0, 0, 0};
            return new double[]{avg, peakDb, v[0], v[1], v[2]};
        } catch (Throwable e) {
            return null;
        } finally {
            if (r != null) { try { r.stop(); } catch (Throwable ignored) { } try { r.release(); } catch (Throwable ignored) { } }
        }
    }
}
