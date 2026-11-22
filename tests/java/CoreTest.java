import com.krvcf.aiopssensor.core.LineQueue;
import com.krvcf.aiopssensor.core.LocalAlarm;
import com.krvcf.aiopssensor.core.ToneDetector;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/** 센서 앱의 안드로이드 비의존 핵심 코드(core/)를 실제 Java 로 실행해 확인(2.52.0). 실패하면 종료 코드 1 */
public class CoreTest {
    static int fails = 0;

    static void ok(boolean c, String what) {
        System.out.println((c ? "PASS " : "FAIL ") + what);
        if (!c) fails++;
    }

    static double[] run(short[] sig) {
        ToneDetector.Window w = new ToneDetector.Window();
        short[] buf = new short[1600];
        for (int b = 0; b + 1600 <= sig.length; b += 1600) {
            System.arraycopy(sig, b, buf, 0, 1600);
            double s = 0;
            for (short v : buf) s += (double) v * v;
            double db = 20 * Math.log10(Math.sqrt(s / 1600) / 32768.0 + 1e-9);
            w.add(ToneDetector.tonal(buf, 1600, db));
        }
        return w.verdict();
    }

    static short clip(double v) { return (short) Math.max(-32768, Math.min(32767, Math.round(v))); }

    public static void main(String[] a) throws Exception {
        Random r = new Random(7);
        int n = 3 * 16000;
        short[] beep = new short[n], steady = new short[n], noise = new short[n], fan = new short[n], quiet = new short[n], chirp = new short[n];
        for (int i = 0; i < n; i++) {
            double t = i / 16000.0;
            beep[i] = clip(((t % 1.0) < 0.5 ? 6000 * Math.sin(2 * Math.PI * 3150 * t) : 0) + r.nextGaussian() * 800);
            steady[i] = clip(5000 * Math.sin(2 * Math.PI * 2730 * t) + r.nextGaussian() * 800);
            noise[i] = clip(r.nextGaussian() * 4000);
            fan[i] = clip(4000 * Math.sin(2 * Math.PI * 120 * t) + 2500 * Math.sin(2 * Math.PI * 360 * t) + r.nextGaussian() * 2000);
            quiet[i] = clip(30 * Math.sin(2 * Math.PI * 3000 * t));                       // 너무 작은 순음 — 판단 제외
            chirp[i] = clip(5000 * Math.sin(2 * Math.PI * (1500 + 1000 * t) * t) + r.nextGaussian() * 500);   // 주파수가 계속 변하는 소리
        }
        double[] v;
        v = run(beep);   ok(v[2] == 1 && v[0] >= 30 && v[0] <= 70 && Math.abs(v[1] - 3150) <= 100, "반복 경보음 3150Hz 감지 " + java.util.Arrays.toString(v));
        v = run(steady); ok(v[2] == 1 && v[0] >= 80 && Math.abs(v[1] - 2730) <= 100, "지속 경보음 2730Hz 감지 " + java.util.Arrays.toString(v));
        v = run(noise);  ok(v[2] == 0 && v[0] == 0, "백색잡음 무시 " + java.util.Arrays.toString(v));
        v = run(fan);    ok(v[2] == 0, "팬 소음 무시 " + java.util.Arrays.toString(v));
        v = run(quiet);  ok(v[2] == 0, "아주 작은 소리 판단 제외 " + java.util.Arrays.toString(v));
        v = run(chirp);  ok(v[0] < 100, "변하는 소리 계산 이상 없음 " + java.util.Arrays.toString(v));
        for (int hz = 1500; hz <= 4500; hz += 37) {                                        // 대역 안 어느 주파수든
            short[] s = new short[1600];
            for (int i = 0; i < 1600; i++) s[i] = clip(6000 * Math.sin(2 * Math.PI * hz * i / 16000.0));
            if (ToneDetector.tonal(s, 1600, -10) == 0) { ok(false, "순음 " + hz + "Hz 놓침"); break; }
        }
        ok(true, "1.5~4.5kHz 전 구간 순음 검출");
        ok(ToneDetector.tonal(new short[1600], 1600, -120) == 0 && ToneDetector.tonal(new short[100], 100, -10) == 0, "무음·짧은 구간 안전");

        File d = Files.createTempDirectory("q").toFile();
        File f = new File(d, "queue.jsonl");
        LineQueue q = new LineQueue(f);
        for (int i = 0; i < 25; i++) q.add("{\"i\":" + i + "}", 20);
        ok(q.size() <= 22 && q.size() >= 20, "최대 건수 근처로 정리 size=" + q.size());
        LineQueue q2 = new LineQueue(f);
        ok(q2.size() == q.size(), "재시작 뒤 건수 복원");
        List<String> head = q.peek(5);
        ok(head.size() == 5 && !head.get(0).equals("{\"i\":0}"), "오래된 것부터 버림 " + head.get(0));
        q.drop(5);
        ok(q.size() == q2.size() - 5 && !q.peek(1).get(0).equals(head.get(0)), "앞에서 5건 제거");
        q.add("bad\nline", 20);
        ok(!new String(Files.readAllBytes(f.toPath()), "UTF-8").contains("bad"), "줄바꿈 든 값 거부");
        try (FileWriter w = new FileWriter(f, true)) { w.write("\n\n"); }
        ok(new LineQueue(f).size() == q.size(), "빈 줄 무시");
        q.drop(1000);
        ok(q.size() == 0 && q.peek(3).isEmpty(), "전부 제거");
        ok(!new File(d, "queue.jsonl.tmp").exists(), "임시 파일 남지 않음");
        q.add("x", 0);
        ok(q.size() == 0, "max=0 이면 쌓지 않음");
        q.clear();

        LocalAlarm la = new LocalAlarm();
        Map<String, double[]> th = new HashMap<>();
        th.put("temp_c", new double[]{35, 5});
        th.put("humidity", new double[]{80, Double.NaN});
        Map<String, Double> m = new HashMap<>();
        m.put("temp_c", 30.0); m.put("humidity", 50.0);
        ok(la.check(th, m).isEmpty() && !la.any(), "정상 — 경보 없음");
        m.put("temp_c", 36.0);
        ok(la.check(th, m).equals("temp_c") && la.any(), "위험 진입 1회");
        ok(la.check(th, m).isEmpty(), "같은 위험 반복 안 울림");
        m.put("temp_c", 20.0); m.put("humidity", 85.0);
        ok(la.check(th, m).equals("humidity"), "다른 측정값 위험");
        m.put("temp_c", 4.0);
        ok(la.check(th, m).equals("temp_c"), "하한 위험");
        m.remove("temp_c");
        ok(la.check(th, m).isEmpty(), "값 없음은 상태 유지");

        System.out.println(fails == 0 ? "ALL PASS" : fails + " FAILED");
        System.exit(fails == 0 ? 0 : 1);
    }
}
