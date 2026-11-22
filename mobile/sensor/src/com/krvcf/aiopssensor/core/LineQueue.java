package com.krvcf.aiopssensor.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/** 줄 단위 파일 대기열(안드로이드 의존 없음 — JVM 에서 단위 시험).
 *  덧붙이기는 파일 끝에 쓰기만(빠름), 앞에서 빼기·최대 건수 정리는 임시 파일에 쓴 뒤 이름 바꾸기(원자적). 건수는 메모리에 둠 */
public final class LineQueue {
    private final File f;
    private int count = -1;

    public LineQueue(File f) { this.f = f; }

    private List<String> read() {
        List<String> out = new ArrayList<>();
        if (!f.exists()) return out;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
            String l;
            while ((l = r.readLine()) != null) if (!l.isEmpty()) out.add(l);
        } catch (Exception ignored) { }
        return out;
    }

    private boolean rewrite(List<String> lines) {
        File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), "UTF-8")) {
            for (String l : lines) { w.write(l); w.write('\n'); }
        } catch (Exception e) { tmp.delete(); return false; }
        if (!tmp.renameTo(f)) { tmp.delete(); return false; }
        count = lines.size();
        return true;
    }

    public synchronized int size() {
        if (count < 0) count = read().size();
        return count;
    }

    public synchronized void add(String line, int max) {
        if (max <= 0 || line == null || line.indexOf('\n') >= 0) return;
        try (Writer w = new OutputStreamWriter(new FileOutputStream(f, true), "UTF-8")) {
            w.write(line); w.write('\n');
        } catch (Exception e) { return; }
        count = count < 0 ? read().size() : count + 1;
        if (count > max + Math.max(1, max / 10)) {           // 최대 건수의 10% 넘게 넘치면 한꺼번에 정리(매번 다시 쓰지 않음)
            List<String> l = read();
            rewrite(new ArrayList<>(l.subList(Math.max(0, l.size() - max), l.size())));
        }
    }

    public synchronized List<String> peek(int n) {
        List<String> l = read();
        return new ArrayList<>(l.subList(0, Math.min(n, l.size())));
    }

    public synchronized void drop(int n) {
        List<String> l = read();
        rewrite(n >= l.size() ? new ArrayList<String>() : new ArrayList<>(l.subList(n, l.size())));
    }

    public synchronized void clear() { f.delete(); count = 0; }
}
