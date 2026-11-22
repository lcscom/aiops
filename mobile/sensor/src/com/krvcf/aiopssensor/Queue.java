package com.krvcf.aiopssensor;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

/** 통신이 끊긴 동안 측정값을 앱 내부 저장소(queue.jsonl)에 쌓아 두었다가 다시 연결되면 시각과 함께 보낸다(2.51.0).
 *  한 줄 = {"ts": 초, "samples": {...}}. 최대 건수를 넘으면 오래된 것부터 버림. 소리·사진은 쌓지 않음(숫자만) */
final class Queue {
    private Queue() { }
    private static final Object LOCK = new Object();

    private static File file(Context c) { return new File(c.getFilesDir(), "queue.jsonl"); }

    private static List<String> read(Context c) {
        List<String> out = new ArrayList<>();
        File f = file(c);
        if (!f.exists()) return out;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(f), "UTF-8"))) {
            String l;
            while ((l = r.readLine()) != null) if (!l.isEmpty()) out.add(l);
        } catch (Exception ignored) { }
        return out;
    }

    private static void write(Context c, List<String> lines) {
        File tmp = new File(c.getFilesDir(), "queue.tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), "UTF-8")) {
            for (String l : lines) { w.write(l); w.write('\n'); }
        } catch (Exception e) { return; }
        if (!tmp.renameTo(file(c))) tmp.delete();
    }

    static int size(Context c) { synchronized (LOCK) { return read(c).size(); } }

    static void add(Context c, JSONObject samples, int max) {
        if (max <= 0) return;
        synchronized (LOCK) {
            List<String> l = read(c);
            try { l.add(new JSONObject().put("ts", System.currentTimeMillis() / 1000.0).put("samples", samples).toString()); } catch (Exception e) { return; }
            if (l.size() > max) l = new ArrayList<>(l.subList(l.size() - max, l.size()));
            write(c, l);
        }
    }

    static JSONArray peek(Context c, int n) {
        JSONArray a = new JSONArray();
        synchronized (LOCK) {
            List<String> l = read(c);
            for (int i = 0; i < Math.min(n, l.size()); i++) { try { a.put(new JSONObject(l.get(i))); } catch (Exception ignored) { } }
        }
        return a;
    }

    static void drop(Context c, int n) {
        synchronized (LOCK) {
            List<String> l = read(c);
            write(c, n >= l.size() ? new ArrayList<String>() : new ArrayList<>(l.subList(n, l.size())));
        }
    }
}
