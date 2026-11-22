package com.krvcf.aiopssensor;

import android.content.Context;

import com.krvcf.aiopssensor.core.LineQueue;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.List;

/** 통신이 끊긴 동안 측정값(숫자만)을 앱 내부 저장소에 쌓았다가 다시 연결되면 시각과 함께 보냄 — 실제 저장은 core.LineQueue */
final class Queue {
    private Queue() { }
    private static LineQueue q;

    private static synchronized LineQueue q(Context c) {
        if (q == null) q = new LineQueue(new File(c.getApplicationContext().getFilesDir(), "queue.jsonl"));
        return q;
    }

    static int size(Context c) { return q(c).size(); }

    static void add(Context c, JSONObject samples, int max) {
        try { q(c).add(new JSONObject().put("ts", System.currentTimeMillis() / 1000.0).put("samples", samples).toString(), max); } catch (Exception ignored) { }
    }

    static volatile int lastPeek;                        // peek 이 읽은 원본 줄 수 — 깨진 줄이 있어도 정확히 그만큼 지움

    static JSONArray peek(Context c, int n) {
        JSONArray a = new JSONArray();
        List<String> l = q(c).peek(n);
        lastPeek = l.size();
        for (String s : l) { try { a.put(new JSONObject(s)); } catch (Exception ignored) { } }
        return a;
    }

    static void drop(Context c, int n) { q(c).drop(n); }

    static void clear(Context c) { q(c).clear(); }
}
