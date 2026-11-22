package com.krvcf.aiopssensor;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

/** 현장 표시 모드(2.52.0) — 전산실 벽·랙 위에 세워 두는 큰 글씨 화면. 화면 켜짐 유지, 3초마다 갱신,
 *  폰 기준값으로 위험이면 빨강·경고면 노랑. 화면을 두 번 누르면 닫힘 */
public class DisplayActivity extends Activity {
    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView title, big, rows, foot;
    private LinearLayout root;
    private long lastTap;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON | WindowManager.LayoutParams.FLAG_FULLSCREEN);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        int p = (int) (24 * getResources().getDisplayMetrics().density);
        root.setPadding(p, p, p, p);
        title = tv(22, true); big = tv(84, true); rows = tv(30, false); foot = tv(15, false);
        root.addView(title); root.addView(big); root.addView(rows); root.addView(foot);
        root.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) {
            long n = System.currentTimeMillis(); if (n - lastTap < 400) finish(); lastTap = n; } });
        setContentView(root);
    }

    private TextView tv(int sp, boolean bold) {
        TextView t = new TextView(this);
        t.setTextSize(sp);
        t.setGravity(Gravity.CENTER);
        t.setTextColor(Color.WHITE);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    @Override protected void onResume() {
        super.onResume();
        int k = getIntent() == null ? 0 : getIntent().getIntExtra("kiosk", 0);       // 2.53.0 원격 전용 화면 고정(기기 소유자만)
        if (k == 1 && Remote.owner(this)) { try { startLockTask(); } catch (Exception ignored) { } }
        if (k == 2) { try { stopLockTask(); } catch (Exception ignored) { } finish(); return; }
        loop();
    }

    @Override protected void onNewIntent(android.content.Intent i) { super.onNewIntent(i); setIntent(i); }
    @Override protected void onPause() { super.onPause(); ui.removeCallbacksAndMessages(null); }

    private void loop() { draw(); ui.postDelayed(new Runnable() { @Override public void run() { loop(); } }, 3000); }

    private static double crit(JSONObject th, String k, double v, String side) {
        JSONObject o = th == null ? null : th.optJSONObject(k);
        return o == null ? Double.NaN : o.optDouble(side, Double.NaN);
    }

    /** 0 정상, 1 경고, 2 위험 */
    private static int level(JSONObject th, String k, double v) {
        if (th == null || Double.isNaN(v)) return 0;
        JSONObject o = th.optJSONObject(k);
        if (o == null) return 0;
        if (v >= o.optDouble("crit_hi", Double.MAX_VALUE) || v <= o.optDouble("crit_lo", -Double.MAX_VALUE)) return 2;
        if (v >= o.optDouble("warn_hi", Double.MAX_VALUE) || v <= o.optDouble("warn_lo", -Double.MAX_VALUE)) return 1;
        return 0;
    }

    private void draw() {
        JSONObject s;
        try { s = new JSONObject(SensorService.lastValues.isEmpty() ? "{}" : SensorService.lastValues); } catch (Exception e) { s = new JSONObject(); }
        JSONObject cfg = SensorService.cfg(this), th = cfg.optJSONObject("thresholds");
        double temp = s.has("ambient_c") ? s.optDouble("ambient_c") : s.has("battery_c") ? s.optDouble("battery_c") + cfg.optDouble("temp_offset_c", 0) : Double.NaN;
        int lv = level(th, "temp_c", temp);
        StringBuilder r = new StringBuilder();
        if (s.has("humidity")) { r.append("습도 ").append(Math.round(s.optDouble("humidity"))).append("%   "); lv = Math.max(lv, level(th, "humidity", s.optDouble("humidity"))); }
        if (s.has("sound_db")) { r.append("소리 ").append(Math.round(s.optDouble("sound_db"))).append("dB"); lv = Math.max(lv, level(th, "sound_db", s.optDouble("sound_db"))); }
        if (s.optDouble("alarm_tone", 0) >= 1) { r.append("\n🔔 경보음 감지"); lv = 2; }
        long age = SensorService.lastOk == 0 ? -1 : (System.currentTimeMillis() - SensorService.lastOk) / 1000;
        root.setBackgroundColor(lv == 2 ? Color.parseColor("#B3261E") : lv == 1 ? Color.parseColor("#8A5A00") : Color.parseColor("#1B2A32"));
        title.setText(Prefs.get(this, "name") + (lv == 2 ? "  ·  위험" : lv == 1 ? "  ·  경고" : ""));
        big.setText(Double.isNaN(temp) ? "—" : (Math.round(temp * 10) / 10.0) + "°C");
        rows.setText(r.toString());
        foot.setText((s.has("ambient_c") ? "" : "온도는 배터리 기반 추정 · ")
                + (age < 0 ? "아직 전송 전" : age < 180 ? "서버 전송 " + age + "초 전" : "서버 연결 끊김 " + (age / 60) + "분 — 폰에 쌓는 중")
                + "\n화면 두 번 누르면 닫기");
    }
}
