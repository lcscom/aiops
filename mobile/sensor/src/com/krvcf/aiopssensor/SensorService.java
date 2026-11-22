package com.krvcf.aiopssensor;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.PowerManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/** 측정·전송 루프(포그라운드 서비스) — 간격마다 값 모아 /api/sensor/push, 응답의 설정·촬영 요청 반영 */
public class SensorService extends Service {
    static final String CH = "sensor";
    static volatile String status = "";               // 화면 표시용 마지막 결과
    static volatile long lastOk = 0L;
    static volatile String lastValues = "";
    static volatile boolean running = false;

    private HandlerThread ht;
    private Handler h;
    private Collector col;
    private boolean full;                              // 카메라·마이크·위치까지 쓸 수 있는 시작인가(앱 화면에서 시작)
    private int fails = 0;
    private JSONObject lastSample;

    static void start(Context c, boolean fromUi) {
        Intent i = new Intent(c, SensorService.class).putExtra("ui", fromUi);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
    }

    static void stop(Context c) { c.stopService(new Intent(c, SensorService.class)); }

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int id) {
        boolean ui = intent != null && intent.getBooleanExtra("ui", false);
        full = ui;
        goForeground(ui ? "측정 준비" : "측정 중(카메라·마이크·위치는 앱을 열면 다시 켜짐)");
        if (ht == null) {
            ht = new HandlerThread("sensor-loop");
            ht.start();
            h = new Handler(ht.getLooper());
            col = new Collector(this, h);
        }
        running = true;
        h.removeCallbacksAndMessages(null);
        h.post(new Runnable() { @Override public void run() { col.start(sensors(cfg(SensorService.this), full)); tick(); } });
        return START_STICKY;
    }

    @Override public void onDestroy() {
        running = false;
        if (h != null) h.removeCallbacksAndMessages(null);
        if (col != null) col.stop();
        if (ht != null) ht.quitSafely();
        super.onDestroy();
    }

    static JSONObject cfg(Context c) {
        try { return new JSONObject(Prefs.get(c, "config").isEmpty() ? "{}" : Prefs.get(c, "config")); } catch (Exception e) { return new JSONObject(); }
    }

    /** 서버 설정의 켤 센서 중 이번 시작에서 쓸 수 있는 것만(권한·포그라운드 종류) */
    List<String> sensors(JSONObject cfg, boolean full) {
        JSONArray a = cfg.optJSONArray("sensors");
        List<String> on = a == null ? Collector.list(new JSONArray().put("temperature").put("humidity").put("pressure").put("light")
                .put("sound").put("motion").put("location").put("camera").put("battery").put("wifi")) : Collector.list(a);
        if (!full || !Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) && !Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION)) on.remove("location");
        if (!full || !Collector.has(this, Manifest.permission.RECORD_AUDIO)) on.remove("sound");
        if (!full || !Collector.has(this, Manifest.permission.CAMERA)) on.remove("camera");
        return on;
    }

    private void goForeground(String text) {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CH) == null) {
            NotificationChannel ch = new NotificationChannel(CH, "센서 측정", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, CH).setSmallIcon(R.drawable.ic_stat).setContentTitle("AIops 센서 — " + Prefs.get(this, "name"))
                .setContentText(text).setOngoing(true).setContentIntent(pi).build();
        if (Build.VERSION.SDK_INT >= 34) {
            int t = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE;
            if (full) {
                if (Collector.has(this, Manifest.permission.CAMERA)) t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
                if (Collector.has(this, Manifest.permission.RECORD_AUDIO)) t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
                if (Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) || Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION))
                    t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
            }
            try { startForeground(1, n, t); } catch (Exception e) { startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE); full = false; }
        } else if (Build.VERSION.SDK_INT >= 29) {
            int t = 0;
            if (full) t = ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE | ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
            try { startForeground(1, n, t); } catch (Exception e) { startForeground(1, n); }
        } else {
            startForeground(1, n);
        }
    }

    private void note(String text) {
        status = text;
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        nm.notify(1, new Notification.Builder(this, CH).setSmallIcon(R.drawable.ic_stat).setContentTitle("AIops 센서 — " + Prefs.get(this, "name"))
                .setContentText(text).setOngoing(true).setContentIntent(pi).build());
    }

    /** 한 번 측정·전송하고 다음 차례 예약 */
    private void tick() {
        JSONObject cfg = cfg(this);
        int interval = Math.max(15, cfg.optInt("interval_s", 60));
        lastSample = null;
        PowerManager.WakeLock wl = ((PowerManager) getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "aiops:sensor");
        wl.acquire(60000L);
        try {
            List<String> on = sensors(cfg, full);
            JSONObject s = col.snapshot(on);
            lastSample = s;
            if (on.contains("sound")) {
                boolean tone = cfg.optBoolean("tone_detect", true);
                double[] db = SoundMeter.measure(Math.max(1, Math.min(10, cfg.optInt("sound_window_s", 3))), tone);
                if (db != null) {
                    double off = cfg.optDouble("sound_offset_db", 90);
                    s.put("sound_db", Math.round((db[0] + off) * 10) / 10.0);
                    s.put("sound_peak", Math.round((db[1] + off) * 10) / 10.0);
                    if (tone) { s.put("alarm_tone", db[4]); s.put("tonal_pct", db[2]); if (db[3] > 0) s.put("tone_hz", db[3]); }
                }
            }
            int queued = Queue.size(this);
            if (queued > 0) s.put("queued", queued);
            JSONObject body = new JSONObject().put("samples", s);
            JSONArray batch = Queue.peek(this, 300);                   // 2.51.0 통신이 끊긴 동안 쌓인 값 — 300건씩 함께 보냄
            if (batch.length() > 0) body.put("batch", batch);
            if (Prefs.getLong(this, "info_sent") != 1L) body.put("info", MainActivity.info(this));
            Net.Res r = Net.json(this, "/api/sensor/push", body.toString());
            if (r.code == 200) {
                JSONObject j = new JSONObject(r.body);
                if (batch.length() > 0) Queue.drop(this, batch.length());
                Prefs.putLong(this, "info_sent", 1L);
                JSONObject nc = j.optJSONObject("config");
                if (nc != null) {
                    boolean changed = !nc.toString().equals(Prefs.get(this, "config"));
                    Prefs.put(this, "config", nc.toString());
                    if (changed) col.start(sensors(nc, full));
                    interval = Math.max(15, nc.optInt("interval_s", interval));
                }
                fails = 0;
                lastOk = System.currentTimeMillis();
                lastValues = s.toString();
                String msg = "보냄 " + new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.KOREA).format(new java.util.Date()) + " · " + summary(s);
                if (j.optBoolean("snap")) msg += snap(cfg(this));
                note(msg);
            } else if (r.code == 401) {
                note("장치 토큰이 폐기되었습니다 — 앱에서 다시 등록하세요");
                Prefs.forget(this);
                stopSelf();
                return;
            } else {
                fails++;
                if (r.code >= 500 || r.code == 429) Queue.add(this, s, cfg.optInt("buffer_max", 2880));
                else if ((r.code == 400 || r.code == 413) && batch.length() > 0) Queue.drop(this, batch.length());   // 서버가 거부한 묶음은 버림(무한 재시도 방지)
                note("서버 응답 " + r.code + " — " + r.body.replaceAll("\\s+", " ").substring(0, Math.min(80, r.body.length())));
            }
        } catch (Exception e) {
            fails++;
            if (lastSample != null) Queue.add(this, lastSample, cfg.optInt("buffer_max", 2880));
            note("전송 실패(" + fails + "회, 쌓인 값 " + Queue.size(this) + "건): " + e.getClass().getSimpleName() + " " + (e.getMessage() == null ? "" : e.getMessage()));
        } finally {
            if (wl.isHeld()) wl.release();
        }
        long next = fails == 0 ? interval * 1000L : Math.min(interval * 1000L, 15000L * fails);   // 실패하면 짧게 재시도(간격까지)
        h.postDelayed(new Runnable() { @Override public void run() { tick(); } }, next);
    }

    private String snap(JSONObject cfg) {
        if (!sensors(cfg, full).contains("camera")) return " · 촬영 요청(카메라 꺼짐 — 앱을 열어 다시 시작)";
        byte[] jpg = Snapper.take(this, "front".equals(cfg.optString("camera")), cfg.optInt("snap_quality", 70));
        if (jpg == null) return " · 촬영 실패";
        try {
            Net.Res r = Net.send(this, "/api/sensor/snap", "POST", jpg, "image/jpeg");
            return r.code == 200 ? " · 사진 " + (jpg.length / 1024) + "KB" : " · 사진 전송 " + r.code;
        } catch (Exception e) { return " · 사진 전송 실패"; }
    }

    static String summary(JSONObject s) {
        StringBuilder b = new StringBuilder();
        String[][] k = {{"ambient_c", "°C"}, {"battery_c", "°C(배터리)"}, {"humidity", "%"}, {"sound_db", "dB"}, {"vibration", "m/s²"}, {"battery_pct", "%🔋"}};
        for (String[] x : k) if (s.has(x[0])) b.append(s.optDouble(x[0])).append(x[1]).append(' ');
        return b.toString().trim();
    }
}
