package com.krvcf.aiopssensor;

import android.Manifest;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.PowerManager;
import android.os.StatFs;
import android.os.SystemClock;

import com.krvcf.aiopssensor.core.LocalAlarm;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/** 측정·전송 루프(포그라운드 서비스, 2.52.0 안정성 개편)
 *  - 깨우기: Handler 지연은 기기가 깊은 잠에 들면 멈추므로(uptimeMillis), 충전 중이면 부분 WakeLock 을 계속 잡고,
 *    배터리로 돌 때는 AlarmManager(setAndAllowWhileIdle)로 깨운다. 둘 다 '정해진 시각이 지났을 때만' 측정(중복 방지)
 *  - 센서 리스너는 별도 스레드 — 소리 측정·촬영·전송이 길어져도 진동·위치 콜백이 밀리지 않음
 *  - 진단(권한·배터리 최적화 제외·재시작 횟수·지연·저장 공간·네트워크)과 앱 오류 기록을 서버로 보고 */
public class SensorService extends Service {
    static final String CH = "sensor", CH_ALERT = "sensor_alert", ACT_TICK = "tick";
    static volatile String status = "";
    static volatile long lastOk = 0L;
    static volatile String lastValues = "";
    static volatile boolean running = false, fullMode = false;
    static volatile String update = "";                 // 서버가 알려 준 새 앱 버전 이름
    static volatile String updateSha = "";

    private HandlerThread work, sens;
    private Handler h, sh;
    private Collector col;
    private boolean full;
    private int fails = 0, restarts = 0;
    private long nextAt = 0L, lateMax = 0L;
    private long startedAt = 0L;
    private JSONObject lastSample;
    private String lastError = "";
    private PowerManager.WakeLock keep;               // 충전 중 상시 WakeLock
    private final LocalAlarm local = new LocalAlarm();

    static void start(Context c, boolean fromUi) {
        Intent i = new Intent(c, SensorService.class).putExtra("ui", fromUi);
        if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i); else c.startService(i);
    }

    static void stop(Context c) { c.stopService(new Intent(c, SensorService.class)); }

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent != null && ACT_TICK.equals(intent.getAction()) && h != null) {      // 알람으로 깨어남 — 시각이 됐으면 측정
            h.post(new Runnable() { @Override public void run() { if (System.currentTimeMillis() >= nextAt - 2000) tick(); } });
            return START_STICKY;
        }
        boolean ui = intent != null && intent.getBooleanExtra("ui", false);
        boolean wasRunning = h != null;
        if (wasRunning && fullMode && !ui) return START_STICKY;                         // 이미 전체 모드로 도는 중 — 그대로
        full = ui || (wasRunning && fullMode);
        if (!wasRunning && intent == null) restarts++;                                   // 시스템이 다시 살린 경우
        goForeground(full ? "측정 준비" : "측정 중(카메라·마이크·위치는 앱을 열면 다시 켜짐)");
        if (!wasRunning) {
            startedAt = System.currentTimeMillis();
            work = new HandlerThread("sensor-loop"); work.start(); h = new Handler(work.getLooper());
            sens = new HandlerThread("sensor-events"); sens.start(); sh = new Handler(sens.getLooper());
            col = new Collector(this, sh);
        }
        running = true;
        fullMode = full;
        final boolean restartNow = !wasRunning || ui;
        h.post(new Runnable() { @Override public void run() {
            col.start(sensors(cfg(SensorService.this), full));
            if (restartNow && System.currentTimeMillis() >= nextAt - 2000) tick(); else schedule(Math.max(1000L, nextAt - System.currentTimeMillis()));
        } });
        return START_STICKY;
    }

    @Override public void onDestroy() {
        running = false;
        fullMode = false;
        if (h != null) h.removeCallbacksAndMessages(null);
        cancelAlarm();
        if (col != null) col.stop();
        if (work != null) work.quitSafely();
        if (sens != null) sens.quitSafely();
        if (keep != null && keep.isHeld()) keep.release();
        super.onDestroy();
    }

    static JSONObject cfg(Context c) {
        try { return new JSONObject(Prefs.get(c, "config").isEmpty() ? "{}" : Prefs.get(c, "config")); } catch (Exception e) { return new JSONObject(); }
    }

    List<String> sensors(JSONObject cfg, boolean full) {
        JSONArray a = cfg.optJSONArray("sensors");
        List<String> on = a == null ? Collector.list(new JSONArray().put("temperature").put("humidity").put("pressure").put("light")
                .put("sound").put("motion").put("location").put("camera").put("battery").put("wifi")) : Collector.list(a);
        if (!full || !Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) && !Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION)) on.remove("location");
        if (!full || !Collector.has(this, Manifest.permission.RECORD_AUDIO)) on.remove("sound");
        if (!full || !Collector.has(this, Manifest.permission.CAMERA)) on.remove("camera");
        return on;
    }

    private void channels() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm.getNotificationChannel(CH) == null) {
            NotificationChannel ch = new NotificationChannel(CH, "센서 측정", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        if (nm.getNotificationChannel(CH_ALERT) == null) {
            NotificationChannel ch = new NotificationChannel(CH_ALERT, "현장 경보", NotificationManager.IMPORTANCE_HIGH);
            ch.enableVibration(true);
            ch.setVibrationPattern(new long[]{0, 600, 300, 600, 300, 600});
            nm.createNotificationChannel(ch);
        }
    }

    private Notification notif(String text) {
        PendingIntent pi = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CH).setSmallIcon(R.drawable.ic_stat).setContentTitle("AIops 센서 — " + Prefs.get(this, "name"))
                .setContentText(text).setStyle(new Notification.BigTextStyle().bigText(text)).setOngoing(true).setContentIntent(pi).build();
    }

    private void goForeground(String text) {
        channels();
        Notification n = notif(text);
        if (Build.VERSION.SDK_INT >= 34) {
            int t = ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE;
            if (full) {
                if (Collector.has(this, Manifest.permission.CAMERA)) t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
                if (Collector.has(this, Manifest.permission.RECORD_AUDIO)) t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
                if (Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) || Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION))
                    t |= ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION;
            }
            try { startForeground(1, n, t); }
            catch (Exception e) { lastError = "startForeground: " + e.getClass().getSimpleName(); startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE); full = false; }
        } else if (Build.VERSION.SDK_INT >= 29) {
            int t = full ? ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE | ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION : 0;
            try { startForeground(1, n, t); } catch (Exception e) { lastError = "startForeground: " + e.getClass().getSimpleName(); startForeground(1, n); }
        } else {
            startForeground(1, n);
        }
    }

    private void note(String text) {
        status = text;
        try { ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).notify(1, notif(text)); } catch (Exception ignored) { }
    }

    // ------------------------------------------------------------------ 깨우기
    private PendingIntent tickIntent() {
        return PendingIntent.getService(this, 7, new Intent(this, SensorService.class).setAction(ACT_TICK),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    private void cancelAlarm() {
        try { ((AlarmManager) getSystemService(ALARM_SERVICE)).cancel(tickIntent()); } catch (Exception ignored) { }
    }

    /** 다음 측정 예약 — 충전 중: WakeLock 유지 + Handler, 배터리: WakeLock 놓고 AlarmManager(+Handler 는 깨어 있을 때 대비) */
    private void schedule(long delay) {
        nextAt = System.currentTimeMillis() + delay;
        boolean plugged = Collector.plugged(this);
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (plugged) {
            if (keep == null) { keep = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "aiops:sensor-keep"); keep.setReferenceCounted(false); }
            if (!keep.isHeld()) keep.acquire();
            cancelAlarm();
        } else {
            if (keep != null && keep.isHeld()) keep.release();
            try {
                ((AlarmManager) getSystemService(ALARM_SERVICE)).setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP,
                        SystemClock.elapsedRealtime() + delay, tickIntent());
            } catch (Exception e) { lastError = "alarm: " + e.getClass().getSimpleName(); }
        }
        h.removeCallbacksAndMessages(null);
        h.postDelayed(new Runnable() { @Override public void run() { tick(); } }, delay);
    }

    // ------------------------------------------------------------------ 진단
    private JSONObject diag(JSONObject cfg) throws Exception {
        JSONObject d = new JSONObject();
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        d.put("app_code", Prefs.versionCode(this)).put("app", Prefs.versionName(this)).put("sdk", Build.VERSION.SDK_INT)
         .put("uptime_s", (System.currentTimeMillis() - startedAt) / 1000).put("starts", Prefs.getLong(this, "starts"))
         .put("restarts", restarts).put("full", full).put("battery_exempt", pm.isIgnoringBatteryOptimizations(getPackageName()))
         .put("plugged", Collector.plugged(this)).put("wake", keep != null && keep.isHeld() ? "wakelock" : "alarm")
         .put("late_s", lateMax / 1000).put("fails", fails).put("queue", Queue.size(this));
        lateMax = 0;
        JSONObject p = new JSONObject();
        p.put("camera", Collector.has(this, Manifest.permission.CAMERA)).put("mic", Collector.has(this, Manifest.permission.RECORD_AUDIO))
         .put("location", Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) || Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION))
         .put("notify", ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).areNotificationsEnabled());
        d.put("perms", p);
        try { StatFs st = new StatFs(getFilesDir().getPath()); d.put("free_mb", st.getAvailableBytes() / (1024 * 1024)); } catch (Exception ignored) { }
        d.put("net", netType());
        if (!lastError.isEmpty()) d.put("last_error", lastError.length() > 200 ? lastError.substring(0, 200) : lastError);
        return d;
    }

    private String netType() {
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            NetworkCapabilities nc = cm.getNetworkCapabilities(cm.getActiveNetwork());
            if (nc == null) return "none";
            if (nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "wifi";
            if (nc.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) return "cellular";
            if (nc.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) return "ethernet";
            return "other";
        } catch (Exception e) { return "?"; }
    }

    private String readCrash() {
        File f = new File(getFilesDir(), "crash.txt");
        if (!f.exists()) return "";
        try (FileInputStream in = new FileInputStream(f)) { return new String(Net.readAll(in, 16384), "UTF-8"); } catch (Exception e) { return ""; }
    }

    // ------------------------------------------------------------------ 폰 자체 경보(통신이 끊겨도 현장에서 알 수 있게)
    private void localAlarm(JSONObject cfg, JSONObject s) {
        if (!cfg.optBoolean("local_alarm", true)) return;
        JSONObject th = cfg.optJSONObject("thresholds");
        if (th == null) return;
        Map<String, double[]> t = new HashMap<>();
        Map<String, Double> v = new HashMap<>();
        Iterator<String> it = th.keys();
        while (it.hasNext()) {
            String k = it.next();
            JSONObject o = th.optJSONObject(k);
            if (o == null || !(o.has("crit_hi") || o.has("crit_lo"))) continue;
            t.put(k, new double[]{o.optDouble("crit_hi", Double.NaN), o.optDouble("crit_lo", Double.NaN)});
        }
        double off = cfg.optDouble("temp_offset_c", 0);
        if (s.has("ambient_c")) v.put("temp_c", s.optDouble("ambient_c"));
        else if (s.has("battery_c")) v.put("temp_c", s.optDouble("battery_c") + off);
        for (String k : new String[]{"humidity", "sound_db", "alarm_tone", "vibration"}) if (s.has(k)) v.put(k, s.optDouble(k));
        if (s.has("battery_pct") && s.optDouble("charging", 1) < 0.5) v.put("battery_pct", s.optDouble("battery_pct"));
        String hit = local.check(t, v);
        if (hit.isEmpty()) return;
        StringBuilder m = new StringBuilder();
        for (String k : hit.split(",")) { if (m.length() > 0) m.append(", "); m.append(label(k)).append(' ').append(v.get(k) == null ? "" : String.valueOf(Math.round(v.get(k) * 10) / 10.0)); }
        PendingIntent pi = PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        try {
            ((NotificationManager) getSystemService(NOTIFICATION_SERVICE)).notify(2, new Notification.Builder(this, CH_ALERT)
                    .setSmallIcon(R.drawable.ic_stat).setContentTitle("현장 경보 — " + Prefs.get(this, "name")).setContentText(m.toString())
                    .setCategory(Notification.CATEGORY_ALARM).setAutoCancel(true).setContentIntent(pi).build());
        } catch (Exception ignored) { }
    }

    static String label(String k) {
        switch (k) {
            case "temp_c": return "온도";
            case "humidity": return "습도";
            case "sound_db": return "소리";
            case "alarm_tone": return "경보음";
            case "vibration": return "진동";
            case "battery_pct": return "배터리";
            default: return k;
        }
    }

    // ------------------------------------------------------------------ 측정·전송
    private void tick() {
        long now = System.currentTimeMillis();
        if (nextAt > 0 && now - nextAt > lateMax) lateMax = now - nextAt;        // 예정보다 늦게 깨어난 시간(잠 문제 진단)
        JSONObject cfg = cfg(this);
        int interval = Math.max(15, cfg.optInt("interval_s", 60));
        lastSample = null;
        PowerManager.WakeLock wl = ((PowerManager) getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "aiops:sensor");
        wl.acquire(90000L);
        JSONArray batch = new JSONArray();
        int peeked = 0;
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
                } else lastError = "마이크 사용 불가(다른 앱 사용 중이거나 권한 없음)";
            }
            localAlarm(cfg, s);
            int queued = Queue.size(this);
            if (queued > 0) s.put("queued", queued);
            JSONObject body = new JSONObject().put("samples", s).put("diag", diag(cfg));
            batch = Queue.peek(this, 300);
            peeked = Queue.lastPeek;
            if (batch.length() > 0) body.put("batch", batch);
            if (Prefs.getLong(this, "info_sent") != 1L) body.put("info", MainActivity.info(this));
            String crash = readCrash();
            if (!crash.isEmpty()) body.put("crash", crash);
            Net.Res r = Net.json(this, "/api/sensor/push", body.toString());
            if (r.code == 200) {
                JSONObject j = new JSONObject(r.body);
                if (peeked > 0) Queue.drop(this, peeked);
                if (!crash.isEmpty()) new File(getFilesDir(), "crash.txt").delete();
                Prefs.putLong(this, "info_sent", 1L);
                JSONObject nc = j.optJSONObject("config");
                if (nc != null) {
                    boolean changed = !nc.toString().equals(Prefs.get(this, "config"));
                    Prefs.put(this, "config", nc.toString());
                    if (changed) { final List<String> nOn = sensors(nc, full); sh.post(new Runnable() { @Override public void run() { col.start(nOn); } }); }
                    interval = Math.max(15, nc.optInt("interval_s", interval));
                }
                JSONObject up = j.optJSONObject("app");
                update = up == null ? "" : up.optString("name");
                updateSha = up == null ? "" : up.optString("sha256");
                fails = 0;
                lastError = "";
                lastOk = System.currentTimeMillis();
                lastValues = s.toString();
                String msg = "보냄 " + new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.KOREA).format(new java.util.Date()) + " · " + summary(s);
                if (peeked > 0) msg += " · 밀린 값 " + peeked + "건 보냄";
                if (!update.isEmpty()) msg += " · 새 버전 " + update;
                if (j.optBoolean("snap")) msg += snap(cfg(this));
                note(msg);
            } else if (r.code == 401) {
                note("장치 토큰이 폐기되었습니다 — 앱에서 다시 등록하세요");
                Prefs.forget(this);
                Queue.clear(this);
                running = false;
                stopSelf();
                return;
            } else {
                fails++;
                lastError = "서버 응답 " + r.code;
                if (r.code >= 500 || r.code == 429) Queue.add(this, s, cfg.optInt("buffer_max", 2880));
                else if ((r.code == 400 || r.code == 413) && peeked > 0) Queue.drop(this, peeked);     // 서버가 거부한 묶음은 버림(무한 재시도 방지)
                note("서버 응답 " + r.code + " — " + r.body.replaceAll("\\s+", " ").substring(0, Math.min(80, r.body.length())));
            }
        } catch (Throwable e) {
            fails++;
            lastError = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " " + e.getMessage());
            if (lastSample != null) Queue.add(this, lastSample, cfg.optInt("buffer_max", 2880));
            note("전송 실패(" + fails + "회, 쌓인 값 " + Queue.size(this) + "건): " + lastError);
        } finally {
            if (wl.isHeld()) wl.release();
        }
        long next = fails == 0 ? interval * 1000L : Math.min(interval * 1000L, 15000L * fails);
        schedule(next);
    }

    private String snap(JSONObject cfg) {
        if (!sensors(cfg, full).contains("camera")) return " · 촬영 요청(카메라 꺼짐 — 앱을 열어 다시 시작)";
        byte[] jpg = Snapper.take(this, "front".equals(cfg.optString("camera")), cfg.optInt("snap_quality", 70));
        if (jpg == null) { lastError = "촬영 실패(카메라를 다른 앱이 쓰는 중이거나 권한 없음)"; return " · 촬영 실패"; }
        try {
            Net.Res r = Net.send(this, "/api/sensor/snap", "POST", jpg, "image/jpeg");
            return r.code == 200 ? " · 사진 " + (jpg.length / 1024) + "KB" : " · 사진 전송 " + r.code;
        } catch (Exception e) { return " · 사진 전송 실패"; }
    }

    static String summary(JSONObject s) {
        StringBuilder b = new StringBuilder();
        String[][] k = {{"ambient_c", "°C"}, {"battery_c", "°C(배터리)"}, {"humidity", "%"}, {"sound_db", "dB"}, {"vibration", "m/s²"}, {"battery_pct", "%🔋"}};
        for (String[] x : k) if (s.has(x[0])) b.append(s.optDouble(x[0])).append(x[1]).append(' ');
        if (s.optDouble("alarm_tone", 0) >= 1) b.append("🔔경보음");
        return b.toString().trim();
    }
}
