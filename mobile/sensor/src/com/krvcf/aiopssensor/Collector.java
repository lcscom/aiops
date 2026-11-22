package com.krvcf.aiopssensor;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.PowerManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** 폰 센서 값 모으기 — 센서 리스너는 계속 듣고, 전송 때 최신값·구간 최대 진동을 꺼낸다 */
final class Collector implements SensorEventListener, LocationListener {
    private final Context c;
    private final SensorManager sm;
    private final Handler h;
    private final Object lock = new Object();
    private float ambient = Float.NaN, humidity = Float.NaN, pressure = Float.NaN, light = Float.NaN, prox = Float.NaN;
    private float vibMax = 0f;
    private Location loc;
    private boolean motionOn, locOn;

    Collector(Context c, Handler h) {
        this.c = c.getApplicationContext();
        this.h = h;
        this.sm = (SensorManager) c.getSystemService(Context.SENSOR_SERVICE);
    }

    static boolean has(Context c, String p) { return c.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED; }

    /** 켤 센서 목록대로 리스너 등록(없는 센서는 건너뜀) */
    void start(List<String> on) {
        stop();
        if (sm == null) return;
        if (on.contains("temperature")) reg(Sensor.TYPE_AMBIENT_TEMPERATURE);
        if (on.contains("humidity")) reg(Sensor.TYPE_RELATIVE_HUMIDITY);
        if (on.contains("pressure")) reg(Sensor.TYPE_PRESSURE);
        if (on.contains("light")) reg(Sensor.TYPE_LIGHT);
        if (on.contains("proximity")) reg(Sensor.TYPE_PROXIMITY);
        motionOn = on.contains("motion") && (reg(Sensor.TYPE_LINEAR_ACCELERATION) || reg(Sensor.TYPE_ACCELEROMETER));
        locOn = false;
        if (on.contains("location") && (has(c, Manifest.permission.ACCESS_FINE_LOCATION) || has(c, Manifest.permission.ACCESS_COARSE_LOCATION))) {
            try {
                LocationManager lm = (LocationManager) c.getSystemService(Context.LOCATION_SERVICE);
                for (String p : new String[]{LocationManager.NETWORK_PROVIDER, LocationManager.GPS_PROVIDER}) {
                    if (lm.isProviderEnabled(p)) { lm.requestLocationUpdates(p, 60000L, 0f, this, h.getLooper()); locOn = true; }
                    Location last = lm.getLastKnownLocation(p);
                    if (last != null && better(last)) loc = last;
                }
            } catch (SecurityException | IllegalArgumentException ignored) { }
        }
    }

    private boolean reg(int type) {
        Sensor s = sm.getDefaultSensor(type);
        return s != null && sm.registerListener(this, s, SensorManager.SENSOR_DELAY_NORMAL, h);
    }

    void stop() {
        try { if (sm != null) sm.unregisterListener(this); } catch (Exception ignored) { }
        try { ((LocationManager) c.getSystemService(Context.LOCATION_SERVICE)).removeUpdates(this); } catch (Exception ignored) { }
    }

    /** 이 폰에 있는 센서(서버 표시용) */
    static JSONArray available(Context c) {
        JSONArray a = new JSONArray();
        SensorManager sm = (SensorManager) c.getSystemService(Context.SENSOR_SERVICE);
        int[] t = {Sensor.TYPE_AMBIENT_TEMPERATURE, Sensor.TYPE_RELATIVE_HUMIDITY, Sensor.TYPE_PRESSURE, Sensor.TYPE_LIGHT,
                Sensor.TYPE_PROXIMITY, Sensor.TYPE_LINEAR_ACCELERATION, Sensor.TYPE_ACCELEROMETER};
        String[] n = {"ambient_temperature", "humidity", "pressure", "light", "proximity", "linear_acceleration", "accelerometer"};
        for (int i = 0; i < t.length; i++) if (sm != null && sm.getDefaultSensor(t[i]) != null) a.put(n[i]);
        PackageManager pm = c.getPackageManager();
        if (pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) a.put("camera");
        if (pm.hasSystemFeature(PackageManager.FEATURE_MICROPHONE)) a.put("microphone");
        if (pm.hasSystemFeature(PackageManager.FEATURE_LOCATION_GPS)) a.put("gps");
        return a;
    }

    @Override public void onSensorChanged(SensorEvent e) {
        synchronized (lock) {
            switch (e.sensor.getType()) {
                case Sensor.TYPE_AMBIENT_TEMPERATURE: ambient = e.values[0]; break;
                case Sensor.TYPE_RELATIVE_HUMIDITY: humidity = e.values[0]; break;
                case Sensor.TYPE_PRESSURE: pressure = e.values[0]; break;
                case Sensor.TYPE_LIGHT: light = e.values[0]; break;
                case Sensor.TYPE_PROXIMITY: prox = e.values[0]; break;
                case Sensor.TYPE_LINEAR_ACCELERATION: {
                    float m = (float) Math.sqrt(e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]);
                    if (m > vibMax) vibMax = m;
                    break;
                }
                case Sensor.TYPE_ACCELEROMETER: {               // 선형 가속도 센서가 없는 기종 — 중력(9.81) 빼고 근사
                    float m = Math.abs((float) Math.sqrt(e.values[0] * e.values[0] + e.values[1] * e.values[1] + e.values[2] * e.values[2]) - 9.81f);
                    if (m > vibMax) vibMax = m;
                    break;
                }
                default: break;
            }
        }
    }

    @Override public void onAccuracyChanged(Sensor s, int a) { }

    private boolean better(Location n) {
        if (loc == null) return true;
        if (n.getTime() - loc.getTime() > 120000) return true;
        return n.getAccuracy() <= loc.getAccuracy();
    }

    @Override public void onLocationChanged(Location l) { synchronized (lock) { if (better(l)) loc = l; } }
    @Override public void onStatusChanged(String p, int s, Bundle b) { }
    @Override public void onProviderEnabled(String p) { }
    @Override public void onProviderDisabled(String p) { }

    private static void put(JSONObject o, String k, double v) {
        if (Double.isNaN(v) || Double.isInfinite(v)) return;
        try { o.put(k, Math.round(v * 100.0) / 100.0); } catch (Exception ignored) { }
    }

    /** 지금 값(진동은 지난 전송 뒤 최대값) */
    JSONObject snapshot(List<String> on) {
        JSONObject o = new JSONObject();
        synchronized (lock) {
            if (on.contains("temperature")) put(o, "ambient_c", ambient);
            if (on.contains("humidity")) put(o, "humidity", humidity);
            if (on.contains("pressure")) put(o, "pressure", pressure);
            if (on.contains("light")) put(o, "light", light);
            if (on.contains("proximity")) put(o, "proximity", prox);
            if (motionOn) { put(o, "vibration", vibMax); vibMax = 0f; }
            if (locOn && loc != null && System.currentTimeMillis() - loc.getTime() < 15 * 60000L) {
                try {
                    o.put("lat", Math.round(loc.getLatitude() * 1e6) / 1e6);
                    o.put("lon", Math.round(loc.getLongitude() * 1e6) / 1e6);
                } catch (Exception ignored) { }
                put(o, "loc_acc", loc.getAccuracy());
            }
        }
        Intent b = c.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (b != null) {
            int t = b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
            if (t != Integer.MIN_VALUE && on.contains("temperature")) put(o, "battery_c", t / 10.0);
            int lv = b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1), sc = b.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            if (on.contains("battery")) {
                if (lv >= 0 && sc > 0) put(o, "battery_pct", lv * 100.0 / sc);
                put(o, "charging", b.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0 ? 1 : 0);
                int hl = b.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN);   // 2.52.0 배터리 상태
                put(o, "battery_health", hl == BatteryManager.BATTERY_HEALTH_GOOD ? 0
                        : hl == BatteryManager.BATTERY_HEALTH_OVERHEAT || hl == BatteryManager.BATTERY_HEALTH_DEAD
                          || hl == BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE ? 2 : hl == BatteryManager.BATTERY_HEALTH_UNKNOWN ? Double.NaN : 1);
            }
        }
        if (on.contains("battery") && Build.VERSION.SDK_INT >= 29) {
            try { put(o, "thermal", ((PowerManager) c.getSystemService(Context.POWER_SERVICE)).getCurrentThermalStatus()); } catch (Exception ignored) { }
        }
        if (on.contains("wifi")) {
            try {
                WifiInfo w = ((WifiManager) c.getSystemService(Context.WIFI_SERVICE)).getConnectionInfo();
                if (w != null && w.getNetworkId() != -1 && w.getRssi() > -127) put(o, "wifi_rssi", w.getRssi());
            } catch (Exception ignored) { }
        }
        return o;
    }

    /** 충전기에 꽂혀 있는가(측정 루프의 깨우기 방식 결정) */
    static boolean plugged(Context c) {
        Intent b = c.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        return b != null && b.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0;
    }

    static List<String> list(JSONArray a) {
        List<String> out = new ArrayList<>();
        if (a != null) for (int i = 0; i < a.length(); i++) out.add(a.optString(i));
        return out;
    }
}
