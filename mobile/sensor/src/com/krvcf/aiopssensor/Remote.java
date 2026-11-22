package com.krvcf.aiopssensor;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

/** 포털 원격 설정 실행(2.53.0). 서버가 전송 응답에 명령을 실어 보내면(폰이 가져가는 방식 — 서버가 폰에 직접 접속하지 않음)
 *  여기서 실행하고 결과를 다음 전송 때 보고한다.
 *  - 기기 소유자(Device Owner)면: 권한 부여·화면 켜짐 유지(충전 중)·잠금 화면 끄기·전용 화면 고정·밝기·재부팅을 바로 적용
 *  - 아니면: 앱이 직접 할 수 있는 것(알람 음량·서비스 재시작·서버 주소 변경 등)만 하고, 사람 손이 필요한 것은 폰에 '눌러서 설정' 알림 */
final class Remote {
    private Remote() { }

    static ComponentName admin(Context c) { return new ComponentName(c, Admin.class); }

    static boolean owner(Context c) {
        try { return ((DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE)).isDeviceOwnerApp(c.getPackageName()); }
        catch (Exception e) { return false; }
    }

    /** 이 폰에서 원격으로 바로 바꿀 수 있는 것 */
    static JSONArray caps(Context c) {
        JSONArray a = new JSONArray().put("alarm_volume").put("restart").put("server").put("clear_queue").put("display");
        if (owner(c)) {
            a.put("grant_perms").put("stay_awake").put("keyguard").put("kiosk").put("reboot");
            if (Build.VERSION.SDK_INT >= 28) a.put("brightness");
        } else {
            a.put("battery_prompt").put("perm_prompt");
        }
        return a;
    }

    /** 명령 목록 실행 → [{id, ok, msg}] */
    static JSONArray run(Context c, JSONArray cmds) {
        JSONArray out = new JSONArray();
        for (int i = 0; cmds != null && i < cmds.length(); i++) {
            JSONObject cmd = cmds.optJSONObject(i);
            if (cmd == null) continue;
            String id = cmd.optString("id"), op = cmd.optString("op");
            JSONObject args = cmd.optJSONObject("args") == null ? new JSONObject() : cmd.optJSONObject("args");
            String msg;
            boolean ok;
            try {
                msg = exec(c, op, args);
                ok = !msg.startsWith("!");
                if (!ok) msg = msg.substring(1);
            } catch (Throwable e) {
                ok = false;
                msg = e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage());
            }
            try { out.put(new JSONObject().put("id", id).put("op", op).put("ok", ok).put("msg", msg.length() > 300 ? msg.substring(0, 300) : msg)); }
            catch (Exception ignored) { }
        }
        return out;
    }

    private static String exec(Context c, String op, JSONObject a) throws Exception {
        DevicePolicyManager dpm = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
        boolean own = owner(c);
        ComponentName adm = admin(c);
        switch (op) {
            case "grant_perms": {
                if (!own) { prompt(c, 11, "권한 허용이 필요합니다", "눌러서 카메라·마이크·위치·알림 허용", new Intent(c, MainActivity.class).putExtra("ask_perms", true)); return "!기기 소유자가 아님 — 폰에 '권한 허용' 알림을 띄움"; }
                String[] ps = {Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO, Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION, "android.permission.POST_NOTIFICATIONS"};
                StringBuilder r = new StringBuilder();
                for (String p : ps) {
                    if (p.endsWith("POST_NOTIFICATIONS") && Build.VERSION.SDK_INT < 33) continue;
                    boolean g = dpm.setPermissionGrantState(adm, c.getPackageName(), p, DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED);
                    r.append(p.substring(p.lastIndexOf('.') + 1)).append(g ? "=허용 " : "=실패 ");
                }
                SensorService.restartFull(c);
                return r.toString().trim();
            }
            case "stay_awake": {                                  // 충전 중 화면 켜짐 유지(AC·USB·무선 = 7)
                if (!own) return "!기기 소유자만 가능 — 폰의 개발자 옵션 › '켜진 상태로 유지'를 직접 켜세요";
                dpm.setGlobalSetting(adm, Settings.Global.STAY_ON_WHILE_PLUGGED_IN, a.optBoolean("on", true) ? "7" : "0");
                return a.optBoolean("on", true) ? "충전 중 화면 켜짐 유지" : "화면 켜짐 유지 해제";
            }
            case "keyguard": {
                if (!own) return "!기기 소유자만 가능";
                boolean off = a.optBoolean("disable", true);
                return dpm.setKeyguardDisabled(adm, off) ? (off ? "잠금 화면 끔" : "잠금 화면 켬") : "!잠금 화면 설정 실패(화면 잠금 비밀번호가 있으면 먼저 지워야 함)";
            }
            case "kiosk": {                                       // 현장 표시 모드를 전용 화면으로 고정(홈·최근 앱 버튼 막힘)
                if (!own) return "!기기 소유자만 가능";
                boolean on = a.optBoolean("on", true);
                dpm.setLockTaskPackages(adm, on ? new String[]{c.getPackageName()} : new String[0]);
                c.startActivity(new Intent(c, DisplayActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("kiosk", on ? 1 : 2));
                return on ? "현장 표시 모드로 고정" : "고정 해제";
            }
            case "reboot": {
                if (!own) return "!기기 소유자만 가능";
                dpm.reboot(adm);
                return "재부팅";
            }
            case "brightness": {
                if (!own || Build.VERSION.SDK_INT < 28) return "!기기 소유자·Android 9 이상만 가능";
                int v = Math.max(0, Math.min(255, a.optInt("value", 40)));
                dpm.setSystemSetting(adm, Settings.System.SCREEN_BRIGHTNESS_MODE, "0");
                dpm.setSystemSetting(adm, Settings.System.SCREEN_BRIGHTNESS, String.valueOf(v));
                return "밝기 " + v;
            }
            case "battery_prompt": {
                if (Watchdog.exempt(c)) return "이미 배터리 최적화 제외";
                prompt(c, 12, "배터리 최적화 제외가 필요합니다", "눌러서 '허용' — 꺼지지 않고 자동으로 다시 켜짐",
                        new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + c.getPackageName())));
                return "!폰에서 사람이 눌러야 함 — 알림을 띄움(기기 소유자 설치 스크립트를 쓰면 처음부터 제외됨)";
            }
            case "perm_prompt": {
                prompt(c, 11, "권한 허용이 필요합니다", "눌러서 카메라·마이크·위치·알림 허용", new Intent(c, MainActivity.class).putExtra("ask_perms", true));
                return "!폰에서 사람이 눌러야 함 — 알림을 띄움";
            }
            case "alarm_volume": {
                AudioManager am = (AudioManager) c.getSystemService(Context.AUDIO_SERVICE);
                int max = am.getStreamMaxVolume(AudioManager.STREAM_ALARM);
                int v = Math.round(max * Math.max(0, Math.min(100, a.optInt("percent", 80))) / 100f);
                am.setStreamVolume(AudioManager.STREAM_ALARM, v, 0);
                am.setStreamVolume(AudioManager.STREAM_NOTIFICATION, Math.round(am.getStreamMaxVolume(AudioManager.STREAM_NOTIFICATION) * v / (float) Math.max(1, max)), 0);
                return "경보 음량 " + v + "/" + max;
            }
            case "restart": {
                SensorService.restartFull(c);
                return "측정 서비스 다시 시작";
            }
            case "clear_queue": {
                int n = Queue.size(c);
                Queue.clear(c);
                return "밀린 값 " + n + "건 삭제";
            }
            case "display": {
                c.startActivity(new Intent(c, DisplayActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
                return "현장 표시 모드 열기 요청";
            }
            case "server": {                                      // 서버 주소 바꾸기(IP 변경 등) — 새 주소로 연결 시험 후에만 바꿈
                String url = a.optString("url").trim().replaceAll("/+$", "");
                if (!url.matches("^https?://[A-Za-z0-9.\\-\\[\\]:]+(/[\\w\\-./]*)?$")) return "!주소 형식이 맞지 않음";
                String old = Prefs.server(c);
                Prefs.put(c, "server", url);
                try {
                    Net.Res r = Net.json(c, "/api/sensor/push", new JSONObject().put("samples", new JSONObject()).toString());
                    if (r.code == 200) return "서버 주소 변경: " + url;
                    Prefs.put(c, "server", old);
                    return "!새 주소 응답 " + r.code + " — 원래 주소 유지";
                } catch (Exception e) {
                    Prefs.put(c, "server", old);
                    return "!새 주소에 연결 실패(" + e.getClass().getSimpleName() + ") — 원래 주소 유지";
                }
            }
            default:
                return "!모르는 명령: " + op;
        }
    }

    static void prompt(Context c, int id, String title, String text, Intent target) {
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm.getNotificationChannel(SensorService.CH_ALERT) == null)
            nm.createNotificationChannel(new NotificationChannel(SensorService.CH_ALERT, "현장 경보", NotificationManager.IMPORTANCE_HIGH));
        PendingIntent pi = PendingIntent.getActivity(c, id, target.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE);
        nm.notify(id, new Notification.Builder(c, SensorService.CH_ALERT).setSmallIcon(R.drawable.ic_stat).setContentTitle(title)
                .setContentText(text).setAutoCancel(true).setContentIntent(pi).build());
    }
}
