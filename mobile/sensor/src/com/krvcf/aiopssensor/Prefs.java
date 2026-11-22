package com.krvcf.aiopssensor;

import android.content.Context;
import android.content.SharedPreferences;

/** 설정 저장 — 서버 주소·장치 ID·장치 토큰(Keystore 암호화)·서버가 내려준 설정(JSON)·신뢰한 인증서 지문 */
final class Prefs {
    private Prefs() { }
    private static volatile String tok;

    static SharedPreferences sp(Context c) { return c.getApplicationContext().getSharedPreferences("sensor", Context.MODE_PRIVATE); }
    static String get(Context c, String k) { return sp(c).getString(k, ""); }
    static long getLong(Context c, String k) { return sp(c).getLong(k, 0L); }
    static void put(Context c, String k, String v) { sp(c).edit().putString(k, v == null ? "" : v).apply(); }
    static void putLong(Context c, String k, long v) { sp(c).edit().putLong(k, v).apply(); }

    static String server(Context c) { return get(c, "server"); }

    static String token(Context c) {
        String t = tok;
        if (t != null) return t;
        String e = get(c, "token_e");
        t = e.isEmpty() ? "" : Vault.dec(e);
        tok = t;
        return t;
    }

    static boolean setToken(Context c, String t) {
        String e = Vault.enc(t);
        if (e.isEmpty()) return false;                    // Keystore 를 못 쓰면 저장하지 않음(평문 저장 안 함)
        put(c, "token_e", e);
        tok = t;
        return true;
    }

    static void forget(Context c) { sp(c).edit().remove("token_e").remove("device").remove("config").remove("name").apply(); tok = null; }

    /** 앱 버전 코드 — getLongVersionCode 는 Android 9(API 28)부터라 8.x 에서 죽지 않게 옛 필드를 씀 */
    @SuppressWarnings("deprecation")
    static long versionCode(Context c) {
        try { return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionCode; } catch (Exception e) { return 0L; }
    }

    static String versionName(Context c) {
        try { return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName; } catch (Exception e) { return "?"; }
    }
}
