package com.krvcf.vcfaiops;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.net.Uri;

/** 앱 설정 저장(서버 주소·기기 토큰·알림 커서·신뢰한 인증서 지문) */
final class Prefs {
    private Prefs() { }

    static SharedPreferences sp(Context c) { return c.getApplicationContext().getSharedPreferences("aiops", Context.MODE_PRIVATE); }
    static String get(Context c, String k) { return sp(c).getString(k, ""); }
    static long getLong(Context c, String k) { return sp(c).getLong(k, 0L); }
    static void put(Context c, String k, String v) { sp(c).edit().putString(k, v == null ? "" : v).apply(); }
    static void putLong(Context c, String k, long v) { sp(c).edit().putLong(k, v).apply(); }
    static void remove(Context c, String... ks) {
        SharedPreferences.Editor e = sp(c).edit();
        for (String k : ks) { e.remove(k); if ("token".equals(k)) { e.remove("token_e"); tok = null; } }
        e.apply();
    }
    static void clearAll(Context c) { sp(c).edit().clear().apply(); tok = null; }
    static boolean on(Context c, String k) { return getLong(c, k) == 1L; }

    static String server(Context c) { return get(c, "server"); }
    private static volatile String tok;                     // 복호화한 토큰(프로세스 메모리에만)

    /** 기기 토큰 — Keystore 로 암호화해 저장(token_e). 2.30.0 의 평문(token)은 처음 읽을 때 옮긴다 */
    static String token(Context c) {
        String t = tok;
        if (t != null) return t;
        synchronized (Prefs.class) {
            if (tok != null) return tok;
            String e = get(c, "token_e"), plain = get(c, "token");
            if (!e.isEmpty()) t = Vault.dec(e);
            else if (!plain.isEmpty()) { t = plain; setToken(c, plain); }
            else t = "";
            if (t.isEmpty() && !plain.isEmpty()) t = plain;       // Keystore 를 못 쓰는 기기 — 평문 유지
            tok = t;
            return t;
        }
    }

    static void setToken(Context c, String v) {
        String e = Vault.enc(v);
        SharedPreferences.Editor ed = sp(c).edit();
        if (e.isEmpty() || !v.equals(Vault.dec(e))) ed.putString("token", v).remove("token_e");
        else ed.putString("token_e", e).remove("token");
        ed.apply();
        tok = v;
    }
    static String host(Context c) { String s = server(c); return s.isEmpty() ? "" : hostOf(s); }

    static String hostOf(String url) {
        try { String h = Uri.parse(url).getHost(); return h == null ? "" : h.toLowerCase(java.util.Locale.ROOT); } catch (Exception e) { return ""; }
    }

    /** 입력한 주소 정리: 스킴 없으면 https, 끝 슬래시·경로 제거. 잘못되면 "" */
    static String normalize(String raw) {
        String s = raw == null ? "" : raw.trim();
        if (s.isEmpty()) return "";
        if (!s.matches("(?i)^https?://.*")) s = "https://" + s;
        try {
            Uri u = Uri.parse(s);
            String sc = u.getScheme() == null ? "" : u.getScheme().toLowerCase(java.util.Locale.ROOT);
            if (!(sc.equals("https") || sc.equals("http")) || u.getHost() == null || u.getHost().isEmpty()) return "";
            if (u.getUserInfo() != null) return "";
            return sc + "://" + u.getHost().toLowerCase(java.util.Locale.ROOT) + (u.getPort() > 0 ? ":" + u.getPort() : "");
        } catch (Exception e) { return ""; }
    }

    static int versionCode(Context c) {
        // 2.52.0 getLongVersionCode 는 Android 9(API 28)부터 — 8.0/8.1 에서 NoSuchMethodError 로 죽지 않게 옛 필드 사용
        try { PackageInfo p = c.getPackageManager().getPackageInfo(c.getPackageName(), 0); return versionCodeOf(p); } catch (Exception e) { return 0; }
    }

    static String versionName(Context c) {
        try { return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName; } catch (Exception e) { return "?"; }
    }

    @SuppressWarnings("deprecation")
    static int versionCodeOf(PackageInfo p) {
        return android.os.Build.VERSION.SDK_INT >= 28 ? (int) p.getLongVersionCode() : p.versionCode;
    }
}
