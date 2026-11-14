package com.krvcf.vcfaiops;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.CancellationSignal;

/** 앱 잠금(선택) — 앱을 열 때·1분 넘게 나갔다 올 때 지문·얼굴 또는 기기 PIN·패턴으로 확인 */
final class Lock {
    private Lock() { }
    static final int RQ = 12;
    static final long GRACE_MS = 60000L;

    interface Done { void result(boolean ok); }

    static boolean on(Context c) { return Prefs.on(c, "lock"); }

    /** 기기에 화면 잠금(PIN·패턴·비밀번호)이 있어야 쓸 수 있다 */
    static boolean available(Context c) {
        KeyguardManager km = (KeyguardManager) c.getSystemService(Context.KEYGUARD_SERVICE);
        return km != null && km.isDeviceSecure();
    }

    /** 확인 창을 띄운다. 28 미만·생체 창을 못 띄우는 기기는 기기 잠금 확인 화면(onActivityResult 의 RQ) */
    static void prompt(Activity a, Done d) {
        if (!available(a)) { d.result(true); return; }                 // 기기 잠금을 지운 경우 — 막아 둘 방법이 없으므로 통과(설정 화면에 안내)
        if (Build.VERSION.SDK_INT >= 28) {
            try { Api28.show(a, d); return; } catch (Throwable ignored) { }
        }
        credential(a, d);
    }

    @SuppressWarnings("deprecation")
    static void credential(Activity a, Done d) {
        try {
            KeyguardManager km = (KeyguardManager) a.getSystemService(Context.KEYGUARD_SERVICE);
            Intent i = km.createConfirmDeviceCredentialIntent("VCF AIops", "잠금을 해제하세요");
            if (i == null) { d.result(true); return; }
            a.startActivityForResult(i, RQ);
        } catch (Exception e) { d.result(false); }
    }

    /** android.hardware.biometrics.BiometricPrompt(API 28+) — 따로 둔 클래스라 낮은 버전에서는 읽히지 않는다 */
    private static final class Api28 {
        @SuppressWarnings("deprecation")
        static void show(final Activity a, final Done d) {
            android.hardware.biometrics.BiometricPrompt.Builder b = new android.hardware.biometrics.BiometricPrompt.Builder(a)
                    .setTitle("VCF AIops").setSubtitle("잠금을 해제하세요");
            if (Build.VERSION.SDK_INT >= 30) b.setAllowedAuthenticators(0x000000FF | 0x00008000);     // BIOMETRIC_WEAK | DEVICE_CREDENTIAL
            else if (Build.VERSION.SDK_INT == 29) b.setDeviceCredentialAllowed(true);
            else b.setNegativeButton("PIN·패턴 사용", a.getMainExecutor(), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface x, int w) { credential(a, d); } });
            b.build().authenticate(new CancellationSignal(), a.getMainExecutor(), new android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                @Override public void onAuthenticationSucceeded(android.hardware.biometrics.BiometricPrompt.AuthenticationResult r) { d.result(true); }
                @Override public void onAuthenticationError(int code, CharSequence msg) { d.result(false); }
            });
        }
    }
}
