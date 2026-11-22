package com.krvcf.aiopssensor;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.security.MessageDigest;

/** 센서 앱 자체 업데이트(2.52.0) — 서버가 알려 준 새 버전을 장치 토큰으로 내려받아 SHA-256 확인 후 설치 화면(사용자 확인 필요) */
final class Updater {
    private Updater() { }
    private static volatile boolean busy;

    static void toast(final Activity a, final String m) {
        a.runOnUiThread(new Runnable() { public void run() { Toast.makeText(a, m, Toast.LENGTH_LONG).show(); } });
    }

    static void start(final Activity a) {
        if (busy) return;
        final String want = SensorService.updateSha;
        if (want.isEmpty()) { toast(a, "새 버전이 없습니다"); return; }
        busy = true;
        toast(a, "새 버전을 내려받는 중…");
        new Thread(new Runnable() { public void run() {
            File f = new File(a.getCacheDir(), "update.apk");
            try {
                HttpURLConnection h = Net.open(a, Prefs.server(a) + "/api/sensor/app.apk", "GET");
                h.setRequestProperty("Accept", "application/vnd.android.package-archive");
                if (h.getResponseCode() != 200) throw new Exception("서버 응답 " + h.getResponseCode());
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                InputStream in = h.getInputStream();
                OutputStream out = new FileOutputStream(f);
                byte[] buf = new byte[65536];
                int n; long total = 0;
                while ((n = in.read(buf)) > 0) { out.write(buf, 0, n); md.update(buf, 0, n); total += n; if (total > 32L * 1024 * 1024) throw new Exception("파일이 너무 큽니다"); }
                out.close(); in.close(); h.disconnect();
                if (!want.equalsIgnoreCase(Net.hex(md.digest()))) throw new Exception("파일 검증 실패(SHA-256 불일치)");
                PackageInstaller pi = a.getPackageManager().getPackageInstaller();
                PackageInstaller.SessionParams sp = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                sp.setAppPackageName(a.getPackageName());
                int sid = pi.createSession(sp);
                PackageInstaller.Session s = pi.openSession(sid);
                OutputStream so = s.openWrite("base.apk", 0, f.length());
                InputStream fi = new FileInputStream(f);
                while ((n = fi.read(buf)) > 0) so.write(buf, 0, n);
                s.fsync(so); so.close(); fi.close();
                Intent cb = new Intent(a, InstallReceiver.class);
                PendingIntent p = PendingIntent.getBroadcast(a, sid, cb, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
                s.commit(p.getIntentSender());
                s.close();
            } catch (Exception e) {
                toast(a, "업데이트 실패: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            } finally {
                busy = false;
                f.delete();
            }
        } }, "sensor-update").start();
    }
}
