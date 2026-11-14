package com.krvcf.vcfaiops;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.webkit.CookieManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** 앱 설정 — 서버 주소, 기기 연결, 알림 권한, 지금 확인, 신뢰한 인증서 */
public class SettingsActivity extends Activity {
    private TextView info;
    private Button lockBtn, liveBtn;

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + .5f); }

    private Button btn(LinearLayout root, String t, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        root.addView(b, new LinearLayout.LayoutParams(-1, -2));
        return b;
    }

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        ScrollView sv = new ScrollView(this);
        sv.setFitsSystemWindows(true);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(20), dp(20), dp(20));
        sv.addView(root);
        TextView h = new TextView(this);
        h.setText("앱 설정");
        h.setTextSize(22);
        root.addView(h);
        info = new TextView(this);
        info.setPadding(0, dp(12), 0, dp(16));
        info.setTextIsSelectable(true);
        root.addView(info);
        btn(root, "지금 알림 확인", new View.OnClickListener() { public void onClick(View v) {
            new Thread(new Runnable() { public void run() {
                final String r = Poller.poll(getApplicationContext());
                runOnUiThread(new Runnable() { public void run() { Toast.makeText(SettingsActivity.this, r, Toast.LENGTH_LONG).show(); refresh(); } });
            } }).start();
        } });
        liveBtn = btn(root, "", new View.OnClickListener() { public void onClick(View v) {
            if (Prefs.on(SettingsActivity.this, "live")) { Prefs.putLong(SettingsActivity.this, "live", 0); LiveService.sync(SettingsActivity.this); refresh(); return; }
            new AlertDialog.Builder(SettingsActivity.this).setTitle("실시간 알림").setMessage("서버에 연결을 열어 두고 새 알림을 바로 받습니다(보통 몇 초 안).\n\n· 상단에 '실시간 알림 연결 중' 고정 알림이 보입니다.\n· 15분 주기 확인보다 배터리를 더 씁니다.\n· 화면이 꺼진 뒤에도 바로 받으려면 '배터리 사용 제한 없음'으로 두세요.")
                    .setNegativeButton("취소", null).setNeutralButton("배터리 설정", new DialogInterface.OnClickListener() { public void onClick(DialogInterface d, int w) {
                        try { startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)); } catch (Exception e) { Toast.makeText(SettingsActivity.this, "설정 화면을 열 수 없습니다", Toast.LENGTH_SHORT).show(); }
                    } }).setPositiveButton("켜기", new DialogInterface.OnClickListener() { public void onClick(DialogInterface d, int w) {
                        if (Prefs.token(SettingsActivity.this).isEmpty()) { Toast.makeText(SettingsActivity.this, "먼저 기기를 연결하세요(포털 › 모바일 앱)", Toast.LENGTH_LONG).show(); return; }
                        Prefs.putLong(SettingsActivity.this, "live", 1);
                        LiveService.sync(SettingsActivity.this);
                        refresh();
                    } }).show();
        } });
        lockBtn = btn(root, "", new View.OnClickListener() { public void onClick(View v) {
            if (Lock.on(SettingsActivity.this)) { Prefs.putLong(SettingsActivity.this, "lock", 0); refresh(); return; }
            if (!Lock.available(SettingsActivity.this)) {
                Toast.makeText(SettingsActivity.this, "기기에 화면 잠금(PIN·패턴·지문)을 먼저 설정하세요", Toast.LENGTH_LONG).show();
                try { startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS)); } catch (Exception ignored) { }
                return;
            }
            Prefs.putLong(SettingsActivity.this, "lock", 1);
            Toast.makeText(SettingsActivity.this, "앱 잠금을 켰습니다 — 앱을 열 때와 1분 넘게 나갔다 올 때 확인합니다", Toast.LENGTH_LONG).show();
            refresh();
        } });
        btn(root, "알림 설정 열기(권한·소리·채널)", new View.OnClickListener() { public void onClick(View v) {
            startActivity(new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName()));
        } });
        btn(root, "앱 업데이트 확인·설치", new View.OnClickListener() { public void onClick(View v) {
            new Thread(new Runnable() { public void run() {
                Poller.poll(getApplicationContext());
                runOnUiThread(new Runnable() { public void run() { refresh(); Updater.start(SettingsActivity.this); } });
            } }).start();
        } });
        btn(root, "기기 연결 해제(알림 중지)", new View.OnClickListener() { public void onClick(View v) {
            Prefs.remove(SettingsActivity.this, "token", "device", "cursor");
            Poller.schedule(SettingsActivity.this);
            LiveService.sync(SettingsActivity.this);
            Toast.makeText(SettingsActivity.this, "연결을 해제했습니다. 포털 › 모바일 앱에서 기기도 지우면 토큰이 폐기됩니다.", Toast.LENGTH_LONG).show();
            refresh();
        } });
        btn(root, "서버 바꾸기(로그인·신뢰 인증서 지움)", new View.OnClickListener() { public void onClick(View v) {
            new AlertDialog.Builder(SettingsActivity.this).setTitle("서버 바꾸기").setMessage("서버 주소·기기 연결·로그인 쿠키·신뢰한 인증서를 지우고 처음 화면으로 돌아갑니다.")
                    .setNegativeButton("취소", null).setPositiveButton("지우기", new DialogInterface.OnClickListener() { public void onClick(DialogInterface d, int w) {
                        Prefs.clearAll(SettingsActivity.this);
                        LiveService.sync(SettingsActivity.this);
                        CookieManager.getInstance().removeAllCookies(null);
                        Poller.schedule(SettingsActivity.this);
                        startActivity(new Intent(SettingsActivity.this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("reset", true));
                        finish();
                    } }).show();
        } });
        btn(root, "닫기", new View.OnClickListener() { public void onClick(View v) { finish(); } });
        setContentView(sv);
    }

    @Override protected void onResume() { super.onResume(); refresh(); }

    private void refresh() {
        boolean live = Prefs.on(this, "live"), lock = Lock.on(this);
        liveBtn.setText(live ? "실시간 알림 끄기(15분 주기로)" : "실시간 알림 켜기(바로 받기)");
        lockBtn.setText(lock ? "앱 잠금 끄기" : "앱 잠금 켜기(지문·얼굴·PIN)");
        if (lock) getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        long ok = Prefs.getLong(this, "last_ok");
        String host = Prefs.host(this);
        String pin = Net.pin(this, host);
        info.setText("서버: " + (Prefs.server(this).isEmpty() ? "(없음)" : Prefs.server(this))
                + "\n서버 버전: " + (Prefs.get(this, "server_ver").isEmpty() ? "-" : Prefs.get(this, "server_ver"))
                + "\n기기 연결: " + (Prefs.token(this).isEmpty() ? "안 됨 — 포털 › 모바일 앱에서 '이 기기 연결'" : "연결됨(기기 " + Prefs.get(this, "device") + ")")
                + "\n알림 권한: " + (Notifier.enabled(this) ? "허용" : "꺼짐")
                + "\n알림 받기: " + (live ? "실시간(연결 유지)" : Math.max(15, Prefs.getLong(this, "poll_min")) + "분마다 확인")
                + "\n앱 잠금: " + (lock ? (Lock.available(this) ? "켬" : "켬 — 기기 화면 잠금이 없어 동작하지 않음") : "끔")
                + "\n토큰 보관: " + (Prefs.token(this).isEmpty() ? "-" : Prefs.get(this, "token_e").isEmpty() ? "일반 저장" : "기기 보안 저장소(Keystore) 암호화")
                + "\n마지막 확인: " + (ok == 0 ? "-" : new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(new Date(ok)))
                + (pin.isEmpty() ? "" : "\n신뢰한 사설 인증서 지문(SHA-256): " + pin)
                + "\n앱 버전: " + Prefs.versionName(this) + " (" + Prefs.versionCode(this) + ")"
                + (Prefs.getLong(this, "app_code") > Prefs.versionCode(this) ? "\n새 버전 있음: " + Prefs.get(this, "app_name") : ""));
    }
}
