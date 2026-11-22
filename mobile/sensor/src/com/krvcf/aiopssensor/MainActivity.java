package com.krvcf.aiopssensor;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONObject;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** 등록·권한·시작/정지·상태 화면. 포털의 '현장 센서 › 장치 추가' QR(vcfaiops-sensor://enroll?u=…&c=…)을 폰 카메라로 찍으면 여기로 열린다 */
public class MainActivity extends Activity {
    private EditText server, code;
    private TextView state, values;
    private Button enrollBtn, runBtn;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        int p = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(p, p, p, p);
        TextView title = new TextView(this);
        title.setText("VCF AIops 현장 센서");
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextColor(Color.parseColor("#1B2A32"));
        root.addView(title);
        TextView sub = text("안 쓰는 폰을 전산실·장비실에 두고 온도·습도·소리·진동·위치·사진을 포털로 보냅니다. 충전기에 꽂아 두세요. 소리는 크기만 재고 녹음하지 않습니다.", 13, "#5F6B73");
        root.addView(sub);
        state = text("", 15, "#1B2A32");
        state.setPadding(0, p, 0, dp(8));
        root.addView(state);
        server = edit("서버 주소 (예: https://aiops.example.com)", InputType.TYPE_TEXT_VARIATION_URI);
        server.setText(Prefs.server(this));
        root.addView(server);
        code = edit("등록 코드 (포털 › 현장 센서 › 장치 추가)", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        root.addView(code);
        enrollBtn = button("등록", new View.OnClickListener() { @Override public void onClick(View v) { enroll(); } });
        root.addView(enrollBtn);
        root.addView(button("권한 허용(카메라·마이크·위치·알림)", new View.OnClickListener() { @Override public void onClick(View v) { askPerms(); } }));
        runBtn = button("", new View.OnClickListener() { @Override public void onClick(View v) { toggle(); } });
        root.addView(runBtn);
        root.addView(button("배터리 최적화 제외(꺼지지 않게)", new View.OnClickListener() { @Override public void onClick(View v) { battery(); } }));
        values = text("", 13, "#33424B");
        values.setTypeface(Typeface.MONOSPACE);
        values.setPadding(0, p, 0, 0);
        root.addView(values);
        root.addView(button("등록 해제(이 폰의 토큰 삭제)", new View.OnClickListener() { @Override public void onClick(View v) { forget(); } }));
        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
        handle(getIntent());
        refresh();
        if (!Prefs.token(this).isEmpty()) Watchdog.schedule(this);
    }

    @Override protected void onNewIntent(Intent i) { super.onNewIntent(i); handle(i); }

    @Override protected void onResume() {
        super.onResume();
        if (!Prefs.token(this).isEmpty() && Prefs.getLong(this, "run") == 1L) SensorService.start(this, true);   // 화면에서 다시 켜 카메라·마이크·위치 사용
        tickUi();
    }

    @Override protected void onPause() { super.onPause(); ui.removeCallbacksAndMessages(null); }

    private void tickUi() { refresh(); ui.postDelayed(new Runnable() { @Override public void run() { tickUi(); } }, 3000); }

    /** QR 링크 vcfaiops-sensor://enroll?u=<서버>&c=<코드> */
    private void handle(Intent i) {
        Uri u = i == null ? null : i.getData();
        if (u == null || !"vcfaiops-sensor".equals(u.getScheme())) return;
        String s = u.getQueryParameter("u"), c = u.getQueryParameter("c");
        if (s != null) server.setText(s);
        if (c != null) code.setText(c);
        if (s != null && c != null && Prefs.token(this).isEmpty()) {
            new AlertDialog.Builder(this).setTitle("이 서버에 등록할까요?").setMessage(s)
                    .setPositiveButton("등록", new DialogInterface.OnClickListener() { @Override public void onClick(DialogInterface d, int w) { enroll(); } })
                    .setNegativeButton("취소", null).show();
        }
    }

    private void refresh() {
        boolean enrolled = !Prefs.token(this).isEmpty();
        enrollBtn.setEnabled(!enrolled);
        code.setEnabled(!enrolled);
        server.setEnabled(!enrolled);
        boolean run = SensorService.running;
        runBtn.setText(run ? "측정 멈추기" : "측정 시작");
        runBtn.setEnabled(enrolled);
        StringBuilder st = new StringBuilder();
        if (!enrolled) st.append("등록 전 — 포털에서 장치를 추가하고 QR을 찍거나 코드를 넣으세요.");
        else {
            st.append("장치: ").append(Prefs.get(this, "name")).append(" (").append(Prefs.get(this, "device")).append(")\n");
            st.append(run ? "측정 중" : "멈춤");
            if (SensorService.lastOk > 0) st.append(" · 마지막 전송 ").append(new java.text.SimpleDateFormat("HH:mm:ss", Locale.KOREA).format(new java.util.Date(SensorService.lastOk)));
            if (!SensorService.status.isEmpty()) st.append("\n").append(SensorService.status);
            List<String> miss = missing();
            if (!miss.isEmpty()) st.append("\n권한 없음: ").append(join(miss)).append(" — 해당 센서는 건너뜁니다");
        }
        state.setText(st.toString());
        String v = SensorService.lastValues;
        values.setText(v.isEmpty() ? "이 폰의 센서: " + Collector.available(this).toString().replace("\"", "").replace(",", ", ")
                : v.replace(",\"", "\n\"").replace("\"", "").replace("{", "").replace("}", ""));
    }

    private List<String> missing() {
        List<String> m = new ArrayList<>();
        if (!Collector.has(this, Manifest.permission.CAMERA)) m.add("카메라");
        if (!Collector.has(this, Manifest.permission.RECORD_AUDIO)) m.add("마이크");
        if (!Collector.has(this, Manifest.permission.ACCESS_FINE_LOCATION) && !Collector.has(this, Manifest.permission.ACCESS_COARSE_LOCATION)) m.add("위치");
        return m;
    }

    private static String join(List<String> l) { StringBuilder b = new StringBuilder(); for (String s : l) { if (b.length() > 0) b.append(", "); b.append(s); } return b.toString(); }

    private void askPerms() {
        List<String> p = new ArrayList<>();
        p.add(Manifest.permission.CAMERA);
        p.add(Manifest.permission.RECORD_AUDIO);
        p.add(Manifest.permission.ACCESS_FINE_LOCATION);
        p.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        if (Build.VERSION.SDK_INT >= 33) p.add("android.permission.POST_NOTIFICATIONS");
        requestPermissions(p.toArray(new String[0]), 1);
    }

    @Override public void onRequestPermissionsResult(int rc, String[] p, int[] g) {
        if (SensorService.running) SensorService.start(this, true);            // 새 권한으로 포그라운드 종류 다시 지정
        refresh();
    }

    private void toggle() {
        if (SensorService.running) { Prefs.putLong(this, "run", 0L); SensorService.stop(this); SensorService.running = false; }
        else { Prefs.putLong(this, "run", 1L); SensorService.start(this, true); }
        ui.postDelayed(new Runnable() { @Override public void run() { refresh(); } }, 500);
    }

    private void battery() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        if (pm.isIgnoringBatteryOptimizations(getPackageName())) { toast("이미 제외되어 있습니다"); return; }
        try { startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + getPackageName()))); }
        catch (Exception e) { startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)); }
    }

    private void forget() {
        new AlertDialog.Builder(this).setTitle("등록 해제").setMessage("이 폰의 장치 토큰을 지웁니다. 다시 쓰려면 포털에서 새 등록 코드를 받으세요.")
                .setPositiveButton("해제", new DialogInterface.OnClickListener() { @Override public void onClick(DialogInterface d, int w) {
                    SensorService.stop(MainActivity.this); SensorService.running = false; Prefs.putLong(MainActivity.this, "run", 0L);
                    Prefs.forget(MainActivity.this); SensorService.lastValues = ""; SensorService.status = ""; refresh();
                } }).setNegativeButton("취소", null).show();
    }

    static JSONObject info(Context c) {
        JSONObject o = new JSONObject();
        try {
            o.put("model", Build.MODEL).put("maker", Build.MANUFACTURER).put("android", Build.VERSION.RELEASE).put("app", Prefs.versionName(c))
             .put("sensors", Collector.available(c));
        } catch (Exception ignored) { }
        return o;
    }

    private void enroll() {
        final String s = server.getText().toString().trim().replaceAll("/+$", "");
        final String c = code.getText().toString().trim();
        if (!s.startsWith("http://") && !s.startsWith("https://")) { toast("서버 주소는 http:// 또는 https:// 로 시작해야 합니다"); return; }
        if (c.length() < 6) { toast("등록 코드를 넣으세요"); return; }
        Prefs.put(this, "server", s);
        enrollBtn.setEnabled(false);
        new Thread(new Runnable() { @Override public void run() {
            String err;
            try {
                JSONObject body = new JSONObject().put("code", c).put("info", info(MainActivity.this));
                Net.Res r = Net.json(MainActivity.this, "/api/sensor/enroll", body.toString());
                if (r.code == 200) {
                    JSONObject j = new JSONObject(r.body);
                    if (!Prefs.setToken(MainActivity.this, j.getString("token"))) throw new Exception("이 폰은 Keystore 를 쓸 수 없어 토큰을 안전하게 저장할 수 없습니다");
                    Prefs.put(MainActivity.this, "device", j.optString("device_id"));
                    Prefs.put(MainActivity.this, "name", j.optString("name"));
                    JSONObject cfg = j.optJSONObject("config");
                    if (cfg != null) Prefs.put(MainActivity.this, "config", cfg.toString());
                    Prefs.putLong(MainActivity.this, "info_sent", 0L);
                    Prefs.putLong(MainActivity.this, "run", 1L);
                    ui.post(new Runnable() { @Override public void run() {
                        toast("등록 완료 — 측정을 시작합니다"); askPerms(); SensorService.start(MainActivity.this, true); Watchdog.schedule(MainActivity.this); refresh();
                    } });
                    return;
                }
                String d = r.body;
                try { d = new JSONObject(r.body).optString("detail", r.body); } catch (Exception ignored) { }
                err = "등록 실패(" + r.code + "): " + d;
            } catch (javax.net.ssl.SSLException e) {
                trustPrompt(s);
                return;
            } catch (Exception e) {
                err = "등록 실패: " + e.getClass().getSimpleName() + " " + (e.getMessage() == null ? "" : e.getMessage());
            }
            final String m = err;
            ui.post(new Runnable() { @Override public void run() { toast(m); enrollBtn.setEnabled(true); } });
        } }).start();
    }

    /** 사설 인증서 — 지문을 보여 주고 사용자가 확인하면 이 서버 인증서만 신뢰(포털 › 시스템 › 인증서 지문과 비교) */
    private void trustPrompt(final String s) {
        try {
            final String host = new URL(s).getHost().toLowerCase(Locale.ROOT);
            final String fp = Net.peekCert(s);
            ui.post(new Runnable() { @Override public void run() {
                enrollBtn.setEnabled(true);
                if (fp.isEmpty()) { toast("서버 인증서를 읽지 못했습니다"); return; }
                new AlertDialog.Builder(MainActivity.this).setTitle("사설 인증서").setMessage(host + "\n\nSHA-256\n" + fp.replaceAll("(.{2})(?!$)", "$1:")
                        + "\n\n포털 인증서 지문과 같을 때만 신뢰하세요.")
                        .setPositiveButton("이 서버 신뢰", new DialogInterface.OnClickListener() { @Override public void onClick(DialogInterface d, int w) {
                            Prefs.put(MainActivity.this, "pin:" + host, fp); enroll(); } })
                        .setNegativeButton("취소", null).show();
            } });
        } catch (Exception e) {
            ui.post(new Runnable() { @Override public void run() { enrollBtn.setEnabled(true); toast("인증서 확인 실패"); } });
        }
    }

    private void toast(String m) { android.widget.Toast.makeText(this, m, android.widget.Toast.LENGTH_LONG).show(); }
    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + 0.5f); }

    private TextView text(String t, int size, String color) {
        TextView v = new TextView(this);
        v.setText(t);
        v.setTextSize(size);
        v.setTextColor(Color.parseColor(color));
        return v;
    }

    private EditText edit(String hint, int type) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setSingleLine(true);
        e.setInputType(InputType.TYPE_CLASS_TEXT | type);
        return e;
    }

    private Button button(String t, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(t);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        return b;
    }
}
