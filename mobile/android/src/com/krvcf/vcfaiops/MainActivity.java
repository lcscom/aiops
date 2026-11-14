package com.krvcf.vcfaiops;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.ActivityNotFoundException;
import android.content.ContentValues;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.Uri;
import android.net.http.SslCertificate;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.text.InputType;
import android.util.Base64;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.JavascriptInterface;
import android.webkit.SslErrorHandler;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;

/** 포털 화면(WebView) + 처음 연결 화면. 기기 연결(알림용 토큰)·앱 업데이트·파일 올리기/내려받기는 네이티브로 처리 */
public class MainActivity extends Activity {
    private WebView web;
    private ProgressBar bar;
    private ScrollView setup;
    private LinearLayout errBox;
    private TextView errText;
    private EditText urlIn;
    private ValueCallback<Uri[]> fileCb;
    private volatile String pageHost = "";
    private boolean mainFailed;
    private LinearLayout lockView;
    private boolean unlocked, prompting;
    private long leftAt;

    private int dp(int v) { return (int) (v * getResources().getDisplayMetrics().density + .5f); }

    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        Notifier.channels(this);
        FrameLayout root = new FrameLayout(this);
        root.setFitsSystemWindows(true);
        web = new WebView(this);
        root.addView(web, new FrameLayout.LayoutParams(-1, -1));
        bar = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal);
        bar.setMax(100);
        root.addView(bar, new FrameLayout.LayoutParams(-1, dp(3), Gravity.TOP));
        buildError(root);
        buildSetup(root);
        buildLock(root);
        setContentView(root);
        initWeb();
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                && Prefs.getLong(this, "asked_notify") == 0) {
            Prefs.putLong(this, "asked_notify", 1);
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 7);
        }
        if (!handleIntent(getIntent())) start();
    }

    @Override protected void onNewIntent(Intent i) { super.onNewIntent(i); setIntent(i); handleIntent(i); }

    @Override protected void onStop() { super.onStop(); leftAt = android.os.SystemClock.elapsedRealtime(); }

    // ------------------------------------------------------------------ 앱 잠금
    private void buildLock(FrameLayout root) {
        lockView = new LinearLayout(this);
        lockView.setOrientation(LinearLayout.VERTICAL);
        lockView.setGravity(Gravity.CENTER);
        lockView.setBackgroundColor(0xFF1B2A32);
        lockView.setClickable(true);                                  // 아래 화면으로 터치가 새지 않게
        TextView t = new TextView(this);
        t.setText("VCF AIops");
        t.setTextSize(26);
        t.setTextColor(0xFFFFFFFF);
        t.setGravity(Gravity.CENTER);
        lockView.addView(t);
        TextView d = new TextView(this);
        d.setText("잠겨 있습니다");
        d.setTextColor(0xFFB8C4CC);
        d.setGravity(Gravity.CENTER);
        d.setPadding(0, dp(8), 0, dp(24));
        lockView.addView(d);
        Button b = new Button(this);
        b.setText("잠금 해제");
        b.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { askUnlock(); } });
        lockView.addView(b, new LinearLayout.LayoutParams(-2, -2));
        lockView.setVisibility(View.GONE);
        root.addView(lockView, new FrameLayout.LayoutParams(-1, -1));
    }

    /** 잠금이 켜져 있으면 처음 열 때와 1분 넘게 나갔다 올 때 가린다. 최근 앱 목록·화면 캡처에도 내용이 보이지 않게 한다 */
    private void checkLock() {
        boolean on = Lock.on(this);
        if (on) getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        else getWindow().clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE);
        if (!on) { unlocked = true; lockView.setVisibility(View.GONE); return; }
        if (unlocked && leftAt != 0 && android.os.SystemClock.elapsedRealtime() - leftAt > Lock.GRACE_MS) unlocked = false;
        leftAt = 0;
        if (unlocked) { lockView.setVisibility(View.GONE); return; }
        lockView.setVisibility(View.VISIBLE);
        askUnlock();
    }

    private void askUnlock() {
        if (prompting) return;
        prompting = true;
        Lock.prompt(this, new Lock.Done() { public void result(final boolean ok) {
            runOnUiThread(new Runnable() { public void run() { unlockResult(ok); } });
        } });
    }

    private void unlockResult(boolean ok) {
        prompting = false;
        if (ok) { unlocked = true; lockView.setVisibility(View.GONE); }
    }

    @Override protected void onResume() {
        super.onResume();
        checkLock();
        Poller.schedule(this);
        LiveService.sync(this);
        if (!Prefs.token(this).isEmpty()) new Thread(new Runnable() { public void run() { Poller.poll(getApplicationContext()); } }).start();
    }

    // ------------------------------------------------------------------ 화면 구성
    private void buildSetup(FrameLayout root) {
        setup = new ScrollView(this);
        setup.setBackgroundColor(0xFFFFFFFF);
        setup.setFillViewport(true);
        LinearLayout b = new LinearLayout(this);
        b.setOrientation(LinearLayout.VERTICAL);
        b.setGravity(Gravity.CENTER_HORIZONTAL);
        b.setPadding(dp(28), dp(56), dp(28), dp(28));
        TextView t = new TextView(this);
        t.setText("VCF AIops");
        t.setTextSize(28);
        t.setTextColor(0xFF1B2A32);
        b.addView(t);
        TextView d = new TextView(this);
        d.setText("포털 주소를 입력하세요.\n포털 › 모바일 앱 화면의 QR을 휴대폰 카메라로 찍으면 주소 입력과 기기 연결이 한 번에 됩니다.");
        d.setPadding(0, dp(12), 0, dp(20));
        d.setTextColor(0xFF4A5A67);
        b.addView(d);
        urlIn = new EditText(this);
        urlIn.setHint("https://aiops.example.com");
        urlIn.setSingleLine(true);
        urlIn.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        urlIn.setImeOptions(EditorInfo.IME_ACTION_GO);
        urlIn.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            public boolean onEditorAction(TextView v, int a, KeyEvent e) { connectTyped(); return true; }
        });
        b.addView(urlIn, new LinearLayout.LayoutParams(-1, -2));
        Button go = new Button(this);
        go.setText("연결");
        go.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { connectTyped(); } });
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(12);
        b.addView(go, lp);
        TextView ver = new TextView(this);
        ver.setText("앱 " + Prefs.versionName(this));
        ver.setPadding(0, dp(24), 0, 0);
        ver.setTextColor(0xFF8A96A0);
        b.addView(ver);
        setup.addView(b);
        setup.setVisibility(View.GONE);
        root.addView(setup, new FrameLayout.LayoutParams(-1, -1));
    }

    private void buildError(FrameLayout root) {
        errBox = new LinearLayout(this);
        errBox.setOrientation(LinearLayout.VERTICAL);
        errBox.setGravity(Gravity.CENTER);
        errBox.setBackgroundColor(0xFFFFFFFF);
        errBox.setPadding(dp(28), dp(28), dp(28), dp(28));
        errText = new TextView(this);
        errText.setGravity(Gravity.CENTER);
        errText.setTextColor(0xFF4A5A67);
        errBox.addView(errText);
        Button retry = new Button(this);
        retry.setText("다시 시도");
        retry.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { errBox.setVisibility(View.GONE); start(); } });
        errBox.addView(retry, new LinearLayout.LayoutParams(-2, -2));
        Button st = new Button(this);
        st.setText("앱 설정");
        st.setOnClickListener(new View.OnClickListener() { public void onClick(View v) { startActivity(new Intent(MainActivity.this, SettingsActivity.class)); } });
        errBox.addView(st, new LinearLayout.LayoutParams(-2, -2));
        errBox.setVisibility(View.GONE);
        root.addView(errBox, new FrameLayout.LayoutParams(-1, -1));
    }

    private void connectTyped() {
        String u = Prefs.normalize(urlIn.getText().toString());
        if (u.isEmpty()) { Toast.makeText(this, "주소 형식이 올바르지 않습니다(예: https://aiops.example.com)", Toast.LENGTH_LONG).show(); return; }
        Prefs.put(this, "server", u);
        start();
    }

    private void start() {
        String s = Prefs.server(this);
        if (s.isEmpty()) { setup.setVisibility(View.VISIBLE); return; }
        setup.setVisibility(View.GONE);
        errBox.setVisibility(View.GONE);
        mainFailed = false;
        web.loadUrl(s + "/");
    }

    // ------------------------------------------------------------------ 링크·알림에서 들어옴
    private boolean handleIntent(Intent i) {
        if (i == null) return false;
        if (i.getBooleanExtra("reset", false)) { i.removeExtra("reset"); web.loadUrl("about:blank"); web.clearHistory(); start(); return true; }
        Uri d = i.getData();
        if (d != null && "vcfaiops".equals(d.getScheme()) && "connect".equals(d.getHost())) {
            i.setData(null);
            final String url = Prefs.normalize(d.getQueryParameter("url"));
            final String code = d.getQueryParameter("code") == null ? "" : d.getQueryParameter("code");
            if (url.isEmpty()) { Toast.makeText(this, "연결 링크가 올바르지 않습니다", Toast.LENGTH_LONG).show(); return false; }
            String cur = Prefs.server(this);
            String msg = (cur.isEmpty() || cur.equals(url) ? "" : "지금 서버: " + cur + "\n\n") + "이 서버에 연결할까요?\n" + url
                    + (code.isEmpty() ? "" : "\n\n이 기기를 알림 수신 기기로 등록합니다.") + "\n\n모르는 사람이 보낸 링크라면 취소하세요.";
            new AlertDialog.Builder(this).setTitle("서버 연결").setMessage(msg).setNegativeButton("취소", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface x, int w) { start(); }
            }).setPositiveButton("연결", new DialogInterface.OnClickListener() { public void onClick(DialogInterface x, int w) {
                if (!url.equals(Prefs.server(MainActivity.this))) { Prefs.remove(MainActivity.this, "token", "device", "cursor"); }
                Prefs.put(MainActivity.this, "server", url);
                start();
                if (!code.isEmpty()) pair(code);
            } }).setCancelable(false).show();
            return true;
        }
        if (i.getBooleanExtra("update", false)) { i.removeExtra("update"); start(); Updater.start(this); return true; }
        String view = i.getStringExtra("view");
        if (view != null && view.matches("[A-Za-z0-9_-]{1,40}") && !Prefs.server(this).isEmpty()) {
            i.removeExtra("view");
            setup.setVisibility(View.GONE);
            String base = Prefs.server(this) + "/";
            String cur = web.getUrl();
            // 같은 화면이면 해시만 바뀌어 다시 읽지 않는다(웹의 hashchange 가 메뉴를 연다)
            web.loadUrl(base + "#go=" + view + (cur != null && cur.startsWith(base + "#go=" + view) ? "&t=" + System.currentTimeMillis() : ""));
            return true;
        }
        return false;
    }

    /** 일회용 연결 코드 → 기기 토큰 */
    private void pair(final String code) {
        new Thread(new Runnable() { public void run() {
            String msg;
            try {
                JSONObject b = new JSONObject();
                b.put("code", code);
                b.put("name", Build.MANUFACTURER + " " + Build.MODEL);
                b.put("os", "Android " + Build.VERSION.RELEASE);
                b.put("app", Prefs.versionCode(MainActivity.this));
                Net.Res r = Net.call(MainActivity.this, "/api/mobile/pair", "POST", b.toString(), false);
                if (r.code == 200 && r.json()) {
                    JSONObject j = new JSONObject(r.body);
                    Prefs.setToken(MainActivity.this, j.getString("token"));
                    Prefs.put(MainActivity.this, "device", String.valueOf(j.optInt("device_id")));
                    Prefs.putLong(MainActivity.this, "cursor", j.optLong("cursor"));
                    Prefs.putLong(MainActivity.this, "fails", 0);
                    Poller.schedule(MainActivity.this);
                    LiveService.sync(MainActivity.this);
                    msg = "이 기기를 연결했습니다 — 서버 업데이트·경보 알림을 받습니다";
                } else {
                    String dmsg = "";
                    try { dmsg = new JSONObject(r.body).optString("detail"); } catch (Exception ignored) { }
                    msg = "기기 연결 실패(" + r.code + ")" + (dmsg.isEmpty() ? "" : ": " + dmsg);
                }
            } catch (Exception e) {
                msg = "기기 연결 실패: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
            final String m = msg;
            runOnUiThread(new Runnable() { public void run() {
                Toast.makeText(MainActivity.this, m, Toast.LENGTH_LONG).show();
                web.evaluateJavascript("window.AIOPS_MOBILE&&window.AIOPS_MOBILE.load&&window.AIOPS_MOBILE.load()", null);
            } });
        } }, "aiops-pair").start();
    }

    // ------------------------------------------------------------------ WebView
    private boolean sameHost(String url) { String h = Prefs.host(this); return !h.isEmpty() && h.equals(Prefs.hostOf(url)); }

    private static String certSha(SslError e) {
        try {
            SslCertificate c = e.getCertificate();
            if (Build.VERSION.SDK_INT >= 29) {
                X509Certificate x = c.getX509Certificate();
                return x == null ? "" : Net.sha256(x.getEncoded());
            }
            byte[] der = SslCertificate.saveState(c).getByteArray("x509-certificate");      // Android 8~9
            return der == null ? "" : Net.sha256(der);
        } catch (Throwable t) { return ""; }
    }

    private void initWeb() {
        WebSettings ws = web.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setDatabaseEnabled(true);
        ws.setSupportZoom(true);
        ws.setBuiltInZoomControls(true);
        ws.setDisplayZoomControls(false);
        ws.setAllowFileAccess(false);
        ws.setAllowContentAccess(false);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        ws.setUserAgentString(ws.getUserAgentString() + " VCFAIopsApp/" + Prefs.versionName(this));
        CookieManager.getInstance().setAcceptCookie(true);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, true);          // Cloudflare Access 로그인 왕복
        web.addJavascriptInterface(new Bridge(), "AIOPSApp");
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView v, WebResourceRequest r) {
                Uri u = r.getUrl();
                String sc = u.getScheme() == null ? "" : u.getScheme();
                if (sc.equals("http") || sc.equals("https")) {
                    if (!r.isForMainFrame() || sameHost(u.toString()) || r.isRedirect()) return false;   // 같은 서버·SSO 리디렉션은 앱 안에서
                    String h = u.getHost() == null ? "" : u.getHost();
                    if (h.endsWith(".cloudflareaccess.com") || !r.hasGesture()) return false;
                }
                try { startActivity(new Intent(Intent.ACTION_VIEW, u)); } catch (ActivityNotFoundException ignored) { }
                return true;
            }

            @Override public void onPageStarted(WebView v, String url, Bitmap f) { pageHost = Prefs.hostOf(url); bar.setVisibility(View.VISIBLE); }

            @Override public void onPageFinished(WebView v, String url) {
                bar.setVisibility(View.GONE);
                CookieManager.getInstance().flush();
                if (!mainFailed) errBox.setVisibility(View.GONE);
            }

            @Override public void onReceivedError(WebView v, WebResourceRequest r, WebResourceError e) {
                if (!r.isForMainFrame()) return;
                mainFailed = true;
                errText.setText("서버에 연결할 수 없습니다\n" + Prefs.server(MainActivity.this) + "\n\n" + e.getDescription() + "\n");
                errBox.setVisibility(View.VISIBLE);
            }

            @Override public void onReceivedSslError(WebView v, final SslErrorHandler h, SslError e) {
                final String host = Prefs.hostOf(e.getUrl());
                final String sha = certSha(e);
                String pin = Net.pin(MainActivity.this, host);
                if (!sha.isEmpty() && sha.equals(pin)) { h.proceed(); return; }
                if (sha.isEmpty() || !host.equals(Prefs.host(MainActivity.this))) { h.cancel(); return; }
                String m = (pin.isEmpty() ? "이 서버의 인증서를 기기가 신뢰하지 않습니다(사설·자체 서명 인증서)." : "⚠ 전에 신뢰한 인증서와 다릅니다. 서버 인증서를 바꾼 적이 없다면 취소하세요.")
                        + "\n\n서버: " + host + "\n지문(SHA-256):\n" + sha.replaceAll("(.{16})", "$1\n")
                        + "\n서버 관리자가 알려 준 지문과 같을 때만 신뢰하세요. 같은 지문일 때만 계속 연결합니다.";
                new AlertDialog.Builder(MainActivity.this).setTitle("인증서 확인").setMessage(m).setCancelable(false)
                        .setNegativeButton("취소", new DialogInterface.OnClickListener() { public void onClick(DialogInterface d, int w) { h.cancel(); } })
                        .setPositiveButton("이 서버 신뢰", new DialogInterface.OnClickListener() { public void onClick(DialogInterface d, int w) {
                            Prefs.put(MainActivity.this, "pin:" + host, sha);
                            h.cancel();
                            start();
                        } }).show();
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public void onProgressChanged(WebView v, int p) { bar.setProgress(p); }

            @Override public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams p) {
                if (fileCb != null) fileCb.onReceiveValue(null);
                fileCb = cb;
                try { startActivityForResult(p.createIntent(), 11); } catch (Exception e) { fileCb = null; return false; }
                return true;
            }
        });
        web.setDownloadListener(new DownloadListener() {
            public void onDownloadStart(String url, String ua, String cd, String mime, long len) {
                if (!sameHost(url) || !(url.startsWith("http://") || url.startsWith("https://"))) return;
                if (!Net.pin(MainActivity.this, Prefs.hostOf(url)).isEmpty()) {       // 사설 인증서 서버는 시스템 다운로더가 거부함 → 앱이 직접 받는다
                    fetchAndSave(url, URLUtil.guessFileName(url, cd, mime), mime);
                    return;
                }
                try {
                    DownloadManager.Request rq = new DownloadManager.Request(Uri.parse(url));
                    String ck = CookieManager.getInstance().getCookie(url);
                    if (ck != null) rq.addRequestHeader("Cookie", ck);
                    rq.addRequestHeader("User-Agent", ua);
                    String name = URLUtil.guessFileName(url, cd, mime);
                    rq.setTitle(name);
                    rq.setMimeType(mime);
                    rq.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                    rq.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
                    ((DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE)).enqueue(rq);
                    Toast.makeText(MainActivity.this, "내려받는 중: " + name, Toast.LENGTH_SHORT).show();
                } catch (Exception e) {
                    Toast.makeText(MainActivity.this, "내려받기 실패: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    /** 내려받기 폴더에 저장 — Android 10+ 는 MediaStore, 그 아래는 앱 전용 외부 폴더(권한 불필요) */
    private void saveBytes(String name, String mime, byte[] data) {
        String n = (name == null ? "" : name).replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_");
        if (n.isEmpty() || n.startsWith(".")) n = "vcf-aiops-" + System.currentTimeMillis();
        if (n.length() > 120) n = n.substring(n.length() - 120);
        if (mime == null || mime.isEmpty() || mime.contains("apk") || n.toLowerCase(java.util.Locale.ROOT).endsWith(".apk")) mime = "application/octet-stream";
        String where;
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues v = new ContentValues();
                v.put(MediaStore.MediaColumns.DISPLAY_NAME, n);
                v.put(MediaStore.MediaColumns.MIME_TYPE, mime);
                v.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                Uri u = getContentResolver().insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, v);
                if (u == null) throw new Exception("저장 위치를 만들 수 없습니다");
                OutputStream os = getContentResolver().openOutputStream(u);
                os.write(data); os.close();
                where = "내려받기 폴더";
            } else {
                File d = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (d == null) throw new Exception("저장소를 쓸 수 없습니다");
                FileOutputStream os = new FileOutputStream(new File(d, n));
                os.write(data); os.close();
                where = "Android/data/" + getPackageName() + "/files/Download";
            }
        } catch (Exception e) { toastUi("저장 실패: " + e.getMessage()); return; }
        toastUi("저장함: " + n + " (" + where + ")");
    }

    private void toastUi(final String m) {
        runOnUiThread(new Runnable() { public void run() { Toast.makeText(MainActivity.this, m, Toast.LENGTH_LONG).show(); } });
    }

    private void fetchAndSave(final String url, final String name, final String mime) {
        Toast.makeText(this, "내려받는 중: " + name, Toast.LENGTH_SHORT).show();
        new Thread(new Runnable() { public void run() {
            java.net.HttpURLConnection h = null;
            try {
                h = Net.open(getApplicationContext(), url, "GET", false);
                h.setRequestProperty("Accept", "*/*");
                h.setReadTimeout(120000);
                int code = h.getResponseCode();
                if (code != 200) throw new Exception("HTTP " + code);
                byte[] b = Net.readAll(h.getInputStream(), 64 * 1024 * 1024);
                saveBytes(name, mime, b);
            } catch (Exception e) { toastUi("내려받기 실패: " + e.getMessage()); }
            finally { if (h != null) h.disconnect(); }
        } }).start();
    }

    @Override protected void onActivityResult(int rq, int res, Intent data) {
        if (rq == Lock.RQ) { unlockResult(res == RESULT_OK); return; }
        if (rq == 11 && fileCb != null) {
            fileCb.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(res, data));
            fileCb = null;
        }
    }

    @Override public void onBackPressed() {
        if (lockView.getVisibility() == View.VISIBLE) { moveTaskToBack(true); return; }
        if (setup.getVisibility() == View.VISIBLE || errBox.getVisibility() == View.VISIBLE) { super.onBackPressed(); return; }
        web.evaluateJavascript("(function(){try{return !!(window.AIOPS_MOBILE&&window.AIOPS_MOBILE.back&&window.AIOPS_MOBILE.back())}catch(e){return false}})()",
                new ValueCallback<String>() { public void onReceiveValue(String v) {
                    if ("true".equals(v)) return;                              // 웹이 열린 화면(서랍·메뉴)을 닫음
                    if (web.canGoBack()) web.goBack(); else moveTaskToBack(true);
                } });
    }

    /** 포털 화면(같은 서버일 때만)이 부르는 기능 */
    private final class Bridge {
        private boolean ok() { return !pageHost.isEmpty() && pageHost.equals(Prefs.host(MainActivity.this)) && (unlocked || !Lock.on(MainActivity.this)); }

        @JavascriptInterface public String info() {
            if (!ok()) return "{}";
            try {
                JSONObject j = new JSONObject();
                j.put("app", Prefs.versionName(MainActivity.this));
                j.put("code", Prefs.versionCode(MainActivity.this));
                j.put("paired", !Prefs.token(MainActivity.this).isEmpty());
                j.put("device", Prefs.get(MainActivity.this, "device"));
                j.put("notify", Notifier.enabled(MainActivity.this));
                j.put("lock", Lock.on(MainActivity.this));
                j.put("live", Prefs.on(MainActivity.this, "live"));
                j.put("secure_store", !Prefs.get(MainActivity.this, "token_e").isEmpty());
                j.put("last_ok", Prefs.getLong(MainActivity.this, "last_ok"));
                j.put("update", Prefs.getLong(MainActivity.this, "app_code") > Prefs.versionCode(MainActivity.this));
                return j.toString();
            } catch (Exception e) { return "{}"; }
        }

        @JavascriptInterface public void pair(String code) { if (ok() && code != null && code.matches("[A-Za-z0-9_-]{16,80}")) MainActivity.this.pair(code); }

        /** 화면에서 만든 파일(CSV 등) 저장 — WebView 는 blob: 내려받기를 못 한다 */
        @JavascriptInterface public boolean saveFile(String name, String b64, String mime) {
            if (!ok() || b64 == null || b64.length() > 28 * 1024 * 1024) return false;
            final byte[] data;
            try { data = Base64.decode(b64, Base64.DEFAULT); } catch (Exception e) { return false; }
            final String n = name, m = mime;
            new Thread(new Runnable() { public void run() { saveBytes(n, m, data); } }).start();
            return true;
        }

        @JavascriptInterface public void openSettings() { if (ok()) startActivity(new Intent(MainActivity.this, SettingsActivity.class)); }

        @JavascriptInterface public void installUpdate() {
            if (!ok()) return;
            new Thread(new Runnable() { public void run() {
                Poller.poll(getApplicationContext());
                runOnUiThread(new Runnable() { public void run() { Updater.start(MainActivity.this); } });
            } }).start();
        }

        @JavascriptInterface public void checkNow() {
            if (!ok()) return;
            new Thread(new Runnable() { public void run() {
                final String r = Poller.poll(getApplicationContext());
                runOnUiThread(new Runnable() { public void run() { Toast.makeText(MainActivity.this, r, Toast.LENGTH_LONG).show(); } });
            } }).start();
        }
    }
}
