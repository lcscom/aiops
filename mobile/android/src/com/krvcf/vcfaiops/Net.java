package com.krvcf.vcfaiops;

import android.content.Context;
import android.webkit.CookieManager;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** 서버 호출 — 기기 토큰(Bearer) + WebView 쿠키(Cloudflare Access 세션) + 사설 인증서 지문 고정 */
final class Net {
    private Net() { }

    static final class Res {
        int code; String body = ""; String type = ""; String location = "";
        boolean json() { return type.contains("json"); }
    }

    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }

    static String sha256(byte[] b) { try { return hex(MessageDigest.getInstance("SHA-256").digest(b)); } catch (Exception e) { return ""; } }

    static String pin(Context c, String host) { return Prefs.get(c, "pin:" + host); }

    static HttpURLConnection open(Context c, String url, String method, boolean withToken) throws Exception {
        URL u = new URL(url);
        HttpURLConnection h = (HttpURLConnection) u.openConnection();
        final String host = u.getHost().toLowerCase(java.util.Locale.ROOT);
        final String pin = pin(c, host);
        if (h instanceof HttpsURLConnection && !pin.isEmpty()) {            // 사용자가 지문을 보고 신뢰한 사설 인증서만 허용
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] ch, String t) throws CertificateException { throw new CertificateException("client"); }
                public void checkServerTrusted(X509Certificate[] ch, String t) throws CertificateException {
                    if (ch == null || ch.length == 0 || !pin.equals(sha256(ch[0].getEncoded()))) throw new CertificateException("인증서 지문이 다릅니다");
                }
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            ((HttpsURLConnection) h).setSSLSocketFactory(ctx.getSocketFactory());
            ((HttpsURLConnection) h).setHostnameVerifier(new HostnameVerifier() {
                public boolean verify(String hn, SSLSession s) { return host.equalsIgnoreCase(hn); }
            });
        }
        h.setRequestMethod(method);
        h.setConnectTimeout(15000);
        h.setReadTimeout(30000);
        h.setInstanceFollowRedirects(false);
        h.setRequestProperty("Accept", "application/json");
        h.setRequestProperty("X-Requested-With", "aiops");
        h.setRequestProperty("User-Agent", "VCFAIopsApp/" + Prefs.versionName(c) + " (Android " + android.os.Build.VERSION.RELEASE + ")");
        if (withToken && !Prefs.token(c).isEmpty()) h.setRequestProperty("Authorization", "Bearer " + Prefs.token(c));
        try {
            String ck = CookieManager.getInstance().getCookie(url);
            if (ck != null && !ck.isEmpty()) h.setRequestProperty("Cookie", ck);
        } catch (Throwable ignored) { }
        return h;
    }

    static byte[] readAll(InputStream in, int max) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) { o.write(buf, 0, n); if (o.size() > max) throw new Exception("응답이 너무 큽니다"); }
        return o.toByteArray();
    }

    static Res call(Context c, String path, String method, String jsonBody, boolean withToken) throws Exception {
        return call(c, path, method, jsonBody, withToken, 0);
    }

    static Res call(Context c, String path, String method, String jsonBody, boolean withToken, int readTimeoutMs) throws Exception {
        HttpURLConnection h = open(c, Prefs.server(c) + path, method, withToken);
        if (readTimeoutMs > 0) h.setReadTimeout(readTimeoutMs);
        try {
            if (jsonBody != null) {
                h.setDoOutput(true);
                h.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                OutputStream os = h.getOutputStream();
                os.write(jsonBody.getBytes("UTF-8"));
                os.close();
            }
            Res r = new Res();
            r.code = h.getResponseCode();
            r.type = h.getContentType() == null ? "" : h.getContentType().toLowerCase(java.util.Locale.ROOT);
            r.location = h.getHeaderField("Location") == null ? "" : h.getHeaderField("Location");
            InputStream in = r.code >= 400 ? h.getErrorStream() : h.getInputStream();
            if (in != null) { r.body = new String(readAll(in, 2 * 1024 * 1024), "UTF-8"); in.close(); }
            return r;
        } finally { h.disconnect(); }
    }
}
