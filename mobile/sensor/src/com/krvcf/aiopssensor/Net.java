package com.krvcf.aiopssensor;

import android.content.Context;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Locale;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** 서버 호출 — 장치 토큰(Bearer) + 사설 인증서는 사용자가 지문을 보고 신뢰한 것만(지문 고정) */
final class Net {
    private Net() { }

    static final class Res { int code; String body = ""; }

    static String hex(byte[] b) { StringBuilder s = new StringBuilder(); for (byte x : b) s.append(String.format("%02x", x & 0xff)); return s.toString(); }
    static String sha256(byte[] b) { try { return hex(MessageDigest.getInstance("SHA-256").digest(b)); } catch (Exception e) { return ""; } }

    static HttpURLConnection open(Context c, String url, String method) throws Exception {
        URL u = new URL(url);
        HttpURLConnection h = (HttpURLConnection) u.openConnection();
        final String host = u.getHost().toLowerCase(Locale.ROOT);
        final String pin = Prefs.get(c, "pin:" + host);
        if (h instanceof HttpsURLConnection && !pin.isEmpty()) {
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
        h.setRequestProperty("User-Agent", "VCFAIopsSensor/" + Prefs.versionName(c) + " (Android " + android.os.Build.VERSION.RELEASE + ")");
        String t = Prefs.token(c);
        if (!t.isEmpty()) h.setRequestProperty("Authorization", "Bearer " + t);
        return h;
    }

    /** 사설 인증서 지문 읽기(신뢰 확인용 — 이 연결로는 아무것도 보내지 않음) */
    static String peekCert(String url) throws Exception {
        URL u = new URL(url);
        HttpsURLConnection h = (HttpsURLConnection) u.openConnection();
        final String[] fp = {""};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] ch, String t) throws CertificateException { throw new CertificateException("client"); }
            public void checkServerTrusted(X509Certificate[] ch, String t) throws CertificateException {
                if (ch != null && ch.length > 0) fp[0] = sha256(ch[0].getEncoded());
                throw new CertificateException("peek");
            }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        h.setSSLSocketFactory(ctx.getSocketFactory());
        h.setConnectTimeout(10000);
        try { h.connect(); } catch (Exception ignored) { } finally { h.disconnect(); }
        return fp[0];
    }

    static byte[] readAll(InputStream in, int max) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) { o.write(buf, 0, n); if (o.size() > max) throw new Exception("응답이 너무 큽니다"); }
        return o.toByteArray();
    }

    static Res send(Context c, String path, String method, byte[] body, String type) throws Exception {
        HttpURLConnection h = open(c, Prefs.server(c) + path, method);
        try {
            if (body != null) {
                h.setDoOutput(true);
                h.setFixedLengthStreamingMode(body.length);
                h.setRequestProperty("Content-Type", type);
                OutputStream os = h.getOutputStream();
                os.write(body);
                os.close();
            }
            Res r = new Res();
            r.code = h.getResponseCode();
            InputStream in = r.code >= 400 ? h.getErrorStream() : h.getInputStream();
            if (in != null) { r.body = new String(readAll(in, 512 * 1024), "UTF-8"); in.close(); }
            return r;
        } finally { h.disconnect(); }
    }

    static Res json(Context c, String path, String json) throws Exception {
        return send(c, path, "POST", json.getBytes("UTF-8"), "application/json; charset=utf-8");
    }
}
