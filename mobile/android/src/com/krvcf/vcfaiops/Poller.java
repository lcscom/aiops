package com.krvcf.vcfaiops;

import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

/** 서버 알림 피드 확인(15분마다 PollJob, 앱을 열 때, '지금 확인') → 알림 표시 */
final class Poller {
    private Poller() { }
    static final int JOB = 1;

    static void schedule(Context c) {
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (Prefs.server(c).isEmpty() || Prefs.token(c).isEmpty()) { js.cancel(JOB); return; }
        long min = Math.max(15, Prefs.getLong(c, "poll_min"));
        JobInfo cur = js.getPendingJob(JOB);
        if (cur != null && cur.getIntervalMillis() == min * 60000L) return;        // 이미 같은 주기로 예약됨
        js.schedule(new JobInfo.Builder(JOB, new ComponentName(c, PollJob.class)).setPeriodic(min * 60000L)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY).setPersisted(true).build());
    }

    /** @return 사용자에게 보여 줄 결과 한 줄 */
    static String poll(Context c) { return poll(c, 0); }

    /** 마지막 확인이 성공했는지(실시간 연결이 재시도 간격을 정할 때) */
    static volatile boolean lastOk;

    /** @param wait 0 = 바로 응답, 그 외 = 새 알림이 생길 때까지 서버가 기다려 주는 시간(초, 실시간 연결) */
    static String poll(Context c, int wait) {
        lastOk = false;
        if (Prefs.server(c).isEmpty()) return "서버 주소가 없습니다";
        if (Prefs.token(c).isEmpty()) return "기기가 연결되지 않았습니다 — 포털 › 모바일 앱에서 '이 기기 연결'";
        Net.Res r;
        final long since = Prefs.getLong(c, "cursor");
        try {
            r = Net.call(c, "/api/mobile/feed?since=" + since + "&app=" + Prefs.versionCode(c) + (wait > 0 ? "&wait=" + wait : ""),
                    "GET", null, true, wait > 0 ? (wait + 20) * 1000 : 0);
        } catch (Exception e) {
            Prefs.putLong(c, "fails", Prefs.getLong(c, "fails") + 1);
            return "확인 실패: " + e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " " + e.getMessage());
        }
        return handle(c, r, since);
    }

    private static synchronized String handle(Context c, Net.Res r, long since) {
        try {
            if (r.code == 401) {                                               // 토큰 폐기·만료
                Prefs.remove(c, "token", "device");
                schedule(c);
                LiveService.sync(c);
                Notifier.show(c, 900001, Notifier.CH_STATE, "기기 연결이 해제되었습니다", "포털 › 모바일 앱에서 '이 기기 연결'을 다시 누르세요.", "mobile", false);
                return "기기 연결이 해제되었습니다";
            }
            if (r.code != 200 || !r.json()) {                                  // Cloudflare Access 로그인 화면·점검 등
                long f = Prefs.getLong(c, "fails") + 1;
                Prefs.putLong(c, "fails", f);
                if (f == 4) Notifier.show(c, 900002, Notifier.CH_STATE, "알림을 확인할 수 없습니다",
                        "서버 로그인(Cloudflare Access)이 만료되었거나 서버에 닿지 않습니다. 앱을 열어 다시 로그인하세요.", "", false);
                return "서버 응답 " + r.code + (r.location.isEmpty() ? "" : " → 로그인 필요");
            }
            Prefs.putLong(c, "fails", 0);
            Prefs.putLong(c, "last_ok", System.currentTimeMillis());
            lastOk = true;
            long seen = Prefs.getLong(c, "cursor");
            JSONObject j = new JSONObject(r.body);
            JSONObject srv = j.optJSONObject("server");
            if (srv != null) Prefs.put(c, "server_ver", srv.optString("version"));
            long poll = j.optLong("poll", 900) / 60;
            if (poll != Prefs.getLong(c, "poll_min")) { Prefs.putLong(c, "poll_min", poll); schedule(c); }
            JSONArray ev = j.optJSONArray("events");
            int n = 0;
            for (int i = 0; ev != null && i < ev.length(); i++) {
                JSONObject e = ev.getJSONObject(i);
                if (e.optLong("id") <= seen) continue;                         // 다른 확인(주기·실시간)이 먼저 보여 준 알림
                String kind = e.optString("kind");
                Notifier.show(c, (int) (e.optLong("id") % 800000), "update".equals(kind) || "test".equals(kind) ? Notifier.CH_UPDATE : Notifier.CH_ALERT,
                        e.optString("title"), e.optString("body"), e.optString("view"), false);
                n++;
            }
            long cur = j.optLong("cursor", seen);
            if (cur > seen || cur < since) Prefs.putLong(c, "cursor", cur);    // 요청한 값보다 작게 오는 것은 서버 DB 를 새로 만든 경우뿐
            JSONObject br = j.optJSONObject("brief");
            if (br != null && br.has("inc")) {                                 // 홈 화면 위젯 값
                Prefs.putLong(c, "w_inc", br.optLong("inc"));
                Prefs.putLong(c, "w_crit", br.optLong("inc_crit"));
                Prefs.putLong(c, "w_open", br.optLong("inc_open"));
                Prefs.putLong(c, "w_ts", System.currentTimeMillis());
                StatusWidget.render(c);
            }
            JSONObject app = j.optJSONObject("app");
            if (app != null && app.optInt("code") > Prefs.versionCode(c)) {
                Prefs.put(c, "app_sha", app.optString("sha256"));
                Prefs.put(c, "app_name", app.optString("name"));
                Prefs.putLong(c, "app_code", app.optInt("code"));
                if (Prefs.getLong(c, "app_notified") != app.optInt("code")) {
                    Prefs.putLong(c, "app_notified", app.optInt("code"));
                    Notifier.show(c, 900003, Notifier.CH_UPDATE, "앱 새 버전 " + app.optString("name"), "눌러서 업데이트하세요(서버에서 내려받아 설치).", "", true);
                }
            } else {
                Prefs.remove(c, "app_sha", "app_name", "app_code");
            }
            return "확인 완료 — 새 알림 " + n + "건 · 서버 " + Prefs.get(c, "server_ver");
        } catch (Exception e) {
            Prefs.putLong(c, "fails", Prefs.getLong(c, "fails") + 1);
            return "확인 실패: " + e.getClass().getSimpleName() + (e.getMessage() == null ? "" : " " + e.getMessage());
        }
    }
}
