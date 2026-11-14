package com.krvcf.vcfaiops;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** 홈 화면 위젯 — 진행 중 인시던트·심각·미접수 수와 서버 버전. 값은 알림 확인 응답에 함께 온 것을 쓴다(따로 통신하지 않음) */
public class StatusWidget extends AppWidgetProvider {
    @Override public void onUpdate(final Context c, AppWidgetManager m, int[] ids) {
        render(c);
        final PendingResult pr = goAsync();                             // 30분마다: 이참에 새 값도 받아 온다
        new Thread(new Runnable() { public void run() {
            try { Poller.poll(c.getApplicationContext()); } catch (Exception ignored) { }
            try { pr.finish(); } catch (Exception ignored) { }
        } }, "aiops-widget").start();
    }

    static void render(Context c) {
        try {
            AppWidgetManager m = AppWidgetManager.getInstance(c);
            int[] ids = m.getAppWidgetIds(new ComponentName(c, StatusWidget.class));
            if (ids == null || ids.length == 0) return;
            RemoteViews v = new RemoteViews(c.getPackageName(), R.layout.widget);
            long ts = Prefs.getLong(c, "w_ts");
            boolean paired = !Prefs.token(c).isEmpty();
            if (!paired || ts == 0) {
                v.setTextViewText(R.id.w_num, "–");
                v.setTextViewText(R.id.w_sub, paired ? "아직 받은 값이 없습니다" : "앱에서 기기를 연결하세요");
                v.setTextViewText(R.id.w_extra, "");
                v.setTextViewText(R.id.w_time, "");
            } else {
                long inc = Prefs.getLong(c, "w_inc"), crit = Prefs.getLong(c, "w_crit"), open = Prefs.getLong(c, "w_open");
                v.setTextViewText(R.id.w_num, String.valueOf(inc));
                v.setTextColor(R.id.w_num, crit > 0 ? 0xFFFF8A75 : inc > 0 ? 0xFFFFC966 : 0xFF8BD58B);
                v.setTextViewText(R.id.w_sub, "진행 중 인시던트 · 심각 " + crit + " · 미접수 " + open);
                String ver = Prefs.get(c, "server_ver");
                v.setTextViewText(R.id.w_extra, ver.isEmpty() ? "" : "서버 " + ver);
                boolean stale = System.currentTimeMillis() - ts > 3600000L;
                v.setTextViewText(R.id.w_time, (stale ? "오래된 값 " : "") + new SimpleDateFormat("HH:mm", Locale.getDefault()).format(new Date(ts)));
            }
            Intent i = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP).putExtra("view", "mhome").setAction("widget");
            v.setOnClickPendingIntent(R.id.w_root, PendingIntent.getActivity(c, 900020, i, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE));
            m.updateAppWidget(ids, v);
        } catch (Exception ignored) { }
    }
}
