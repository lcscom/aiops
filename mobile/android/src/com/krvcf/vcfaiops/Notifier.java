package com.krvcf.vcfaiops;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

/** 알림 채널 4종(서버·앱 업데이트 / 경보 / 연결 상태 / 실시간 연결 고정 표시)과 알림 표시 */
final class Notifier {
    private Notifier() { }
    static final String CH_UPDATE = "updates", CH_ALERT = "alerts", CH_STATE = "state", CH_LIVE = "live";

    static void channels(Context c) {
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel u = new NotificationChannel(CH_UPDATE, "서버·앱 업데이트", NotificationManager.IMPORTANCE_DEFAULT);
        u.setDescription("서버 패키지가 새 버전으로 패치되었거나 앱 새 버전이 있을 때");
        NotificationChannel a = new NotificationChannel(CH_ALERT, "경보(위험 이상 징후·DR·백업·성능)", NotificationManager.IMPORTANCE_HIGH);
        a.setDescription("포털에서 고른 종류의 경보");
        NotificationChannel s = new NotificationChannel(CH_STATE, "연결 상태", NotificationManager.IMPORTANCE_LOW);
        s.setDescription("로그인 만료·기기 연결 해제 안내");
        nm.createNotificationChannel(u);
        nm.createNotificationChannel(a);
        nm.createNotificationChannel(s);
        NotificationChannel l = new NotificationChannel(CH_LIVE, "실시간 알림 연결(고정 표시)", NotificationManager.IMPORTANCE_MIN);
        l.setDescription("실시간 알림을 켰을 때 연결이 유지되고 있음을 보여 주는 고정 알림");
        l.setShowBadge(false);
        nm.createNotificationChannel(l);
    }

    static boolean enabled(Context c) {
        return ((NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE)).areNotificationsEnabled();
    }

    static void show(Context c, int id, String channel, String title, String body, String view, boolean update) {
        channels(c);
        Intent i = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        if (view != null && !view.isEmpty()) i.putExtra("view", view);
        if (update) i.putExtra("update", true);
        i.setAction("n" + id);                                     // 알림마다 다른 PendingIntent 가 되게
        PendingIntent pi = PendingIntent.getActivity(c, id, i, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = new Notification.Builder(c, channel).setSmallIcon(R.drawable.ic_stat).setContentTitle(title)
                .setContentText(body).setStyle(new Notification.BigTextStyle().bigText(body)).setAutoCancel(true).setContentIntent(pi)
                .setColor(0xFF1A5FBF).setShowWhen(true).setWhen(System.currentTimeMillis());
        try { ((NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE)).notify(id, b.build()); } catch (SecurityException ignored) { }
    }
}
