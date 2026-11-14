package com.krvcf.vcfaiops;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/** 실시간 알림(선택) — 서버에 연결을 열어 두고 새 알림이 생기면 바로 받는다(long-poll). 상단에 고정 알림이 보인다.
 *  끄면 15분 주기 확인(PollJob)만 쓴다. 배터리 최적화가 걸려 있으면 화면이 꺼진 뒤 늦어질 수 있다. */
public class LiveService extends Service implements Runnable {
    static final int ID = 900010;
    private volatile boolean running;
    private Thread th;

    static boolean wanted(Context c) { return Prefs.on(c, "live") && !Prefs.token(c).isEmpty() && !Prefs.server(c).isEmpty(); }

    /** 설정·연결 상태에 맞춰 켜거나 끈다. 백그라운드에서 시작이 막히면(안드로이드 12+) 다음에 앱을 열 때 다시 시도 */
    static void sync(Context c) {
        Context a = c.getApplicationContext();
        Intent i = new Intent(a, LiveService.class);
        try {
            if (wanted(a)) a.startForegroundService(i); else a.stopService(i);
        } catch (Exception ignored) { }
    }

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent i, int flags, int startId) {
        Notifier.channels(this);
        PendingIntent pi = PendingIntent.getActivity(this, ID, new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification n = new Notification.Builder(this, Notifier.CH_LIVE).setSmallIcon(R.drawable.ic_stat).setContentTitle("실시간 알림 연결 중")
                .setContentText(Prefs.host(this)).setOngoing(true).setContentIntent(pi).setShowWhen(false).build();
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(ID, n, 0x40000000);          // FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            else startForeground(ID, n);
        } catch (Exception e) { stopSelf(); return START_NOT_STICKY; }
        if (!wanted(this)) { stopForeground(true); stopSelf(); return START_NOT_STICKY; }
        if (th == null || !th.isAlive()) {
            running = true;
            th = new Thread(this, "aiops-live");
            th.start();
        }
        return START_STICKY;
    }

    public void run() {
        long backoff = 5000L;
        while (running) {
            if (!wanted(this)) break;
            Poller.poll(getApplicationContext(), 50);
            if (!running) break;
            if (Poller.lastOk) { backoff = 5000L; continue; }
            try { Thread.sleep(backoff); } catch (InterruptedException e) { break; }
            backoff = Math.min(backoff * 2, 300000L);                                    // 실패가 이어지면 5초 → 최대 5분 간격
        }
        running = false;
        try { stopForeground(true); } catch (Exception ignored) { }
        stopSelf();
    }

    @Override public void onDestroy() {
        running = false;
        if (th != null) th.interrupt();
        super.onDestroy();
    }
}
