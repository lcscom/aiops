package com.krvcf.aiopssensor;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.PowerManager;

/** 15분마다 측정 서비스가 살아 있는지 확인(2.51.0, 2.52.0 보강)
 *  Android 12 부터 백그라운드(작업 예약 포함)에서는 포그라운드 서비스를 시작할 수 없다. 예외: 사용자가 이 앱의 배터리 최적화를 끈 경우.
 *  → 배터리 최적화 제외면 다시 켜고, 아니면 '열어서 다시 시작' 알림을 띄운다(알림을 누르면 앱 화면 → 서비스 시작) */
public class Watchdog extends JobService {
    static void schedule(Context c) {
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) return;
        try {
            js.schedule(new JobInfo.Builder(4711, new ComponentName(c, Watchdog.class))
                    .setPeriodic(15 * 60 * 1000L).setPersisted(true).build());
        } catch (Exception ignored) { }
    }

    static boolean exempt(Context c) {
        PowerManager pm = (PowerManager) c.getSystemService(Context.POWER_SERVICE);
        return pm != null && pm.isIgnoringBatteryOptimizations(c.getPackageName());
    }

    @Override public boolean onStartJob(JobParameters p) {
        if (Prefs.token(this).isEmpty() || Prefs.getLong(this, "run") != 1L || SensorService.running) return false;
        boolean started = false;
        if (Build.VERSION.SDK_INT < 31 || exempt(this)) {
            try { SensorService.start(this, false); started = true; } catch (Exception ignored) { }
        }
        if (!started) remind();
        return false;
    }

    private void remind() {
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm.getNotificationChannel(SensorService.CH_ALERT) == null)
            nm.createNotificationChannel(new NotificationChannel(SensorService.CH_ALERT, "현장 경보", NotificationManager.IMPORTANCE_HIGH));
        PendingIntent pi = PendingIntent.getActivity(this, 3, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        nm.notify(3, new Notification.Builder(this, SensorService.CH_ALERT).setSmallIcon(R.drawable.ic_stat)
                .setContentTitle("AIops 센서가 멈췄습니다").setContentText("눌러서 다시 시작 — 앱의 '배터리 최적화 제외'를 켜 두면 자동으로 다시 켜집니다")
                .setAutoCancel(true).setContentIntent(pi).build());
    }

    @Override public boolean onStopJob(JobParameters p) { return false; }
}
