package com.krvcf.aiopssensor;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;

/** 15분마다 측정 서비스가 살아 있는지 확인하고, 제조사 절전 정책 등으로 꺼졌으면 다시 켠다(2.51.0) */
public class Watchdog extends JobService {
    static void schedule(Context c) {
        JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
        if (js == null) return;
        js.schedule(new JobInfo.Builder(4711, new ComponentName(c, Watchdog.class))
                .setPeriodic(15 * 60 * 1000L).setPersisted(true).build());
    }

    @Override public boolean onStartJob(JobParameters p) {
        if (!Prefs.token(this).isEmpty() && Prefs.getLong(this, "run") == 1L && !SensorService.running) {
            try { SensorService.start(this, false); } catch (Exception ignored) { }
        }
        return false;
    }

    @Override public boolean onStopJob(JobParameters p) { return false; }
}
