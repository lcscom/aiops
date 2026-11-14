package com.krvcf.vcfaiops;

import android.app.job.JobParameters;
import android.app.job.JobService;

public class PollJob extends JobService {
    @Override public boolean onStartJob(final JobParameters p) {
        new Thread(new Runnable() { public void run() {
            try { Poller.poll(getApplicationContext()); } finally { jobFinished(p, false); }
        } }, "aiops-poll").start();
        return true;
    }

    @Override public boolean onStopJob(JobParameters p) { return false; }
}
