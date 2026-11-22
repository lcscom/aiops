package com.krvcf.aiopssensor;

import android.app.Application;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

/** 앱 전역 — 잡지 못한 오류를 crash.txt 에 남기고(다음 전송 때 서버로 보고) 기본 처리기에 넘김 */
public class App extends Application {
    @Override public void onCreate() {
        super.onCreate();
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        final File f = new File(getFilesDir(), "crash.txt");
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override public void uncaughtException(Thread t, Throwable e) {
                try {
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    String s = "thread=" + t.getName() + " app=" + Prefs.versionName(App.this) + " sdk=" + android.os.Build.VERSION.SDK_INT
                            + " time=" + (System.currentTimeMillis() / 1000) + "\n" + sw;
                    if (s.length() > 6000) s = s.substring(0, 6000);
                    FileOutputStream o = new FileOutputStream(f);
                    o.write(s.getBytes("UTF-8"));
                    o.close();
                } catch (Throwable ignored) { }
                if (prev != null) prev.uncaughtException(t, e);
            }
        });
        Prefs.putLong(this, "starts", Prefs.getLong(this, "starts") + 1);
    }
}
