package com.krvcf.aiopssensor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

/** 센서 앱 자체 업데이트 결과(설치 확인 화면 띄우기·성공·실패) */
public class InstallReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        int st = i.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
        if (st == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            Intent confirm = i.getParcelableExtra(Intent.EXTRA_INTENT);
            if (confirm != null) {
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try { c.startActivity(confirm); } catch (Exception e) { Toast.makeText(c, "설치 화면을 열 수 없습니다 — 앱을 연 상태에서 다시 시도하세요", Toast.LENGTH_LONG).show(); }
            }
        } else if (st == PackageInstaller.STATUS_SUCCESS) {
            SensorService.update = "";
            Toast.makeText(c, "앱을 업데이트했습니다", Toast.LENGTH_LONG).show();
        } else {
            String m = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
            Toast.makeText(c, "앱 업데이트 실패" + (m == null ? "" : ": " + m), Toast.LENGTH_LONG).show();
        }
    }
}
