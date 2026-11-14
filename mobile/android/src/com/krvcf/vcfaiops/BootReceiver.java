package com.krvcf.vcfaiops;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** 재부팅·앱 업데이트 뒤 — 주기 확인 예약과 실시간 연결을 다시 켠다 */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        String a = i == null ? null : i.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(a) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) return;
        try { Poller.schedule(c); } catch (Exception ignored) { }
        LiveService.sync(c);
    }
}
