package com.krvcf.aiopssensor;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** 재부팅·앱 업데이트 뒤 자동 시작 — Android 14 부터 백그라운드 시작은 카메라·마이크·위치를 쓸 수 없어
 *  그 셋은 앱을 한 번 열 때까지 쉬고(알림으로 안내), 나머지 센서는 바로 다시 보낸다 */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context c, Intent i) {
        if (Prefs.token(c).isEmpty() || Prefs.getLong(c, "run") != 1L) return;
        SensorService.start(c, false);
    }
}
