package com.krvcf.aiopssensor;

import android.app.admin.DeviceAdminReceiver;

/** 기기 소유자 수신기(2.53.0) — `adb shell dpm set-device-owner com.krvcf.aiopssensor/.Admin` 로 지정하면
 *  포털에서 이 폰의 권한·화면·잠금·재부팅을 원격으로 바꿀 수 있다(Remote.java). 지정하지 않으면 아무 일도 하지 않음 */
public class Admin extends DeviceAdminReceiver { }
