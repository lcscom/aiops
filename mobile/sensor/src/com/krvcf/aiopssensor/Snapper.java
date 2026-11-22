package com.krvcf.aiopssensor;

import android.content.Context;
import android.graphics.ImageFormat;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Surface;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** 화면 없이 사진 1장(Camera2) — 작은 YUV 미리보기로 1.5초 노출·초점을 맞춘 뒤 JPEG 촬영. 실패하면 null */
final class Snapper {
    private Snapper() { }

    static byte[] take(Context ctx, boolean front, int quality) {
        final HandlerThread ht = new HandlerThread("snap");
        ht.start();
        final Handler h = new Handler(ht.getLooper());
        final byte[][] out = {null};
        final CountDownLatch done = new CountDownLatch(1);
        final CameraDevice[] dev = {null};
        ImageReader jpeg = null, prev = null;
        try {
            CameraManager cm = (CameraManager) ctx.getSystemService(Context.CAMERA_SERVICE);
            String id = null;
            int want = front ? CameraCharacteristics.LENS_FACING_FRONT : CameraCharacteristics.LENS_FACING_BACK;
            for (String c : cm.getCameraIdList()) {
                Integer f = cm.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (f != null && f == want) { id = c; break; }
                if (id == null) id = c;
            }
            if (id == null) return null;
            CameraCharacteristics ch = cm.getCameraCharacteristics(id);
            StreamConfigurationMap map = ch.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            Size js = pick(map.getOutputSizes(ImageFormat.JPEG), 1920);
            Size ps = pick(map.getOutputSizes(ImageFormat.YUV_420_888), 640);
            Integer orient = ch.get(CameraCharacteristics.SENSOR_ORIENTATION);
            final ImageReader jr = ImageReader.newInstance(js.getWidth(), js.getHeight(), ImageFormat.JPEG, 2);
            final ImageReader pr = ImageReader.newInstance(ps.getWidth(), ps.getHeight(), ImageFormat.YUV_420_888, 3);
            jpeg = jr; prev = pr;
            pr.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() {
                @Override public void onImageAvailable(ImageReader r) { Image i = r.acquireLatestImage(); if (i != null) i.close(); }
            }, h);
            jr.setOnImageAvailableListener(new ImageReader.OnImageAvailableListener() {
                @Override public void onImageAvailable(ImageReader r) {
                    Image i = r.acquireLatestImage();
                    if (i == null) return;
                    try {
                        ByteBuffer b = i.getPlanes()[0].getBuffer();
                        byte[] a = new byte[b.remaining()];
                        b.get(a);
                        out[0] = a;
                    } finally { i.close(); done.countDown(); }
                }
            }, h);
            final int q = quality, ori = orient == null ? 0 : orient;
            cm.openCamera(id, new CameraDevice.StateCallback() {
                @Override public void onOpened(final CameraDevice d) {
                    dev[0] = d;
                    try {
                        d.createCaptureSession(Arrays.asList(pr.getSurface(), jr.getSurface()), new CameraCaptureSession.StateCallback() {
                            @Override public void onConfigured(final CameraCaptureSession s) {
                                try {
                                    CaptureRequest.Builder p = d.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
                                    p.addTarget(pr.getSurface());
                                    p.set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_AUTO);
                                    s.setRepeatingRequest(p.build(), null, h);
                                    h.postDelayed(new Runnable() {
                                        @Override public void run() {
                                            try {
                                                CaptureRequest.Builder c = d.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE);
                                                c.addTarget(jr.getSurface());
                                                c.set(CaptureRequest.CONTROL_MODE, CaptureRequest.CONTROL_MODE_AUTO);
                                                c.set(CaptureRequest.JPEG_QUALITY, (byte) q);
                                                c.set(CaptureRequest.JPEG_ORIENTATION, ori);
                                                s.capture(c.build(), null, h);
                                            } catch (Exception e) { done.countDown(); }
                                        }
                                    }, 1500);
                                } catch (Exception e) { done.countDown(); }
                            }
                            @Override public void onConfigureFailed(CameraCaptureSession s) { done.countDown(); }
                        }, h);
                    } catch (CameraAccessException e) { done.countDown(); }
                }
                @Override public void onDisconnected(CameraDevice d) { d.close(); done.countDown(); }
                @Override public void onError(CameraDevice d, int e) { d.close(); done.countDown(); }
            }, h);
            done.await(12, TimeUnit.SECONDS);
            return out[0];
        } catch (SecurityException e) {
            return null;
        } catch (Exception e) {
            return null;
        } finally {
            try { if (dev[0] != null) dev[0].close(); } catch (Throwable ignored) { }
            if (jpeg != null) jpeg.close();
            if (prev != null) prev.close();
            ht.quitSafely();
        }
    }

    /** 긴 변이 max 이하인 가장 큰 크기(없으면 가장 작은 것) */
    private static Size pick(Size[] sizes, int max) {
        Size best = null, small = null;
        for (Size s : sizes) {
            int l = Math.max(s.getWidth(), s.getHeight());
            if (small == null || l < Math.max(small.getWidth(), small.getHeight())) small = s;
            if (l <= max && (best == null || s.getWidth() * s.getHeight() > best.getWidth() * best.getHeight())) best = s;
        }
        return best != null ? best : small;
    }
}
