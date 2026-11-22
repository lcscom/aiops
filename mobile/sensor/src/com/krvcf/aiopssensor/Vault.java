package com.krvcf.aiopssensor;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** 기기 토큰 암호화 — 키는 Android Keystore(기기 밖으로 꺼낼 수 없음), AES-256-GCM. 실패하면 "" */
final class Vault {
    private Vault() { }
    private static final String ALIAS = "aiops_sensor_token_v1";

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        java.security.Key k = ks.getKey(ALIAS, null);
        if (k instanceof SecretKey) return (SecretKey) k;
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        g.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build());
        return g.generateKey();
    }

    static String enc(String plain) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key());
            byte[] iv = c.getIV(), ct = c.doFinal(plain.getBytes("UTF-8"));
            byte[] out = new byte[1 + iv.length + ct.length];
            out[0] = (byte) iv.length;
            System.arraycopy(iv, 0, out, 1, iv.length);
            System.arraycopy(ct, 0, out, 1 + iv.length, ct.length);
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (Throwable e) { return ""; }
    }

    static String dec(String s) {
        try {
            byte[] in = Base64.decode(s, Base64.NO_WRAP);
            int n = in[0];
            if (n < 12 || n > 16 || in.length < 1 + n + 16) return "";
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, in, 1, n));
            return new String(c.doFinal(in, 1 + n, in.length - 1 - n), "UTF-8");
        } catch (Throwable e) { return ""; }
    }
}
