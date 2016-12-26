package com.rajesh.androidkeystore;


import android.content.Context;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;

public abstract class CryptoManager implements ICryptoManager {
    public KeyStore mKeyStore;
    public Cipher mCipher;
    public Context mContext;
    public int mode = -1;
    public static final String SHA_256 = "SHA-256";
    public static final String MGF_1 = "MGF1";
    public static final String RSA_ECB_OAEPWITH_SHA_256_AND_MGF1_PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String KEY_ALIAS = "hello";
    public static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    public CryptoManager(Context context) {
        this.mContext = context;
        init();
    }

    @Override
    public KeyStore getKeyStore() {
        try {
            KeyStore keyStore = KeyStore.getInstance(PostMCryptoManager.ANDROID_KEY_STORE);
            keyStore.load(null);
            return keyStore;
        } catch (KeyStoreException exception) {
            throw new RuntimeException("Failed to get an instance of KeyStore", exception);
        } catch (CertificateException e) {
            throw new RuntimeException("Certification exception");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such algorithm");
        } catch (IOException e) {
            throw new RuntimeException("io exception");
        }
    }
}
