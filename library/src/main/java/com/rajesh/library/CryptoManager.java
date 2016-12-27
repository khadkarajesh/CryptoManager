package com.rajesh.library;


import android.content.Context;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;

/**
 * Direct known classes {@link PreMCryptoManager} {@link PostMCryptoManager} {@link DefaultCryptoManager}
 *
 * @see PostMCryptoManager
 * @see PreMCryptoManager
 * @see DefaultCryptoManager
 */
public abstract class CryptoManager implements ICryptoManager {
    protected KeyStore mKeyStore;
    protected Cipher mCipher;
    protected Context mContext;
    protected int mode = -1;
    protected static final String SHA_256 = "SHA-256";
    protected static final String MGF_1 = "MGF1";
    protected static final String RSA_ECB_OAEPWITH_SHA_256_AND_MGF1_PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    protected static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    protected String keyAlias;
    protected static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";
    protected static final String RSA = "RSA";
    protected static final String UTF_8 = "UTF8";

    public CryptoManager(Context context) {
        this.mContext = context;
        keyAlias = context.getString(R.string.key_alias);
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
