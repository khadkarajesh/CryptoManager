package com.rajesh.library;


import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Manager which is used to encrypt/decrypt data for  marshmallow and above api level
 */
public class PostMCryptoManager extends CryptoManager {
    private KeyPairGenerator mKeyPairGenerator;

    public PostMCryptoManager(Context context) {
        super(context);
    }

    @Override
    public void init() {
        mKeyPairGenerator = getKeyPairGenerator();
        createKeyPair();
        mKeyStore = getKeyStore();
        mCipher = getCipher();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public String encrypt(String data) {
        try {
            initCipher(Cipher.ENCRYPT_MODE);
            byte[] bytes = mCipher.doFinal(data.getBytes());
            return Base64.encodeToString(bytes, Base64.NO_WRAP);
        } catch (IllegalBlockSizeException | BadPaddingException exception) {
            throw new RuntimeException("Failed to encrypt password", exception);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public String decrypt(String data) {
        initCipher(Cipher.DECRYPT_MODE);
        try {
            byte[] bytes = Base64.decode(data, Base64.NO_WRAP);
            return new String(mCipher.doFinal(bytes), UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException exception) {
            throw new RuntimeException("Failed to decrypt password", exception);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("bad encoding");
        }
    }

    @Override
    public KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance(ANDROID_KEY_STORE);
        } catch (KeyStoreException exception) {
            throw new RuntimeException("Failed to get an instance of KeyStore", exception);
        }
    }

    private KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance(RSA, ANDROID_KEY_STORE);
        } catch (NoSuchAlgorithmException | NoSuchProviderException exception) {
            throw new RuntimeException("Failed to get an instance of KeyPairGenerator", exception);
        }
    }

    @Override
    public Cipher getCipher() {
        try {
            return Cipher.getInstance(RSA_ECB_OAEPWITH_SHA_256_AND_MGF1_PADDING);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new RuntimeException("Failed to get an instance of Cipher", exception);
        }
    }

    @Override
    public void createKeyPair() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mKeyPairGenerator.initialize(new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setRandomizedEncryptionRequired(false)
                        .build());
            }
            mKeyPairGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException exception) {
            throw new RuntimeException("Failed to generate key pair", exception);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public boolean initCipher(int mode) {
        try {
            mKeyStore.load(null);
            if (mode == Cipher.ENCRYPT_MODE) {
                PublicKey key = mKeyStore.getCertificate(keyAlias).getPublicKey();

                PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm())
                        .generatePublic(new X509EncodedKeySpec(key.getEncoded()));

                OAEPParameterSpec spec = new OAEPParameterSpec(
                        SHA_256, MGF_1, MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                mCipher.init(mode, unrestricted, spec);
            } else {
                PrivateKey key = (PrivateKey) mKeyStore.getKey(keyAlias, null);
                mCipher.init(mode, key);
            }

            return true;
        } catch (KeyPermanentlyInvalidatedException exception) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException
                | IOException | NoSuchAlgorithmException | InvalidKeyException
                | InvalidAlgorithmParameterException exception) {
            throw new RuntimeException("Failed to initialize Cipher", exception);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return false;
    }

}
