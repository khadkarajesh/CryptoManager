package com.rajesh.androidkeystore;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

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

public class SecondActivity extends AppCompatActivity {
    private static final String KEY_ALIAS = "hello";
    private KeyPairGenerator mKeyPairGenerator;
    private KeyStore mKeyStore;
    private Cipher mCipher;
    private String TAG = SecondActivity.class.getSimpleName();
    private String enc;
    private String dyc;

    PostMCryptoManager postMCryptoManager;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_second);
//        mKeyPairGenerator = getKeyPairGenerator();
//        createKeyPair();
//        mKeyStore = getKeyStore();
//        mCipher = getCipher();
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//            initCipher(Cipher.ENCRYPT_MODE);
//        }
//        encrypt("rajesh");
//
//        mCipher = getCipher();
//        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//            initCipher(Cipher.DECRYPT_MODE);
//        }
//        Log.d(TAG, "onCreate: decrypt " + decrypt());
//        decrypt();
//        Log.e("test", "test");

        //postMCryptoManager = new PostMCryptoManager();
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            String res = postMCryptoManager.decrypt(postMCryptoManager.encrypt("ramesh"));
            Log.d(TAG, "onCreate: " + res);
        }
    }

    public KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException exception) {
            throw new RuntimeException("Failed to get an instance of KeyStore", exception);
        }
    }

    public KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException exception) {
            throw new RuntimeException("Failed to get an instance of KeyPairGenerator", exception);
        }
    }

    public Cipher getCipher() {
        try {
            return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new RuntimeException("Failed to get an instance of Cipher", exception);
        }
    }

    private void createKeyPair() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                mKeyPairGenerator.initialize(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
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
    private boolean initCipher(int opmode) {
        try {
            mKeyStore.load(null);

            if (opmode == Cipher.ENCRYPT_MODE) {
                PublicKey key = mKeyStore.getCertificate(KEY_ALIAS).getPublicKey();

                PublicKey unrestricted = KeyFactory.getInstance(key.getAlgorithm())
                        .generatePublic(new X509EncodedKeySpec(key.getEncoded()));

                OAEPParameterSpec spec = new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
                mCipher.init(opmode, unrestricted, spec);
            } else {
                PrivateKey key = (PrivateKey) mKeyStore.getKey(KEY_ALIAS, null);
                mCipher.init(opmode, key);
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

    private void encrypt(String password) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                initCipher(Cipher.ENCRYPT_MODE);
            }
            byte[] bytes = mCipher.doFinal(password.getBytes());
            String encrypted = Base64.encodeToString(bytes, Base64.NO_WRAP);
            enc = encrypted;
            Log.d(TAG, "encrypt: " + encrypted);
            //mPreferences.getString("password").set(encrypted);
        } catch (IllegalBlockSizeException | BadPaddingException exception) {
            throw new RuntimeException("Failed to encrypt password", exception);
        }
    }

    private String decrypt() {
        try {
            String encoded = enc;
            byte[] bytes = Base64.decode(encoded, Base64.NO_WRAP);
            return new String(mCipher.doFinal(bytes), "UTF8");
        } catch (IllegalBlockSizeException | BadPaddingException exception) {
            throw new RuntimeException("Failed to decrypt password", exception);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("bad encoding");
        }
    }
}
