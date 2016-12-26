package com.rajesh.androidkeystore;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity {

    private static final String AndroidKeyStore = "AndroidKeyStore";
    private static final String AES_MODE = "AES/GCM/NoPadding";

    private static final String KEY_ALIAS = "hello";
    private static final String FIXED_IV = "androiddebug";
    private static final String TAG = MainActivity.class.getSimpleName();
    byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    private KeyStore keyStore;
    private ArrayList<String> keyAliases;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            keyStore = KeyStore.getInstance(AndroidKeyStore);
            keyStore.load(null);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        //Log.d(TAG, "onCreate: " + encryptData("rajeshskjklsdjfl".getBytes()));//encryptData("rajesh".getBytes());
//        try {
//            keyStore.aliases();
//            keyAliases = new ArrayList<>();
//
//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                keyAliases.add(aliases.nextElement());
//            }
//            for (String s : keyAliases) {
//                Log.d(TAG, "onCreate: key :"+s);
//            }
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }

        String encryptedData = encryptData("rajesh".getBytes());
        Log.d(TAG, "onCreate: encrypted data " + encryptedData);
        Log.d(TAG, "onCreate: decrypted data " + decryptData(encryptedData.getBytes()));
        //encryptData(new byte[]{'a','b','c','d'});

    }

    public SecretKey getSecretKey() {
        SecretKey secretKey = null;
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                    .setRandomizedEncryptionRequired(false)
                                    .build());
                }
                secretKey = keyGenerator.generateKey();
            } else {
                secretKey = (SecretKey) keyStore.getKey(KEY_ALIAS, null);
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return secretKey;
    }

    public String encryptData(byte[] input) {
        Cipher c = null;
        String encryptedBase64Encoded = null;
        try {
            c = Cipher.getInstance(AES_MODE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                c.init(Cipher.ENCRYPT_MODE, getSecretKey(), new GCMParameterSpec(128, FIXED_IV.getBytes()));
            }
            byte[] encodedBytes = c.doFinal(input);
            encryptedBase64Encoded = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return encryptedBase64Encoded;
    }

    public byte[] decryptData(byte[] encrypted) {
        Cipher c = null;
        byte[] decodedBytes = new byte[0];
        try {
            c = Cipher.getInstance(AES_MODE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                c.init(Cipher.DECRYPT_MODE, getSecretKey());
            }
            decodedBytes = c.doFinal(encrypted);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return decodedBytes;
    }


}
