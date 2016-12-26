package com.rajesh.androidkeystore;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

/**
 * Manager which is used to encrypt/decrypt data for API level 18  and less marshmallow
 */
public class PreMCryptoManager extends CryptoManager {

    public PreMCryptoManager(Context context) {
        super(context);
    }

    @Override
    public void init() {
        mKeyStore = getKeyStore();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            createKeyPair();
        }
        mCipher = getCipher();
    }

    @Override
    public String encrypt(String data) {
        if (mode != Cipher.ENCRYPT_MODE) {
            mode = Cipher.ENCRYPT_MODE;
            initCipher(Cipher.ENCRYPT_MODE);
        }
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, mCipher);
            cipherOutputStream.write(data.getBytes(UTF_8));
            cipherOutputStream.close();
            return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unsupported Encoding exception");
        } catch (IOException e) {
            throw new RuntimeException("IoException");
        }
    }

    @Override
    public String decrypt(String data) {
        if (mode != Cipher.DECRYPT_MODE) {
            mode = Cipher.DECRYPT_MODE;
            initCipher(Cipher.DECRYPT_MODE);
        }
        try {
            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(data, Base64.DEFAULT)), mCipher);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }
            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }
            return new String(bytes, 0, bytes.length, UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("Unsupported Encoding exception");
        } catch (IOException e) {
            throw new RuntimeException("IOException ");
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Override
    public void createKeyPair() {
        try {
            if (!mKeyStore.containsAlias(keyAlias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 30);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                        .setAlias(keyAlias)
                        .setSubject(new X500Principal("CN=Sample Name, O=Leaprfog Technology"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PostMCryptoManager.ANDROID_KEY_STORE);
                generator.initialize(spec);
                generator.generateKeyPair();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    @Override
    public boolean initCipher(int mode) {
        try {
            if (mode == Cipher.ENCRYPT_MODE) {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(keyAlias, null);
                RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();
                mCipher.init(mode, publicKey);
            } else {
                KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(keyAlias, null);
                mCipher.init(mode, privateKeyEntry.getPrivateKey());
            }
            return true;
        } catch (InvalidKeyException e) {
            throw new RuntimeException("invalid key exception");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("No such algorithm");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Key store exception");
        } catch (UnrecoverableEntryException e) {
            throw new RuntimeException("Unrecoverable entry exception");
        }
    }

    @Override
    public Cipher getCipher() {
        try {
            return Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException exception) {
            throw new RuntimeException("Failed to get an instance of Cipher", exception);
        }
    }
}
