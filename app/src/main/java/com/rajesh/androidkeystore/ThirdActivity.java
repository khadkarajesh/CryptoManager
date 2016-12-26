package com.rajesh.androidkeystore;

import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static com.rajesh.androidkeystore.CryptoManager.RSA_ECB_PKCS1_PADDING;

public class ThirdActivity extends AppCompatActivity {
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String SHARED_PREFENCE_NAME = "user";
    private static final String AES_MODE = "AES/ECB/PKCS7Padding";
    private static final String ENCRYPTED_KEY = "enc_key";

    private static String SECRETE_KEY = "rajesh";
    private static final String TAG = ThirdActivity.class.getSimpleName();
    private KeyStore keyStore;
    private String aliasText = "hello";

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_third);

        CryptoManager cryptoManager = CryptoFactory.getInstance(this);
        Log.d(TAG, "onCreate: ddcrypt " + cryptoManager.decrypt(cryptoManager.encrypt("ramu ji")));
    }

    private KeyStore getKeyStore() {
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


    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    public void createNewKeys() {
        String alias = aliasText.toString();
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(alias)) {
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 30);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
                        .setAlias(alias)
                        .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, PostMCryptoManager.ANDROID_KEY_STORE);
                generator.initialize(spec);
                generator.generateKeyPair();
            }
        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
    }

    public String encryptString() {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(PostMCryptoManager.KEY_ALIAS, null);
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            // Encrypt the text
            String initialText = "algebra algebra";
            //Cipher input = Cipher.getInstance(RSA_ECB_PKCS1_PADDING, PostMCryptoManager.ANDROID_OPEN_SSL);
            Cipher input = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            input.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, input);
            cipherOutputStream.write(initialText.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte[] vals = outputStream.toByteArray();
            return Base64.encodeToString(vals, Base64.DEFAULT);
        } catch (Exception e) {
            throw new RuntimeException("exception ");
        }
    }

    public String decryptString(String encryptedText) {
        String finalText = null;
        KeyStore.PrivateKeyEntry privateKeyEntry = null;
        try {
            privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(PostMCryptoManager.KEY_ALIAS, null);
            Cipher output = null;
            output = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            finalText = new String(bytes, 0, bytes.length, "UTF-8");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return finalText;
    }

}
