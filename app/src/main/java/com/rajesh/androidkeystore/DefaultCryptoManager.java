package com.rajesh.androidkeystore;


import android.content.Context;

import javax.crypto.Cipher;

/**
 * It returns the same data as sent. Below api level 18 keystore doesn't support
 */
public class DefaultCryptoManager extends CryptoManager {
    public DefaultCryptoManager(Context context) {
        super(context);
    }

    @Override
    public void init() {
    }

    @Override
    public String encrypt(String data) {
        return data;
    }

    @Override
    public String decrypt(String data) {
        return data;
    }

    @Override
    public void createKeyPair() {
    }

    @Override
    public boolean initCipher(int cipherMode) {
        return false;
    }

    @Override
    public Cipher getCipher() {
        return null;
    }
}
