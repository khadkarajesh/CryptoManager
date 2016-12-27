package com.rajesh.library;


import java.security.KeyStore;

import javax.crypto.Cipher;

public interface ICryptoManager {
    void init();

    String encrypt(String data);

    String decrypt(String data);

    KeyStore getKeyStore();

    void createKeyPair();

    boolean initCipher(int cipherMode);

    Cipher getCipher();
}
