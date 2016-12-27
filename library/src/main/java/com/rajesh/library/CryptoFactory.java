package com.rajesh.library;


import android.content.Context;
import android.os.Build;

/**
 * Create instance of CryptoManager {@link CryptoManager} according to android os version
 */
public class CryptoFactory {
    public static CryptoManager getInstance(Context context) {
        CryptoManager cryptoManager = null;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            cryptoManager = new PostMCryptoManager(context);
        } else if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2 && android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.M) {
            cryptoManager = new PreMCryptoManager(context);
        } else {
            cryptoManager = new DefaultCryptoManager(context);
        }
        return cryptoManager;
    }
}
