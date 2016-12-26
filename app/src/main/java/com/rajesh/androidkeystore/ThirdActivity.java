package com.rajesh.androidkeystore;

import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

public class ThirdActivity extends AppCompatActivity {
    private static final String TAG = ThirdActivity.class.getSimpleName();

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_third);
        CryptoManager cryptoManager = CryptoFactory.getInstance(this);
        Log.d(TAG, "onCreate: decrypt " + cryptoManager.decrypt(cryptoManager.encrypt("test test")));
    }


}
