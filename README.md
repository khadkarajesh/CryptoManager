# CryptoManager
Android Library for encryption and decryption.

Download
-------------------
```groovy

```

How do I use Glide?
-------------------
Create key alias in strings.xml

```
<resources>
    <string name="key_alias">YOUR_KEY_ALIAS</string>
</resources>
```

```

public class CryptoApplication extends Application {
    public static CryptoManager cryptoManager;
    public static Context context;

    @Override
    public void onCreate() {
        super.onCreate();
        this.context = this;
    }

    public static CryptoManager getCryptoManager() {
        return cryptoManager = CryptoFactory.getInstance(context);
    }
}
  
```

In Activity or Fragment
```
CryptoManager cryptoManager = CryptoApplication.getCryptoManager();
cryptoManager.decrypt(cryptoManager.encrypt("hello testing"));

```


License
--------

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.


