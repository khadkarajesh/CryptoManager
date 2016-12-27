# CryptoManager
Android Library for encryption and decryption.

## Uses
Create key alias in strings.xml

```
<resources>
    <string name="key_alias">YOUR_KEY_ALIAS</string>
</resources>
```

```
  CryptoManager cryptoManager = CryptoFactory.getInstance(this);
  cryptoManager.decrypt(cryptoManager.encrypt("hello testing"));
  
```
