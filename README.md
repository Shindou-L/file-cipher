A simple file cipher to encrypt/decrypt file.

#### cipher build

```
builder, err := file_cipher.NewFileCipherBuilder(password)
if err != nil {
    panic(err)
}
fileCipher = builder.WithBufferSize(bufferSize).WithSignature(prefixBytes).Build()
```

#### Encrypt

```
fileCipher.Encrypt(path, writer)
```

#### Decrypt

```
fileCipher.Decrypt(path, writer)
```


