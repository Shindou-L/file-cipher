A simple file cipher to encrypt/decrypt file.

#### cipher build

```
builder, err := file_cipher.NewFileCipherBuilder(password)
if err != nil {
    panic(err)
}
fileCipher = builder.WithBufferSize(bufferSize).WithSignature(prefixBytes).Build()
```

#### encrypt

```
fileCipher.Encrypt(path, writer)
fileCipher.EncryptWithReader(reader, writer)
```

#### decrypt

```
fileCipher.Decrypt(path, writer)
fileCipher.DecryptWithReader(reader, writer)
```

#### batch encrypt/decrypt

```
file-cipher.exe -encrypt -password "your password" -buffer 4096 /path/to/file/*.txt
file-cipher.exe -decrypt -password "your password" -buffer 4096 /path/to/file/*.encrypt
```

