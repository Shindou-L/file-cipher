package file_cipher

import (
	"bytes"
	"testing"
)

var fc *fileCipher

func init() {
	builder, err := NewFileCipherBuilder("mypassword")
	if err != nil {
		panic(err)
	}
	fc = builder.WithSignature([]byte("test signature")).Build().(*fileCipher)
}

type mywriter struct {
	data   []byte
	length int
}

func (m *mywriter) Write(p []byte) (n int, err error) {
	m.data = append(m.data, p...)
	m.length += len(p)
	return len(p), nil
}

func TestFileCipher(t *testing.T) {
	originalBytes := []byte("fdasf43189hfa8fd7as98fh5439fd23=54235+_S(DF_*f0s79r0w=replain text")
	reader := bytes.NewReader(originalBytes)

	writer := &mywriter{}
	fc.EncryptWithReader(reader, writer)
	if writer.length != len(originalBytes)+len(fc.signature) {
		t.Fail()
	}

	encryptedBytes := writer.data[:writer.length]
	recoverWriter := &mywriter{}
	fc.DecryptWithReader(bytes.NewReader(encryptedBytes), recoverWriter)

	decryptedBytes := recoverWriter.data[:recoverWriter.length]
	if !bytes.Equal(originalBytes, decryptedBytes) {
		t.Fatalf("expected:%v\n acutal:%v\n", originalBytes, decryptedBytes)
	}
}
