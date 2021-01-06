package file_cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

const PasswordLength =  32

type FileCipher interface {
	Encrypt(input string, writer io.Writer) error
	Decrypt(input string, writer io.Writer) error
}

type fileCipherBuilder struct {
	block       cipher.Block
	bufferSize  int
	signature   []byte
}

func (b *fileCipherBuilder) WithBufferSize(size int) *fileCipherBuilder {
	if size <= 0 {
		size = 1024
	}
	if mod := size % 16; mod != 0 { // 取16的整数
		size += 16 - mod
	}
	b.bufferSize = size
	return b
}

func (b *fileCipherBuilder) WithSignature(signature []byte) *fileCipherBuilder {
	b.signature = signature
	return b
}

func (b *fileCipherBuilder) Build() FileCipher {
	return &fileCipher{
		block: b.block,
		bufferSize: b.bufferSize,
		signature: b.signature,
	}
}

func NewFileCipherBuilder(password string) (*fileCipherBuilder, error)  {
	bytes := []byte(password)
	if len(bytes) > PasswordLength {
		return nil, errors.New("password too long")
	}
	newPasswordBytes := make([]byte, PasswordLength)
	copy(newPasswordBytes[:len(bytes)], bytes)
	block, err := aes.NewCipher(newPasswordBytes)
	if err != nil {
		return nil,err
	}
	return &fileCipherBuilder{
		block: block,
		bufferSize: 1024,
	},nil
}
