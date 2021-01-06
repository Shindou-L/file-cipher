package file_cipher

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"os"
)

type fileCipher struct {
	block      cipher.Block
	bufferSize int
	signature  []byte
}

func (f *fileCipher) Encrypt(input string, writer io.Writer) error {
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	writer.Write(f.signature)
	return f.handlerFile(file, writer, f.block.Encrypt)
}

func (f *fileCipher) EncryptWithReader(reader io.Reader, writer io.Writer) error {
	writer.Write(f.signature)
	return f.handlerFile(reader, writer, f.block.Encrypt)
}

func (f *fileCipher) Decrypt(input string, writer io.Writer) error {
	file, err := os.Open(input)
	if err != nil {
		return err
	}
	defer file.Close()
	if len(f.signature) > 0 {
		signature := make([]byte, len(f.signature))
		file.Read(signature)
		if !bytes.Equal(f.signature, signature) {
			return errors.New("mismatching signature")
		}
	}
	return f.handlerFile(file, writer, f.block.Decrypt)
}

func (f *fileCipher) DecryptWithReader(reader io.Reader, writer io.Writer) error {
	if len(f.signature) > 0 {
		signature := make([]byte, len(f.signature))
		reader.Read(signature)
		if !bytes.Equal(f.signature, signature) {
			return errors.New("mismatching signature")
		}
	}
	return f.handlerFile(reader, writer, f.block.Decrypt)
}

func (f *fileCipher) handlerFile(reader io.Reader, writer io.Writer, bytesHandler func(dst, src []byte)) error {
	buffer := make([]byte, f.bufferSize)
	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		writer.Write(handleBytes(buffer[:n], bytesHandler))
		if err == io.EOF {
			return nil
		}
	}
}

func handleBytes(bytes []byte, handler func(dst, src []byte)) []byte {
	length := len(bytes)
	res := make([]byte, length)
	times := length / 16
	for i := 0; i < times; i++ {
		handler(res[i*16:(i+1)*16], bytes[i*16:(i+1)*16])
	}
	if mod := length % 16; mod != 0 { // do not handle remain bytes
		for mod > 0 {
			res[length-mod] = bytes[length-mod]
			mod--
		}
	}
	return res
}
