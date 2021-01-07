package main

import (
	"bufio"
	"file-cipher"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var (
	prefixBytes = []byte("signature for file-cipher")
	encryptMode bool
	decryptMode bool
	password    string
	inputFiles  []string
	bufferSize  int

	fileCipher file_cipher.FileCipher
)

func main() {
	checkAndInit()
	for _, file := range inputFiles {
		dir, filePattern := filepath.Split(file)
		if dir == "" {
			dir = "."
		}
		i := 0
		filepath.Walk(dir, func(path string, info os.FileInfo, _ error) error {
			i++
			if i == 1 || info == nil { // i=1不对本目录进行处理
				return nil
			}
			if info.IsDir() {
				return filepath.SkipDir // 不扫描子目录
			}
			fileName := info.Name()
			match, _ := filepath.Match(filePattern, fileName)
			if !match {
				return nil
			}
			fmt.Printf("%v: ", fileName)
			var outFile *os.File
			var writer *bufio.Writer
			var err error
			if encryptMode {
				outFile, err = os.Create(fileName + ".encrypt")
				if err != nil {
					fmt.Printf("create output file failed:%v\n", err)
					return nil
				}
				writer = bufio.NewWriterSize(outFile, bufferSize)
				err := fileCipher.Encrypt(path, writer)
				if err != nil {
					fmt.Println(err)
					outFile.Close()
					os.Remove(outFile.Name())
					return nil
				}
			} else {
				outFile, err = os.Create(fileName + ".decrypt")
				if err != nil {
					fmt.Printf("create output file failed:%v\n", err)
					return nil
				}
				writer = bufio.NewWriterSize(outFile, bufferSize)
				err := fileCipher.Decrypt(path, writer)
				if err != nil {
					fmt.Println(err)
					outFile.Close()
					os.Remove(outFile.Name())
					return nil
				}
			}
			fmt.Println(outFile.Name())
			writer.Flush()
			outFile.Close()
			return nil
		})
	}
}

func checkAndInit() {
	if !encryptMode && !decryptMode {
		fmt.Println("please choose one mode: encrypt or decrypt")
		flag.Usage()
		os.Exit(1)
	}
	if encryptMode && decryptMode {
		fmt.Println("can only choose one mode: encrypt or decrypt")
		flag.Usage()
		os.Exit(1)
	}
	inputFiles = flag.Args()
	if len(inputFiles) <= 0 {
		fmt.Println("please specify file to deal with")
		flag.Usage()
		os.Exit(1)
	}
	builder, err := file_cipher.NewFileCipherBuilder(password)
	if err != nil {
		fmt.Println("invalid password:", err)
		os.Exit(1)
	}
	fileCipher = builder.WithBufferSize(bufferSize).WithSignature(prefixBytes).Build()
}

func init() {
	flag.BoolVar(&encryptMode, "encrypt", false, "encrypt file")
	flag.BoolVar(&decryptMode, "decrypt", false, "decrypt file")
	flag.StringVar(&password, "password", "", "password for encrypt/decrypt")
	flag.IntVar(&bufferSize, "buffer", 1024, "read buffer")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "A simple tool to encrypt/decrypt file. Usage: %s file1 file2 file3\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
}
