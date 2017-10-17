package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"io"
	"os"
)

// Represents either encrypt or decrypt
type op int

const (
	encrypt op = iota
	decrypt
)

func encryptOrDecrypt(d op, passphrase, infilePath, outfilePath string) error {
	key := getKey(passphrase)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)

	infile, err := os.Open(infilePath)
	if err != nil {
		return err
	}
	// In buffer
	br := bufio.NewReader(infile)

	outfile, err := os.Create(outfilePath)
	if err != nil {
		return err
	}
	// Out buffer
	bw := bufio.NewWriter(outfile)

	if d == encrypt {
		rand.Read(iv)
		keystream := cipher.NewCTR(block, iv)
		bw.Write(iv) // according to protocol, write iv as first 16 bytes

		streamWriter := cipher.StreamWriter{S: keystream, W: bw}
		if _, err := br.WriteTo(streamWriter); err != nil {
			return err
		}
	} else if d == decrypt {
		if _, err := io.ReadFull(br, iv); err != nil {
			return err
		}
		keystream := cipher.NewCTR(block, iv)
		streamReader := cipher.StreamReader{S: keystream, R: br}
		if _, err := bw.ReadFrom(streamReader); err != nil {
			return err
		}
	}

	bw.Flush()
	return nil
}

func getKey(passphrase string) []byte {
	key := sha3.Sum256([]byte(passphrase))
	return key[:]
}
