package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/sha3"
	"io"
	"reflect"
)

// Represents either encrypt or decrypt
type op int

const (
	encrypt op = iota
	decrypt
)

var signature = []byte{0xf5, 0x40, 0x12, 0xf1} // Try ...

// Looks for signature and advances reader past signature if so
func readSignature(r *bufio.Reader) bool {
	if b, err := r.Peek(4); err == nil && reflect.DeepEqual(b, signature) {
		r.Discard(4)
		return true
	}
	return false
}

// Writes file signature to buffer
func writeSignature(w *bufio.Writer) error {
	_, err := w.Write(signature)
	return err
}

func encryptOrDecrypt(d op, passphrase string, in *bufio.Reader, out *bufio.Writer) error {
	key := getKey(passphrase)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)

	if d == encrypt {
		rand.Read(iv)
		keystream := cipher.NewCTR(block, iv)
		out.Write(iv) // according to protocol, write iv as first 16 bytes

		streamWriter := cipher.StreamWriter{S: keystream, W: out}
		if _, err := in.WriteTo(streamWriter); err != nil {
			return err
		}
	} else if d == decrypt {
		if _, err := io.ReadFull(in, iv); err != nil {
			return err
		}
		keystream := cipher.NewCTR(block, iv)
		streamReader := cipher.StreamReader{S: keystream, R: in}
		if _, err := out.ReadFrom(streamReader); err != nil {
			return err
		}
	}

	out.Flush()
	return nil
}

func getKey(passphrase string) []byte {
	key := sha3.Sum256([]byte(passphrase))
	return key[:]
}
