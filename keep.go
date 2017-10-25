package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

var ErrHmacMismatch = errors.New("HMAC mismatched. Wrong password?")

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

func encryptOrDecrypt(d op, passphrase string, in *bufio.Reader, out *bufio.Writer, fileSize int64) error {
	key := getKey(passphrase)
	block, _ := aes.NewCipher(key)
	iv := make([]byte, 16)

	h := hmac.New(sha3.New256, key)
	if d == encrypt {
		rand.Read(iv)
		keystream := cipher.NewCTR(block, iv)
		buf := make([]byte, binary.MaxVarintLen64)
		l := binary.PutVarint(buf, fileSize)
		out.Write(buf[0:l])

		out.Write(iv) // according to protocol, write iv as first 16 bytes

		streamWriter := cipher.StreamWriter{S: keystream, W: out}
		mw := io.MultiWriter(streamWriter, h) // hmac needs the data too
		if _, err := in.WriteTo(mw); err != nil {
			return err
		}
		out.Write(h.Sum(nil))
	} else if d == decrypt {
		var err error
		if fileSize, err = binary.ReadVarint(in); err != nil {
			return err
		}
		if _, err = io.ReadFull(in, iv); err != nil {
			return err
		}
		keystream := cipher.NewCTR(block, iv)
		lr := io.LimitReader(in, fileSize)
		streamReader := cipher.StreamReader{S: keystream, R: lr}

		mw := io.MultiWriter(out, h) // hmac needs the data too
		if _, err = io.Copy(mw, streamReader); err != nil {
			return err
		}
		// hmac verification

		givenHmac := make([]byte, 32)
		if _, err = io.ReadFull(in, givenHmac); err != nil {
			return err
		}
		if !hmac.Equal(h.Sum(nil), givenHmac) {
			return ErrHmacMismatch
		}
	}

	out.Flush()
	return nil
}

func getKey(passphrase string) []byte {
	key := sha3.Sum256([]byte(passphrase))
	return key[:]
}
