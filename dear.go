package dear

import (
	"crypto/rand"
	"errors"
	"io"
)

var ErrDecryptionFailed = errors.New("decryption failed")

type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

func NewKey() ([32]byte, error) {
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}
