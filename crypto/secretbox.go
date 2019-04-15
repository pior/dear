package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/pior/dear/key"
	"golang.org/x/crypto/nacl/secretbox"
)

var ErrDecryptionFailed = errors.New("decryption failed")

type SecretBox struct{}

func (c *SecretBox) Encrypt(key *key.Key, cleartext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], cleartext, &nonce, key)
	return encrypted, nil
}

func (c *SecretBox) Decrypt(key *key.Key, encrypted []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	cleartext, ok := secretbox.Open(nil, encrypted[24:], &nonce, key)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return cleartext, nil
}
