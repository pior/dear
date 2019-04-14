package dear

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

type SecretBox struct {
	key [32]byte
}

func (c *SecretBox) Encrypt(cleartext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], cleartext, &nonce, &c.key)
	return encrypted, nil
}

func (c *SecretBox) Decrypt(encrypted []byte) ([]byte, error) {
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	cleartext, ok := secretbox.Open(nil, encrypted[24:], &nonce, &c.key)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	return cleartext, nil
}
