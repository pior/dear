package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pior/dear/key"
)

type AESGCM struct{}

func (a *AESGCM) Encrypt(key *key.Key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nonce[:], nonce, plaintext, nil)
	return ciphertext, nil
}

func (a *AESGCM) Decrypt(key *key.Key, ciphertext []byte) ([]byte, error) {
	var nonce [12]byte
	copy(nonce[:], ciphertext[:12])
	ciphertext = ciphertext[12:]

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
