package dear

import (
	"errors"
	"fmt"

	"github.com/pior/dear/crypto"
	"github.com/pior/dear/key"
)

type encrypter interface {
	Encrypt(*key.Key, []byte) ([]byte, error)
	Decrypt(*key.Key, []byte) ([]byte, error)
}

type DearEncryptor struct {
	KeyProvider key.KeyProvider

	KeyID       int
	EncrypterID int

	encrypters map[int]encrypter
}

func New(keyProvider key.KeyProvider) *DearEncryptor {
	e := &DearEncryptor{
		KeyProvider: keyProvider,
		encrypters: map[int]encrypter{
			0: &crypto.AESGCM{},
			1: &crypto.SecretBox{},
		},
	}

	_, err := e.KeyProvider.Get(e.KeyID)
	if err != nil {
		panic(fmt.Sprintf("encryption key missing for key %d", e.KeyID))
	}

	return e
}

// Header:
// 00: key ID
// 01: encrypter ID
//       00: AES-GCM
//       01: Nacl SecretBox

func (e *DearEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	key, err := e.KeyProvider.Get(e.KeyID)
	if err != nil {
		return nil, err
	}

	encrypter := e.encrypters[e.EncrypterID]
	cyphertext, err := encrypter.Encrypt(key, plaintext)

	header := []byte{byte(e.KeyID), byte(e.EncrypterID)}
	cyphertext = append(header, cyphertext...)
	return cyphertext, nil
}

var ErrUnknownEncryptor = errors.New("unknown encrypter")

func (e *DearEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	header := ciphertext[:2]
	ciphertext = ciphertext[2:]

	keyID := int(byte(header[0]))
	encrypterID := int(byte(header[1]))

	key, err := e.KeyProvider.Get(keyID)
	if err != nil {
		return nil, err
	}

	encrypter, ok := e.encrypters[encrypterID]
	if !ok {
		return nil, ErrUnknownEncryptor
	}

	return encrypter.Decrypt(key, ciphertext)
}
