package dear

import (
	"math/rand"
	"testing"

	"github.com/pior/dear/crypto"
	"github.com/pior/dear/key"
	"github.com/stretchr/testify/require"
)

func makeKey() *[32]byte {
	return &[32]byte{
		0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f,
		0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72,
		0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d,
		0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6, 0x49,
	}
}

func makeKey2() *[32]byte {
	return &[32]byte{
		0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6, 0x49,
		0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d,
		0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72,
		0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f,
	}
}

func makeMessage(size int) []byte {
	buffer := make([]byte, size)
	n, err := rand.New(rand.NewSource(42)).Read(buffer)
	if err != nil {
		panic(err.Error())
	}
	if n != size {
		panic("makeMessage failed to generate a random message of expected size")
	}
	return buffer
}

func testEncryptor(enc encrypter, key *[32]byte, message []byte) func(t *testing.T) {
	return func(t *testing.T) {
		ciphertext, err := enc.Encrypt(key, message)
		require.NoError(t, err)

		clear, err := enc.Decrypt(key, ciphertext)
		require.NoError(t, err)
		require.Equal(t, message, clear)
	}
}

func TestEncrypters(t *testing.T) {
	message := makeMessage(64)
	key := makeKey()

	t.Run("secretbox", testEncryptor(
		&crypto.SecretBox{},
		key,
		message,
	))
	t.Run("aesgcm", testEncryptor(
		&crypto.AESGCM{},
		key,
		message,
	))
}

func TestDearKeys(t *testing.T) {
	message := makeMessage(64)

	kp1 := key.NewStaticKeyProvider(*makeKey())
	kp2 := key.NewStaticKeyProvider(*makeKey(), *makeKey2())

	dearKey1 := New(kp1)

	dearKey2 := New(kp2)
	dearKey2.KeyID = 1

	dearKey3 := New(kp2)
	dearKey3.KeyID = 42

	tests := []struct {
		name         string
		encrypt      *DearEncryptor
		decrypt      *DearEncryptor
		encryptError error
		decryptError error
	}{
		{
			"same config",
			dearKey1,
			dearKey1,
			nil,
			nil,
		},
		{
			"new key",
			dearKey1,
			dearKey2,
			nil,
			nil,
		},
		{
			"unknown decryption key",
			dearKey2,
			dearKey1,
			nil,
			key.ErrKeyNotFound,
		},
		{
			"unknown encryption key",
			dearKey3,
			nil, // will crash before
			key.ErrKeyNotFound,
			nil,
		},
	}

	for _, test := range tests {
		ciphertext, err := test.encrypt.Encrypt(message)
		require.Equal(t, test.encryptError, err)
		if err != nil {
			continue
		}

		clear, err := test.decrypt.Decrypt(ciphertext)
		require.Equal(t, test.decryptError, err)
		if err != nil {
			continue
		}

		require.Equal(t, message, clear)
	}
}

func TestNew_MissingDefaultKey(t *testing.T) {
	require.PanicsWithValue(t, "encryption key missing for key 0", func() {
		New(key.NewStaticKeyProvider())
	})
}
