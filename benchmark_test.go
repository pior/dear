package dear

import (
	"fmt"
	"testing"

	"github.com/pior/dear/crypto"
	"github.com/stretchr/testify/require"
)

func benchDecryption(enc encrypter, key *[32]byte, ciphertext []byte) func(b *testing.B) {
	return func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := enc.Decrypt(key, ciphertext)
			if err != nil {
				panic(err.Error())
			}
		}
	}
}

func BenchmarkDecryption(b *testing.B) {
	key := makeKey()
	messageSizes := []int{32, 512, 8192}
	box := &crypto.SecretBox{}
	aes := &crypto.AESGCM{}

	for _, messageSize := range messageSizes {
		message := makeMessage(messageSize)

		ciphertext, err := box.Encrypt(key, message)
		require.NoError(b, err)
		b.Run(fmt.Sprintf("secretbox-%dbytes", messageSize), benchDecryption(box, key, ciphertext))

		ciphertext, err = aes.Encrypt(key, message)
		require.NoError(b, err)
		b.Run(fmt.Sprintf("aesgcm-%dbytes", messageSize), benchDecryption(aes, key, ciphertext))
	}
}

func benchEncryption(enc encrypter, key *[32]byte, plaintext []byte) func(b *testing.B) {
	return func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := enc.Encrypt(key, plaintext)
			if err != nil {
				panic(err.Error())
			}
		}
	}
}

func BenchmarkEncryption(b *testing.B) {
	key := makeKey()
	messageSizes := []int{32, 512, 8192}
	box := &crypto.SecretBox{}
	aes := &crypto.AESGCM{}

	for _, messageSize := range messageSizes {
		message := makeMessage(messageSize)
		b.Run(fmt.Sprintf("secretbox-%dbytes", messageSize), benchEncryption(box, key, message))
		b.Run(fmt.Sprintf("aesgcm-%dbytes", messageSize), benchEncryption(aes, key, message))
	}
}
