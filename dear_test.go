package dear

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func makeKey() [32]byte {
	return [32]byte{
		0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f,
		0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72,
		0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c, 0x4d,
		0x7b, 0xbb, 0x04, 0x07, 0xd1, 0xe2, 0xc6, 0x49,
	}
}

func makeMessage(size int) []byte {
	buffer := make([]byte, size)
	generator := rand.New(rand.NewSource(42))
	n, err := generator.Read(buffer)
	if err != nil {
		panic(err.Error())
	}
	if n != size {
		panic("makeMessage failed to generate a random message of expected size")
	}
	return buffer
}

func testEncryptor(encrypter Encryptor, message []byte) func(t *testing.T) {
	return func(t *testing.T) {
		ciphertext, err := encrypter.Encrypt(message)
		require.NoError(t, err)

		clear, err := encrypter.Decrypt(ciphertext)
		require.NoError(t, err)
		require.Equal(t, message, clear)
	}
}

func TestEncrypters(t *testing.T) {
	message := makeMessage(64)

	t.Run("secretbox", testEncryptor(
		&SecretBox{key: makeKey()},
		message,
	))
	t.Run("aesgcm", testEncryptor(
		&AESGCM{key: makeKey()},
		message,
	))
}

func benchDecryption(encryptor Encryptor, ciphertext []byte) func(b *testing.B) {
	return func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := encryptor.Decrypt(ciphertext)
			if err != nil {
				panic(err.Error())
			}
		}
	}
}

func BenchmarkDecryption(b *testing.B) {
	key := makeKey()
	messageSizes := []int{32, 512, 8192}
	box := &SecretBox{key: key}
	aes := &AESGCM{key: key}

	for _, messageSize := range messageSizes {
		message := makeMessage(messageSize)

		ciphertext, err := box.Encrypt(message)
		require.NoError(b, err)
		b.Run(fmt.Sprintf("secretbox-%dbytes", messageSize), benchDecryption(box, ciphertext))

		ciphertext, err = aes.Encrypt(message)
		require.NoError(b, err)
		b.Run(fmt.Sprintf("aesgcm-%dbytes", messageSize), benchDecryption(aes, ciphertext))
	}
}

func benchEncryption(encryptor Encryptor, plaintext []byte) func(b *testing.B) {
	return func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			_, err := encryptor.Encrypt(plaintext)
			if err != nil {
				panic(err.Error())
			}
		}
	}
}
func BenchmarkEncryption(b *testing.B) {
	key := makeKey()
	messageSizes := []int{32, 512, 8192}
	box := &SecretBox{key: key}
	aes := &AESGCM{key: key}

	for _, messageSize := range messageSizes {
		message := makeMessage(messageSize)
		b.Run(fmt.Sprintf("secretbox-%dbytes", messageSize), benchEncryption(box, message))
		b.Run(fmt.Sprintf("aesgcm-%dbytes", messageSize), benchEncryption(aes, message))
	}
}
