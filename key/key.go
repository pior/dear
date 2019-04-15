package key

import (
	"crypto/rand"
	"errors"
	"io"
)

type Key = [32]byte

func GenerateKey() (*Key, error) {
	var key Key
	_, err := io.ReadFull(rand.Reader, key[:])
	return &key, err
}

var ErrKeyNotFound = errors.New("decryption key not found")

type KeyProvider interface {
	Get(id int) (*Key, error)
}

type StaticKeyProvider struct {
	keys []Key
}

func NewStaticKeyProvider(keys ...Key) *StaticKeyProvider {
	return &StaticKeyProvider{keys}
}

func (p *StaticKeyProvider) Get(id int) (*Key, error) {
	if id >= len(p.keys) {
		return nil, ErrKeyNotFound
	}
	key := p.keys[id]
	return &key, nil
}
