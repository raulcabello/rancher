package pbkdf2

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
)

const (
	iterations = 210000
	keyLength  = 32
)

type Hasher struct{}

func (h *Hasher) Hash(password string) ([]byte, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHashed, err := pbkdf2.Key(sha3.New512, password, salt, iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return passwordHashed, salt, nil
}

func (h *Hasher) Verify(password string, salt []byte) ([]byte, []byte, error) {
	passwordHashed, err := pbkdf2.Key(sha3.New512, password, salt, iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return passwordHashed, salt, nil
}
