package pbkdf2

import (
	"bytes"
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

func NewHasher() *Hasher {
	return &Hasher{}
}

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

func (h *Hasher) Verify(passwordToValidate string, passwordHashed []byte, salt []byte) (bool, error) {
	passwordToValidateHashed, err := pbkdf2.Key(sha3.New512, passwordToValidate, salt, iterations, keyLength)
	if err != nil {
		return false, err
	}

	return bytes.Equal(passwordToValidateHashed, passwordHashed), nil
}
