package session

import (
	"crypto/rand"
	"math/big"
)

const (
	characters         = "bcdfghjklmnpqrstvwxz2456789"
	clientIDLength     = 10
	codeLength         = 56
	clientSecretLength = 56
	clientIDPrefix     = "client-"
	codePrefix         = "code-"
	clientSecretPrefix = "secret-"
)

type RandomStringGenerator struct{}

var charsLength = big.NewInt(int64(len(characters)))

func (r *RandomStringGenerator) GenerateClientID() (string, error) {
	return r.generateRandomString(clientIDPrefix, clientIDLength)
}

func (r *RandomStringGenerator) GenerateClientSecret() (string, error) {
	return r.generateRandomString(clientSecretPrefix, clientSecretLength)
}

func (r *RandomStringGenerator) GenerateCode() (string, error) {
	return r.generateRandomString(codePrefix, codeLength)
}

func (r *RandomStringGenerator) generateRandomString(prefix string, length int) (string, error) {
	token := make([]byte, length)
	for i := range token {
		r, err := rand.Int(rand.Reader, charsLength)
		if err != nil {
			return "", err
		}
		token[i] = characters[r.Int64()]
	}
	return prefix + string(token), nil
}
