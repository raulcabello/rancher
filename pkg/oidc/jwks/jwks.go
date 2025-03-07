package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"math/big"
	"net/http"
	"strings"
)

const (
	keyBits            = 2048
	keySecretNamespace = "cattle-system"
	keySecretName      = "oidc-signing-key"
)

type Handler struct {
	secretCache  corecontrollers.SecretCache
	secretClient corecontrollers.SecretClient
}

func NewHandler(secretCache corecontrollers.SecretCache, secretClient corecontrollers.SecretClient) (*Handler, error) {
	_, err := secretClient.Get(keySecretNamespace, keySecretName, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}

	if errors.IsNotFound(err) {
		// generate default key
		privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, err
		}
		privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyDER})

		publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})

		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      keySecretName,
				Namespace: keySecretNamespace,
			},
			Data: map[string][]byte{
				"key.pem": privateKeyPEM,
				"key.pub": publicKeyPEM,
			},
		}

		_, err = secretClient.Create(secret)
		if err != nil {
			return nil, err
		}
	}

	return &Handler{
		secretCache:  secretCache,
		secretClient: secretClient,
	}, nil
}

func (h *Handler) JWKSEndpoint(w http.ResponseWriter, r *http.Request) {
	s, err := h.secretCache.Get(keySecretNamespace, keySecretName)
	if err != nil {
		http.Error(w, "failed to get secret with public keys", http.StatusInternalServerError)
		return
	}
	keys := []JWK{}
	for name, value := range s.Data {
		if strings.HasSuffix(name, ".pub") {
			pubKey, err := getPublicKeyFromSecretData(value)
			if err != nil {
				http.Error(w, "failed to get public keys", http.StatusInternalServerError)
				return
			}
			n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())
			keys = append(keys, JWK{
				Kty: "RSA",
				Use: "sig",
				Kid: strings.TrimSuffix(name, ".pub"),
				N:   n,
				E:   e,
			})
		}
	}
	jwks := JWKS{
		Keys: keys,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		http.Error(w, "failed to encode JWKS", http.StatusInternalServerError)
	}
}

func (h *Handler) GetSigningKey() (*rsa.PrivateKey, string, error) {
	s, err := h.secretCache.Get(keySecretNamespace, keySecretName)
	if err != nil {
		return nil, "", err
	}
	for name, value := range s.Data {
		if strings.HasSuffix(name, ".pem") {
			return getPrivateKeyFromSecretData(name, value)
		}
	}
	return nil, "", fmt.Errorf("signing key not found")
}

func (h *Handler) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	s, err := h.secretCache.Get(keySecretNamespace, keySecretName)
	if err != nil {
		return nil, err
	}
	for name, value := range s.Data {
		if name == kid+".pub" {
			return getPublicKeyFromSecretData(value)
		}
	}
	return nil, fmt.Errorf("public key not found")
}

func getPrivateKeyFromSecretData(name string, privateKeyPEM []byte) (*rsa.PrivateKey, string, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, "", fmt.Errorf("failed to decode PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse RSA private key: %v", err)
	}
	return privateKey, strings.TrimSuffix(name, ".pem"), nil
}

func getPublicKeyFromSecretData(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
	}
	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return publicKey, nil
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type (e.g., RSA)
	Use string `json:"use"` // Key Usage (e.g., sig)
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // Modulus
	E   string `json:"e"`   // Exponent
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}
