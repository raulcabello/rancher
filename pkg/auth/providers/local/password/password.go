package password

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	passwordNamespace = "cattle-local-user-passwords"
	iterations        = 210000
	keyLength         = 32
)

type Manager struct {
	secretLister v1.SecretCache
	secretClient v1.SecretClient
}

func NewManager(secretLister v1.SecretCache, secretClient v1.SecretClient) *Manager {
	return &Manager{
		secretLister: secretLister,
		secretClient: secretClient,
	}
}

func (h *Manager) CreateSecret(userId string, password string) error {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	hashedPassword, err := pbkdf2.Key(sha3.New512, password, salt, iterations, keyLength)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = h.secretClient.Create(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userId,
			Namespace: passwordNamespace,
			Annotations: map[string]string{
				"cattle.io/hash": "pbkdf2sha3512",
			},
		},
		// TODO add owner reference!
		Data: map[string][]byte{
			"password": hashedPassword,
			"salt":     salt,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

func (h *Manager) SetSecret(userId string, newPassword string) error {
	secret, err := h.secretLister.Get(passwordNamespace, userId)
	if err != nil {
		return fmt.Errorf("failed to get password secret: %w", err)
	}

	hashedNewPassword, err := pbkdf2.Key(sha3.New512, newPassword, secret.Data["salt"], iterations, keyLength)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// TODO use patch!
	_, err = h.secretClient.Update(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userId,
			Namespace: passwordNamespace,
			Annotations: map[string]string{
				"cattle.io/hash": "pbkdf2sha3512",
			},
		},
		Data: map[string][]byte{
			"password": hashedNewPassword,
			"salt":     secret.Data["salt"],
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// TODO refactor to use SetPasswordSecret!
func (h *Manager) UpdateSecret(userId string, currentPassword, newPassword string) error {
	secret, err := h.secretLister.Get(passwordNamespace, userId)
	if err != nil {
		return fmt.Errorf("failed to get password secret: %w", err)
	}

	hashedPassword, err := pbkdf2.Key(sha3.New512, currentPassword, secret.Data["salt"], iterations, keyLength)
	if !bytes.Equal(hashedPassword, secret.Data["password"]) {
		return fmt.Errorf("invalid current password")
	}

	hashedNewPassword, err := pbkdf2.Key(sha3.New512, newPassword, secret.Data["salt"], iterations, keyLength)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// TODO use patch!
	_, err = h.secretClient.Update(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userId,
			Namespace: passwordNamespace,
			Annotations: map[string]string{
				"cattle.io/hash": "pbkdf2sha3512",
			},
		},
		Data: map[string][]byte{
			"password": hashedNewPassword,
			"salt":     secret.Data["salt"],
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

func (h *Manager) Verify(user *v3.User, password string) (bool, error) {
	secret, err := h.secretLister.Get(passwordNamespace, user.Name)
	if err != nil && !errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get password secret: %w", err)
	}
	if errors.IsNotFound(err) {
		// TODO falback!
		return false, nil
	}
	// TODO if "cattle.io/hash" is bcrypt migrate!
	hashedPassword, err := pbkdf2.Key(sha3.New512, password, secret.Data["salt"], iterations, keyLength)

	return bytes.Equal(hashedPassword, secret.Data["password"]), nil
}
