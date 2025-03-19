package session

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

const (
	namespace   = "cattle-oidc-codes" //TODO remove
	secretKey   = "session"
	secretLabel = "cattle.io/oidc-code"
)

type SecretStorage struct {
	secretCache  corecontrollers.SecretCache
	secretClient corecontrollers.SecretClient
	expiryTime   time.Duration
	mu           sync.Mutex
}

func NewSecretStorage(ctx context.Context, secretCache corecontrollers.SecretCache, secretClient corecontrollers.SecretClient, expiryTime time.Duration) *SecretStorage {
	storage := &SecretStorage{
		secretCache:  secretCache,
		secretClient: secretClient,
		expiryTime:   expiryTime,
	}
	t := time.NewTicker(expiryTime)
	go storage.cleanUpExpiredSessions(ctx, t.C)

	return storage
}

func (m *SecretStorage) AddSession(code string, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.secretCache.Get(namespace, code)
	if err == nil {
		return fmt.Errorf("code already exists")
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("error getting code: %v", err)
	}
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("error marshalling session: %v", err)
	}
	_, err = m.secretClient.Create(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      code,
			Namespace: namespace,
			Labels: map[string]string{
				secretLabel: "true",
			},
		},
		Data: map[string][]byte{
			secretKey: sessionBytes,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating session: %v", err)
	}

	return nil
}

func (m *SecretStorage) GetAndRemoveSession(code string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var secret *corev1.Secret
	// Retry if the secret is not available yet. In most cases (if not all), the secret will be available, even if it was created on a different node.
	err := wait.ExponentialBackoff(retry.DefaultBackoff, func() (bool, error) {
		var err error
		secret, err = m.secretClient.Get(namespace, code, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return Session{}, fmt.Errorf("invalid code: %v", err)
	}

	var session Session
	err = json.Unmarshal(secret.Data[secretKey], &session)
	if err != nil {
		return Session{}, fmt.Errorf("error unmarshalling session: %v", err)
	}
	err = m.secretClient.Delete(namespace, code, &metav1.DeleteOptions{})
	if err != nil {
		return Session{}, fmt.Errorf("error deleting session: %v", err)
	}
	if time.Since(session.CreatedAt) > m.expiryTime {
		return Session{}, fmt.Errorf("the code has expired")
	}

	return session, nil
}

func (m *SecretStorage) cleanUpExpiredSessions(ctx context.Context, c <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			m.mu.Lock()
			secrets, err := m.secretCache.List(namespace, labels.Set{secretLabel: "true"}.AsSelector())
			if err != nil {
				return //TODO log error!
			}
			for _, secret := range secrets {
				var session Session
				err = json.Unmarshal(secret.Data[secretKey], &session)
				if err != nil {
					//TODO log error
				}
				if time.Since(session.CreatedAt) > m.expiryTime {
					err := m.secretClient.Delete(namespace, secret.Name, &metav1.DeleteOptions{})
					if err != nil {
						// TODO log error
					}
				}
			}
			m.mu.Unlock()
		}
	}
}
