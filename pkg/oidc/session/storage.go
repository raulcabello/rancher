package session

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type MemoryStorage struct {
	data       map[string]Session
	expiryTime time.Duration
	mu         sync.Mutex
}

func NewMemoryStorage(ctx context.Context, expiryTime time.Duration) *MemoryStorage {
	storage := &MemoryStorage{
		data:       make(map[string]Session),
		expiryTime: expiryTime,
	}
	t := time.NewTicker(expiryTime)
	go storage.cleanUpExpiredSessions(ctx, t.C)

	return storage
}

func (m *MemoryStorage) AddSession(code string, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[code]; ok {
		return fmt.Errorf("code already exists")
	}
	m.data[code] = session

	return nil
}

func (m *MemoryStorage) GetAndRemoveSession(code string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.data[code]
	if !ok {
		return Session{}, fmt.Errorf("invalid code")
	}
	delete(m.data, code)
	if time.Since(s.CreatedAt) > m.expiryTime {
		return Session{}, fmt.Errorf("the code has expired")
	}

	return s, nil
}

func (m *MemoryStorage) cleanUpExpiredSessions(ctx context.Context, c <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			m.mu.Lock()
			for code, session := range m.data {
				if time.Since(session.CreatedAt) > m.expiryTime {
					delete(m.data, code)
				}
			}
			m.mu.Unlock()
		}
	}
}
