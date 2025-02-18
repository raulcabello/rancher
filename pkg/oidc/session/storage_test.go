package session

import (
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"sync"
	"testing"
	"time"
)

func TestAddSession(t *testing.T) {
	tests := map[string]struct {
		data           map[string]Session
		inputSession   Session
		inputCode      string
		expectedData   map[string]Session
		expectedErrMsg string
	}{
		"code is not present": {
			data: map[string]Session{},
			inputSession: Session{
				ClientID: "client-id",
			},
			inputCode: "code",
			expectedData: map[string]Session{
				"code": {
					ClientID: "client-id",
				},
			},
		},
		"code is already present": {
			data: map[string]Session{
				"code": {
					ClientID: "client-id",
				},
			},
			inputSession: Session{
				ClientID: "client-id",
			},
			inputCode: "code",
			expectedData: map[string]Session{
				"code": {
					ClientID: "client-id",
				},
			},
			expectedErrMsg: "code already exists",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			storage := &MemoryStorage{
				data:       test.data,
				expiryTime: time.Hour,
			}

			err := storage.AddSession(test.inputCode, test.inputSession)

			if test.expectedErrMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedErrMsg)
			}
			assert.Equal(t, test.expectedData, storage.data)
		})
	}
}

func TestGetAndRemoveSession(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		data            map[string]Session
		inputCode       string
		expectedData    map[string]Session
		expectedSession Session
		expectedErrMsg  string
	}{
		"code is present": {
			data: map[string]Session{
				"code": {
					ClientID:  "client-id",
					CreatedAt: now,
				},
			},
			inputCode: "code",
			expectedSession: Session{
				ClientID:  "client-id",
				CreatedAt: now,
			},
			expectedData: map[string]Session{},
		},
		"code is not present": {
			data:           map[string]Session{},
			inputCode:      "code",
			expectedData:   map[string]Session{},
			expectedErrMsg: "invalid code",
		},
		"code expired": {
			data: map[string]Session{
				"code": {
					ClientID:  "client-id",
					CreatedAt: time.Unix(0, 0),
				},
			},
			inputCode:      "code",
			expectedData:   map[string]Session{},
			expectedErrMsg: "the code has expired",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			storage := &MemoryStorage{
				data:       test.data,
				expiryTime: time.Hour,
			}

			session, err := storage.GetAndRemoveSession(test.inputCode)

			if test.expectedErrMsg == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.expectedErrMsg)
			}
			assert.Equal(t, test.expectedSession, session)
			assert.Equal(t, test.expectedData, storage.data)
		})
	}
}

func TestCleanUpExpiredSession(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		data         map[string]Session
		expectedData map[string]Session
	}{
		"remove expired session": {
			data: map[string]Session{
				"code": {
					ClientID:  "client-id",
					CreatedAt: time.Unix(0, 0),
				},
			},
			expectedData: map[string]Session{},
		},
		"remove only expired session": {
			data: map[string]Session{
				"code": {
					ClientID:  "client-id",
					CreatedAt: time.Unix(0, 0),
				},
				"code2": {
					ClientID:  "client-id",
					CreatedAt: now,
				},
			},
			expectedData: map[string]Session{
				"code2": {
					ClientID:  "client-id",
					CreatedAt: now,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			storage := &MemoryStorage{
				data:       test.data,
				expiryTime: time.Hour,
			}
			ctx, cancel := context.WithCancel(context.TODO())
			c := make(chan time.Time)

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				storage.cleanUpExpiredSessions(ctx, c)
			}()

			c <- time.Unix(0, 0)
			cancel()
			wg.Wait()

			assert.Equal(t, test.expectedData, storage.data)
		})
	}

}
