package session

import "time"

type Session struct {
	ClientID      string
	TokenName     string
	Scope         []string
	CodeChallenge string
	Nonce         string
	CreatedAt     time.Time
}

type Storage interface {
	AddSession(code string, session Session) error
	GetAndRemoveSession(code string) (Session, error)
}
