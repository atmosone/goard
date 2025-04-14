package goard

import (
	"context"
	"sync"
)

type store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func (s *store) CreateSession(_ context.Context, session *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID()] = session
	return nil
}

func (s *store) InvokeSession(_ context.Context, id string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session, ok := s.sessions[id]; ok {
		return session, nil
	}
	return nil, ErrSessionNotFound
}

func (s *store) RevokeSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *store) Count(_ context.Context) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *store) Reset(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.RUnlock()
	s.sessions = make(map[string]*Session)
	return nil
}

func (s *store) ForEach(ctx context.Context, callback func(session *Session) error) error {
	s.mu.RLock()
	tmp := make([]*Session, 0, len(s.sessions))
	for id := range s.sessions {
		tmp = append(tmp, s.sessions[id])
	}
	s.mu.RUnlock()
	for _, session := range tmp {
		if err := callback(session); err != nil {
			return err
		}
	}
	return nil
}

func NewStore() *store {
	return &store{
		sessions: make(map[string]*Session),
	}
}
