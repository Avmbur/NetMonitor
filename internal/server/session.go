package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

type session struct {
	user string
	exp  time.Time
}

type sessStore struct {
	mu sync.Mutex
	m  map[string]session
}

func newSess() *sessStore { return &sessStore{m: map[string]session{}} }

func (s *sessStore) put(user string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	s.mu.Lock()
	s.m[id] = session{user: user, exp: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	return id
}

func (s *sessStore) get(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	if !ok || time.Now().After(v.exp) {
		delete(s.m, id)
		return false
	}
	return true
}

func (s *sessStore) del(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

func setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "nm_sess",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		MaxAge:   12 * 3600,
	})
}

func cookieID(r *http.Request) string {
	c, err := r.Cookie("nm_sess")
	if err != nil {
		return ""
	}
	return c.Value
}
