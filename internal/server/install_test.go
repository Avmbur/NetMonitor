package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivateWebDoesNotTrustForwardedHeaders(t *testing.T) {
	h := privateWeb(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, tc := range []struct {
		addr, path string
		code       int
	}{
		{"192.168.20.50:5000", "/", 200}, {"[fd00::2]:5000", "/ui/api/state", 200},
		{"203.0.113.5:5000", "/ui/login", 403}, {"[2001:db8::2]:5000", "/ui/static/a", 403},
		{"203.0.113.5:5000", "/v1/poll", 200}, {"bad", "/", 403},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		r.RemoteAddr = tc.addr
		r.Header.Set("X-Forwarded-For", "192.168.10.1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatal(tc, w.Code)
		}
	}
}
