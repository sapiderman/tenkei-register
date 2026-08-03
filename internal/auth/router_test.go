package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
)

func TestNewRouter_RoutesRegistered(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}

	// db is nil: none of the exercised routes touch the database.
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg)

	// Login route wired: malformed JSON fails in DecodeJSON before any DB use.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("login route: got %d, want 400", w.Code)
	}

	// Authenticated route wired: profile without session cookie is rejected.
	req = httptest.NewRequest(http.MethodGet, "/v1/auth/profile", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("profile route: got %d, want 401", w.Code)
	}

	// Logout route wired (also session-protected).
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("logout route: got %d, want 401", w.Code)
	}

	// Unknown route falls through to chi's default 404.
	req = httptest.NewRequest(http.MethodGet, "/v1/auth/nope", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route: got %d, want 404", w.Code)
	}
}

func TestNewRouter_LoginRateLimit(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}

	// db is nil: the malformed-JSON path fails in DecodeJSON before any DB use,
	// but the rate limiter still counts every request that reaches the route.
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg)

	// Login is rate-limited to 10/min per IP; the 11th attempt is throttled.
	var last int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{bad`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("11th login: got %d, want 429 (rate limit 10/min)", last)
	}
}
