package register

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
)

func TestNewRouter_RoutesRegistered(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{TurnstileEnabled: false}}

	// db is nil: none of the exercised paths touch the database
	// (count is a stub, and an empty-body submission fails in DecodeJSON first).
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, &fakeMailer{})

	// Count route wired: the stub handler returns 200 with an empty body.
	req := httptest.NewRequest(http.MethodGet, "/v1/register/count", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("count route: got %d, want 200", w.Code)
	}

	// Submission route wired: an empty body fails JSON decoding before any DB
	// use, so a non-404 means the handler is mounted.
	req = httptest.NewRequest(http.MethodPost, "/v1/register/", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound {
		t.Error("submission route: got 404, want the route to be wired")
	}

	// Unknown route falls through to chi's default 404.
	req = httptest.NewRequest(http.MethodGet, "/v1/register/nope", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route: got %d, want 404", w.Code)
	}
}

func TestNewRouter_RateLimit(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{TurnstileEnabled: false}}

	// Single router instance so the httprate limiter state is shared.
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, &fakeMailer{})

	// The register group is rate-limited to 5/min per IP; the 6th request
	// within the window is throttled.
	var last int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/register/count", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429 (rate limit 5/min)", last)
	}
}
