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
	// (count is asserted by route enumeration, and an empty-body submission
	// fails in DecodeJSON first).
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, &fakeMailer{})

	// Count route wired by enumeration, not execution: getUserCount needs a real db.
	var countWired bool
	err := chi.Walk(r, func(method, pattern string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == http.MethodGet && pattern == "/v1/register/count" {
			countWired = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	if !countWired {
		t.Error("count route not registered")
	}

	// Submission route wired: an empty body fails JSON decoding before any DB
	// use, so a non-404 means the handler is mounted.
	req := httptest.NewRequest(http.MethodPost, "/v1/register/", nil)
	w := httptest.NewRecorder()
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
	// within the window is throttled. Probes POST with an empty body so the
	// 400 lands in DecodeJSON before any db use.
	var last int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/register/", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("6th request: got %d, want 429 (rate limit 5/min)", last)
	}
}
