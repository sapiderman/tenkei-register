package turnstile

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// --- Verify enabled-path ---
//
// The Cloudflare siteverify URL is injected via VerifyURL so the enabled path
// can be exercised against a fake server.

func TestVerify_DisabledBypass(t *testing.T) {
	v := &Verifier{logger: zerolog.Nop(), enabled: false}
	if err := v.Verify(httptest.NewRequest("POST", "/", nil), ""); err != nil {
		t.Errorf("expected nil when turnstile disabled, got %v", err)
	}
}

func TestVerify_Enabled(t *testing.T) {
	// Pure branches: no network call.
	t.Run("empty token rejected", func(t *testing.T) {
		v := &Verifier{logger: zerolog.Nop(), enabled: true, secret: "s"}
		err := v.Verify(httptest.NewRequest("POST", "/", nil), "")
		if err == nil || !strings.Contains(err.Error(), "token is empty") {
			t.Fatalf("want token-empty error, got %v", err)
		}
	})

	t.Run("empty secret rejected", func(t *testing.T) {
		v := &Verifier{logger: zerolog.Nop(), enabled: true}
		err := v.Verify(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("want not-configured error, got %v", err)
		}
	})

	// newFake spins up a httptest.Server standing in for Cloudflare.
	newFake := func(t *testing.T, handler http.HandlerFunc) *Verifier {
		t.Helper()
		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)
		return &Verifier{
			logger:    zerolog.Nop(),
			enabled:   true,
			secret:    "test-secret",
			VerifyURL: ts.URL,
		}
	}

	t.Run("success returns nil", func(t *testing.T) {
		v := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"hostname":"example.com","challenge_ts":"2024-01-01T00:00:00Z","action":"register","cdata":"custom"}`))
		})
		if err := v.Verify(httptest.NewRequest("POST", "/", nil), "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("failure surfaces error codes", func(t *testing.T) {
		v := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["missing-input-secret","invalid-input-secret","missing-input-response","invalid-input-response","bad-request","timeout-or-duplicate","internal-error","unknown-code"]}`))
		})
		err := v.Verify(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil {
			t.Fatal("want error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid-input-response") {
			t.Errorf("want error code in message, got %v", err)
		}
	})

	t.Run("non-200 status rejected", func(t *testing.T) {
		v := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})
		err := v.Verify(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "non-OK status") {
			t.Fatalf("want non-OK status error, got %v", err)
		}
	})

	t.Run("malformed body rejected", func(t *testing.T) {
		v := newFake(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		})
		err := v.Verify(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "failed to decode") {
			t.Fatalf("want decode error, got %v", err)
		}
	})

	t.Run("prefers CF-Connecting-IP", func(t *testing.T) {
		var gotRemote string
		v := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotRemote = r.FormValue("remoteip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		})
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("CF-Connecting-IP", "203.0.113.7")
		req.RemoteAddr = "10.0.0.1:1234"
		if err := v.Verify(req, "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		if gotRemote != "203.0.113.7" {
			t.Errorf("remoteip: want 203.0.113.7, got %q", gotRemote)
		}
	})

	t.Run("falls back to RemoteAddr host", func(t *testing.T) {
		var gotRemote string
		v := newFake(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotRemote = r.FormValue("remoteip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		})
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		if err := v.Verify(req, "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		if gotRemote != "10.0.0.1" {
			t.Errorf("remoteip: want 10.0.0.1 (port stripped), got %q", gotRemote)
		}
	})
}
