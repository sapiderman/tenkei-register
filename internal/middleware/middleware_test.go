package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestXCFBypass(t *testing.T) {
	const secret = "super-secret-key"

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantCalled bool
	}{
		{"empty header", "", http.StatusNotFound, false},
		{"wrong header", "nope", http.StatusNotFound, false},
		{"wrong-length prefix", secret[:3], http.StatusNotFound, false},
		{"correct header", secret, http.StatusOK, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("x-cf-bypass", tc.header)
			}

			XCFBypass(secret)(next).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if called != tc.wantCalled {
				t.Fatalf("next called = %v, want %v", called, tc.wantCalled)
			}
		})
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name string
		cfIP string
		ra   string
		want string
	}{
		{"CF header wins", " 203.0.113.7 ", "10.0.0.1:1234", "203.0.113.7"},
		{"RemoteAddr host, port stripped", "", "10.0.0.1:1234", "10.0.0.1"},
		{"RemoteAddr without port", "", "10.0.0.1", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.cfIP != "" {
				req.Header.Set("CF-Connecting-IP", tc.cfIP)
			}
			req.RemoteAddr = tc.ra
			if got := ClientIP(req); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimit_KeysOnClientIP(t *testing.T) {
	// Limit 2/min keyed on ClientIP: the 3rd request from the same client IP
	// is throttled, but a different client IP gets a fresh bucket (the
	// per-CF-edge failure mode of RemoteAddr keying).
	h := RateLimit(2, time.Minute)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	do := func(cfIP string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-Connecting-IP", cfIP)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := do("203.0.113.7"); got != http.StatusOK {
		t.Fatalf("1st from A: %d, want 200", got)
	}
	if got := do("203.0.113.7"); got != http.StatusOK {
		t.Fatalf("2nd from A: %d, want 200", got)
	}
	if got := do("203.0.113.7"); got != http.StatusTooManyRequests {
		t.Fatalf("3rd from A: %d, want 429", got)
	}
	if got := do("198.51.100.9"); got != http.StatusOK {
		t.Fatalf("1st from B after A exhausted: %d, want 200 (fresh bucket per client IP)", got)
	}
}

func TestAccessLog(t *testing.T) {
	// Capture the global package logger so we can assert the access log line.
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf).With().Timestamp().Logger()
	t.Cleanup(func() { log.Logger = orig })

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("hello"))
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/register/", nil)

	AccessLog(next).ServeHTTP(rec, req)

	// AccessLog must pass the response through untouched.
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "hello")
	}

	// AccessLog must emit an access log entry with method, path, and status.
	out := buf.String()
	for _, want := range []string{`"method":"POST"`, `"path":"/v1/register/"`, `"status":201`} {
		if !strings.Contains(out, want) {
			t.Errorf("access log missing %s, got: %s", want, out)
		}
	}
}
