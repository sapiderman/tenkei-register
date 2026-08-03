package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
