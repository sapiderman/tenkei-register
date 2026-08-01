package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
