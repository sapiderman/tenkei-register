package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
)

// mockVerifier implements Verifier for testing.
type mockVerifier struct {
	userID      int64
	requires2FA bool
	err         error
}

func (m *mockVerifier) Verify(ctx context.Context, identifier, password string) (int64, bool, error) {
	return m.userID, m.requires2FA, m.err
}

func newTestAuthenticator(v Verifier, s SessionStore) *authenticator {
	return &authenticator{
		logger:   zerolog.Nop(),
		validate: validator.New(),
		db:       nil, // not used in handler tests
		verifier: v,
		sessions: s,
		cookies:  cookieConfig{Path: "/v1/auth", Secure: true, SameSite: http.SameSiteLaxMode},
	}
}

func TestHandleLogin_Success(t *testing.T) {
	v := &mockVerifier{userID: 1, requires2FA: false, err: nil}
	s := &mockSessionStore{}
	a := newTestAuthenticator(v, s)

	body := `{"identifier":"test@example.com","password":"correctpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %s", resp["status"])
	}
}

func TestHandleLogin_InvalidCredentials(t *testing.T) {
	v := &mockVerifier{userID: 0, requires2FA: false, err: ErrInvalidCredentials}
	s := &mockSessionStore{}
	a := newTestAuthenticator(v, s)

	body := `{"identifier":"test@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid credentials" {
		t.Errorf("expected 'invalid credentials', got %s", resp["error"])
	}
}

func TestHandleLogin_2FARequired(t *testing.T) {
	v := &mockVerifier{userID: 1, requires2FA: true, err: nil}
	s := &mockSessionStore{}
	a := newTestAuthenticator(v, s)

	body := `{"identifier":"test@example.com","password":"correctpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "2fa_required" {
		t.Errorf("expected status '2fa_required', got %s", resp["status"])
	}
}

func TestHandleLogin_MissingFields(t *testing.T) {
	v := &mockVerifier{}
	s := &mockSessionStore{}
	a := newTestAuthenticator(v, s)

	body := `{"identifier":""}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleLogout_Success(t *testing.T) {
	s := &mockSessionStore{}
	a := newTestAuthenticator(nil, s)

	req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session"})
	// Inject user ID into context (simulating sessionRequired middleware)
	ctx := context.WithValue(req.Context(), ctxKeyUserID{}, int64(1))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	a.handleLogout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestMask(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"test@example.com", "t**************m"},
		{"ab", "a*b"},
		{"a", "***"},
		{"", "***"},
	}
	for _, tt := range tests {
		result := mask(tt.input)
		if len(tt.input) <= 2 && result != "***" {
			t.Errorf("mask(%q): expected all masked, got %q", tt.input, result)
		}
		if len(tt.input) > 2 && result != tt.expected {
			t.Errorf("mask(%q): expected %q, got %q", tt.input, tt.expected, result)
		}
	}
}
