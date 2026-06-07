package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockSessionStore implements SessionStore for testing.
type mockSessionStore struct {
	validateResult int64
	validateErr    error
	invalidateErr  error
}

func (m *mockSessionStore) Create(ctx context.Context, userID int64, verified bool) (string, error) {
	return "mock-session-id", nil
}
func (m *mockSessionStore) Validate(ctx context.Context, sessionID string) (int64, error) {
	return m.validateResult, m.validateErr
}
func (m *mockSessionStore) Invalidate(ctx context.Context, sessionID string) error {
	return m.invalidateErr
}
func (m *mockSessionStore) InvalidateAll(ctx context.Context, userID int64) error {
	return nil
}

func TestSessionRequired_MissingCookie(t *testing.T) {
	a := &authenticator{
		sessions: &mockSessionStore{},
		cookies:  cookieConfig{Path: "/v1/auth"},
	}

	req := httptest.NewRequest("GET", "/v1/auth/profile", nil)
	w := httptest.NewRecorder()

	called := false
	handler := a.sessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	handler.ServeHTTP(w, req)

	if called {
		t.Error("next handler should not be called when cookie is missing")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSessionRequired_InvalidSession(t *testing.T) {
	a := &authenticator{
		sessions: &mockSessionStore{validateErr: ErrSessionNotFound},
		cookies:  cookieConfig{Path: "/v1/auth"},
	}

	req := httptest.NewRequest("GET", "/v1/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-session"})
	w := httptest.NewRecorder()

	called := false
	handler := a.sessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	handler.ServeHTTP(w, req)

	if called {
		t.Error("next handler should not be called when session is invalid")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestSessionRequired_ValidSession(t *testing.T) {
	a := &authenticator{
		sessions: &mockSessionStore{validateResult: 42},
		cookies:  cookieConfig{Path: "/v1/auth"},
	}

	req := httptest.NewRequest("GET", "/v1/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-session"})
	w := httptest.NewRecorder()

	var gotUserID int64
	handler := a.sessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
	}))

	handler.ServeHTTP(w, req)

	if gotUserID != 42 {
		t.Errorf("expected userID 42, got %d", gotUserID)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
