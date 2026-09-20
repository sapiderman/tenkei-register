package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockSessionStore implements SessionStore for testing.
type mockSessionStore struct {
	validateResult        int64
	validateRole          string
	validateErr           error
	invalidateErr         error
	invalidateAllErr      error
	createErr             error
	createCalls           int
	validatePendingResult int64
	validatePendingErr    error
	markVerifiedErr       error
	recordFailAttempts    int
	recordFailErr         error
}

func (m *mockSessionStore) Create(ctx context.Context, userID int64, verified bool) (string, error) {
	m.createCalls++
	if m.createErr != nil {
		return "", m.createErr
	}
	return "mock-session-id", nil
}
func (m *mockSessionStore) Validate(ctx context.Context, sessionID string) (int64, string, error) {
	return m.validateResult, m.validateRole, m.validateErr
}
func (m *mockSessionStore) Invalidate(ctx context.Context, sessionID string) error {
	return m.invalidateErr
}
func (m *mockSessionStore) InvalidateAll(ctx context.Context, userID int64) error {
	return m.invalidateAllErr
}

func (m *mockSessionStore) ValidatePending(_ context.Context, _ string) (int64, error) {
	if m.validatePendingErr != nil {
		return 0, m.validatePendingErr
	}
	return m.validatePendingResult, nil
}
func (m *mockSessionStore) MarkVerified(_ context.Context, _ string) error { return m.markVerifiedErr }
func (m *mockSessionStore) RecordTOTPFailure(_ context.Context, _ string) (int, error) {
	if m.recordFailErr != nil {
		return 0, m.recordFailErr
	}
	return m.recordFailAttempts, nil
}

func TestSessionRequired_MissingCookie(t *testing.T) {
	a := &authenticator{
		sessions: &mockSessionStore{},
		cookies:  cookieConfig{Path: "/"},
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
		cookies:  cookieConfig{Path: "/"},
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
		sessions: &mockSessionStore{validateResult: 42, validateRole: "user"},
		cookies:  cookieConfig{Path: "/"},
	}

	req := httptest.NewRequest("GET", "/v1/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "valid-session"})
	w := httptest.NewRecorder()

	var gotUserID int64
	var gotRole string
	handler := a.sessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID = userIDFromContext(r.Context())
		gotRole = roleFromContext(r.Context())
	}))

	handler.ServeHTTP(w, req)

	if gotUserID != 42 {
		t.Errorf("expected userID 42, got %d", gotUserID)
	}
	if gotRole != "user" {
		t.Errorf("expected role 'user', got %q", gotRole)
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestRoleRequired verifies >= admission: a session at or above the minimum
// passes, a lower-level session is rejected with 403. sessionRequired already
// returned 401 for no/invalid sessions, so roleRequired only ever emits 403.
func TestRoleRequired(t *testing.T) {
	a := &authenticator{}

	cases := []struct {
		name     string
		role     string
		minLevel int
		wantCode int
		wantCall bool
	}{
		{"admin admitted at admin gate", "admin", 2, http.StatusOK, true},
		{"superuser admitted at admin gate", "superuser", 2, http.StatusOK, true},
		{"user rejected at admin gate", "user", 2, http.StatusForbidden, false},
		{"new rejected at admin gate", "new", 2, http.StatusForbidden, false},
		{"superuser admitted at superuser gate", "superuser", 3, http.StatusOK, true},
		{"admin rejected at superuser gate", "admin", 3, http.StatusForbidden, false},
		{"empty role fails closed", "", 2, http.StatusForbidden, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := a.roleRequired(tc.minLevel)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			ctx := context.WithValue(context.Background(), ctxKeyRole{}, tc.role)
			req := httptest.NewRequest("GET", "/x", nil).WithContext(ctx)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if called != tc.wantCall {
				t.Errorf("next called = %v, want %v", called, tc.wantCall)
			}
			if w.Code != tc.wantCode {
				t.Errorf("status = %d, want %d", tc.wantCode, w.Code)
			}
		})
	}
}

// TestRoleRequired_Chain401 verifies the full sessionRequired -> roleRequired
// chain returns 401 (not 403) when there is no session, satisfying the
// "401 with no/invalid session" requirement.
func TestRoleRequired_Chain401(t *testing.T) {
	mw := NewMiddleware(&mockSessionStore{}, false)

	chain := mw.SessionRequired(mw.RoleRequired(2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not run without a session")
	})))

	req := httptest.NewRequest("GET", "/v1/admin/users", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no-session chain: got %d, want 401", w.Code)
	}
}

// findCookie returns the named cookie from the recorder, or fails the test.
func findCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Errorf("expected cookie %q in Set-Cookie: %v", name, w.Result().Header.Get("Set-Cookie"))
	return nil
}

func TestSetSessionCookie(t *testing.T) {
	a := &authenticator{cookies: cookieConfig{Path: "/", Secure: true, SameSite: http.SameSiteLaxMode}}

	w := httptest.NewRecorder()
	a.setSessionCookie(w, "sid-123")

	c := findCookie(t, w, sessionCookieName)
	if c == nil {
		return
	}
	if c.Value != "sid-123" {
		t.Errorf("Value = %q, want %q", c.Value, "sid-123")
	}
	if !c.HttpOnly {
		t.Error("cookie must be HttpOnly")
	}
	if !c.Secure {
		t.Error("cookie must be Secure in production mode")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want %v", c.SameSite, http.SameSiteLaxMode)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if c.MaxAge != int(sessionMaxAge.Seconds()) {
		t.Errorf("MaxAge = %d, want %d", c.MaxAge, int(sessionMaxAge.Seconds()))
	}
}

func TestSetSessionCookie_InsecureMode(t *testing.T) {
	a := &authenticator{cookies: cookieConfig{Path: "/", Secure: false, SameSite: http.SameSiteLaxMode}}

	w := httptest.NewRecorder()
	a.setSessionCookie(w, "sid-123")

	c := findCookie(t, w, sessionCookieName)
	if c == nil {
		return
	}
	if c.Secure {
		t.Error("cookie must not be Secure in non-production mode")
	}
}

func TestClearSessionCookie(t *testing.T) {
	a := &authenticator{cookies: cookieConfig{Path: "/", Secure: true, SameSite: http.SameSiteLaxMode}}

	w := httptest.NewRecorder()
	a.clearSessionCookie(w)

	c := findCookie(t, w, sessionCookieName)
	if c == nil {
		return
	}
	if c.Value != "" {
		t.Errorf("Value = %q, want empty (cleared)", c.Value)
	}
	if c.Path != "/" {
		t.Errorf("Path = %q, want %q", c.Path, "/")
	}
	if !c.HttpOnly {
		t.Error("cleared cookie must stay HttpOnly")
	}
}

func TestPendingSessionRequired(t *testing.T) {
	tests := []struct {
		name        string
		store       *mockSessionStore
		cookie      string
		wantStatus  int
		wantUserID  int64
		wantReached bool
		wantCode    string // expected machine code in the 401 body (2fa-plan Step 2)
	}{
		{
			name:        "no cookie",
			store:       &mockSessionStore{},
			wantStatus:  http.StatusUnauthorized,
			wantReached: false,
		},
		{
			name:        "not a pending session",
			store:       &mockSessionStore{validatePendingErr: ErrSessionNotFound},
			cookie:      "tenkei_session=whatever",
			wantStatus:  http.StatusUnauthorized,
			wantReached: false,
			wantCode:    "session_expired",
		},
		{
			name:        "infrastructure failure is 500 not 401",
			store:       &mockSessionStore{validatePendingErr: errNotSessionNotFound},
			cookie:      "tenkei_session=whatever",
			wantStatus:  http.StatusInternalServerError,
			wantReached: false,
		},
		{
			name:        "valid pending session",
			store:       &mockSessionStore{validatePendingResult: 42},
			cookie:      "tenkei_session=whatever",
			wantStatus:  http.StatusOK,
			wantUserID:  42,
			wantReached: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authenticator{sessions: tt.store, cookies: cookieConfigFor(false)}
			var reachedWith int64
			handler := a.pendingSessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reachedWith = UserIDFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/verify", nil)
			if tt.cookie != "" {
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "whatever"})
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantCode != "" {
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode 401 body: %v", err)
				}
				if body["code"] != tt.wantCode || body["error"] == "" {
					t.Errorf("body = %v, want code %q plus human error text", body, tt.wantCode)
				}
			}
			if tt.wantReached && reachedWith != tt.wantUserID {
				t.Errorf("handler saw userID %d, want %d", reachedWith, tt.wantUserID)
			}
		})
	}
}

// errNotSessionNotFound is a non-ErrSessionNotFound error: the middleware must surface
// it as 500, never mask an outage as "session expired".
var errNotSessionNotFound = errors.New("db is down")
