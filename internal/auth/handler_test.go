package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
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
		cookies:  cookieConfig{Path: "/", Secure: true, SameSite: http.SameSiteLaxMode},
	}
}

// assertSessionCookieSet fails unless the response carries a tenkei_session
// cookie with the given value, and returns it for further assertions.
func assertSessionCookieSet(t *testing.T, w *httptest.ResponseRecorder, value string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value == value {
			return c
		}
	}
	t.Errorf("expected tenkei_session cookie = %q, got Set-Cookie: %v", value, w.Result().Header.Get("Set-Cookie"))
	return nil
}

// assertSessionCookieCleared fails unless the response clears the
// tenkei_session cookie (empty value).
func assertSessionCookieCleared(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value == "" {
			return
		}
	}
	t.Errorf("expected tenkei_session cookie cleared (empty value), got Set-Cookie: %v", w.Result().Header.Get("Set-Cookie"))
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

	// Login must set the session cookie with the security attributes.
	c := assertSessionCookieSet(t, w, "mock-session-id")
	if c != nil {
		if !c.HttpOnly {
			t.Error("session cookie must be HttpOnly")
		}
		if c.Path != "/" {
			t.Errorf("session cookie Path = %q, want %q", c.Path, "/")
		}
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
	assertSessionCookieCleared(t, w)
}

// --- handleLogin error paths ---

func TestHandleLogin_InvalidJSON(t *testing.T) {
	a := newTestAuthenticator(&mockVerifier{}, &mockSessionStore{})

	body := `{bad json`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleLogin_VerifierError(t *testing.T) {
	a := newTestAuthenticator(&mockVerifier{err: errors.New("db exploded")}, &mockSessionStore{})

	body := `{"identifier":"test@example.com","password":"correctpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestHandleLogin_SessionCreateError(t *testing.T) {
	a := newTestAuthenticator(&mockVerifier{userID: 1}, &mockSessionStore{createErr: errors.New("boom")})

	body := `{"identifier":"test@example.com","password":"correctpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

// --- handleLogin audit (DB-backed) ---

// TestHandleLogin_SuccessIsAudited verifies a successful login writes an
// audit row bound to the real user id.
func TestHandleLogin_SuccessIsAudited(t *testing.T) {
	db := setupTestDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "audit-success@example.com", "+628500000010", string(hash))

	a := &authenticator{
		logger:   zerolog.Nop(),
		validate: validator.New(),
		db:       db,
		verifier: &mockVerifier{userID: userID},
		sessions: &mockSessionStore{},
		cookies:  cookieConfig{Path: "/", Secure: true, SameSite: http.SameSiteLaxMode},
	}

	body := `{"identifier":"audit-success@example.com","password":"testpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var count int
	err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = 'login'`, userID).Scan(t.Context(), &count)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 login audit row, got %d", count)
	}
}

// TestHandleLogin_FailureIsAudited verifies a failed login writes an audit row.
// Verify returns userID 0 for both "not found" and "wrong password" (anti-
// enumeration), so the row carries a NULL user_id rather than a bogus 0.
func TestHandleLogin_FailureIsAudited(t *testing.T) {
	db := setupTestDB(t)
	a := &authenticator{
		logger:   zerolog.Nop(),
		validate: validator.New(),
		db:       db,
		verifier: &mockVerifier{userID: 0, err: ErrInvalidCredentials},
		sessions: &mockSessionStore{},
		cookies:  cookieConfig{Path: "/"},
	}

	body := `{"identifier":"test@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// The audit table is append-only and shared across runs, so capture a
	// baseline before the act and assert the delta afterward.
	var before int
	if err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE action = 'login_failed' AND user_id IS NULL`).Scan(t.Context(), &before); err != nil {
		t.Fatalf("audit query (before): %v", err)
	}

	a.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	var after int
	if err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE action = 'login_failed' AND user_id IS NULL`).Scan(t.Context(), &after); err != nil {
		t.Fatalf("audit query (after): %v", err)
	}
	if after-before != 1 {
		t.Errorf("expected 1 new login_failed audit row with NULL user_id, got delta %d", after-before)
	}
}

// --- handleGetProfile / handleUpdateProfile (DB-backed) ---

// newDBTestAuthenticator builds an authenticator wired to the test database.
func newDBTestAuthenticator(t *testing.T) (*authenticator, *bun.DB) {
	t.Helper()
	db := setupTestDB(t)
	return &authenticator{
		logger:   zerolog.Nop(),
		validate: validator.New(),
		db:       db,
		cookies:  cookieConfig{Path: "/"},
	}, db
}

// withUserID injects a user ID into the request context, as sessionRequired does.
func withUserID(req *http.Request, userID int64) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ctxKeyUserID{}, userID))
}

func TestHandleGetProfile_Success(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "profile-get@example.com", "+628500000001", string(hash))

	req := withUserID(httptest.NewRequest("GET", "/v1/auth/profile", nil), userID)
	w := httptest.NewRecorder()
	a.handleGetProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "password_hash") {
		t.Error("response must never contain password_hash")
	}
	var profile ProfileResponse
	if err := json.NewDecoder(w.Body).Decode(&profile); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if profile.ID != userID {
		t.Errorf("id: got %d, want %d", profile.ID, userID)
	}
	if profile.Email != "profile-get@example.com" {
		t.Errorf("email: got %q", profile.Email)
	}
	if profile.WhatsApp != "+628500000001" {
		t.Errorf("whatsapp: got %q", profile.WhatsApp)
	}
}

func TestHandleGetProfile_NotFound(t *testing.T) {
	a, _ := newDBTestAuthenticator(t)

	req := withUserID(httptest.NewRequest("GET", "/v1/auth/profile", nil), 999999999)
	w := httptest.NewRecorder()
	a.handleGetProfile(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleUpdateProfile_Success(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "profile-upd@example.com", "+628500000002", string(hash))

	body := `{"name":"Updated Name","rank":"5th Kyu"}`
	req := withUserID(httptest.NewRequest("PUT", "/v1/auth/profile", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Verify the update landed in the DB.
	user, err := GetUserByID(t.Context(), a.db, userID)
	if err != nil {
		t.Fatalf("dbGetUserByID: %v", err)
	}
	if user.Name != "Updated Name" {
		t.Errorf("name: got %q", user.Name)
	}
	if user.Rank != "5th Kyu" {
		t.Errorf("rank: got %q", user.Rank)
	}

	// The update must be audited.
	var count int
	err = db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = 'profile_update'`, userID).Scan(t.Context(), &count)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 audit record, got %d", count)
	}
}

func TestHandleUpdateProfile_InvalidJSON(t *testing.T) {
	a, _ := newDBTestAuthenticator(t)

	req := withUserID(httptest.NewRequest("PUT", "/v1/auth/profile", strings.NewReader(`{bad`)), 1)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateProfile_ValidationError(t *testing.T) {
	a, _ := newDBTestAuthenticator(t)

	// Name over 255 chars fails DecodeAndValidate.
	body := `{"name":"` + strings.Repeat("a", 256) + `"}`
	req := withUserID(httptest.NewRequest("PUT", "/v1/auth/profile", strings.NewReader(body)), 1)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateProfile_InvalidRank(t *testing.T) {
	a, _ := newDBTestAuthenticator(t)

	body := `{"rank":"Black Belt Supreme"}`
	req := withUserID(httptest.NewRequest("PUT", "/v1/auth/profile", strings.NewReader(body)), 1)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleUpdateProfile_Conflict(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	_ = insertTestUser(t, db, "profile-conflict1@example.com", "+628500000003", string(hash))
	user2ID := insertTestUser(t, db, "profile-conflict2@example.com", "+628500000004", string(hash))

	// Try to steal user1's email.
	body := `{"email":"profile-conflict1@example.com"}`
	req := withUserID(httptest.NewRequest("PUT", "/v1/auth/profile", strings.NewReader(body)), user2ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", w.Code)
	}
}

func TestHandleLogout_InvalidateError(t *testing.T) {
	// Server-side invalidation failing must still clear the cookie and return 200.
	s := &mockSessionStore{invalidateErr: errors.New("db down")}
	a := newTestAuthenticator(nil, s)

	req := httptest.NewRequest("POST", "/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "test-session"})
	req = withUserID(req, 1)
	w := httptest.NewRecorder()

	a.handleLogout(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// The cookie must still be cleared client-side even though the server-side
	// invalidation failed — that is the whole point of this path.
	assertSessionCookieCleared(t, w)
}

func TestHandleLogoutAll_Success(t *testing.T) {
	db := setupTestDB(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "logout-all@example.com", "+628600000001", string(hash))

	// Two active sessions, as if logged in from two devices.
	store := NewDBSessionStore(db)
	s1, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("create session 1: %v", err)
	}
	s2, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("create session 2: %v", err)
	}

	a := &authenticator{
		logger:   zerolog.Nop(),
		validate: validator.New(),
		db:       db,
		sessions: store,
		cookies:  cookieConfig{Path: "/"},
	}

	req := withUserID(httptest.NewRequest("POST", "/v1/auth/logout-all", nil), userID)
	w := httptest.NewRecorder()
	a.handleLogoutAll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	assertSessionCookieCleared(t, w)

	// Both sessions must be gone from the DB.
	var count int
	err = db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE user_id = ? AND id IN (?, ?)`, userID, s1, s2).Scan(t.Context(), &count)
	if err != nil {
		t.Fatalf("sessions query: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 remaining sessions, got %d", count)
	}

	// The revocation must be audited.
	var auditCount int
	err = db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = 'logout_all'`, userID).Scan(t.Context(), &auditCount)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("expected 1 logout_all audit row, got %d", auditCount)
	}
}

func TestHandleLogoutAll_InvalidateAllError(t *testing.T) {
	s := &mockSessionStore{invalidateAllErr: errors.New("db down")}
	a := &authenticator{
		logger:   zerolog.Nop(),
		sessions: s,
		cookies:  cookieConfig{Path: "/"},
	}

	req := withUserID(httptest.NewRequest("POST", "/v1/auth/logout-all", nil), 1)
	w := httptest.NewRecorder()
	a.handleLogoutAll(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
	// Cookie must NOT be cleared on failure — the user must know revocation failed.
	if c := w.Result().Header.Get("Set-Cookie"); c != "" {
		t.Errorf("expected no Set-Cookie on failure, got %q", c)
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
