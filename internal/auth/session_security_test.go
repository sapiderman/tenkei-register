package auth

// Security-fix tests (findings.md #4, #8, #10 — session store hardening).
// All DB-backed tests skip cleanly without TENKEI_DATABASE_CONNECTION_STRING.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDBSessionStore_StoresHashedToken verifies #4: the at-rest session ID
// must be the SHA-256 of the bearer token, never the plaintext token.
func TestDBSessionStore_StoresHashedToken(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-hash@example.com", "+62899999991", hash)

	store := NewDBSessionStore(db)
	token, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	var storedID string
	err = db.NewRaw(`SELECT id FROM sessions WHERE user_id = ?`, userID).Scan(t.Context(), &storedID)
	if err != nil {
		t.Fatalf("read stored session row: %v", err)
	}

	sum := sha256.Sum256([]byte(token))
	want := hex.EncodeToString(sum[:])
	if storedID != want {
		t.Errorf("stored ID = %q, want SHA-256 hex %q", storedID, want)
	}
	if storedID == token {
		t.Error("stored ID must not equal the plaintext bearer token")
	}
}

// TestDBSessionStore_PurgeOnCreate verifies #10: creating a session removes
// already-expired rows, and never removes live ones.
func TestDBSessionStore_PurgeOnCreate(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-purge@example.com", "+62899999992", hash)

	expiredID := "expired-purge-0000000000000000000000000000000000000000000"
	liveID := "live-purge-0000000000000000000000000000000000000000000000001"
	_, _ = db.NewRaw(`DELETE FROM sessions WHERE id = ? OR id = ?`, expiredID, liveID).Exec(t.Context())
	if _, err := db.NewRaw(
		`INSERT INTO sessions (id, user_id, expires_at, verified) VALUES (?, ?, ?, true), (?, ?, ?, true)`,
		expiredID, userID, time.Now().Add(-1*time.Hour),
		liveID, userID, time.Now().Add(1*time.Hour),
	).Exec(t.Context()); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}

	store := NewDBSessionStore(db)
	if _, err := store.Create(t.Context(), userID, true); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	var n int
	if err := db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE id = ?`, expiredID).Scan(t.Context(), &n); err != nil {
		t.Fatalf("count expired: %v", err)
	}
	if n != 0 {
		t.Error("expired session must be purged by Create")
	}
	if err := db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE id = ?`, liveID).Scan(t.Context(), &n); err != nil {
		t.Fatalf("count live: %v", err)
	}
	if n != 1 {
		t.Error("live session must survive the purge")
	}
}

// TestDBSessionStore_ValidateDBErrorNotSessionNotFound verifies #8: an
// infrastructure failure must not masquerade as ErrSessionNotFound.
func TestDBSessionStore_ValidateDBErrorNotSessionNotFound(t *testing.T) {
	db := setupTestDB(t)

	store := NewDBSessionStore(db)
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	_, _, err := store.Validate(t.Context(), "whatever-token")
	if err == nil {
		t.Fatal("expected an error from a closed DB")
	}
	if errors.Is(err, ErrSessionNotFound) {
		t.Errorf("infrastructure error must not be ErrSessionNotFound, got %v", err)
	}
}

// TestSessionRequired_StoreErrorReturns500 verifies the middleware half of
// #8: a non-ErrSessionNotFound store failure yields 500, not 401.
func TestSessionRequired_StoreErrorReturns500(t *testing.T) {
	a := &authenticator{
		sessions: &mockSessionStore{validateErr: fmt.Errorf("db down")},
		cookies:  cookieConfig{Path: "/"},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/auth/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "some-token"})
	w := httptest.NewRecorder()

	called := false
	a.sessionRequired(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(w, req)

	if called {
		t.Error("next handler must not run on a store failure")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for store failure, got %d", w.Code)
	}
}
