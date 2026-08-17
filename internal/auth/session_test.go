package auth

import (
	"testing"
	"time"
)

func TestGenerateSessionID(t *testing.T) {
	id1, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID() error: %v", err)
	}
	if len(id1) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Errorf("expected session ID length 64, got %d", len(id1))
	}

	id2, err := generateSessionID()
	if err != nil {
		t.Fatalf("generateSessionID() error: %v", err)
	}
	if id1 == id2 {
		t.Error("two consecutive session IDs must not be equal")
	}
}

func TestDBSessionStore_CRUD(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12" // dummy hash
	userID := insertTestUser(t, db, "session-crud@example.com", "+62844444444", hash)

	store := NewDBSessionStore(db)

	// Create
	sessionID, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if len(sessionID) != 64 {
		t.Errorf("expected session ID length 64, got %d", len(sessionID))
	}

	// Validate
	gotUserID, gotRole, err := store.Validate(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("expected userID %d, got %d", userID, gotUserID)
	}
	if gotRole != "user" {
		t.Errorf("expected role 'user', got %q", gotRole)
	}

	// Invalidate
	err = store.Invalidate(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("Invalidate() error: %v", err)
	}

	// Validate after invalidate — should fail
	_, _, err = store.Validate(t.Context(), sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound after invalidate, got %v", err)
	}
}

func TestDBSessionStore_InvalidateAll(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-invall@example.com", "+62855555555", hash)

	store := NewDBSessionStore(db)

	// Create multiple sessions
	id1, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	id2, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// InvalidateAll
	err = store.InvalidateAll(t.Context(), userID)
	if err != nil {
		t.Fatalf("InvalidateAll() error: %v", err)
	}

	// Both should be gone
	_, _, err = store.Validate(t.Context(), id1)
	if err != ErrSessionNotFound {
		t.Errorf("session1: expected ErrSessionNotFound, got %v", err)
	}
	_, _, err = store.Validate(t.Context(), id2)
	if err != ErrSessionNotFound {
		t.Errorf("session2: expected ErrSessionNotFound, got %v", err)
	}
}

func TestDBSessionStore_ExpiredSessionRejected(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-expired@example.com", "+62866666666", hash)

	// Insert a session that already expired
	sessionID := "expired-session-id-000000000000000000000000000000000000000000000"
	// Clean up any leftover session with this ID first
	_, _ = db.NewRaw(`DELETE FROM sessions WHERE id = ?`, sessionID).Exec(t.Context())

	_, err := db.NewRaw(
		`INSERT INTO sessions (id, user_id, expires_at, verified) VALUES (?, ?, ?, true)`,
		sessionID, userID, time.Now().Add(-1*time.Hour),
	).Exec(t.Context())
	if err != nil {
		t.Fatalf("insert expired session: %v", err)
	}

	store := NewDBSessionStore(db)
	_, _, err = store.Validate(t.Context(), sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound for expired session, got %v", err)
	}
}

func TestDBSessionStore_UnverifiedSessionRejected(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-unverified@example.com", "+62877777777", hash)

	// Create a session with verified=false (2FA pending)
	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Validate should reject unverified sessions
	_, _, err = store.Validate(t.Context(), sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound for unverified session, got %v", err)
	}
}

// TestDBSessionStore_ValidateReturnsCurrentRole verifies the sessions⋈users
// join returns the user's current role, so an out-of-band role change takes
// effect on the very next request without reissuing the session.
func TestDBSessionStore_ValidateReturnsCurrentRole(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-role@example.com", "+62833333330", hash)

	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Initially 'user' (insertTestUser creates role='user').
	if _, role, err := store.Validate(t.Context(), sessionID); err != nil || role != "user" {
		t.Fatalf("initial role = %q, err = %v, want %q", role, err, "user")
	}

	// Flip the user's role out-of-band; the same session must now report it.
	if _, err := db.NewRaw(`UPDATE users SET role = 'admin' WHERE id = ?`, userID).Exec(t.Context()); err != nil {
		t.Fatalf("update role: %v", err)
	}

	_, role, err := store.Validate(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("Validate after role change: %v", err)
	}
	if role != "admin" {
		t.Errorf("role = %q, want %q (join must reflect the new role)", role, "admin")
	}
}
