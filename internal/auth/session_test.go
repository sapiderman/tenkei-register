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
	gotUserID, err := store.Validate(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("expected userID %d, got %d", userID, gotUserID)
	}

	// Invalidate
	err = store.Invalidate(t.Context(), sessionID)
	if err != nil {
		t.Fatalf("Invalidate() error: %v", err)
	}

	// Validate after invalidate — should fail
	_, err = store.Validate(t.Context(), sessionID)
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
	_, err = store.Validate(t.Context(), id1)
	if err != ErrSessionNotFound {
		t.Errorf("session1: expected ErrSessionNotFound, got %v", err)
	}
	_, err = store.Validate(t.Context(), id2)
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
	_, err = store.Validate(t.Context(), sessionID)
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
	_, err = store.Validate(t.Context(), sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound for unverified session, got %v", err)
	}
}
