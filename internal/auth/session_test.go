package auth

import (
	"sync"
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

// --- Pending (2FA) session primitives — otp-plan.md Phase 2 ---

func TestDBSessionStore_PendingSessionShortTTL(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-pending-ttl@example.com", "+62833333331", hash)

	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create(verified=false) error: %v", err)
	}

	// The row must expire within pendingSessionTTL (with a small clock-margin
	// allowance), not the full sessionMaxAge. Compared in SQL: pgdriver
	// cannot Scan a Postgres interval into a Go duration.
	var shortTTL bool
	err = db.NewRaw(
		`SELECT expires_at - NOW() <= ? * interval '1 second' FROM sessions WHERE id = ?`,
		int64((pendingSessionTTL+30*time.Second).Seconds()), hashSessionID(sessionID),
	).Scan(t.Context(), &shortTTL)
	if err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	if !shortTTL {
		t.Errorf("pending session must expire within pendingSessionTTL + 30s, not the full sessionMaxAge")
	}
}

func TestDBSessionStore_ValidateAndValidatePendingPartition(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-partition@example.com", "+62833333332", hash)

	store := NewDBSessionStore(db)

	// Pending session: Validate rejects, ValidatePending admits.
	pending, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create(verified=false): %v", err)
	}
	if _, _, err := store.Validate(t.Context(), pending); err != ErrSessionNotFound {
		t.Errorf("Validate(pending) = %v, want ErrSessionNotFound", err)
	}
	if got, err := store.ValidatePending(t.Context(), pending); err != nil || got != userID {
		t.Errorf("ValidatePending(pending) = (%d, %v), want (%d, nil)", got, err, userID)
	}

	// Verified session: Validate admits, ValidatePending rejects.
	verified, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create(verified=true): %v", err)
	}
	if _, err := store.ValidatePending(t.Context(), verified); err != ErrSessionNotFound {
		t.Errorf("ValidatePending(verified) = %v, want ErrSessionNotFound", err)
	}
	if _, _, err := store.Validate(t.Context(), verified); err != nil {
		t.Errorf("Validate(verified) = %v, want nil", err)
	}

	// Unknown session: both reject identically.
	if _, err := store.ValidatePending(t.Context(), "no-such-session"); err != ErrSessionNotFound {
		t.Errorf("ValidatePending(unknown) = %v, want ErrSessionNotFound", err)
	}
}

func TestDBSessionStore_RotatePending(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-rotate@example.com", "+62833333333", hash)

	store := NewDBSessionStore(db)
	pending, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create(verified=false): %v", err)
	}

	rotated, err := store.RotatePending(t.Context(), pending, userID)
	if err != nil {
		t.Fatalf("RotatePending: %v", err)
	}
	if rotated == pending {
		t.Fatal("rotation must mint a new token")
	}

	// The old pending token is dead on both paths: normal endpoints and the
	// verify endpoint itself (partitioned Validate/ValidatePending).
	if _, _, err := store.Validate(t.Context(), pending); err != ErrSessionNotFound {
		t.Errorf("Validate(old token) = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.ValidatePending(t.Context(), pending); err != ErrSessionNotFound {
		t.Errorf("ValidatePending(old token) = %v, want ErrSessionNotFound", err)
	}

	// The new token validates and was issued the full sessionMaxAge
	// (compared in SQL: pgdriver cannot Scan an interval into a Go duration).
	gotUserID, _, err := store.Validate(t.Context(), rotated)
	if err != nil || gotUserID != userID {
		t.Fatalf("Validate(rotated) = (%d, %v), want (%d, nil)", gotUserID, err, userID)
	}
	var extended bool
	if err := db.NewRaw(
		`SELECT expires_at - NOW() > ? * interval '1 second' FROM sessions WHERE id = ?`,
		int64((pendingSessionTTL+time.Hour).Seconds()), hashSessionID(rotated),
	).Scan(t.Context(), &extended); err != nil {
		t.Fatalf("read expires_at: %v", err)
	}
	if !extended {
		t.Errorf("expiry after rotation must exceed pendingSessionTTL + 1h (full sessionMaxAge)")
	}

	// Second rotation of the same pending token: nothing left to delete.
	if _, err := store.RotatePending(t.Context(), pending, userID); err != ErrSessionNotFound {
		t.Errorf("double RotatePending = %v, want ErrSessionNotFound", err)
	}
}

func TestDBSessionStore_RotatePendingExpiredPending(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-rotateexp@example.com", "+62833333334", hash)

	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Expire it out-of-band.
	if _, err := db.NewRaw(`UPDATE sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = ?`, hashSessionID(sessionID)).
		Exec(t.Context()); err != nil {
		t.Fatalf("expire session: %v", err)
	}

	// Rotation must not mint a full session for an expired pending: the
	// INSERT selects zero rows, and the user is left with exactly the one
	// (expired) row they started with.
	if _, err := store.RotatePending(t.Context(), sessionID, userID); err != ErrSessionNotFound {
		t.Errorf("RotatePending(expired) = %v, want ErrSessionNotFound", err)
	}
	var n int
	if err := db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE user_id = ?`, userID).
		Scan(t.Context(), &n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 1 {
		t.Errorf("sessions after failed rotation = %d, want 1 (no new row inserted)", n)
	}
}

func TestDBSessionStore_RecordTOTPFailure(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-attempts@example.com", "+62833333335", hash)

	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for want := 1; want <= 3; want++ {
		got, err := store.RecordTOTPFailure(t.Context(), sessionID)
		if err != nil {
			t.Fatalf("RecordTOTPFailure #%d: %v", want, err)
		}
		if got != want {
			t.Errorf("attempt #%d reported %d, want %d", want, got, want)
		}
	}

	// A verified session (or any nonexistent row) cannot be counted.
	verified, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("Create verified: %v", err)
	}
	if _, err := store.RecordTOTPFailure(t.Context(), verified); err != ErrSessionNotFound {
		t.Errorf("RecordTOTPFailure(verified) = %v, want ErrSessionNotFound", err)
	}
}

func TestDBSessionStore_RotatePendingConcurrent(t *testing.T) {
	db := setupTestDB(t)

	hash := "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12"
	userID := insertTestUser(t, db, "session-rotateconcurrent@example.com", "+62833333336", hash)

	store := NewDBSessionStore(db)
	sessionID, err := store.Create(t.Context(), userID, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Two concurrent rotations of the same pending session: exactly one
	// statement may delete the verified=FALSE row; losers get ErrSessionNotFound.
	const workers = 4
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.RotatePending(t.Context(), sessionID, userID)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	wins := 0
	for err := range results {
		switch err {
		case nil:
			wins++
		case ErrSessionNotFound:
			// loser — fine
		default:
			t.Fatalf("unexpected error from RotatePending: %v", err)
		}
	}
	if wins != 1 {
		t.Errorf("concurrent RotatePending: %d winners, want exactly 1", wins)
	}

	// Exactly one verified session row for the user; the pending row is gone.
	var verified int
	if err := db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE user_id = ? AND verified`, userID).
		Scan(t.Context(), &verified); err != nil {
		t.Fatalf("count verified sessions: %v", err)
	}
	if verified != 1 {
		t.Errorf("verified sessions after concurrent rotation = %d, want 1", verified)
	}
	if _, _, err := store.Validate(t.Context(), sessionID); err != ErrSessionNotFound {
		t.Errorf("Validate(old pending token) = %v, want ErrSessionNotFound", err)
	}
}
