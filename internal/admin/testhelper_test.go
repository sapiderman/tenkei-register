package admin

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// setupTestDB connects to the test database or skips the test when no DB is
// available. Mirrors the pattern in internal/auth/testhelper_test.go.
func setupTestDB(t *testing.T) *bun.DB {
	t.Helper()

	dsn := os.Getenv("TENKEI_DATABASE_CONNECTION_STRING")
	if dsn == "" {
		t.Skip("skipping: TENKEI_DATABASE_CONNECTION_STRING not set")
		return nil
	}

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())

	if err := db.Ping(); err != nil {
		t.Skipf("skipping: cannot connect to PostgreSQL: %v", err)
		return nil
	}

	t.Cleanup(func() { db.Close() })
	return db
}

// insertUser creates a test user with the given role and unique email, returns
// its id, and registers a cleanup that deletes the row (and its audit/session
// children) after the test.
func insertUser(t *testing.T, db *bun.DB, name, email, role string) int64 {
	t.Helper()

	var id int64
	err := db.NewRaw(
		`INSERT INTO users (name, email, password_hash, role, consent_datastore)
		 VALUES (?, ?, 'x', ?, true)
		 RETURNING id`,
		name, email, role,
	).Scan(t.Context(), &id)
	if err != nil {
		t.Fatalf("insertUser(%s,%s,%s): %v", name, email, role, err)
	}

	// context.Background: t.Context is cancelled before Cleanup runs.
	t.Cleanup(func() {
		_, _ = db.NewRaw(`DELETE FROM audit WHERE user_id = ?`, id).Exec(context.Background())
		_, _ = db.NewRaw(`DELETE FROM sessions WHERE user_id = ?`, id).Exec(context.Background())
		_, _ = db.NewRaw(`DELETE FROM users WHERE id = ?`, id).Exec(context.Background())
	})

	return id
}

// seedSession inserts a verified, non-expired session for userID and returns
// its id. Used to assert session-invalidation behavior in role/verify tests.
func seedSession(t *testing.T, db *bun.DB, userID int64) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	sid := hex.EncodeToString(b)
	_, err := db.NewRaw(
		`INSERT INTO sessions (id, user_id, expires_at, verified) VALUES (?, ?, ?, true)`,
		sid, userID, time.Now().Add(time.Hour),
	).Exec(t.Context())
	if err != nil {
		t.Fatalf("seedSession: %v", err)
	}
	return sid
}

// sessionExists reports whether a session row with the given id is present.
func sessionExists(t *testing.T, db *bun.DB, sessionID string) bool {
	t.Helper()
	var n int
	if err := db.NewRaw(`SELECT COUNT(*) FROM sessions WHERE id = ?`, sessionID).Scan(t.Context(), &n); err != nil {
		t.Fatalf("sessionExists: %v", err)
	}
	return n > 0
}

// cleanupRoleTestLeftovers removes any superuser rows leaked from a prior
// interrupted role-test run. The last-superuser guard's invariant is global,
// so the lone/race tests must start from a known slate; within the admin test
// binary every such row carries a role-test email prefix (`role-%@example.com`),
// so this never touches another package's data.
func cleanupRoleTestLeftovers(t *testing.T, db *bun.DB) {
	t.Helper()
	if _, err := db.NewRaw(`DELETE FROM users WHERE role = 'superuser' AND email LIKE 'role-%@example.com'`).Exec(t.Context()); err != nil {
		t.Fatalf("cleanupRoleTestLeftovers: %v", err)
	}
}
