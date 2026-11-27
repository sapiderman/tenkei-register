package attendance

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// setupTestDB connects to the test database or skips the test when no DB is
// available. Mirrors the pattern in internal/admin/testhelper_test.go.
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
// its id, and registers a cleanup that deletes the row (attendance rows
// cascade; audit rows do not) after the test.
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

// seedMember inserts a user whose name is unique per call, so tests can
// filter shared-database lists by name. Returns the id and the name.
func seedMember(t *testing.T, db *bun.DB, role string) (int64, string) {
	t.Helper()
	suffix := time.Now().UnixNano()
	name := fmt.Sprintf("Att Tester %d", suffix)
	return insertUser(t, db, name, fmt.Sprintf("att-%d@example.com", suffix), role), name
}

// seedRecord inserts a pending attendance row without location for userID.
func seedRecord(t *testing.T, db *bun.DB, userID int64, dojo, instructor string) int64 {
	t.Helper()
	rec, err := insertAttendance(t.Context(), db, userID, &LogRequest{Dojo: dojo, Instructor: instructor})
	if err != nil {
		t.Fatalf("seedRecord(%s): %v", dojo, err)
	}
	return rec.ID
}
