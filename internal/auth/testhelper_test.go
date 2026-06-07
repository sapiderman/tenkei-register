package auth

import (
	"database/sql"
	"os"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// setupTestDB creates a test database connection using TENKEI_DATABASE_CONNECTION_STRING.
// Returns nil and skips the test if the env var is unset or the database is unavailable.
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

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

// insertTestUser creates a test user and returns the user with its ID populated.
func insertTestUser(t *testing.T, db *bun.DB, email, whatsapp, passwordHash string) int64 {
	t.Helper()

	_, err := db.NewRaw(
		`INSERT INTO users (name, email, whatsapp_number, password_hash, role, consent_datastore)
		 VALUES (?, ?, ?, ?, 'user', true)
		 ON CONFLICT (whatsapp_number) DO UPDATE SET email = EXCLUDED.email, password_hash = EXCLUDED.password_hash
		 RETURNING id`,
		"Test User", email, whatsapp, passwordHash,
	).Exec(t.Context())
	if err != nil {
		t.Fatalf("insertTestUser: %v", err)
	}

	// Fetch the ID
	var id int64
	err = db.NewRaw(`SELECT id FROM users WHERE whatsapp_number = ?`, whatsapp).Scan(t.Context(), &id)
	if err != nil {
		t.Fatalf("insertTestUser fetch ID: %v", err)
	}

	t.Cleanup(func() {
		_, _ = db.NewRaw(`DELETE FROM audit WHERE user_id = ?`, id).Exec(t.Context())
		_, _ = db.NewRaw(`DELETE FROM sessions WHERE user_id = ?`, id).Exec(t.Context())
		_, _ = db.NewRaw(`DELETE FROM users WHERE id = ?`, id).Exec(t.Context())
	})

	return id
}
