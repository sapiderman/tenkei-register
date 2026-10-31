package database

import (
	"os"
	"strings"
	"testing"
)

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TENKEI_DATABASE_CONNECTION_STRING")
	if dsn == "" {
		t.Skip("skipping: TENKEI_DATABASE_CONNECTION_STRING not set")
	}
	return dsn
}

func TestNew_Success(t *testing.T) {
	db, err := New(testDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if db == nil || db.DB == nil {
		t.Fatal("expected non-nil Database and DB")
	}
	if db.GetDB() != db.DB {
		t.Error("GetDB() should return the underlying *bun.DB")
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestNew_AttachesQueryHook proves the DB New returns carries the query
// hook: WithQueryHook hooks a clone, so discarding its return value leaves
// the hook dead and this buffer empty.
func TestNew_AttachesQueryHook(t *testing.T) {
	buf := captureLog(t)
	db, err := New(testDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if _, err := db.DB.NewRaw("SELECT 1").Exec(t.Context()); err != nil {
		t.Fatalf("SELECT 1: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"level":"debug"`) || !strings.Contains(out, `"message":"SELECT"`) {
		t.Errorf("expected a debug log naming the SELECT operation, got: %s", out)
	}
}

func TestNew_InvalidDSN(t *testing.T) {
	// Loopback port 1 refuses instantly (TCP RST, nothing listening), so
	// Ping fails fast and this test never hangs or touches a real database.
	db, err := New("postgres://user:pass@127.0.0.1:1/db?sslmode=disable")
	if err == nil {
		t.Error("expected error for unreachable DSN")
	}
	if db != nil {
		t.Error("expected nil *Database on failure")
	}
}
