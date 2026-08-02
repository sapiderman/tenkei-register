package database

import (
	"os"
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
