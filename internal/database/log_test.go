package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// captureLog swaps the package logger for a buffer-backed logger and restores
// the original when the test ends, so tests can assert on what was logged.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf).With().Timestamp().Logger()
	t.Cleanup(func() { log.Logger = orig })
	return &buf
}

func TestQueryHook_BeforeQuery(t *testing.T) {
	h := &queryHook{}
	ctx := context.Background()
	if got := h.BeforeQuery(ctx, &bun.QueryEvent{}); got != ctx {
		t.Errorf("BeforeQuery: got %v, want same ctx", got)
	}
}

func TestQueryHook_AfterQuery(t *testing.T) {
	h := &queryHook{}

	t.Run("success logs operation word, never SQL text", func(t *testing.T) {
		buf := captureLog(t)
		h.AfterQuery(context.Background(), &bun.QueryEvent{
			StartTime: time.Now(),
			Query:     "SELECT * FROM users WHERE email = 'leak@example.com'",
		})

		out := buf.String()
		if !strings.Contains(out, `"level":"debug"`) {
			t.Errorf("expected debug-level log, got: %s", out)
		}
		if !strings.Contains(out, `"message":"SELECT"`) {
			t.Errorf("expected operation word as the message, got: %s", out)
		}
		if strings.Contains(out, "leak@example.com") {
			t.Errorf("success log must not contain SQL text or values, got: %s", out)
		}
		if strings.Contains(out, `"level":"error"`) {
			t.Errorf("success path must not log at error level, got: %s", out)
		}
	})

	t.Run("non-pgdriver error logs error text, never SQL text", func(t *testing.T) {
		buf := captureLog(t)
		h.AfterQuery(context.Background(), &bun.QueryEvent{
			StartTime: time.Now().Add(-10 * time.Millisecond),
			Query:     "SELECT * FROM users WHERE email = 'leak@example.com'",
			Err:       errors.New("dial tcp 127.0.0.1:5451: i/o timeout"),
		})

		out := buf.String()
		if !strings.Contains(out, `"level":"error"`) {
			t.Errorf("expected error-level log, got: %s", out)
		}
		if !strings.Contains(out, `"error":"dial tcp 127.0.0.1:5451: i/o timeout"`) {
			t.Errorf("transport errors carry no member data and belong in the log, got: %s", out)
		}
		if strings.Contains(out, "leak@example.com") {
			t.Errorf("error log must not contain SQL text or values, got: %s", out)
		}
	})
}

// setupHookDB opens a bun DB with the query hook attached, or skips when no
// test database is reachable.
func setupHookDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("TENKEI_DATABASE_CONNECTION_STRING")
	if dsn == "" {
		t.Skip("skipping: TENKEI_DATABASE_CONNECTION_STRING not set")
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())
	db.AddQueryHook(&queryHook{})
	if err := db.Ping(); err != nil {
		t.Skipf("skipping: cannot connect to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// hookUser is a minimal users-table model so the test can drive the same
// NewInsert().Model() path production uses for registrations.
type hookUser struct {
	bun.BaseModel `bun:"users,alias:users"`

	Name              string `bun:"name,nullzero"`
	Email             string `bun:"email,nullzero"`
	WhatsAppNumber    string `bun:"whatsapp_number"`
	PasswordHash      string `bun:"password_hash"`
	Role              string `bun:"role"`
	ConsentDatastore  bool   `bun:"consent_datastore"`
	MedicalConditions string `bun:"medical_conditions,nullzero"`
}

// TestQueryHook_DBErrorLogsSqlstateNotPayload runs a real duplicate-email
// INSERT whose payload carries sentinel member values. The captured log must
// keep the operation word and the SQLSTATE while none of the values, nor the
// SQL text itself, appear. The successful seed INSERT must log equally clean.
func TestQueryHook_DBErrorLogsSqlstateNotPayload(t *testing.T) {
	db := setupHookDB(t)
	buf := captureLog(t)

	const (
		sentinelName  = "NAME-SENTINEL"
		sentinelEmail = "piisentinel@example.com"
		sentinelPhone = "+6281299887766"
	)
	newUser := func() *hookUser {
		return &hookUser{
			Name:              sentinelName,
			Email:             sentinelEmail,
			WhatsAppNumber:    sentinelPhone,
			PasswordHash:      "not-a-real-hash",
			Role:              "user",
			ConsentDatastore:  true,
			MedicalConditions: "MEDICAL-SENTINEL",
		}
	}

	if _, err := db.NewInsert().Model(newUser()).Exec(t.Context()); err != nil {
		t.Fatalf("seed insert: %v", err)
	}
	t.Cleanup(func() {
		// context.Background, not t.Context: the test context is cancelled by
		// the time cleanup runs, which would silently no-op this DELETE.
		if _, err := db.NewRaw(`DELETE FROM users WHERE email = ?`, sentinelEmail).Exec(context.Background()); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
	})

	if _, err := db.NewInsert().Model(newUser()).Exec(t.Context()); err == nil {
		t.Fatal("expected duplicate insert to fail")
	}

	out := buf.String()
	if !strings.Contains(out, `"sqlstate":"23505"`) {
		t.Errorf("expected sqlstate 23505 in the failure log, got: %s", out)
	}
	if !strings.Contains(out, `"message":"INSERT"`) {
		t.Errorf("expected operation word INSERT in the log, got: %s", out)
	}
	sentinels := []string{sentinelName, sentinelEmail, sentinelPhone, "MEDICAL-SENTINEL", "not-a-real-hash", "password_hash"}
	for _, s := range sentinels {
		if strings.Contains(out, s) {
			t.Errorf("member data %q leaked into the log, got: %s", s, out)
		}
	}
	if !strings.Contains(out, `"level":"debug"`) {
		t.Errorf("expected the successful seed insert to log at debug, got: %s", out)
	}
}
