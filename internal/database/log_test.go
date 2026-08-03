package database

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"
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

	t.Run("success logs at debug with query", func(t *testing.T) {
		buf := captureLog(t)
		h.AfterQuery(context.Background(), &bun.QueryEvent{StartTime: time.Now(), Query: "SELECT 2"})

		out := buf.String()
		if !strings.Contains(out, `"level":"debug"`) {
			t.Errorf("expected debug-level log, got: %s", out)
		}
		if !strings.Contains(out, "SELECT 2") {
			t.Errorf("expected query in log, got: %s", out)
		}
		if strings.Contains(out, `"level":"error"`) {
			t.Errorf("success path must not log at error level, got: %s", out)
		}
	})

	t.Run("error logs at error level with cause", func(t *testing.T) {
		buf := captureLog(t)
		h.AfterQuery(context.Background(), &bun.QueryEvent{
			StartTime: time.Now().Add(-10 * time.Millisecond),
			Query:     "SELECT 1",
			Err:       errors.New("boom"),
		})

		out := buf.String()
		if !strings.Contains(out, `"level":"error"`) {
			t.Errorf("expected error-level log, got: %s", out)
		}
		if !strings.Contains(out, `"error":"boom"`) {
			t.Errorf("expected error cause in log, got: %s", out)
		}
		if !strings.Contains(out, "SELECT 1") {
			t.Errorf("expected query in log, got: %s", out)
		}
	})
}
