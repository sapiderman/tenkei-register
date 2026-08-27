package mailer

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

type fakeNetErr struct{}

func (fakeNetErr) Error() string   { return "fake net error" }
func (fakeNetErr) Timeout() bool   { return false }
func (fakeNetErr) Temporary() bool { return false }

// TestCategorize_ClosedSetBranches covers the direct categorize branches the
// HTTP-level tests cannot reach (bare net.Error, url.Error, canceled context,
// unknown fallback), pinning the closed-set contract.
func TestCategorize_ClosedSetBranches(t *testing.T) {
	ctx := context.Background()

	if got := categorize(ctx, fakeNetErr{}, 0); got != CategoryNetwork {
		t.Errorf("bare net.Error: got %q, want network", got)
	}
	if got := categorize(ctx, &url.Error{Op: "Post", Err: errors.New("boom")}, 0); got != CategoryNetwork {
		t.Errorf("url.Error: got %q, want network", got)
	}

	// Canceled (not deadline) context with no status: no matching branch —
	// unknown, never a misleading category.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if got := categorize(cctx, context.Canceled, 0); got != CategoryUnknown {
		t.Errorf("canceled: got %q, want unknown", got)
	}

	// Deadline check takes priority over a captured non-2xx status.
	dctx, dcancel := context.WithTimeout(ctx, time.Millisecond)
	dcancel()
	time.Sleep(2 * time.Millisecond)
	if got := categorize(dctx, context.DeadlineExceeded, 500); got != CategoryTimeout {
		t.Errorf("deadline over status: got %q, want timeout", got)
	}

	// Opaque error, no status: unknown.
	if got := categorize(ctx, errors.New("opaque"), 0); got != CategoryUnknown {
		t.Errorf("opaque: got %q, want unknown", got)
	}
}

func TestSendError_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("inner")
	se := &SendError{Category: CategoryAuth, Err: inner}
	if got := se.Error(); got != "email send failed (auth): inner" {
		t.Errorf("Error(): got %q", got)
	}
	if !errors.Is(se, inner) {
		t.Error("Unwrap: errors.Is must reach the inner error")
	}
}
