package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// newTestResend points a ResendMailer at a httptest.Server standing in for
// the Resend API (same trick as register's turnstileVerifyURL).
func newTestResend(t *testing.T, timeout time.Duration, handler http.HandlerFunc) (*ResendMailer, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return &ResendMailer{apiKey: "re_test_key", from: "Tenkei <no-reply@tenkeiaikidojo.org>", timeout: timeout, baseURL: ts.URL}, ts
}

func TestResendMailer_SendSuccess_PayloadAndHeaders(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	m, _ := newTestResend(t, sendTimeout, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"email-123"}`))
	})

	err := m.Send(context.Background(), Message{
		To:      "new@example.com",
		Subject: "Welcome",
		HTML:    "<p>hi</p>",
		Text:    "hi",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotAuth != "Bearer re_test_key" {
		t.Errorf("Authorization: got %q", gotAuth)
	}
	for field, want := range map[string]any{
		"from":    "Tenkei <no-reply@tenkeiaikidojo.org>",
		"subject": "Welcome",
		"html":    "<p>hi</p>",
		"text":    "hi",
	} {
		if gotBody[field] != want {
			t.Errorf("payload %s: got %v, want %v", field, gotBody[field], want)
		}
	}
	if to, ok := gotBody["to"].([]any); !ok || len(to) != 1 || to[0] != "new@example.com" {
		t.Errorf("payload to: got %v", gotBody["to"])
	}
}

func TestResendMailer_CategoryMatrix(t *testing.T) {
	cases := []struct {
		name     string
		status   int  // handler status; 0 = server never responds meaningfully
		closeSrv bool // close server before send (connection refused)
		sleep    bool // handler sleeps past the timeout
		want     string
	}{
		{name: "401 is auth", status: http.StatusUnauthorized, want: CategoryAuth},
		{name: "403 is auth", status: http.StatusForbidden, want: CategoryAuth},
		{name: "400 is api", status: http.StatusBadRequest, want: CategoryAPI},
		{name: "429 is api", status: http.StatusTooManyRequests, want: CategoryAPI},
		{name: "500 is api", status: http.StatusInternalServerError, want: CategoryAPI},
		{name: "503 is api", status: http.StatusServiceUnavailable, want: CategoryAPI},
		{name: "connection refused is network", closeSrv: true, want: CategoryNetwork},
		{name: "deadline is timeout", sleep: true, want: CategoryTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, ts := newTestResend(t, 100*time.Millisecond, func(w http.ResponseWriter, _ *http.Request) {
				if tc.sleep {
					time.Sleep(300 * time.Millisecond)
					return
				}
				w.WriteHeader(tc.status)
			})
			if tc.closeSrv {
				ts.Close()
			}
			err := m.Send(context.Background(), Message{To: "x@example.com", Subject: "s", Text: "t"})
			if err == nil {
				t.Fatal("expected error")
			}
			if got := CategoryOf(err); got != tc.want {
				t.Errorf("category: got %q, want %q (err: %v)", got, tc.want, err)
			}
		})
	}
}

// TestResendMailer_TimeoutAppliesToSlowCallerContext proves the mailer owns
// the timeout: a caller context with no deadline still gets cut off.
func TestResendMailer_TimeoutAppliesToSlowCallerContext(t *testing.T) {
	m, _ := newTestResend(t, 100*time.Millisecond, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	})
	start := time.Now()
	err := m.Send(context.Background(), Message{To: "x@example.com"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if CategoryOf(err) != CategoryTimeout {
		t.Errorf("category: got %q, want timeout", CategoryOf(err))
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Errorf("send took %v, want ~100ms deadline", elapsed)
	}
}

func TestResendMailer_CanceledParentStillHonored(t *testing.T) {
	// A caller-canceled context fails fast with a non-success category; the
	// mailer never overrides an already-canceled context with its own deadline.
	m, _ := newTestResend(t, sendTimeout, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler must not be reached")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.Send(ctx, Message{To: "x@example.com"})
	if err == nil {
		t.Fatal("expected error on canceled context")
	}
}

func TestResendMailer_ZeroTimeoutFallsBackToDefault(t *testing.T) {
	// timeout=0 must fall back to the package default (branch), proven by a
	// fast success — we do not wait out the 5s default here.
	m, _ := newTestResend(t, 0, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"x"}`))
	})
	if err := m.Send(context.Background(), Message{To: "x@example.com"}); err != nil {
		t.Fatalf("Send with default timeout: %v", err)
	}
}

func TestResendMailer_InvalidBaseURLIsUnknown(t *testing.T) {
	m, _ := newTestResend(t, sendTimeout, func(w http.ResponseWriter, _ *http.Request) {}) //nolint:staticcheck // server unused: parse fails before any request
	m.baseURL = "://bad-url"                                                               // url.Parse: missing protocol scheme
	err := m.Send(context.Background(), Message{To: "x@example.com"})
	if err == nil {
		t.Fatal("expected error for unparseable base URL")
	}
	if CategoryOf(err) != CategoryUnknown {
		t.Errorf("category: got %q, want unknown", CategoryOf(err))
	}
}

func TestCategoryOf_NonSendErrorIsUnknown(t *testing.T) {
	if got := CategoryOf(context.Canceled); got != CategoryUnknown {
		t.Errorf("plain error: got %q, want unknown", got)
	}
	if got := CategoryOf(nil); got != CategoryUnknown {
		t.Errorf("nil: got %q, want unknown", got)
	}
}

func TestLogMailer_RendersWithoutNetwork(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	m := &LogMailer{logger: logger, from: "Tenkei <no-reply@tenkeiaikidojo.org>"}

	err := m.Send(context.Background(), Message{
		To: "dev@example.com", Subject: "Welcome to Tenkei", HTML: "<p>Hello</p>", Text: "Hello",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"dev@example.com", "Welcome to Tenkei", "<p>Hello</p>", "Hello", "not sent"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q: %s", want, out)
		}
	}
}

func TestNoopMailer(t *testing.T) {
	m := &noopMailer{}
	if err := m.Send(context.Background(), Message{To: "x@example.com"}); err != nil {
		t.Errorf("noop Send: %v", err)
	}
}

func TestNew_SelectionMatrix(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("disabled returns noop", func(t *testing.T) {
		m, err := New(Config{Enabled: false}, logger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := m.(*noopMailer); !ok {
			t.Errorf("want noopMailer, got %T", m)
		}
	})

	t.Run("enabled with key returns resend", func(t *testing.T) {
		m, err := New(Config{Enabled: true, APIKey: "k"}, logger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := m.(*ResendMailer); !ok {
			t.Errorf("want ResendMailer, got %T", m)
		}
	})

	t.Run("enabled keyless production errors", func(t *testing.T) {
		_, err := New(Config{Enabled: true, Production: true}, logger)
		if err == nil || !strings.Contains(err.Error(), "TENKEI_RESEND_API_KEY") {
			t.Fatalf("want key-missing error, got %v", err)
		}
	})

	t.Run("enabled keyless dev returns log mailer", func(t *testing.T) {
		m, err := New(Config{Enabled: true, Production: false}, logger)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := m.(*LogMailer); !ok {
			t.Errorf("want LogMailer, got %T", m)
		}
	})

	t.Run("whitespace key counts as missing", func(t *testing.T) {
		_, err := New(Config{Enabled: true, APIKey: "   ", Production: true}, logger)
		if err == nil {
			t.Fatal("want error for whitespace key")
		}
	})
}
