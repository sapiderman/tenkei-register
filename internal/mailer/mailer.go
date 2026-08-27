// Package mailer sends transactional email. It is the single seam every
// outbound email flows through (today: registration notifications; future:
// forgot-password), so swapping providers means one new implementation and
// zero caller changes.
package mailer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/resend/resend-go/v4"
	"github.com/rs/zerolog"
)

// sendTimeout bounds every outbound send. The mailer owns the timeout so no
// caller can forget it or double-wrap it — Send applies it to whatever context
// it receives.
const sendTimeout = 5 * time.Second

// Message is one outbound email. Provider-agnostic: callers build it, the
// Mailer delivers it.
type Message struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// Mailer sends a Message. Implementations must be safe for concurrent use.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

// Failure categories — a closed, PII-free set written to audit rows so an
// outage is diagnosable from the audit table alone (expired key: "auth";
// Resend down: "network"; slow Resend: "timeout").
const (
	CategoryTimeout = "timeout"
	CategoryAuth    = "auth"
	CategoryNetwork = "network"
	CategoryAPI     = "api"
	CategoryUnknown = "unknown"
)

// Config selects the mailer implementation at startup. Fields map to
// TENKEI_MAILER_ENABLED / TENKEI_RESEND_API_KEY config keys.
type Config struct {
	Enabled    bool
	APIKey     string // #nosec G117 — never logged; absence is logged, never the value
	From       string // e.g. "Tenkei <no-reply@tenkeiaikidojo.org>"
	Production bool   // true when server mode is "production"
}

// New resolves the selection matrix:
//
//	disabled                → no-op mailer (Info log)
//	enabled + key           → ResendMailer
//	enabled + no key + prod → error (refuse to boot; silent no-mail production is worse)
//	enabled + no key + dev  → LogMailer (Warn log; renders emails, sends nothing)
func New(cfg Config, logger zerolog.Logger) (Mailer, error) {
	if !cfg.Enabled {
		logger.Info().Msg("mailer disabled (TENKEI_MAILER_ENABLED=false); no emails will be sent")
		return &noopMailer{}, nil
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		if cfg.Production {
			return nil, errors.New("mailer enabled but TENKEI_RESEND_API_KEY not configured - refusing to start")
		}
		logger.Warn().Msg("mailer enabled but TENKEI_RESEND_API_KEY not configured - using LogMailer (emails render to logs, nothing is sent)")
		return &LogMailer{logger: logger, from: cfg.From}, nil
	}
	logger.Info().Msg("mailer: ResendMailer active")
	return &ResendMailer{apiKey: cfg.APIKey, from: cfg.From, timeout: sendTimeout}, nil
}

// --- ResendMailer ---

// ResendMailer sends through the Resend HTTP API (resend-go SDK).
type ResendMailer struct {
	apiKey  string
	from    string
	timeout time.Duration
	baseURL string // test hook: overrides the API base URL (zero = real API)
}

// statusTransport captures the HTTP status of the single response it carries,
// so Send can categorize failures by status. Per-send instance — no locks
// needed. The SDK's own error types hide the status for 401/403/5xx
// (DefaultError carries only a message), so without this the "auth" category
// could never fire honestly.
type statusTransport struct {
	base   http.RoundTripper
	status *int
}

func (t *statusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if resp != nil {
		*t.status = resp.StatusCode
	}
	return resp, err
}

// SendError wraps a delivery failure with its category. Callers audit the
// category (a fixed enum, safe to store) and log the wrapped error (masked
// recipient, never raw in the audit row — Resend errors can embed addresses).
type SendError struct {
	Category string
	Err      error
}

func (e *SendError) Error() string { return "email send failed (" + e.Category + "): " + e.Err.Error() }
func (e *SendError) Unwrap() error { return e.Err }

// CategoryOf extracts the failure category from any error chain; non-SendError
// errors (e.g. a panic wrapped by a caller) map to "unknown".
func CategoryOf(err error) string {
	var se *SendError
	if errors.As(err, &se) {
		return se.Category
	}
	return CategoryUnknown
}

// Send delivers one email. It applies the mailer's timeout to the received
// context (callers pass a context detached from the request lifecycle — see
// register.sendRegistrationEmails), then maps any failure to a categorized
// SendError.
func (m *ResendMailer) Send(ctx context.Context, msg Message) error {
	timeout := m.timeout
	if timeout <= 0 {
		timeout = sendTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var status int
	client := resend.NewCustomClient(
		&http.Client{Transport: &statusTransport{base: http.DefaultTransport, status: &status}},
		m.apiKey,
	)
	if m.baseURL != "" {
		u, err := url.Parse(m.baseURL)
		if err != nil {
			return &SendError{Category: CategoryUnknown, Err: err}
		}
		client.BaseURL = u
	}

	_, err := client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    m.from,
		To:      []string{msg.To},
		Subject: msg.Subject,
		Html:    msg.HTML,
		Text:    msg.Text,
	})
	if err != nil {
		return &SendError{Category: categorize(ctx, err, status), Err: err}
	}
	return nil
}

// categorize maps a send failure to the closed category set. Priority: the
// deadline wins over any captured status (a response may exist but arrived
// too late to matter); then the captured HTTP status (401/403 = our key is
// bad; anything else non-2xx = API-side); then transport errors with no
// status at all = network.
func categorize(ctx context.Context, err error, status int) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return CategoryTimeout
	}
	if status != 0 {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return CategoryAuth
		}
		return CategoryAPI
	}
	var netErr net.Error
	// *url.Error itself implements net.Error, so this catches both bare
	// transport errors and the url.Error wrapper http.Client returns.
	if errors.As(err, &netErr) {
		return CategoryNetwork
	}
	return CategoryUnknown
}

// --- LogMailer ---

// LogMailer renders every message through zerolog instead of sending. Local
// development only (selected when the API key is absent outside production) —
// its whole job is letting a developer inspect rendered emails with no
// credentials and no network. Logs the full recipient and body by design.
type LogMailer struct {
	logger zerolog.Logger
	from   string
}

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.logger.Info().
		Str("from", m.from).
		Str("to", msg.To).
		Str("subject", msg.Subject).
		Str("text", msg.Text).
		Str("html", msg.HTML).
		Msg("email (LogMailer - rendered, not sent)")
	return nil
}

// --- noopMailer ---

// noopMailer is the disabled implementation: accepts every send, does nothing.
type noopMailer struct{}

func (*noopMailer) Send(context.Context, Message) error { return nil }
