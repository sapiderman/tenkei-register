package register

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/mailer"
)

// fakeMailer is the register-package test double for mailer.Mailer.
// Thread-safe by design: the handler sends from two concurrent goroutines and
// the suite runs under -race.
type fakeMailer struct {
	mu      sync.Mutex
	sent    []mailer.Message
	failTo  map[string]error // recipient substring → scripted failure
	panicTo map[string]bool  // recipient substring → scripted panic
	delayTo map[string]time.Duration
}

func (f *fakeMailer) Send(_ context.Context, msg mailer.Message) error {
	// Sleep outside the lock so scripted delays overlap (tests parallel sends).
	for sub, d := range f.delayTo {
		if strings.Contains(msg.To, sub) {
			time.Sleep(d)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for sub := range f.panicTo {
		if strings.Contains(msg.To, sub) {
			panic("fakeMailer: scripted panic for " + sub)
		}
	}
	for sub, err := range f.failTo {
		if strings.Contains(msg.To, sub) {
			return err
		}
	}
	f.sent = append(f.sent, msg)
	return nil
}

// sentTo returns the recorded sends whose recipient contains sub.
func (f *fakeMailer) sentTo(sub string) []mailer.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []mailer.Message
	for _, m := range f.sent {
		if strings.Contains(m.To, sub) {
			out = append(out, m)
		}
	}
	return out
}

// emailFailActions returns audit actions (email_send_failed:*) for userID.
func emailFailActions(t *testing.T, reg *registrar, userID int64) []string {
	t.Helper()
	var actions []string
	err := reg.db.NewRaw(
		`SELECT action FROM audit WHERE user_id = ? AND action LIKE 'email_send_failed%'`,
		userID,
	).Scan(context.Background(), &actions)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return actions
}

// registeredUserID fetches the id for email, failing the test if absent.
func registeredUserID(t *testing.T, reg *registrar, email string) int64 {
	t.Helper()
	var id int64
	err := reg.db.NewRaw(`SELECT id FROM users WHERE email = ?`, email).
		Scan(context.Background(), &id)
	if err != nil {
		t.Fatalf("fetch user id: %v", err)
	}
	return id
}

// --- Handler email-path tests (require DB) ---

func TestHandleSubmission_EmailsSentOnSuccess(t *testing.T) {
	reg := newTestRegistrarDB(t)
	wipeUsers(t, reg.db, "mail-ok@example.com")
	fm := &fakeMailer{}
	reg.mailer = fm

	m := validPayloadMap()
	m["email"] = "mail-ok@example.com"
	if w := doJSONRequest(t, reg, marshalJSON(m)); w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, decodeError(t, w))
	}

	if got := fm.sentTo("mail-ok@example.com"); len(got) != 1 {
		t.Errorf("welcome email: got %d sends, want 1", len(got))
	} else if !strings.Contains(got[0].Subject, "Welcome") {
		t.Errorf("welcome subject: got %q", got[0].Subject)
	}
	if got := fm.sentTo("info@tenkeiaikidojo.org"); len(got) != 1 {
		t.Errorf("admin notice: got %d sends, want 1", len(got))
	} else if !strings.Contains(got[0].Subject, "New registration") {
		t.Errorf("admin subject: got %q", got[0].Subject)
	}

	// Success path writes no audit rows.
	uid := registeredUserID(t, reg, "mail-ok@example.com")
	if actions := emailFailActions(t, reg, uid); len(actions) != 0 {
		t.Errorf("success must not audit email failures, got %v", actions)
	}
}

func TestHandleSubmission_WelcomeFails_Still201_AdminStillSent_Audited(t *testing.T) {
	reg := newTestRegistrarDB(t)
	wipeUsers(t, reg.db, "mail-fail@example.com")
	fm := &fakeMailer{failTo: map[string]error{
		"mail-fail@example.com": &mailer.SendError{Category: mailer.CategoryAuth, Err: errFake},
	}}
	reg.mailer = fm

	m := validPayloadMap()
	m["email"] = "mail-fail@example.com"
	if w := doJSONRequest(t, reg, marshalJSON(m)); w.Code != http.StatusCreated {
		t.Fatalf("email failure must not block registration: got %d", w.Code)
	}

	// Independence: the admin notice still went out.
	if got := fm.sentTo("info@tenkeiaikidojo.org"); len(got) != 1 {
		t.Errorf("admin notice must still send, got %d", len(got))
	}

	uid := registeredUserID(t, reg, "mail-fail@example.com")
	actions := emailFailActions(t, reg, uid)
	if len(actions) != 1 || actions[0] != "email_send_failed:welcome:auth" {
		t.Errorf("audit: got %v, want [email_send_failed:welcome:auth]", actions)
	}
}

func TestHandleSubmission_AdminFails_Still201_WelcomeUnaffected(t *testing.T) {
	reg := newTestRegistrarDB(t)
	wipeUsers(t, reg.db, "mail-admin-fail@example.com")
	fm := &fakeMailer{failTo: map[string]error{
		"info@tenkeiaikidojo.org": &mailer.SendError{Category: mailer.CategoryNetwork, Err: errFake},
	}}
	reg.mailer = fm

	m := validPayloadMap()
	m["email"] = "mail-admin-fail@example.com"
	if w := doJSONRequest(t, reg, marshalJSON(m)); w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	if got := fm.sentTo("mail-admin-fail@example.com"); len(got) != 1 {
		t.Errorf("welcome must still send, got %d", len(got))
	}

	uid := registeredUserID(t, reg, "mail-admin-fail@example.com")
	actions := emailFailActions(t, reg, uid)
	if len(actions) != 1 || actions[0] != "email_send_failed:notify_admin:network" {
		t.Errorf("audit: got %v, want [email_send_failed:notify_admin:network]", actions)
	}
}

func TestHandleSubmission_SendPanics_Recovered_201_UnknownCategory(t *testing.T) {
	reg := newTestRegistrarDB(t)
	wipeUsers(t, reg.db, "mail-panic@example.com")
	fm := &fakeMailer{panicTo: map[string]bool{"mail-panic@example.com": true}}
	reg.mailer = fm

	m := validPayloadMap()
	m["email"] = "mail-panic@example.com"
	// If the panic escaped, this test (and the process) would die here.
	if w := doJSONRequest(t, reg, marshalJSON(m)); w.Code != http.StatusCreated {
		t.Fatalf("panic must not block registration: got %d", w.Code)
	}

	uid := registeredUserID(t, reg, "mail-panic@example.com")
	actions := emailFailActions(t, reg, uid)
	if len(actions) != 1 || actions[0] != "email_send_failed:welcome:unknown" {
		t.Errorf("audit: got %v, want [email_send_failed:welcome:unknown]", actions)
	}
}

// TestSendRegistrationEmails_ParallelOverlap proves the two sends overlap:
// called directly (no bcrypt/DB noise), two 150ms scripted delays must finish
// in ~150ms total — serialized sends would take ~300ms.
func TestSendRegistrationEmails_ParallelOverlap(t *testing.T) {
	reg := newTestRegistrar() // no DB: sendRegistrationEmails never audits here on success
	fm := &fakeMailer{delayTo: map[string]time.Duration{
		"test@example.com":        150 * time.Millisecond,
		"info@tenkeiaikidojo.org": 150 * time.Millisecond,
	}}
	reg.mailer = fm

	req := httptest.NewRequest("POST", "/v1/register/", nil)
	start := time.Now()
	reg.sendRegistrationEmails(req, testUser())
	elapsed := time.Since(start)

	if elapsed >= 290*time.Millisecond {
		t.Errorf("sends appear serialized: %v (want < 290ms for parallel 150ms sends)", elapsed)
	}
	if got := len(fm.sentTo("")); got != 2 {
		t.Errorf("both sends must complete, got %d", got)
	}
}

// TestHandleSubmission_DisabledMailer_NoAudits uses the real selection matrix
// (mailer.New disabled → no-op) end to end: registration still succeeds and
// no email failures are audited. The noop's drop-behavior itself is covered
// by TestNoopMailer in internal/mailer.
func TestHandleSubmission_DisabledMailer_NoAudits(t *testing.T) {
	reg := newTestRegistrarDB(t)
	wipeUsers(t, reg.db, "mail-off@example.com")
	// Swap in the real disabled implementation: sends are accepted and dropped.
	disabled, err := mailer.New(mailer.Config{Enabled: false}, reg.logger)
	if err != nil {
		t.Fatalf("mailer.New: %v", err)
	}
	reg.mailer = disabled

	m := validPayloadMap()
	m["email"] = "mail-off@example.com"
	if w := doJSONRequest(t, reg, marshalJSON(m)); w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	uid := registeredUserID(t, reg, "mail-off@example.com")
	if actions := emailFailActions(t, reg, uid); len(actions) != 0 {
		t.Errorf("disabled mailer must not audit, got %v", actions)
	}
}

// errFake is a stand-in underlying error for scripted SendErrors.
var errFake = errors.New("scripted failure")

// TestSendRegistrationEmails_BuildFailureAuditsBoth covers the message-build
// failure guards: broken templates mean no sends; audit writes are no-ops
// without a DB (auth.Audit nil-checks), so this runs DB-free.
func TestSendRegistrationEmails_BuildFailureAuditsBoth(t *testing.T) {
	var logBuf bytes.Buffer
	reg := newTestRegistrar()
	reg.logger = zerolog.New(&logBuf)
	broken := template.Must(template.New("broken").Parse(`{{index .Name 500}}`))
	reg.tmpl.welcomeSubject = broken
	reg.tmpl.adminSubject = broken
	fm := &fakeMailer{}
	reg.mailer = fm

	u := testUser()
	// Must not panic and must not send anything.
	reg.sendRegistrationEmails(httptest.NewRequest("POST", "/v1/register/", nil), u)
	if got := len(fm.sentTo("")); got != 0 {
		t.Errorf("build failure must not send, got %d", got)
	}

	// The welcome failure log must carry the masked intended recipient
	// (user.Email), never the zero-value welcome.To (which masks to "***").
	wantTo := maskAddress(u.Email)
	for _, line := range bytes.Split(bytes.TrimRight(logBuf.Bytes(), "\n"), []byte("\n")) {
		var rec struct {
			Email string `json:"email"`
			To    string `json:"to"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if rec.Email != "welcome" {
			continue
		}
		if rec.To != wantTo {
			t.Errorf("welcome failure to = %q, want %q (masked %q)", rec.To, wantTo, u.Email)
		}
		return
	}
	t.Errorf("no welcome failure log line in %q", logBuf.String())
}

// TestRecordEmailFailure_LogsCategoryNotRawError keeps provider error text
// (which can embed the recipient address, see mailer.SendError) out of logs:
// the log line must carry only the closed-set category and the masked
// recipient. DB-free: auth.Audit no-ops without a DB.
func TestRecordEmailFailure_LogsCategoryNotRawError(t *testing.T) {
	var logBuf bytes.Buffer
	reg := newTestRegistrar()
	reg.logger = zerolog.New(&logBuf)
	reg.mailer = &fakeMailer{failTo: map[string]error{
		// Resend-style error echoing the recipient in its message.
		"test@example.com": &mailer.SendError{
			Category: mailer.CategoryAuth,
			Err:      errors.New(`invalid to: "test@example.com" (resend api)`),
		},
	}}

	reg.sendRegistrationEmails(httptest.NewRequest("POST", "/v1/register/", nil), testUser())

	logs := logBuf.String()
	if strings.Contains(logs, "test@example.com") || strings.Contains(logs, "invalid to") {
		t.Errorf("raw error text leaked into logs: %q", logs)
	}

	var found bool
	for _, line := range bytes.Split(bytes.TrimRight(logBuf.Bytes(), "\n"), []byte("\n")) {
		var rec struct {
			Email    string `json:"email"`
			Category string `json:"category"`
			To       string `json:"to"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Email != "welcome" {
			continue
		}
		found = true
		if rec.Category != mailer.CategoryAuth {
			t.Errorf("category = %q, want %q", rec.Category, mailer.CategoryAuth)
		}
		if want := maskAddress("test@example.com"); rec.To != want {
			t.Errorf("to = %q, want %q", rec.To, want)
		}
		break
	}
	if !found {
		t.Errorf("no welcome failure log line in %q", logs)
	}
}

func TestMaskAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"user@example.com", "u**************m"},
		{"ab", "***"},
		{"a", "***"},
		{"", "***"},
	}
	for _, tc := range cases {
		if got := maskAddress(tc.in); got != tc.want {
			t.Errorf("maskAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
