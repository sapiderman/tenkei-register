package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/mailer"
	"github.com/sapiderman/tenkei-register/internal/turnstile"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// captureMailer records every sent message — the test double of LogMailer:
// the E2E flow "extracts the token from the mailer output" exactly as a
// developer would from the dev log. Sends are asynchronous in production
// (the 200 never waits), so tests use waitEmails to join the goroutine.
type captureMailer struct {
	mu   sync.Mutex
	sent []mailer.Message
}

func (m *captureMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

// count returns the number of captured emails.
func (m *captureMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// waitEmails polls until at least n emails have been captured or the
// deadline passes; returns the count seen.
func (m *captureMailer) waitEmails(n int) int {
	deadline := time.Now().Add(2 * time.Second)
	for m.count() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	return m.count()
}

// resetTestHarness wires a real DBPasswordResetter + authenticator over the
// scratch test database, with Turnstile disabled (bypass) and a capturing
// mailer in LogMailer's seat.
type resetTestHarness struct {
	db     *bun.DB
	mail   *captureMailer
	router chi.Router
	t      *testing.T
}

func newResetTestHarness(t *testing.T) *resetTestHarness {
	t.Helper()
	db := setupTestDB(t)
	mail := &captureMailer{}
	logger := zerolog.Nop()
	resetter := NewDBPasswordResetter(db, NewDBSessionStore(db), mail, logger, "https://web.test")
	a := &authenticator{
		logger:    logger,
		validate:  validator.New(),
		db:        db,
		resetter:  resetter,
		turnstile: turnstile.New("", false, logger), // disabled: bypass
	}
	r := chi.NewRouter()
	r.Post("/v1/auth/forgot-password", a.handleForgotPassword)
	r.Post("/v1/auth/reset-password", a.handleResetPassword)
	return &resetTestHarness{db: db, mail: mail, router: r, t: t}
}

// postReset sends a JSON POST through the harness router.
func (h *resetTestHarness) post(path, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

// lastResetToken pulls the plaintext token out of the newest captured reset
// email — the test equivalent of reading the LogMailer line in dev. Waits
// until at least minPrior+1 emails exist, so back-to-back requests each read
// their own (async-delivered) email.
func (h *resetTestHarness) lastResetToken(minPrior int) string {
	h.t.Helper()
	if h.mail.waitEmails(minPrior+1) <= minPrior {
		h.t.Fatal("no reset email was sent")
	}
	h.mail.mu.Lock()
	defer h.mail.mu.Unlock()
	text := h.mail.sent[len(h.mail.sent)-1].Text
	idx := strings.Index(text, "https://web.test/en/reset-password?token=")
	if idx < 0 {
		h.t.Fatalf("reset URL not found in email text: %q", text)
	}
	token := text[idx+len("https://web.test/en/reset-password?token="):]
	if i := strings.IndexAny(token, " \n\r\t"); i >= 0 {
		token = token[:i]
	}
	return token
}

// --- Store-level behavior (Phase 1 acceptance) ---

func TestRequestReset_StorePosture(t *testing.T) {
	h := newResetTestHarness(t)
	ctx := t.Context()
	userID := insertTestUser(t, h.db, "reset-a@test.dev", "+62811000001", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")
	r := NewDBPasswordResetter(h.db, NewDBSessionStore(h.db), h.mail, zerolog.Nop(), "https://web.test")

	before := time.Now()
	if err := r.RequestReset(ctx, "reset-a@test.dev"); err != nil {
		t.Fatalf("RequestReset: %v", err)
	}

	// Exactly one token row, and it stores only the SHA-256 hash: no
	// plaintext token anywhere at rest.
	var rows []PasswordResetToken
	if err := h.db.NewSelect().Model(&rows).Where("user_id = ?", userID).Scan(ctx, &rows); err != nil {
		t.Fatalf("select tokens: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d token rows, want 1", len(rows))
	}
	row := rows[0]
	if len(row.TokenHash) != 64 {
		t.Errorf("token_hash length = %d, want 64 (sha256 hex)", len(row.TokenHash))
	}
	if row.Consumed {
		t.Error("fresh token must not be consumed")
	}
	if !row.ExpiresAt.After(before.Add(9*time.Minute)) || !row.ExpiresAt.Before(before.Add(11*time.Minute)) {
		t.Errorf("expires_at not ~10 minutes out: %v", row.ExpiresAt)
	}
}

func TestRequestReset_SupersedeAndUnknownEmail(t *testing.T) {
	h := newResetTestHarness(t)
	ctx := t.Context()
	userID := insertTestUser(t, h.db, "reset-b@test.dev", "+62811000002", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")
	r := NewDBPasswordResetter(h.db, NewDBSessionStore(h.db), h.mail, zerolog.Nop(), "https://web.test")

	if err := r.RequestReset(ctx, "reset-b@test.dev"); err != nil {
		t.Fatalf("first RequestReset: %v", err)
	}
	first := h.lastResetToken(0)

	// Second request supersedes the first: only the newest token may later
	// be consumed.
	if err := r.RequestReset(ctx, "reset-b@test.dev"); err != nil {
		t.Fatalf("second RequestReset: %v", err)
	}
	second := h.lastResetToken(1)
	if first == second {
		t.Fatal("two requests produced the same token")
	}

	var count int
	if err := h.db.NewRaw(`SELECT count(*) FROM password_reset_tokens WHERE user_id = ?`, userID).Scan(ctx, &count); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 1 {
		t.Errorf("token rows after supersede = %d, want 1", count)
	}
	if err := r.ConfirmReset(ctx, first, "newpassword1"); !errors.Is(err, ErrResetTokenInvalid) {
		t.Errorf("superseded token: got %v, want ErrResetTokenInvalid", err)
	}

	// Unknown email: silent no-op — no error, no rows, no email. Give the
	// async send goroutine a beat to (incorrectly) fire before asserting.
	if err := r.RequestReset(ctx, "ghost@test.dev"); err != nil {
		t.Errorf("unknown email: got %v, want nil", err)
	}
	var total int
	if err := h.db.NewRaw(`SELECT count(*) FROM password_reset_tokens WHERE user_id = ?`, userID).Scan(ctx, &total); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if total != 1 {
		t.Errorf("token rows after unknown-email request = %d, want 1", total)
	}
	time.Sleep(100 * time.Millisecond)
	if got := h.mail.count(); got != 2 {
		t.Errorf("emails sent = %d, want 2 (no email for unknown address)", got)
	}
}

func TestRequestReset_OneLiveTokenPerUser(t *testing.T) {
	h := newResetTestHarness(t)
	ctx := t.Context()
	userID := insertTestUser(t, h.db, "reset-live@test.dev", "+62811000004", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")
	r := NewDBPasswordResetter(h.db, NewDBSessionStore(h.db), h.mail, zerolog.Nop(), "https://web.test")

	if err := r.RequestReset(ctx, "reset-live@test.dev"); err != nil {
		t.Fatalf("RequestReset: %v", err)
	}

	// The DB is the guard: a second unconsumed row for the same user must be
	// rejected — whether it comes from a concurrent request racing past the
	// delete, manual psql, or a future code path. This is the deterministic
	// stand-in for the concurrent-request race.
	_, err := h.db.NewInsert().Model(&PasswordResetToken{
		TokenHash: hashSessionID("competing-token"),
		UserID:    userID,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	}).Exec(ctx)
	if err == nil {
		t.Fatal("second live token inserted: unique index not enforced")
	}
	if !isUniqueViolation(err) {
		t.Fatalf("second insert: got %v, want a 23505 unique violation", err)
	}

	var live int
	if err := h.db.NewRaw(`SELECT count(*) FROM password_reset_tokens WHERE user_id = ? AND consumed = FALSE`, userID).Scan(ctx, &live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if live != 1 {
		t.Errorf("live token rows = %d, want 1", live)
	}

	// Consumed rows are outside the partial predicate: once the winner is
	// consumed, history rows may coexist.
	if _, err := h.db.NewUpdate().
		Model((*PasswordResetToken)(nil)).
		Where("user_id = ?", userID).
		Set("consumed = TRUE").
		Exec(ctx); err != nil {
		t.Fatalf("consume token: %v", err)
	}
	if _, err := h.db.NewInsert().Model(&PasswordResetToken{
		TokenHash: hashSessionID("after-consumption"),
		UserID:    userID,
		ExpiresAt: time.Now().Add(resetTokenTTL),
	}).Exec(ctx); err != nil {
		t.Fatalf("insert after consumption: %v", err)
	}
}

func TestConfirmReset_TokenStates(t *testing.T) {
	h := newResetTestHarness(t)
	ctx := t.Context()
	userID := insertTestUser(t, h.db, "reset-c@test.dev", "+62811000003", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")
	r := NewDBPasswordResetter(h.db, NewDBSessionStore(h.db), h.mail, zerolog.Nop(), "https://web.test")

	// Unknown token → invalid, without revealing whether anything existed.
	if err := r.ConfirmReset(ctx, strings.Repeat("a", 64), "newpassword1"); !errors.Is(err, ErrResetTokenInvalid) {
		t.Errorf("unknown token: got %v, want ErrResetTokenInvalid", err)
	}

	// Expired token (inserted directly with a past expiry).
	expiredHash := hashSessionID("expired-token-value")
	if _, err := h.db.NewInsert().Model(&PasswordResetToken{
		TokenHash: expiredHash, UserID: userID,
		ExpiresAt: time.Now().Add(-time.Minute),
	}).Exec(ctx); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	if err := r.ConfirmReset(ctx, "expired-token-value", "newpassword1"); !errors.Is(err, ErrResetTokenExpired) {
		t.Errorf("expired token: got %v, want ErrResetTokenExpired", err)
	}

	// Fresh token: single use — second consume reports used.
	if err := r.RequestReset(ctx, "reset-c@test.dev"); err != nil {
		t.Fatalf("RequestReset: %v", err)
	}
	token := h.lastResetToken(0)
	if err := r.ConfirmReset(ctx, token, "newpassword1"); err != nil {
		t.Fatalf("first ConfirmReset: %v", err)
	}
	if err := r.ConfirmReset(ctx, token, "newpassword2"); !errors.Is(err, ErrResetTokenUsed) {
		t.Errorf("second ConfirmReset: got %v, want ErrResetTokenUsed", err)
	}

	// Password actually rotated.
	var hash string
	if err := h.db.NewRaw(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(ctx, &hash); err != nil {
		t.Fatalf("fetch hash: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("newpassword1")) != nil {
		t.Error("password was not rotated to the new value")
	}

	// Sessions invalidated (audit via the sessions table: none may remain).
	var sessions int
	if err := h.db.NewRaw(`SELECT count(*) FROM sessions WHERE user_id = ?`, userID).Scan(ctx, &sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("sessions after reset = %d, want 0", sessions)
	}

	// Audit trail: request + completed events, attributable to the user.
	var audits []struct {
		Action string `bun:"action"`
	}
	if err := h.db.NewRaw(`SELECT action FROM audit WHERE user_id = ? AND action LIKE 'password_reset%' ORDER BY id`, userID).Scan(ctx, &audits); err != nil {
		t.Fatalf("fetch audits: %v", err)
	}
	if len(audits) != 2 || audits[0].Action != "password_reset_requested" || audits[1].Action != "password_reset_completed" {
		t.Errorf("audit trail = %+v, want [password_reset_requested password_reset_completed]", audits)
	}
}

// --- Handler-level mapping + full HTTP E2E (Phase 1 & 2 acceptance) ---

func TestForgotPasswordHandler_GenericPosture(t *testing.T) {
	h := newResetTestHarness(t)
	insertTestUser(t, h.db, "reset-d@test.dev", "+62811000004", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")

	known := h.post("/v1/auth/forgot-password", `{"email":"reset-d@test.dev","cf_turnstile_response":"bypassed"}`)
	unknown := h.post("/v1/auth/forgot-password", `{"email":"ghost@test.dev","cf_turnstile_response":"bypassed"}`)

	if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
		t.Fatalf("got %d/%d, want 200/200", known.Code, unknown.Code)
	}
	// Byte-identical responses: enumeration gets nothing from the body.
	if known.Body.String() != unknown.Body.String() {
		t.Errorf("responses differ:\nknown:   %q\nunknown: %q", known.Body.String(), unknown.Body.String())
	}
	if !strings.Contains(known.Body.String(), "If an account exists") {
		t.Errorf("generic message missing: %q", known.Body.String())
	}
}

func TestForgotPasswordHandler_TurnstileGates(t *testing.T) {
	// Turnstile enabled with a dummy secret: any token fails verification,
	// proving the gate fires before any DB work (harness has a nil-friendly
	// DB anyway, but the response must be the Turnstile 400, not a 500).
	db := setupTestDB(t)
	a := &authenticator{
		logger:    zerolog.Nop(),
		validate:  validator.New(),
		db:        db,
		resetter:  NewDBPasswordResetter(db, NewDBSessionStore(db), &captureMailer{}, zerolog.Nop(), "https://web.test"),
		turnstile: turnstile.New("dummy-secret", true, zerolog.Nop()), // enabled
	}
	r := chi.NewRouter()
	r.Post("/v1/auth/forgot-password", a.handleForgotPassword)

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{"email":"x@test.dev","cf_turnstile_response":"whatever"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400 from Turnstile gate", w.Code)
	}
}

func TestResetPasswordHandler_ErrorMatrix(t *testing.T) {
	h := newResetTestHarness(t)
	insertTestUser(t, h.db, "reset-e@test.dev", "+62811000005", "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6")

	cases := []struct {
		name string
		body string
		want int
		code string // JSON "code" field, when the error carries one
	}{
		{name: "short password", body: `{"token":"x","new_password":"short"}`, want: http.StatusBadRequest},
		{name: "long password", body: `{"token":"x","new_password":"` + strings.Repeat("a", 73) + `"}`, want: http.StatusBadRequest},
		{name: "unknown token", body: `{"token":"` + strings.Repeat("z", 64) + `","new_password":"validpassword1"}`, want: http.StatusBadRequest, code: "invalid_token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := h.post("/v1/auth/reset-password", tc.body)
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d (body: %s)", w.Code, tc.want, w.Body.String())
			}
			if tc.code == "" {
				return
			}
			var resp struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Code != tc.code {
				t.Errorf("code = %q, want %q", resp.Code, tc.code)
			}
		})
	}
}

// TestFullResetFlow_E2E is the runnable form of the CLI acceptance demo:
// forgot-password → extract token from the mailer → reset-password → login
// with the new password succeeds and the old password is dead.
func TestFullResetFlow_E2E(t *testing.T) {
	h := newResetTestHarness(t)
	ctx := t.Context()
	oldHash := "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6" // bcrypt of "oldpassword"
	userID := insertTestUser(t, h.db, "reset-f@test.dev", "+62811000006", oldHash)

	// A pre-existing session must be dead after the reset.
	sessionID, err := NewDBSessionStore(h.db).Create(ctx, userID, true)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// 1. Forgot.
	if w := h.post("/v1/auth/forgot-password", `{"email":"reset-f@test.dev","cf_turnstile_response":"bypassed"}`); w.Code != http.StatusOK {
		t.Fatalf("forgot: got %d", w.Code)
	}
	// 2. Extract token from the mailer (dev: LogMailer log line).
	token := h.lastResetToken(0)
	// 3. Reset.
	if w := h.post("/v1/auth/reset-password", `{"token":"`+token+`","new_password":"brandnewpw1"}`); w.Code != http.StatusOK {
		t.Fatalf("reset: got %d (body: %s)", w.Code, w.Body.String())
	}
	// 4. Login with the new password succeeds; old password rejected.
	v := NewBcryptVerifier(h.db)
	if _, _, err := v.Verify(ctx, "reset-f@test.dev", "brandnewpw1"); err != nil {
		t.Errorf("login with new password: %v", err)
	}
	if _, _, err := v.Verify(ctx, "reset-f@test.dev", "oldpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("login with old password: got %v, want ErrInvalidCredentials", err)
	}
	// 5. Every prior session is dead.
	if _, _, err := NewDBSessionStore(h.db).Validate(ctx, sessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("prior session: got %v, want ErrSessionNotFound", err)
	}
}
