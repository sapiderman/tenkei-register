package auth

// Tests for account self-deletion (PRD #25): POST /v1/auth/delete/request
// (email a 6-digit one-time code) and POST /v1/auth/delete (possession-based
// verification — TOTP when 2FA is on, emailed code when off; no password).
// DB-backed tests skip cleanly without a DSN.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	libtotp "github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/mailer"
	"github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/totp"
	"github.com/sapiderman/tenkei-register/internal/turnstile"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// deleteHarness wires a deletion-capable authenticator (real session store,
// disabled Turnstile, capturing mailer) over the scratch database. Direct
// handler calls (withUserID) cover behavior; the mounted router covers the
// session gate and rate limits.
type deleteHarness struct {
	db   *bun.DB
	auth *authenticator
	mail *captureMailer
	key  []byte // raw TOTP key matching auth.totpKey when 2FA is enabled
	t    *testing.T
	seq  int
}

func newDeleteHarness(t *testing.T, totpEnabled bool) (*deleteHarness, chi.Router) {
	t.Helper()
	db := setupTestDB(t)
	logger := zerolog.Nop()
	key := bytes.Repeat([]byte{0x7f}, 32)

	var totpKey []byte
	if totpEnabled {
		totpKey = key
	}
	a := &authenticator{
		logger:    logger,
		validate:  validator.New(),
		db:        db,
		sessions:  NewDBSessionStore(db),
		cookies:   cookieConfigFor(false),
		turnstile: turnstile.New("", false, logger), // disabled: bypass
		mailer:    &captureMailer{},
		delTmpl:   newDeletionTemplates(),
		totpKey:   totpKey,
	}
	h := &deleteHarness{db: db, auth: a, mail: a.mailer.(*captureMailer), t: t, key: key}

	r := chi.NewRouter()
	r.Route("/v1/auth", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.sessionRequired)
			r.With(middleware.RateLimit(5, 1*time.Minute)).Post("/delete/request", a.handleRequestDeletionCode)
			r.With(middleware.RateLimit(5, 1*time.Minute)).Post("/delete", a.handleDeleteAccount)
		})
	})
	return h, r
}

func (h *deleteHarness) nextWhatsApp() string {
	h.seq++
	return fmt.Sprintf("+628778%05d", h.seq)
}

func (h *deleteHarness) seedUser(email string) int64 {
	h.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.MinCost)
	if err != nil {
		h.t.Fatalf("bcrypt: %v", err)
	}
	return insertTestUser(h.t, h.db, email, h.nextWhatsApp(), string(hash))
}

// enableTOTP enrolls a fresh TOTP secret on the user row and returns the
// plaintext secret (mirrors twofactorHarness.seedTOTPUser).
func (h *deleteHarness) enableTOTP(userID int64, email string) string {
	h.t.Helper()
	key, err := libtotp.Generate(libtotp.GenerateOpts{Issuer: "Tenkei Aikidojo", AccountName: email})
	if err != nil {
		h.t.Fatalf("generate totp key: %v", err)
	}
	enc, err := totp.EncryptSecret(h.key, key.Secret())
	if err != nil {
		h.t.Fatalf("encrypt secret: %v", err)
	}
	if _, err := h.db.NewRaw(
		`UPDATE users SET totp_enabled = TRUE, totp_secret = ? WHERE id = ?`, enc, userID,
	).Exec(h.t.Context()); err != nil {
		h.t.Fatalf("enable totp: %v", err)
	}
	return key.Secret()
}

func (h *deleteHarness) totpCode(secret string) string {
	h.t.Helper()
	c, err := libtotp.GenerateCode(secret, time.Now())
	if err != nil {
		h.t.Fatalf("generate code: %v", err)
	}
	return c
}

// requestCode drives handleRequestDeletionCode directly (no rate limiter —
// behavior tests must not burn its 5/min budget).
func (h *deleteHarness) requestCode(userID int64) *httptest.ResponseRecorder {
	h.t.Helper()
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete/request", nil), userID)
	w := httptest.NewRecorder()
	h.auth.handleRequestDeletionCode(w, req)
	return w
}

// submitDelete drives handleDeleteAccount directly with the given JSON body.
func (h *deleteHarness) submitDelete(userID int64, body string) *httptest.ResponseRecorder {
	h.t.Helper()
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.auth.handleDeleteAccount(w, req)
	return w
}

var deletionCodeRe = regexp.MustCompile(`\b\d{6}\b`)

// lastCode extracts the 6-digit code out of the newest captured email —
// the test equivalent of reading the member's inbox.
func (h *deleteHarness) lastCode(minPrior int) string {
	h.t.Helper()
	if h.mail.waitEmails(minPrior+1) <= minPrior {
		h.t.Fatal("no deletion code email was sent")
	}
	h.mail.mu.Lock()
	defer h.mail.mu.Unlock()
	msg := h.mail.sent[len(h.mail.sent)-1]
	code := deletionCodeRe.FindString(msg.Text)
	if code == "" {
		h.t.Fatalf("no 6-digit code in email text: %q", msg.Text)
	}
	return code
}

// wrongCodeOf derives a code that is provably not the emailed one.
func wrongCodeOf(code string) string {
	n, _ := strconv.Atoi(code)
	return fmt.Sprintf("%06d", (n+1)%1000000)
}

func (h *deleteHarness) userExists(userID int64) bool {
	h.t.Helper()
	return h.db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(h.t.Context(), new(int)) == nil
}

// deletionAudits returns the user's audit actions in write order.
func (h *deleteHarness) deletionAudits(userID int64) []string {
	h.t.Helper()
	var rows []struct {
		Action string `bun:"action"`
	}
	if err := h.db.NewRaw(`SELECT action FROM audit WHERE user_id = ? ORDER BY id`, userID).Scan(h.t.Context(), &rows); err != nil {
		h.t.Fatalf("fetch audits: %v", err)
	}
	actions := make([]string, len(rows))
	for i, r := range rows {
		actions[i] = r.Action
	}
	return actions
}

// --- /delete/request ---

func TestDeleteRequest_IssuesAndEmailsCode(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-req@example.com")

	w := h.requestCode(userID)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "code sent") {
		t.Errorf("body = %q, want status code sent", w.Body.String())
	}

	code := h.lastCode(0)
	if code == "" || len(code) != 6 {
		t.Fatalf("emailed code = %q, want 6 digits", code)
	}

	// The email is addressed to the member and names the flow.
	h.mail.mu.Lock()
	msg := h.mail.sent[len(h.mail.sent)-1]
	h.mail.mu.Unlock()
	if msg.To != "del-req@example.com" {
		t.Errorf("email to = %q, want the member's address", msg.To)
	}
	if msg.Subject != "Your Tenkei account deletion code" {
		t.Errorf("subject = %q", msg.Subject)
	}

	// At rest: one live row, hash only — the plaintext code never lands.
	var rows []AccountDeletionCode
	if err := h.db.NewSelect().Model(&rows).Where("user_id = ?", userID).Scan(t.Context(), &rows); err != nil {
		t.Fatalf("select codes: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("code rows = %d, want 1", len(rows))
	}
	if len(rows[0].CodeHash) != 64 || rows[0].CodeHash == hashSessionID("") {
		t.Errorf("code_hash must be a sha256 hex of the code, got %q", rows[0].CodeHash)
	}
	if rows[0].CodeHash == code {
		t.Error("plaintext code must not be stored")
	}

	// The request is auditable before any delivery outcome exists.
	if got := h.deletionAudits(userID); len(got) != 1 || got[0] != "deletion_code_requested:email=del-req@example.com" {
		t.Errorf("audits = %v, want [deletion_code_requested:email=del-req@example.com]", got)
	}
}

func TestDeleteRequest_SupersedesPriorCode(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-sup@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("first request: %d", w.Code)
	}
	first := h.lastCode(0)
	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("second request: %d", w.Code)
	}
	second := h.lastCode(1)
	if first == second {
		t.Fatal("two requests produced the same code")
	}

	var live int
	if err := h.db.NewRaw(`SELECT count(*) FROM account_deletion_codes WHERE user_id = ?`, userID).Scan(t.Context(), &live); err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if live != 1 {
		t.Errorf("code rows after supersede = %d, want 1", live)
	}

	// The superseded code is dead; the newest one deletes the account.
	if w := h.submitDelete(userID, `{"code":"`+first+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("old code: got %d, want 400", w.Code)
	}
	if !h.userExists(userID) {
		t.Fatal("user must survive a superseded-code attempt")
	}
	if w := h.submitDelete(userID, `{"code":"`+second+`"}`); w.Code != http.StatusOK {
		t.Errorf("new code: got %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	if h.userExists(userID) {
		t.Error("user row must be deleted")
	}
}

func TestDeleteRequest_TOTPEnabledGuard(t *testing.T) {
	h, _ := newDeleteHarness(t, true)
	userID := h.seedUser("del-totp-guard@example.com")
	h.enableTOTP(userID, "del-totp-guard@example.com")

	w := h.requestCode(userID)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for TOTP-enabled member, got %d: %s", w.Code, w.Body.String())
	}
	if got := h.mail.count(); got != 0 {
		t.Errorf("emails sent = %d, want 0 (guard fires before issue/send)", got)
	}
	var count int
	if err := h.db.NewRaw(`SELECT count(*) FROM account_deletion_codes WHERE user_id = ?`, userID).Scan(t.Context(), &count); err != nil {
		t.Fatalf("count codes: %v", err)
	}
	if count != 0 {
		t.Errorf("code rows = %d, want 0", count)
	}
}

func TestDeleteRequest_RateLimited(t *testing.T) {
	h, r := newDeleteHarness(t, false)
	userID := h.seedUser("del-rate@example.com")

	session, err := NewDBSessionStore(h.db).Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/delete/request", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for i := 1; i <= 5; i++ {
		if code := post(); code == http.StatusTooManyRequests {
			t.Fatalf("request %d of 5 rate-limited early", i)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("6th request = %d, want 429 (rate limit 5/min)", code)
	}
}

func TestDeleteRoutes_RequireSession(t *testing.T) {
	h, r := newDeleteHarness(t, false)
	_ = h.seedUser("del-nosession@example.com")

	for _, path := range []string{"/v1/auth/delete/request", "/v1/auth/delete"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s without session = %d, want 401", path, w.Code)
		}
	}
}

// --- /delete: emailed-code path ---

func TestDelete_EmailedCode_Success(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-ok@example.com")

	store := NewDBSessionStore(h.db)
	session, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	code := h.lastCode(0)

	w := h.submitDelete(userID, `{"code":"`+code+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if h.userExists(userID) {
		t.Error("user row must be deleted")
	}
	if _, _, err := store.Validate(t.Context(), session); err == nil {
		t.Error("session must be invalidated by the user delete cascade")
	}

	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected the session cookie to be cleared after deletion")
	}

	// The audit trail is the surviving record: request + erasure, email only.
	audits := h.deletionAudits(userID)
	if len(audits) != 2 || audits[0] != "deletion_code_requested:email=del-ok@example.com" || audits[1] != "data_deletion:email=del-ok@example.com" {
		t.Errorf("audits = %v, want [deletion_code_requested:email=del-ok@example.com data_deletion:email=del-ok@example.com]", audits)
	}
}

func TestDelete_EmailedCode_WrongCode(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-wrong@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	code := h.lastCode(0)

	w := h.submitDelete(userID, `{"code":"`+wrongCodeOf(code)+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid code") {
		t.Errorf("body = %q, want plain invalid code", w.Body.String())
	}
	if !h.userExists(userID) {
		t.Error("user row must survive a rejected deletion")
	}

	if got := h.deletionAudits(userID); len(got) != 2 || got[1] != "data_deletion_rejected:email=del-wrong@example.com" {
		t.Errorf("audits = %v, want rejected row after the request row", got)
	}
}

func TestDelete_EmailedCode_FiveWrongTriesKillTheCode(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-exhaust@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	code := h.lastCode(0)

	for i := 1; i <= 5; i++ {
		if w := h.submitDelete(userID, `{"code":"`+wrongCodeOf(code)+`"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("wrong try %d = %d, want 400", i, w.Code)
		}
	}

	// The real code can no longer win: the attempt budget is spent.
	if w := h.submitDelete(userID, `{"code":"`+code+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("correct code after 5 wrong tries = %d, want 400 (code dead)", w.Code)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive an exhausted code")
	}

	// Two more wrong tries past the budget: the counter stays capped at 5,
	// the dead code keeps answering 400.
	for i := 0; i < 2; i++ {
		if w := h.submitDelete(userID, `{"code":"`+wrongCodeOf(code)+`"}`); w.Code != http.StatusBadRequest {
			t.Fatalf("post-exhaustion try %d = %d, want 400", i, w.Code)
		}
	}
	var attempts int
	if err := h.db.NewRaw(`SELECT attempts FROM account_deletion_codes WHERE user_id = ?`, userID).Scan(t.Context(), &attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != maxDeletionCodeAttempts {
		t.Errorf("attempts = %d, want %d (capped, no writes past the budget)", attempts, maxDeletionCodeAttempts)
	}

	var rejected int
	for _, a := range h.deletionAudits(userID) {
		if a == "data_deletion_rejected:email=del-exhaust@example.com" {
			rejected++
		}
	}
	if rejected != 8 {
		t.Errorf("rejected audit rows = %d, want 8 (five wrong + one dead-code try + two past the budget)", rejected)
	}
}

// TestDelete_VerifyInfraError_Fails500 pins the infra-failure contract: a DB
// error during code verification is a 500 with its own audit key, never a
// wrong-code 400 and never a rejection audit.
func TestDelete_VerifyInfraError_Fails500(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-infra@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	code := h.lastCode(0)

	// Break the code table so the consume UPDATE errors on a missing column.
	// Cleanup uses context.Background(): t.Context() is already canceled by
	// the time cleanup functions run, which would silently skip the restore.
	if _, err := h.db.NewRaw(`ALTER TABLE account_deletion_codes DROP COLUMN attempts`).Exec(t.Context()); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	t.Cleanup(func() {
		if _, err := h.db.NewRaw(`ALTER TABLE account_deletion_codes ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0`).Exec(context.Background()); err != nil {
			t.Errorf("restore attempts column: %v", err)
		}
	})

	w := h.submitDelete(userID, `{"code":"`+code+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("verify with broken table = %d, want 500", w.Code)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive an infra failure")
	}
	for _, a := range h.deletionAudits(userID) {
		if a == "data_deletion_error:email=del-infra@example.com" {
			return // pass
		}
	}
	t.Errorf("audits %v lack data_deletion_error:email=del-infra@example.com", h.deletionAudits(userID))
}

func TestDelete_EmailedCode_Expired(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-expired@example.com")

	// Seed an expired code directly (known plaintext, past expiry).
	if _, err := h.db.NewInsert().Model(&AccountDeletionCode{
		CodeHash:  hashSessionID("314159"),
		UserID:    userID,
		ExpiresAt: time.Now().Add(-time.Minute),
	}).Exec(t.Context()); err != nil {
		t.Fatalf("insert expired code: %v", err)
	}

	if w := h.submitDelete(userID, `{"code":"314159"}`); w.Code != http.StatusBadRequest {
		t.Errorf("expired code = %d, want 400", w.Code)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive an expired code")
	}
	if got := h.deletionAudits(userID); len(got) != 1 || got[0] != "data_deletion_rejected:email=del-expired@example.com" {
		t.Errorf("audits = %v, want [data_deletion_rejected:email=del-expired@example.com]", got)
	}
}

func TestDelete_EmailedCode_ConsumedReplay(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-replay@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	code := h.lastCode(0)

	// Burn the code without deleting the user, then replay it: the second
	// submit must fail exactly like a wrong code (single-use).
	if ok, err := consumeDeletionCode(t.Context(), h.db, userID, code); err != nil || !ok {
		t.Fatalf("first consume of a fresh code must succeed: ok=%v err=%v", ok, err)
	}
	if w := h.submitDelete(userID, `{"code":"`+code+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("replayed code = %d, want 400", w.Code)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive a code replay")
	}
}

func TestDelete_OneLiveCodePerUser(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-unique@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}

	// The DB is the guard: a second live row for the same user must be
	// rejected, whether it comes from a concurrent request racing past the
	// delete or a future code path.
	_, err := h.db.NewInsert().Model(&AccountDeletionCode{
		CodeHash:  hashSessionID("competing-code"),
		UserID:    userID,
		ExpiresAt: time.Now().Add(deletionCodeTTL),
	}).Exec(t.Context())
	if err == nil {
		t.Fatal("second live code inserted: unique index not enforced")
	}
	if !isUniqueViolation(err) {
		t.Fatalf("second insert: got %v, want a 23505 unique violation", err)
	}
}

// A delivery failure must be swallowed end to end: the request still
// answers 200, and the audit table carries the categorized failure row
// (mirrors TestRequestReset_FailingMailerSwallowed).
func TestDeleteRequest_FailingMailerSwallowed(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-mailfail@example.com")
	h.auth.mailer = &failingMailer{err: &mailer.SendError{Category: mailer.CategoryNetwork, Err: errors.New("connection refused")}}

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request with failing mailer = %d, want 200", w.Code)
	}
	if got := h.deletionAudits(userID); len(got) != 2 ||
		got[0] != "deletion_code_requested:email=del-mailfail@example.com" ||
		got[1] != "email_send_failed:deletion_code:network" {
		t.Errorf("audits = %v, want [deletion_code_requested:email=del-mailfail@example.com email_send_failed:deletion_code:network]", got)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive a failed email send")
	}
}

// --- /delete: TOTP path ---

func TestDelete_TOTPPath(t *testing.T) {
	h, _ := newDeleteHarness(t, true)
	userID := h.seedUser("del-totp@example.com")
	secret := h.enableTOTP(userID, "del-totp@example.com")

	// Bad code → 400 + rejected audit, user intact.
	wrong := "000000"
	if code := h.totpCode(secret); wrong == code {
		wrong = "111111"
	}
	if w := h.submitDelete(userID, `{"code":"`+wrong+`"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong TOTP code = %d, want 400", w.Code)
	}
	if !h.userExists(userID) {
		t.Fatal("user row must survive a wrong TOTP code")
	}
	if got := h.deletionAudits(userID); len(got) != 1 || got[0] != "data_deletion_rejected:email=del-totp@example.com" {
		t.Errorf("audits = %v, want [data_deletion_rejected:email=del-totp@example.com]", got)
	}

	// Valid code → 200, user gone.
	code := h.totpCode(secret)
	if w := h.submitDelete(userID, `{"code":"`+code+`"}`); w.Code != http.StatusOK {
		t.Fatalf("valid TOTP code = %d (body %s), want 200", w.Code, w.Body.String())
	}
	if h.userExists(userID) {
		t.Error("user row must be deleted after a valid TOTP code")
	}
}

// Kill switch off (totpKey == nil): a TOTP-enabled member falls back to the
// emailed code — same posture as login while the switch is off.
func TestDelete_TOTPKillSwitchOffFallsToEmail(t *testing.T) {
	h, _ := newDeleteHarness(t, false) // totpEnabled=false → totpKey nil
	userID := h.seedUser("del-switch@example.com")
	h.enableTOTP(userID, "del-switch@example.com")

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code for TOTP-enrolled member under kill switch: %d", w.Code)
	}
	code := h.lastCode(0)
	if w := h.submitDelete(userID, `{"code":"`+code+`"}`); w.Code != http.StatusOK {
		t.Fatalf("delete with emailed code = %d, want 200", w.Code)
	}
	if h.userExists(userID) {
		t.Error("user row must be deleted via the emailed-code path")
	}
}

// --- API contract guard: password is gone from the payload ---

func TestDelete_PasswordPayloadRejected(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	userID := h.seedUser("del-password@example.com")

	// current_password is no longer a known field — DisallowUnknownFields
	// answers 400 before any verification could run.
	w := h.submitDelete(userID, `{"current_password":"testpassword"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("password-only payload = %d, want 400", w.Code)
	}
	if !h.userExists(userID) {
		t.Error("user row must survive a rejected payload")
	}

	// And the code alone no longer pairs with a password.
	w = h.submitDelete(userID, `{"code":"123456","current_password":"testpassword"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("code+password payload = %d, want 400", w.Code)
	}
}

// --- audit hygiene: email is the only PII in any deletion action string ---

func TestDelete_AuditActionsCarryEmailOnly(t *testing.T) {
	h, _ := newDeleteHarness(t, false)
	whatsapp := h.nextWhatsApp()
	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(h.t, h.db, "del-pii@example.com", whatsapp, string(hash))

	if w := h.requestCode(userID); w.Code != http.StatusOK {
		t.Fatalf("request code: %d", w.Code)
	}
	if w := h.submitDelete(userID, `{"code":"000000"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: %d", w.Code)
	}
	code := h.lastCode(0)
	if w := h.submitDelete(userID, `{"code":"`+code+`"}`); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}

	allowed := map[string]bool{
		"deletion_code_requested:email=del-pii@example.com": true,
		"data_deletion_rejected:email=del-pii@example.com":  true,
		"data_deletion:email=del-pii@example.com":           true,
	}
	for _, a := range h.deletionAudits(userID) {
		if !allowed[a] {
			t.Errorf("unexpected audit action %q (only exact email-carrying forms are allowed)", a)
		}
		if strings.Contains(a, whatsapp) {
			t.Errorf("audit action leaks the WhatsApp number: %q", a)
		}
	}
}

// --- code generator shape ---

func TestGenerateDeletionCode_Shape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		code, err := generateDeletionCode()
		if err != nil {
			t.Fatalf("generateDeletionCode: %v", err)
		}
		if !deletionCodeRe.MatchString(code) {
			t.Fatalf("code %q is not 6 digits", code)
		}
		seen[code] = true
	}
	if len(seen) < 90 {
		t.Errorf("only %d distinct codes in 100 draws — distribution looks biased", len(seen))
	}
}
