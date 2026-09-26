package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	libtotp "github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/totp"
	"github.com/sapiderman/tenkei-register/internal/turnstile"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// twofactorHarness wires a full 2FA-capable authenticator (real DB session
// store, real BcryptVerifier, disabled Turnstile) over a scratch database,
// mirroring the production route stack for login / 2fa/verify / profile.
type twofactorHarness struct {
	db     *bun.DB
	key    []byte
	auth   *authenticator
	router chi.Router
	t      *testing.T
	seq    int
}

// nextWhatsApp mints a unique placeholder number per seeded user:
// insertTestUser resolves the inserted row by whatsapp_number, so a shared
// number makes every harness with 2+ users read the wrong row back.
func (h *twofactorHarness) nextWhatsApp() string {
	h.seq++
	return fmt.Sprintf("+628777%05d", h.seq)
}

func new2FAHarness(t *testing.T, totpEnabled bool) *twofactorHarness {
	t.Helper()
	db := setupTestDB(t)
	logger := zerolog.Nop()
	key := bytes.Repeat([]byte{0x7f}, 32)
	sessions := NewDBSessionStore(db)

	var totpKey []byte
	if totpEnabled {
		totpKey = key
	}
	a := &authenticator{
		logger:    logger,
		validate:  validator.New(),
		db:        db,
		verifier:  NewBcryptVerifier(db, totpEnabled),
		sessions:  sessions,
		cookies:   cookieConfigFor(false),
		turnstile: turnstile.New("", false, logger), // disabled: bypass
		totpKey:   totpKey,
	}

	r := chi.NewRouter()
	r.Route("/v1/auth", func(r chi.Router) {
		r.With(middleware.RateLimit(10, 1*time.Minute)).Post("/login", a.handleLogin)
		if totpEnabled {
			r.With(middleware.RateLimit(10, 1*time.Minute), a.pendingSessionRequired).
				Post("/2fa/verify", a.handleVerify2FA)
		}
		r.Group(func(r chi.Router) {
			r.Use(a.sessionRequired)
			r.Get("/profile", a.handleGetProfile)
			if totpEnabled {
				r.Post("/2fa/enroll", a.handleEnroll2FA)
				r.Post("/2fa/confirm", a.handleConfirm2FA)
				r.Post("/2fa/disable", a.handleDisable2FA)
			}
		})
	})
	return &twofactorHarness{db: db, key: key, auth: a, router: r, t: t}
}

func (h *twofactorHarness) post(path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func (h *twofactorHarness) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.router.ServeHTTP(w, req)
	return w
}

func (h *twofactorHarness) login(email, password string) *httptest.ResponseRecorder {
	return h.post("/v1/auth/login", fmt.Sprintf(`{"identifier":%q,"password":%q}`, email, password))
}

// seedTOTPUser inserts a user with a known password, an enrolled and enabled
// TOTP secret (encrypted with the harness key), and returns (userID, secret).
func (h *twofactorHarness) seedTOTPUser(email string) (int64, string) {
	h.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		h.t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(h.t, h.db, email, h.nextWhatsApp(), string(hash))

	key, err := libtotp.Generate(libtotp.GenerateOpts{
		Issuer:      "Tenkei Aikidojo",
		AccountName: email,
	})
	if err != nil {
		h.t.Fatalf("generate totp key: %v", err)
	}
	enc, err := totp.EncryptSecret(h.key, key.Secret())
	if err != nil {
		h.t.Fatalf("encrypt secret: %v", err)
	}
	if _, err := h.db.NewRaw(
		`UPDATE users SET totp_enabled = TRUE, totp_secret = ? WHERE id = ?`,
		enc, userID,
	).Exec(h.t.Context()); err != nil {
		h.t.Fatalf("enable totp: %v", err)
	}
	return userID, key.Secret()
}

func (h *twofactorHarness) code(secret string) string {
	h.t.Helper()
	c, err := libtotp.GenerateCode(secret, time.Now())
	if err != nil {
		h.t.Fatalf("generate code: %v", err)
	}
	return c
}

// seedPlainUser inserts a user with a known password and NO 2FA enrollment.
func (h *twofactorHarness) seedPlainUser(email string) int64 {
	h.t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		h.t.Fatalf("bcrypt: %v", err)
	}
	return insertTestUser(h.t, h.db, email, h.nextWhatsApp(), string(hash))
}

// enroll drives POST /2fa/enroll with the given session and returns the
// response body.
func (h *twofactorHarness) enroll(cookie *http.Cookie) Enroll2FAResponse {
	h.t.Helper()
	rec := h.post("/v1/auth/2fa/enroll", `{}`, cookie)
	if rec.Code != http.StatusOK {
		h.t.Fatalf("enroll = %d %s, want 200", rec.Code, rec.Body.String())
	}
	var body Enroll2FAResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		h.t.Fatalf("decode enroll response: %v", err)
	}
	return body
}

// confirm drives POST /2fa/confirm with password and the code for secret.
func (h *twofactorHarness) confirm(cookie *http.Cookie, password, secret string) *httptest.ResponseRecorder {
	return h.post("/v1/auth/2fa/confirm",
		fmt.Sprintf(`{"code":%q,"current_password":%q}`, h.code(secret), password), cookie)
}

func sessionCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("no session cookie in response")
	return nil
}

func decodeStatus(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return body["status"]
}

func Test2FA_FullLoginFlow_E2E(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-e2e@test.dev")

	// Step 1: password OK → pending session, no profile access yet.
	login := h.login("two-fa-e2e@test.dev", "correct-horse")
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", login.Code, login.Body.String())
	}
	if got := decodeStatus(t, login); got != "2fa_required" {
		t.Fatalf("login status field = %q, want 2fa_required", got)
	}
	cookie := sessionCookieOf(t, login)

	if prof := h.get("/v1/auth/profile", cookie); prof.Code != http.StatusUnauthorized {
		t.Fatalf("profile with pending session = %d, want 401", prof.Code)
	}

	// Step 2: correct code → session rotated. The verify response carries a
	// fresh Set-Cookie; the old pending token must be dead on both paths.
	verify := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify status = %d, body %s", verify.Code, verify.Body.String())
	}
	if got := decodeStatus(t, verify); got != "ok" {
		t.Fatalf("verify status field = %q, want ok", got)
	}
	if prof := h.get("/v1/auth/profile", cookie); prof.Code != http.StatusUnauthorized {
		t.Fatalf("profile with rotated-away pending cookie = %d, want 401", prof.Code)
	}
	full := sessionCookieOf(t, verify)

	// Full session now reaches protected endpoints, and the profile reports
	// the enrollment (FE contract: totp_enabled replaces the enroll-probe).
	prof := h.get("/v1/auth/profile", full)
	if prof.Code != http.StatusOK {
		t.Fatalf("profile after verify = %d, want 200 (body %s)", prof.Code, prof.Body.String())
	}
	var p ProfileResponse
	if err := json.NewDecoder(prof.Body).Decode(&p); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if !p.TOTPEnabled {
		t.Error("totp_enabled: got false, want true for an enrolled member")
	}
}

func Test2FA_WrongCodeThenCorrect(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-wrong-then-right@test.dev")

	login := h.login("two-fa-wrong-then-right@test.dev", "correct-horse")
	cookie := sessionCookieOf(t, login)

	wrong := h.post("/v1/auth/2fa/verify", `{"code":"000000"}`, cookie)
	if wrong.Code != http.StatusUnauthorized || strings.TrimSpace(wrong.Body.String()) != `{"code":"invalid_code","error":"invalid code"}` {
		t.Fatalf("wrong code = %d %s, want 401 invalid code", wrong.Code, wrong.Body.String())
	}

	right := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie)
	if right.Code != http.StatusOK {
		t.Fatalf("correct code after one failure = %d, want 200", right.Code)
	}
}

func Test2FA_ReplayedCodeRejected(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-replay@test.dev")

	// First login: consume a code.
	first := sessionCookieOf(t, h.login("two-fa-replay@test.dev", "correct-horse"))
	code := h.code(secret)
	if rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, code), first); rec.Code != http.StatusOK {
		t.Fatalf("first use = %d, want 200", rec.Code)
	}

	// Second login: the same code must be rejected (counter guard), even
	// within the same or adjacent step window.
	second := sessionCookieOf(t, h.login("two-fa-replay@test.dev", "correct-horse"))
	rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, code), second)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code = %d %s, want 401", rec.Code, rec.Body.String())
	}
}

func Test2FA_LockoutAfterFiveFailures(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-lockout@test.dev")

	login := h.login("two-fa-lockout@test.dev", "correct-horse")
	cookie := sessionCookieOf(t, login)

	for i := 1; i <= maxTOTPAttempts; i++ {
		rec := h.post("/v1/auth/2fa/verify", `{"code":"000000"}`, cookie)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure #%d = %d, want 401", i, rec.Code)
		}
		want := `{"code":"invalid_code","error":"invalid code"}`
		if i == maxTOTPAttempts {
			want = `{"code":"totp_locked","error":"too many attempts, login again"}`
		}
		if strings.TrimSpace(rec.Body.String()) != want {
			t.Fatalf("failure #%d body = %s, want %s", i, rec.Body.String(), want)
		}
	}

	// The pending session is dead: neither verify nor profile work.
	if rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("verify after lockout = %d, want 401", rec.Code)
	}
	if rec := h.get("/v1/auth/profile", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("profile after lockout = %d, want 401", rec.Code)
	}

	// A fresh login starts over cleanly (password re-entry).
	fresh := h.login("two-fa-lockout@test.dev", "correct-horse")
	if decodeStatus(t, fresh) != "2fa_required" {
		t.Fatal("fresh login after lockout must work")
	}
}

func Test2FA_VerifiedSessionRejected(t *testing.T) {
	h := new2FAHarness(t, true)
	// A user WITHOUT 2FA logs in normally (verified session) and must NOT
	// be able to hit the pending-only verify endpoint.
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	insertTestUser(t, h.db, "two-fa-noverify@test.dev", "+62877700002", string(hash))

	login := h.login("two-fa-noverify@test.dev", "correct-horse")
	if decodeStatus(t, login) != "ok" {
		t.Fatalf("non-2fa login = %s, want ok", login.Body.String())
	}
	cookie := sessionCookieOf(t, login)
	if rec := h.post("/v1/auth/2fa/verify", `{"code":"123456"}`, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("verified session on verify = %d, want 401", rec.Code)
	}
}

func Test2FA_KillSwitchDisabled(t *testing.T) {
	h := new2FAHarness(t, false)
	// Even with totp_enabled set on the account, a disabled kill switch
	// means password-only login and no mounted verify route.
	userID, secret := h.seedTOTPUser("two-fa-killed@test.dev")
	_ = userID
	_ = secret

	login := h.login("two-fa-killed@test.dev", "correct-horse")
	if decodeStatus(t, login) != "ok" {
		t.Fatalf("login with kill switch off = %s, want ok (password-only)", login.Body.String())
	}
	cookie := sessionCookieOf(t, login)
	if rec := h.post("/v1/auth/2fa/verify", `{"code":"123456"}`, cookie); rec.Code != http.StatusNotFound {
		t.Fatalf("verify with kill switch off = %d, want 404", rec.Code)
	}
}

// Rate limits for every 2FA route are pinned on the real router wiring in
// TestNewRouter_2FARateLimits (router_test.go): verify 10/min, enrollment
// 5/min.

func TestBcryptVerifier_Requires2FAFlag(t *testing.T) {
	h := new2FAHarness(t, true)
	userID, _ := h.seedTOTPUser("verifier-flag@test.dev")

	// Kill switch ON: enrolled account requires 2FA.
	v := NewBcryptVerifier(h.db, true)
	_, requires2FA, err := v.Verify(h.t.Context(), "verifier-flag@test.dev", "correct-horse")
	if err != nil || !requires2FA {
		t.Fatalf("enabled verifier: (%v, %v), want (true, nil)", requires2FA, err)
	}

	// Kill switch OFF: same account, password-only.
	v = NewBcryptVerifier(h.db, false)
	_, requires2FA, err = v.Verify(h.t.Context(), "verifier-flag@test.dev", "correct-horse")
	if err != nil || requires2FA {
		t.Fatalf("disabled verifier: (%v, %v), want (false, nil)", requires2FA, err)
	}
	_ = userID
}

func TestAcceptTOTPCounter_Monotonic(t *testing.T) {
	h := new2FAHarness(t, true)
	userID, _ := h.seedTOTPUser("counter-monotonic@test.dev")

	ok, err := AcceptTOTPCounter(h.t.Context(), h.db, userID, 1000)
	if err != nil || !ok {
		t.Fatalf("first accept(1000) = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = AcceptTOTPCounter(h.t.Context(), h.db, userID, 1000)
	if err != nil || ok {
		t.Fatalf("replay accept(1000) = (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = AcceptTOTPCounter(h.t.Context(), h.db, userID, 999)
	if err != nil || ok {
		t.Fatalf("lower accept(999) = (%v, %v), want (false, nil)", ok, err)
	}
	ok, err = AcceptTOTPCounter(h.t.Context(), h.db, userID, 1001)
	if err != nil || !ok {
		t.Fatalf("higher accept(1001) = (%v, %v), want (true, nil)", ok, err)
	}
}

// waitForNextStep sleeps until the current 30s TOTP step rolls over, so a
// freshly generated code cannot collide (and be replay-rejected) with one
// the test already consumed inside this step.
func waitForNextStep(t *testing.T) {
	t.Helper()
	const step = 30 * time.Second
	target := time.Now().Truncate(step).Add(step + 100*time.Millisecond)
	if d := time.Until(target); d > 0 {
		time.Sleep(d)
	}
}

// --- Enrollment lifecycle (otp-plan.md Phase 4) ---

func Test2FAEnroll_Confirm_FullLifecycle_E2E(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("lifecycle@test.dev")

	// Login (password-only), enroll, confirm with password + first code.
	cookie := sessionCookieOf(t, h.login("lifecycle@test.dev", "correct-horse"))
	enrolled := h.enroll(cookie)
	if enrolled.Secret == "" || !strings.HasPrefix(enrolled.OtpauthURL, "otpauth://totp/") {
		t.Fatalf("enroll response incomplete: %+v", enrolled)
	}
	if rec := h.confirm(cookie, "correct-horse", enrolled.Secret); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s, want 200", rec.Code, rec.Body.String())
	}

	// Next login now demands 2FA, and the enrolled secret completes it. The
	// confirm above already consumed this step's code, so wait for the next
	// step before verifying (the replay guard would rightly reject it).
	login2 := h.login("lifecycle@test.dev", "correct-horse")
	if decodeStatus(t, login2) != "2fa_required" {
		t.Fatalf("login after enable = %s, want 2fa_required", login2.Body.String())
	}
	waitForNextStep(t)
	cookie2 := sessionCookieOf(t, login2)
	verify := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(enrolled.Secret)), cookie2)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify = %d %s, want 200", verify.Code, verify.Body.String())
	}
}

func Test2FAEnroll_SecretRoundTripEncryptedAtRest(t *testing.T) {
	h := new2FAHarness(t, true)
	userID := h.seedPlainUser("roundtrip@test.dev")

	cookie := sessionCookieOf(t, h.login("roundtrip@test.dev", "correct-horse"))
	enrolled := h.enroll(cookie)

	var stored string
	if err := h.db.NewRaw(`SELECT totp_secret FROM users WHERE id = ?`, userID).
		Scan(t.Context(), &stored); err != nil {
		t.Fatalf("read stored secret: %v", err)
	}
	if stored == "" || stored == enrolled.Secret {
		t.Fatal("stored secret must be non-empty ciphertext, never the plaintext base32")
	}
	dec, err := totp.DecryptSecret(h.key, stored)
	if err != nil {
		t.Fatalf("decrypt stored secret: %v", err)
	}
	if dec != enrolled.Secret {
		t.Fatal("decrypt(stored) must equal the secret returned at enrollment")
	}
}

func Test2FAEnroll_AlreadyEnabled_409(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("already-enabled@test.dev") // seeded with totp_enabled=TRUE

	// Complete the full 2FA login first — enrollment needs a verified session.
	cookie := sessionCookieOf(t, h.login("already-enabled@test.dev", "correct-horse"))
	waitForNextStep(t)
	verify := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify before enroll = %d %s, want 200", verify.Code, verify.Body.String())
	}
	cookie = sessionCookieOf(t, verify) // rotation: the pending cookie died at verify

	rec := h.post("/v1/auth/2fa/enroll", `{}`, cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("enroll while enabled = %d %s, want 409", rec.Code, rec.Body.String())
	}
}

func Test2FAEnroll_UnconfirmedDoesNotAffectLogin(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("unconfirmed@test.dev")

	cookie := sessionCookieOf(t, h.login("unconfirmed@test.dev", "correct-horse"))
	h.enroll(cookie) // never confirmed

	login2 := h.login("unconfirmed@test.dev", "correct-horse")
	if got := decodeStatus(t, login2); got != "ok" {
		t.Fatalf("login after unconfirmed enrollment = %q, want ok", got)
	}
}

func Test2FAConfirm_WrongPassword_403(t *testing.T) {
	h := new2FAHarness(t, true)
	userID := h.seedPlainUser("confirm-wrongpw@test.dev")

	cookie := sessionCookieOf(t, h.login("confirm-wrongpw@test.dev", "correct-horse"))
	enrolled := h.enroll(cookie)

	rec := h.confirm(cookie, "wrong-password", enrolled.Secret)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("confirm with wrong password = %d %s, want 403", rec.Code, rec.Body.String())
	}

	// totp_enabled must still be FALSE — the lock never armed.
	var enabled bool
	if err := h.db.NewRaw(`SELECT totp_enabled FROM users WHERE id = ?`, userID).
		Scan(t.Context(), &enabled); err != nil || enabled {
		t.Fatalf("totp_enabled after rejected confirm = (%v, %v), want (false, nil)", enabled, err)
	}
}

func Test2FAConfirm_WrongCode_400(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("confirm-wrongcode@test.dev")

	cookie := sessionCookieOf(t, h.login("confirm-wrongcode@test.dev", "correct-horse"))
	h.enroll(cookie)

	rec := h.post("/v1/auth/2fa/confirm", `{"code":"000000","current_password":"correct-horse"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm with wrong code = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

func Test2FAConfirm_NoEnrollment_400(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("confirm-nonenroll@test.dev")

	cookie := sessionCookieOf(t, h.login("confirm-nonenroll@test.dev", "correct-horse"))
	rec := h.post("/v1/auth/2fa/confirm", `{"code":"123456","current_password":"correct-horse"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm without enrollment = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

func Test2FADisable_RequiresBothFactors(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("disable@test.dev")

	login := h.login("disable@test.dev", "correct-horse")
	cookie := sessionCookieOf(t, login)
	// Complete 2FA login first — disable needs a verified session.
	verify := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie)
	if verify.Code != http.StatusOK {
		t.Fatalf("verify before disable = %d, want 200", verify.Code)
	}
	cookie = sessionCookieOf(t, verify) // rotation: the pending cookie died at verify

	// Wrong password → 403.
	rec := h.post("/v1/auth/2fa/disable",
		fmt.Sprintf(`{"code":%q,"current_password":"nope"}`, h.code(secret)), cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disable with wrong password = %d, want 403", rec.Code)
	}

	// Wrong code → 400.
	rec = h.post("/v1/auth/2fa/disable",
		`{"code":"000000","current_password":"correct-horse"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable with wrong code = %d, want 400", rec.Code)
	}

	// Both factors → 200, and the next login is password-only. The 2FA
	// login above consumed this step's code; wait for a fresh step.
	waitForNextStep(t)
	rec = h.post("/v1/auth/2fa/disable",
		fmt.Sprintf(`{"code":%q,"current_password":"correct-horse"}`, h.code(secret)), cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable with both factors = %d %s, want 200", rec.Code, rec.Body.String())
	}
	if got := decodeStatus(t, h.login("disable@test.dev", "correct-horse")); got != "ok" {
		t.Fatalf("login after disable = %q, want ok", got)
	}
}

func Test2FADisable_NotEnabled_400(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("disable-notenabled@test.dev")

	cookie := sessionCookieOf(t, h.login("disable-notenabled@test.dev", "correct-horse"))
	rec := h.post("/v1/auth/2fa/disable", `{"code":"123456","current_password":"correct-horse"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("disable when not enabled = %d, want 400", rec.Code)
	}
}

func Test2FA_RoutesAbsentWhenKillSwitchOff(t *testing.T) {
	h := new2FAHarness(t, false)
	h.seedPlainUser("killed-routes@test.dev")

	cookie := sessionCookieOf(t, h.login("killed-routes@test.dev", "correct-horse"))
	for _, path := range []string{"/v1/auth/2fa/enroll", "/v1/auth/2fa/confirm", "/v1/auth/2fa/disable"} {
		if rec := h.post(path, `{}`, cookie); rec.Code != http.StatusNotFound {
			t.Fatalf("%s with kill switch off = %d, want 404", path, rec.Code)
		}
	}
}

// --- Fail-closed paths and fault injection (otp-plan.md ACs + AGENTS.md rule 6) ---

// newFaultAuth builds an authenticator over the harness DB with a
// caller-supplied session store, for tests that inject store errors.
func newFaultAuth(t *testing.T, db *bun.DB, store SessionStore, key []byte) *authenticator {
	t.Helper()
	return &authenticator{
		logger:    zerolog.Nop(),
		validate:  validator.New(),
		db:        db,
		sessions:  store,
		cookies:   cookieConfigFor(false),
		turnstile: turnstile.New("", false, zerolog.Nop()),
		totpKey:   key,
	}
}

// postToHandler invokes a 2FA handler directly, bypassing middleware, with
// the authenticated userID already in context.
func postToHandler(t *testing.T, handler http.HandlerFunc, body string, cookie *http.Cookie, userID int64) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/2fa/x", bytes.NewBufferString(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req = req.WithContext(WithAuth(req.Context(), userID, ""))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// sessionCookieCleared asserts the response expired the session cookie.
func sessionCookieCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			if c.MaxAge < 0 {
				return
			}
			t.Fatalf("session cookie not cleared: MaxAge=%d", c.MaxAge)
		}
	}
	t.Fatal("no session cookie in response")
}

func pendingCookie() *http.Cookie {
	return &http.Cookie{Name: sessionCookieName, Value: "pending-token"}
}

// codeAt generates the code the secret would display at an arbitrary time
// (for skew tests: previous-step and outside-skew codes).
func (h *twofactorHarness) codeAt(secret string, at time.Time) string {
	h.t.Helper()
	c, err := libtotp.GenerateCode(secret, at)
	if err != nil {
		h.t.Fatalf("generate code: %v", err)
	}
	return c
}

func Test2FAVerify_MalformedCode_400(t *testing.T) {
	h := new2FAHarness(t, true)
	_, _ = h.seedTOTPUser("two-fa-malformed@test.dev")
	cookie := sessionCookieOf(t, h.login("two-fa-malformed@test.dev", "correct-horse"))

	rec := h.post("/v1/auth/2fa/verify", `{"code":"12ab45"}`, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed code = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// The account vanishes while a pending session exists (operator SQL; app
// paths cascade sessions, so the handler is driven directly). The body must
// be byte-identical to the plain wrong-code body — no oracle (otp-plan.md).
func Test2FAVerify_UserVanished_NoOracle(t *testing.T) {
	h := new2FAHarness(t, true)
	userID, _ := h.seedTOTPUser("two-fa-vanished@test.dev")
	if _, err := h.db.NewRaw(`DELETE FROM users WHERE id = ?`, userID).Exec(h.t.Context()); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	store := &mockSessionStore{validatePendingResult: userID, recordFailAttempts: 1}
	a := newFaultAuth(t, h.db, store, h.key)

	rec := postToHandler(t, a.handleVerify2FA, `{"code":"123456"}`, pendingCookie(), userID)
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"code":"invalid_code","error":"invalid code"}` {
		t.Fatalf("vanished user = %d %s, want 401 invalid code", rec.Code, rec.Body.String())
	}
}

func Test2FAVerify_CorruptSecretFailsClosed(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-corrupt@test.dev")
	cookie := sessionCookieOf(t, h.login("two-fa-corrupt@test.dev", "correct-horse"))

	if _, err := h.db.NewRaw(`UPDATE users SET totp_secret = 'corrupted-ciphertext' WHERE email = ?`,
		"two-fa-corrupt@test.dev").Exec(h.t.Context()); err != nil {
		t.Fatalf("corrupt secret: %v", err)
	}

	rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, h.code(secret)), cookie)
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"code":"invalid_code","error":"invalid code"}` {
		t.Fatalf("corrupt secret = %d %s, want 401 invalid code", rec.Code, rec.Body.String())
	}
}

func Test2FAConfirm_CorruptSecretFailsClosed(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("confirm-corrupt@test.dev")
	cookie := sessionCookieOf(t, h.login("confirm-corrupt@test.dev", "correct-horse"))
	enrolled := h.enroll(cookie)

	if _, err := h.db.NewRaw(`UPDATE users SET totp_secret = 'corrupted-ciphertext' WHERE email = ?`,
		"confirm-corrupt@test.dev").Exec(h.t.Context()); err != nil {
		t.Fatalf("corrupt secret: %v", err)
	}

	rec := h.confirm(cookie, "correct-horse", enrolled.Secret)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm with corrupt secret = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// End-to-end skew: a previous-step code (inside ±1) verifies; a code from
// more than one step ago (outside skew) is rejected with the standard body.
func Test2FAVerify_SkewEndToEnd(t *testing.T) {
	h := new2FAHarness(t, true)
	_, secret := h.seedTOTPUser("two-fa-skew@test.dev")

	cookie := sessionCookieOf(t, h.login("two-fa-skew@test.dev", "correct-horse"))
	prev := h.codeAt(secret, time.Now().Add(-20*time.Second))
	if rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, prev), cookie); rec.Code != http.StatusOK {
		t.Fatalf("previous-step code = %d %s, want 200", rec.Code, rec.Body.String())
	}

	cookie2 := sessionCookieOf(t, h.login("two-fa-skew@test.dev", "correct-horse"))
	stale := h.codeAt(secret, time.Now().Add(-75*time.Second))
	rec := h.post("/v1/auth/2fa/verify", fmt.Sprintf(`{"code":%q}`, stale), cookie2)
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != `{"code":"invalid_code","error":"invalid code"}` {
		t.Fatalf("stale code = %d %s, want 401 invalid code", rec.Code, rec.Body.String())
	}
}

func Test2FAVerify_RecordFailureFaults(t *testing.T) {
	h := new2FAHarness(t, true)
	userID, _ := h.seedTOTPUser("two-fa-recfault@test.dev")

	tests := []struct {
		name        string
		store       *mockSessionStore
		wantStatus  int
		wantBody    string
		wantCleared bool
	}{
		{
			name:       "infra error surfaces as 500, never a fake 401",
			store:      &mockSessionStore{validatePendingResult: userID, recordFailErr: errNotSessionNotFound},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error"}`,
		},
		{
			name:        "session gone mid-login clears cookie",
			store:       &mockSessionStore{validatePendingResult: userID, recordFailErr: ErrSessionNotFound},
			wantStatus:  http.StatusUnauthorized,
			wantBody:    `{"code":"session_expired","error":"session expired"}`,
			wantCleared: true,
		},
		{
			name:        "lockout invalidation failure still locks",
			store:       &mockSessionStore{validatePendingResult: userID, recordFailAttempts: maxTOTPAttempts, invalidateErr: errNotSessionNotFound},
			wantStatus:  http.StatusUnauthorized,
			wantBody:    `{"code":"totp_locked","error":"too many attempts, login again"}`,
			wantCleared: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newFaultAuth(t, h.db, tt.store, h.key)
			rec := postToHandler(t, a.handleVerify2FA, `{"code":"000000"}`, pendingCookie(), userID)
			if rec.Code != tt.wantStatus || strings.TrimSpace(rec.Body.String()) != tt.wantBody {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}
			if tt.wantCleared {
				sessionCookieCleared(t, rec)
			}
		})
	}
}

// Rotation faults use distinct users: the first valid code burns the
// current step's counter, so a second subtest on the same user would be
// (rightly) rejected as a replay before ever reaching RotatePending.
func Test2FAVerify_RotationFaults(t *testing.T) {
	h := new2FAHarness(t, true)
	uidInfra, secInfra := h.seedTOTPUser("two-fa-promo-infra@test.dev")
	uidGone, secGone := h.seedTOTPUser("two-fa-promo-gone@test.dev")

	tests := []struct {
		name        string
		userID      int64
		secret      string
		rotateErr   error
		wantStatus  int
		wantBody    string
		wantCleared bool
	}{
		{
			name:   "infra error surfaces as 500, counter already burned",
			userID: uidInfra, secret: secInfra, rotateErr: errNotSessionNotFound,
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal server error"}`,
		},
		{
			name:   "session gone mid-rotation clears cookie, never a 500",
			userID: uidGone, secret: secGone, rotateErr: ErrSessionNotFound,
			wantStatus:  http.StatusUnauthorized,
			wantBody:    `{"code":"session_expired","error":"session expired"}`,
			wantCleared: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockSessionStore{validatePendingResult: tt.userID, rotateErr: tt.rotateErr}
			a := newFaultAuth(t, h.db, store, h.key)
			rec := postToHandler(t, a.handleVerify2FA, fmt.Sprintf(`{"code":%q}`, h.code(tt.secret)), pendingCookie(), tt.userID)
			if rec.Code != tt.wantStatus || strings.TrimSpace(rec.Body.String()) != tt.wantBody {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}
			if tt.wantCleared {
				sessionCookieCleared(t, rec)
			}
		})
	}
}

// Every DB touch failing (closed pool) must surface as 500 from each 2FA
// handler's user-fetch path — infrastructure failures never masquerade as
// auth rejections.
func Test2FAHandlers_UserFetchFailure_500(t *testing.T) {
	h := new2FAHarness(t, true)
	userID := h.seedPlainUser("two-fa-fetchfail@test.dev")

	// Hand the handlers a dead pool, but leave h.db open: insertTestUser's
	// t.Cleanup DELETEs run on it after the test, and closing it here makes
	// those fail silently — leaking this row, whose whatsapp number is the
	// one every harness mints first, so the next run's seeds arm the wrong
	// user.
	dead := setupTestDB(t)
	dead.Close()
	h.auth.db = dead

	ck := pendingCookie()
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		body    string
	}{
		{"verify", h.auth.handleVerify2FA, `{"code":"123456"}`},
		{"enroll", h.auth.handleEnroll2FA, `{}`},
		{"confirm", h.auth.handleConfirm2FA, `{"code":"123456","current_password":"x"}`},
		{"disable", h.auth.handleDisable2FA, `{"code":"123456","current_password":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postToHandler(t, tc.handler, tc.body, ck, userID)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s with dead DB = %d %s, want 500", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// The defensive NewRouter posture (key parse failed) must fail closed.
func Test2FAEnroll_UnusableKey_500(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("two-fa-nokey@test.dev")
	cookie := sessionCookieOf(t, h.login("two-fa-nokey@test.dev", "correct-horse"))

	h.auth.totpKey = nil
	rec := h.post("/v1/auth/2fa/enroll", `{}`, cookie)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("enroll with unusable key = %d, want 500", rec.Code)
	}
}

func Test2FAConfirmDisable_MalformedBody_400(t *testing.T) {
	h := new2FAHarness(t, true)
	h.seedPlainUser("two-fa-badbody@test.dev")
	cookie := sessionCookieOf(t, h.login("two-fa-badbody@test.dev", "correct-horse"))

	if rec := h.post("/v1/auth/2fa/confirm", `{"code":"12ab45","current_password":"correct-horse"}`, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm malformed = %d %s, want 400", rec.Code, rec.Body.String())
	}
	if rec := h.post("/v1/auth/2fa/disable", `{"code":"12ab45","current_password":"correct-horse"}`, cookie); rec.Code != http.StatusBadRequest {
		t.Fatalf("disable malformed = %d %s, want 400", rec.Code, rec.Body.String())
	}
}

// otp-plan.md Phase 4 AC: the secret never appears in logs or audit rows.
func Test2FA_SecretNeverLoggedOrAudited(t *testing.T) {
	h := new2FAHarness(t, true)
	var logs bytes.Buffer
	h.auth.logger = zerolog.New(&logs)

	userID := h.seedPlainUser("two-fa-noleak@test.dev")
	cookie := sessionCookieOf(t, h.login("two-fa-noleak@test.dev", "correct-horse"))
	enrolled := h.enroll(cookie)
	if rec := h.confirm(cookie, "correct-horse", enrolled.Secret); rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s, want 200", rec.Code, rec.Body.String())
	}

	if strings.Contains(logs.String(), enrolled.Secret) {
		t.Fatal("secret leaked into logs")
	}
	var actions []string
	if err := h.db.NewRaw(`SELECT action FROM audit WHERE user_id = ?`, userID).Scan(h.t.Context(), &actions); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	for _, action := range actions {
		if strings.Contains(action, enrolled.Secret) {
			t.Fatalf("secret leaked into audit action %q", action)
		}
	}
}
