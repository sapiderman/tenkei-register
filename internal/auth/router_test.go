package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"golang.org/x/crypto/bcrypt"
)

func TestNewRouter_RoutesRegistered(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}

	// db and mailer are nil: none of the exercised routes touch the database
	// or send email — malformed input fails in DecodeAndValidate first.
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, nil)

	// Login route wired: malformed JSON fails in DecodeJSON before any DB use.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("login route: got %d, want 400", w.Code)
	}

	// Authenticated route wired: profile without session cookie is rejected.
	req = httptest.NewRequest(http.MethodGet, "/v1/auth/profile", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("profile route: got %d, want 401", w.Code)
	}

	// Logout route wired (also session-protected).
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("logout route: got %d, want 401", w.Code)
	}

	// Password-change route wired (session-protected).
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/password", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("password route: got %d, want 401", w.Code)
	}

	// Forgot-password route wired: malformed JSON fails in DecodeAndValidate
	// before any DB/mailer use. Reset-password route wired identically.
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("forgot-password route: got %d, want 400", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/auth/reset-password", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("reset-password route: got %d, want 400", w.Code)
	}

	// Unknown route falls through to chi's default 404.
	req = httptest.NewRequest(http.MethodGet, "/v1/auth/nope", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown route: got %d, want 404", w.Code)
	}
}

func TestNewRouter_LoginRateLimit(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}

	// db and mailer are nil: the malformed-JSON path fails in DecodeAndValidate
	// before any DB use, but the rate limiter still counts every request that
	// reaches the route.
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, nil)

	// Login is rate-limited to 10/min per IP; the 11th attempt is throttled.
	var last int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{bad`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("11th login: got %d, want 429 (rate limit 10/min)", last)
	}
}

func TestNewRouter_ForgotPasswordRateLimit(t *testing.T) {
	r := chi.NewRouter()
	cfg := &config.Config{Server: config.ServerConfig{Mode: "test"}}

	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, cfg, nil)

	// Forgot-password is rate-limited to 5/min per IP (it triggers an
	// outbound email per request); the 6th attempt is throttled before any
	// DB use. Each attempt carries malformed JSON, so a non-429 response
	// would be 400 — only the limiter can produce 429 here.
	var last int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/forgot-password", strings.NewReader(`{bad`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("6th forgot-password: got %d, want 429 (rate limit 5/min)", last)
	}
}

// TestNewRouter_2FARateLimits pins the 2FA route budgets on the real router
// wiring (otp-plan.md route table): verify 10/min, enroll/confirm/disable
// 5/min each. Bodies are deliberately empty — nothing but the limiter may
// produce the 429.
func TestNewRouter_2FARateLimits(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	insertTestUser(t, db, "rate-limit-2fa@test.dev", "+62877900001", string(hash))

	cfg := &config.Config{
		Server: config.ServerConfig{Mode: "test"},
		Totp: config.TotpConfig{
			Enabled:       true,
			EncryptionKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		},
	}
	r := chi.NewRouter()
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), db, cfg, nil)

	// The enrollment routes' limiter sits behind sessionRequired, so they
	// need a real verified session (plain account, no 2FA enrolled).
	login := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
		strings.NewReader(`{"identifier":"rate-limit-2fa@test.dev","password":"correct-horse"}`))
	login.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	r.ServeHTTP(loginRec, login)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login = %d %s, want 200", loginRec.Code, loginRec.Body.String())
	}
	cookie := sessionCookieOf(t, loginRec)

	post := func(path, body string, cookies ...*http.Cookie) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	for _, path := range []string{"/v1/auth/2fa/enroll", "/v1/auth/2fa/confirm", "/v1/auth/2fa/disable"} {
		t.Run(path, func(t *testing.T) {
			// One limiter per route: five requests fit, the sixth is throttled.
			for i := 1; i <= 5; i++ {
				if code := post(path, `{}`, cookie); code == http.StatusTooManyRequests {
					t.Fatalf("request %d of 5 for %s rate-limited early", i, path)
				}
			}
			if code := post(path, `{}`, cookie); code != http.StatusTooManyRequests {
				t.Fatalf("6th %s = %d, want 429 (rate limit 5/min)", path, code)
			}
		})
	}

	t.Run("/v1/auth/2fa/verify", func(t *testing.T) {
		// The limiter runs ahead of the pending-session check, so a
		// cookie-less request still counts (the middleware answers 401).
		for i := 1; i <= 10; i++ {
			if code := post("/v1/auth/2fa/verify", `{}`); code == http.StatusTooManyRequests {
				t.Fatalf("verify request %d of 10 rate-limited early", i)
			}
		}
		if code := post("/v1/auth/2fa/verify", `{}`); code != http.StatusTooManyRequests {
			t.Fatalf("11th verify = %d, want 429 (rate limit 10/min)", code)
		}
	})
}
