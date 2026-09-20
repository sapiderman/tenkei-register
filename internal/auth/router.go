package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"github.com/sapiderman/tenkei-register/internal/mailer"
	mymiddleware "github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/totp"
	"github.com/sapiderman/tenkei-register/internal/turnstile"
	"github.com/uptrace/bun"
)

type authenticator struct {
	logger    zerolog.Logger
	validate  *validator.Validate
	db        *bun.DB
	verifier  Verifier
	sessions  SessionStore
	resetter  PasswordResetter
	cookies   cookieConfig
	turnstile *turnstile.Verifier

	// totpKey decrypts users.totp_secret (nil when TOTP is disabled — the
	// verify route is then not mounted at all). See otp-plan.md.
	totpKey []byte
}

// Middleware exposes the session and role middleware bound to an
// authenticator so sibling packages (e.g. internal/admin) can mount the
// same authentication/authorization chain without duplicating it.
type Middleware struct {
	a *authenticator
}

// NewMiddleware builds a Middleware from a session store. It is the single
// constructor for the session/role handle, used by both production wiring
// (internal/http.go) and tests; `secure` controls the cookie posture used
// when clearing a failed session cookie (matches NewDBSessionStore's prod
// authenticator when wired with cfg.Server.Mode == "production").
func NewMiddleware(sessions SessionStore, secure bool) *Middleware {
	return &Middleware{a: &authenticator{sessions: sessions, cookies: cookieConfigFor(secure)}}
}

// SessionRequired is the authentication middleware (see sessionRequired).
func (m *Middleware) SessionRequired(next http.Handler) http.Handler {
	return m.a.sessionRequired(next)
}

// RoleRequired returns the authorization middleware admitting level >= min.
func (m *Middleware) RoleRequired(min int) func(http.Handler) http.Handler {
	return m.a.roleRequired(min)
}

type cookieConfig struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
	Path     string
}

// cookieConfigFor is the single source of truth for the session cookie
// posture; only Secure varies (production vs. not). Path is "/" — the
// cookie must reach both /v1/auth and /v1/admin (a /v1/auth-scoped cookie
// is never sent to admin routes, locking admins out with 401s). SameSite
// is constant across the app.
func cookieConfigFor(secure bool) cookieConfig {
	return cookieConfig{
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	}
}

// NewRouter mounts the auth routes on the given chi.Router. `mail` is the
// shared mailer (constructed once in internal.NewHTTPHandler); it feeds the
// DB-backed PasswordResetter for the forgot/reset-password flow.
func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, cfg *config.Config, mail mailer.Mailer) {
	sessions := NewDBSessionStore(db)

	// TOTP wiring: config already refused to boot when enabled + unusable
	// key, so the parse failure here is unreachable — handled defensively by
	// degrading to password-only (no 2FA demand, no 2FA routes) instead of
	// arming 2FA against a nil key.
	var totpKey []byte
	totpEnabled := false
	if cfg.Totp.Enabled {
		var err error
		if totpKey, err = totp.ParseKey(cfg.Totp.EncryptionKey); err != nil {
			logger.Error().Err(err).Msg("TOTP enabled but key unusable — 2FA routes not mounted, login stays password-only")
		} else {
			totpEnabled = true
		}
	}

	a := &authenticator{
		logger:    logger.With().Str("module", "auth").Logger(),
		validate:  validate,
		db:        db,
		verifier:  NewBcryptVerifier(db, totpEnabled),
		sessions:  sessions,
		resetter:  NewDBPasswordResetter(db, sessions, mail, logger.With().Str("module", "auth").Logger(), cfg.Server.AppURL),
		cookies:   cookieConfigFor(cfg.Server.Mode == "production"),
		turnstile: turnstile.New(cfg.Server.TurnstileSecret, cfg.Server.TurnstileEnabled, logger),
		totpKey:   totpKey,
	}

	r.Route("/v1/auth", func(r chi.Router) {
		// Public: login (rate-limited to prevent brute force)
		r.With(mymiddleware.RateLimit(10, 1*time.Minute)).Post("/login", a.handleLogin)

		// 2FA login step 2: the only endpoint a pending (unverified) session
		// can reach. Mounted only while the kill switch is on — disabled means
		// password-only login for everyone and 404 here (otp-plan.md).
		if totpEnabled {
			r.With(mymiddleware.RateLimit(10, 1*time.Minute), a.pendingSessionRequired).
				Post("/2fa/verify", a.handleVerify2FA)
		}

		// Public: forgot/reset password (PRD #24). Forgot is tighter — it
		// triggers an outbound email per request. Reset has no Turnstile (the
		// emailed link is the proof of inbox control) but keeps a rate limit.
		r.With(mymiddleware.RateLimit(5, 1*time.Minute)).Post("/forgot-password", a.handleForgotPassword)
		r.With(mymiddleware.RateLimit(10, 1*time.Minute)).Post("/reset-password", a.handleResetPassword)

		// Authenticated endpoints: require valid session
		r.Group(func(r chi.Router) {
			r.Use(a.sessionRequired)
			r.Get("/profile", a.handleGetProfile)
			r.Put("/profile", a.handleUpdateProfile)
			r.Post("/password", a.handleChangePassword)
			r.Post("/logout", a.handleLogout)
			r.Post("/logout-all", a.handleLogoutAll)

			// Enrollment lifecycle (otp-plan.md Phase 4). Tighter rate limit:
			// enroll/confirm/disable each touch bcrypt + a secret write.
			if totpEnabled {
				r.With(mymiddleware.RateLimit(5, 1*time.Minute)).Post("/2fa/enroll", a.handleEnroll2FA)
				r.With(mymiddleware.RateLimit(5, 1*time.Minute)).Post("/2fa/confirm", a.handleConfirm2FA)
				r.With(mymiddleware.RateLimit(5, 1*time.Minute)).Post("/2fa/disable", a.handleDisable2FA)
			}
		})
	})
}
