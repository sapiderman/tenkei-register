package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	mymiddleware "github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/uptrace/bun"
)

type authenticator struct {
	logger   zerolog.Logger
	validate *validator.Validate
	db       *bun.DB
	verifier Verifier
	sessions SessionStore
	cookies  cookieConfig
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

// NewRouter mounts the auth routes on the given chi.Router.
func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, cfg *config.Config) {
	a := &authenticator{
		logger:   logger.With().Str("module", "auth").Logger(),
		validate: validate,
		db:       db,
		verifier: NewBcryptVerifier(db),
		sessions: NewDBSessionStore(db),
		cookies:  cookieConfigFor(cfg.Server.Mode == "production"),
	}

	r.Route("/v1/auth", func(r chi.Router) {
		// Public: login (rate-limited to prevent brute force)
		r.With(mymiddleware.RateLimit(10, 1*time.Minute)).Post("/login", a.handleLogin)

		// Authenticated endpoints: require valid session
		r.Group(func(r chi.Router) {
			r.Use(a.sessionRequired)
			r.Get("/profile", a.handleGetProfile)
			r.Put("/profile", a.handleUpdateProfile)
			r.Post("/password", a.handleChangePassword)
			r.Post("/logout", a.handleLogout)
			r.Post("/logout-all", a.handleLogoutAll)
		})
	})
}
