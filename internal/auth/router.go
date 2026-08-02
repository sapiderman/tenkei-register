package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
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

type cookieConfig struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
	Path     string
}

// NewRouter mounts the auth routes on the given chi.Router.
func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, cfg *config.Config) {
	a := &authenticator{
		logger:   logger.With().Str("module", "auth").Logger(),
		validate: validate,
		db:       db,
		verifier: NewBcryptVerifier(db),
		sessions: NewDBSessionStore(db),
		cookies: cookieConfig{
			Secure:   cfg.Server.Mode == "production",
			SameSite: http.SameSiteLaxMode,
			Path:     "/v1/auth",
		},
	}

	r.Route("/v1/auth", func(r chi.Router) {
		// Public: login (rate-limited to prevent brute force)
		r.With(httprate.LimitByIP(10, 1*time.Minute)).Post("/login", a.handleLogin)

		// Authenticated endpoints: require valid session
		r.Group(func(r chi.Router) {
			r.Use(a.sessionRequired)
			r.Get("/profile", a.handleGetProfile)
			r.Put("/profile", a.handleUpdateProfile)
			r.Post("/logout", a.handleLogout)
			r.Post("/logout-all", a.handleLogoutAll)
		})
	})
}
