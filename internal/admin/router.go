// Package admin implements member administration endpoints under /v1/admin,
// mounted behind the shared session + role authorization middleware.
package admin

import (
	"context"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/uptrace/bun"
)

type administrator struct {
	logger   zerolog.Logger
	validate *validator.Validate
	db       *bun.DB
}

// NewRouter mounts the admin area under /v1/admin. Every route sits behind the
// shared session middleware plus roleRequired(>=2) (admin or superuser).
// mw is the auth package's middleware handle, reused so session validation and
// role resolution are defined once.
func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, mw *auth.Middleware) {
	a := &administrator{
		logger:   logger.With().Str("module", "admin").Logger(),
		validate: validate,
		db:       db,
	}

	r.Route("/v1/admin", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(mw.SessionRequired)
			r.Use(mw.RoleRequired(2)) // admin+

			r.Get("/users", a.handleListUsers)
			r.Get("/users/{id}", a.handleGetMember)
			r.Put("/users/{id}", a.handleUpdateMember)
			r.Post("/users/{id}/verify", a.handleVerifyMember)

			// Role management is superuser-only: stack RoleRequired(3) on top of
			// the group's session + admin (>=2) gate.
			r.With(mw.RoleRequired(3)).Put("/users/{id}/role", a.handleRoleMember)
		})
	})
}
