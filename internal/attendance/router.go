// Package attendance implements the two-step attendance log (prd/attendance.prd):
// a member records a practice under /v1/attendance and an admin decides it
// under /v1/admin/attendance. It also serves the per-dojo instructor roster
// that fills the log dialog's picklist. Every route sits behind the shared
// session + role authorization middleware.
package attendance

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/uptrace/bun"
)

type attendanceService struct {
	logger   zerolog.Logger
	validate *validator.Validate
	db       *bun.DB
}

// NewRouter mounts the attendance endpoints. Logging in requires a verified
// role (roleRequired(1)); deciding records requires admin (roleRequired(2)).
// mw is the auth package's middleware handle, reused so session validation and
// role resolution are defined once.
func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, mw *auth.Middleware) {
	s := &attendanceService{
		logger:   logger.With().Str("module", "attendance").Logger(),
		validate: validate,
		db:       db,
	}

	// Keyed by user, not IP: a class ending puts every phone in the dojo on
	// the same NAT address. Per instance, like middleware.RateLimit.
	perUser := httprate.Limit(10, 1*time.Minute, httprate.WithKeyFuncs(keyByUserID))

	r.Route("/v1/attendance", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(mw.SessionRequired)
			r.Use(mw.RoleRequired(1)) // user+

			r.With(perUser).Post("/", s.handleLog)
			r.Get("/me", s.handleMine)
			r.Get("/instructors", s.handleInstructors)
		})
	})

	r.Route("/v1/admin/attendance", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(mw.SessionRequired)
			r.Use(mw.RoleRequired(2)) // admin+

			r.Get("/", s.handleList)
			r.Put("/{id}/confirm", s.handleConfirm)
			r.Put("/{id}/reject", s.handleReject)
		})
	})
}

// keyByUserID rate-limits on the session user; SessionRequired has already
// refused requests without one.
func keyByUserID(r *http.Request) (string, error) {
	return strconv.FormatInt(auth.UserIDFromContext(r.Context()), 10), nil
}
