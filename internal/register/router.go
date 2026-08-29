package register

import (
	"context"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"github.com/sapiderman/tenkei-register/internal/mailer"
	mymiddleware "github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/turnstile"
	"github.com/uptrace/bun"
)

type registrar struct {
	context   context.Context
	logger    zerolog.Logger
	validate  *validator.Validate
	db        *bun.DB
	turnstile *turnstile.Verifier

	// Email notifications: mailer is the shared send seam (constructed once
	// in internal.NewHTTPHandler), tmpl the pre-parsed templates, notifyEmail
	// the fixed group address receiving new-registration notices.
	mailer      mailer.Mailer
	tmpl        *templates
	notifyEmail string
}

func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, cfg *config.Config, mail mailer.Mailer) {
	reg := &registrar{
		context:     ctx,
		logger:      logger,
		validate:    validate,
		db:          db,
		turnstile:   turnstile.New(cfg.Server.TurnstileSecret, cfg.Server.TurnstileEnabled, logger),
		mailer:      mail,
		tmpl:        newTemplates(),
		notifyEmail: cfg.Mailer.NotifyEmail,
	}

	r.Route("/v1/register", func(r chi.Router) {
		// Rate limit: 5 requests per minute per client IP
		r.Use(mymiddleware.RateLimit(5, 1*time.Minute))
		r.Post("/", reg.handleSubmission)
		r.Get("/count", reg.getUserCount)
	})

}
