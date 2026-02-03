package register

import (
	"context"
	"html/template"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"github.com/uptrace/bun"
)

type registrar struct {
	context          context.Context
	logger           zerolog.Logger
	validate         *validator.Validate
	db               *bun.DB
	templates        *template.Template
	turnstileSecret  string
	turnstileEnabled bool
}

func NewRouter(ctx context.Context, r chi.Router, logger zerolog.Logger, validate *validator.Validate, db *bun.DB, cfg *config.Config) {
	reg := &registrar{
		context:          ctx,
		logger:           logger,
		validate:         validate,
		db:               db,
		templates:        template.Must(template.ParseGlob("internal/templates/*.html")),
		turnstileSecret:  cfg.Server.TurnstileSecret,
		turnstileEnabled: cfg.Server.TurnstileEnabled,
	}

	r.Route("/v1/register", func(r chi.Router) {
		r.Post("/", reg.handleSubmission)
		r.Get("/", reg.showRegister)
		r.Get("/count", reg.getUserCount)
	})

}
