package internal

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"github.com/sapiderman/tenkei-register/internal/database"
	mymiddleware "github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/register"
)

func NewHTTPHandler(ctx context.Context, db *database.Database, cfg *config.Config) (http.Handler, error) {
	validator := validator.New()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/health"))
	r.Use(mymiddleware.AccessLog)
	r.Use(mymiddleware.XCFBypass(cfg.Server.XCFBypass))

	r.Use(middleware.Timeout(60 * time.Second))
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	register.NewRouter(ctx, r, log, validator, db.DB, cfg)

	return r, nil
}
