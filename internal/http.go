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
	"github.com/sapiderman/tenkei-register/internal/admin"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/database"
	mymiddleware "github.com/sapiderman/tenkei-register/internal/middleware"
	"github.com/sapiderman/tenkei-register/internal/register"
)

func NewHTTPHandler(ctx context.Context, db *database.Database, cfg *config.Config) (http.Handler, error) {
	validator := validator.New()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(mymiddleware.AccessLog)
	r.Use(middleware.Heartbeat("/health"))
	r.Use(mymiddleware.XCFBypass(cfg.Server.XCFBypass))

	r.Use(middleware.Timeout(60 * time.Second))
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	register.NewRouter(ctx, r, log, validator, db.DB, cfg)
	auth.NewRouter(ctx, r, log, validator, db.DB, cfg)
	// Admin area reuses the auth session/role middleware; wired once here and
	// passed in so authn/authz is defined in exactly one place.
	adminMW := auth.NewMiddleware(auth.NewDBSessionStore(db.DB), cfg.Server.Mode == "production")
	admin.NewRouter(ctx, r, log, validator, db.DB, adminMW)

	return r, nil
}
