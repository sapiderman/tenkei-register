// Package internal with server.go as the main server setup and management file
package internal

import (
	"context"
	"net"
	"net/http"
	"os/signal"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/config"
	"github.com/sapiderman/tenkei-register/internal/database"
	"golang.org/x/sys/unix"

	"github.com/rs/zerolog/log"
)

type Server struct {
	// Server fields
	timeStart time.Time
	handler   http.Handler
	validator *validator.Validate
	logger    *zerolog.Logger
	database  *database.Database
}

func StartServer(ctx context.Context) {
	server := &Server{}

	// Initialize database
	config, err := config.LoadConfig(".")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("Failed to load config")
		return
	}

	db, err := database.New(config.Database.ConnectionString)
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("db didnt want to play pong")
		return
	}

	server.timeStart = time.Now()
	server.validator = validator.New()
	server.database = db

	server.handler, err = NewHTTPHandler(ctx, server.database, config)
	if err != nil {
		server.logger.Error().Err(err).Msg("Failed to initialize HTTP handler")
		return
	}

	l, err := net.Listen("tcp", ":"+config.Server.Port)
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to listen on port %v", config.Server.Port)
	}
	log.Info().Msgf("Server is listening on %v", config.Server.Port)

	ServeWith(ctx, l, server.handler, *config)
}

func ServeWith(ctx context.Context, listener net.Listener, handler http.Handler, cfg config.Config) error {
	serviceCtx, serviceCancel := signal.NotifyContext(ctx, unix.SIGTERM, unix.SIGINT, unix.SIGQUIT)
	defer serviceCancel()

	readHeaderTimeout, err := time.ParseDuration(cfg.Server.ReadHeaderTimeout)
	if err != nil {
		// Handle error: log it and set a safe default
		log.Warn().Err(err).Msg("Invalid ReadHeaderTimeout in config, defaulting to 10s")
		readHeaderTimeout = 10 * time.Second
	}

	log.Info().Msg("Server version: " + cfg.Server.Version + " starting and listening on port " + cfg.Server.Port)

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		BaseContext: func(l net.Listener) context.Context {
			return serviceCtx
		},
		ReadHeaderTimeout: readHeaderTimeout,
	}

	go func() {

		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server crashed")
			serviceCancel()
		}
	}()
	<-serviceCtx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	log.Info().Msg("Shutting down server...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("Server shutdown failed")
		return err
	}
	log.Info().Msg("Server gracefully stopped")
	return nil
}
