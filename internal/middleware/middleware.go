// Package middleware provides all middleware functions
package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/server"
)

func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", ww.Status()).
			Dur("duration", time.Since(start)).
			Msg("request completed")
	})
}

func XCFBypass(key string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bypass := r.Header.Get("x-cf-bypass")
			if bypass == "" {
				log.Error().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("x-cf-bypass header is empty")
				server.SendSimpleResponse(w, http.StatusForbidden, "bypass header is empty")
				return
			}
			if bypass != key {
				log.Error().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("x-cf-bypass header is invalid")
				server.SendSimpleResponse(w, http.StatusForbidden, "bypass header is invalid")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
