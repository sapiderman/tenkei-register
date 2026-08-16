// Package middleware provides all middleware functions
package middleware

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
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

// ClientIP resolves the requester's IP: Cloudflare's CF-Connecting-IP when
// present, else the RemoteAddr host. Rate-limit buckets must key on this,
// not on RemoteAddr — behind Cloudflare the socket address is a shared CF
// edge, so RemoteAddr-keyed limits are per-edge, not per-client. The header
// is only trusted after the XCFBypass gate has run (secret header required),
// so it cannot be spoofed to mint fresh buckets by unauthenticated callers.
func ClientIP(r *http.Request) string {
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// RateLimit returns a per-client-IP rate-limiting middleware. Identical to
// httprate.LimitByIP except the bucket key is ClientIP (CF-aware) instead of
// the socket address.
func RateLimit(requests int, window time.Duration) func(next http.Handler) http.Handler {
	keyFn := func(r *http.Request) (string, error) { return ClientIP(r), nil }
	return httprate.Limit(requests, window, httprate.WithKeyFuncs(keyFn))
}

func XCFBypass(key string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bypass := r.Header.Get("x-cf-bypass")
			if bypass == "" {
				log.Error().Caller().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("x-cf-bypass header is empty")
				server.SendSimpleResponse(w, http.StatusNotFound, "Not Found")
				return
			}
			if subtle.ConstantTimeCompare([]byte(bypass), []byte(key)) != 1 {
				log.Error().Caller().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Msg("x-cf-bypass header is invalid")
				server.SendSimpleResponse(w, http.StatusNotFound, "Not Found")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
