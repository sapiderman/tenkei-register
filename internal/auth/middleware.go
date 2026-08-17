package auth

import (
	"context"
	"net/http"

	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
)

type ctxKeyUserID struct{}
type ctxKeyRole struct{}

// sessionRequired is the authentication middleware. It extracts the session
// cookie, validates it against the session store, and injects the authenticated
// user ID and current role into the request context.
//
// On failure: clears the session cookie and returns 401 JSON.
func (a *authenticator) sessionRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		userID, role, err := a.sessions.Validate(r.Context(), cookie.Value)
		if err != nil {
			a.clearSessionCookie(w)
			server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}

		ctx := WithAuth(r.Context(), userID, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// roleRequired returns an authorization middleware that admits viewers whose
// role level is >= minLevel and returns 403 below. It must run after
// sessionRequired, which guarantees a valid role in the context (and supplies
// the 401 for no/invalid session). Unknown/empty roles level as -1, so a
// misconfigured chain fails closed (403).
func (a *authenticator) roleRequired(minLevel int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if types.RoleLevel(roleFromContext(r.Context())) < minLevel {
				server.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithAuth injects the authenticated user ID and role into a context. It is
// the single setter used by sessionRequired and by tests; downstream handlers
// read the values via UserIDFromContext / RoleFromContext.
func WithAuth(ctx context.Context, userID int64, role string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyUserID{}, userID)
	return context.WithValue(ctx, ctxKeyRole{}, role)
}

// UserIDFromContext extracts the authenticated user ID from the request context.
func UserIDFromContext(ctx context.Context) int64 {
	return userIDFromContext(ctx)
}

// RoleFromContext extracts the authenticated user's role from the request context.
func RoleFromContext(ctx context.Context) string {
	return roleFromContext(ctx)
}

// userIDFromContext extracts the authenticated user ID from the request context.
func userIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(ctxKeyUserID{}).(int64)
	return id
}

// roleFromContext extracts the authenticated user's role from the request context.
func roleFromContext(ctx context.Context) string {
	role, _ := ctx.Value(ctxKeyRole{}).(string)
	return role
}

// setSessionCookie sets an HttpOnly, Secure (in production), SameSite=Lax
// session cookie on the response.
func (a *authenticator) setSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     a.cookies.Path,
		MaxAge:   int(sessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   a.cookies.Secure,
		SameSite: a.cookies.SameSite,
	})
}

// clearSessionCookie removes the session cookie by setting MaxAge=-1.
func (a *authenticator) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     a.cookies.Path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cookies.Secure,
		SameSite: a.cookies.SameSite,
	})
}
