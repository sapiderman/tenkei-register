package auth

import (
	"context"
	"net/http"
)

type ctxKeyUserID struct{}

// sessionRequired is the authentication middleware. It extracts the session
// cookie, validates it against the session store, and injects the authenticated
// user ID into the request context.
//
// On failure: clears the session cookie and returns 401 JSON.
func (a *authenticator) sessionRequired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}

		userID, err := a.sessions.Validate(r.Context(), cookie.Value)
		if err != nil {
			a.clearSessionCookie(w)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserID{}, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// userIDFromContext extracts the authenticated user ID from the request context.
func userIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(ctxKeyUserID{}).(int64)
	return id
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
