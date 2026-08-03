package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/server"
)

func (a *authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		return // DecodeJSON writes the error response
	}

	if err := a.validate.Struct(req); err != nil {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "identifier and password are required"})
		return
	}

	userID, requires2FA, err := a.verifier.Verify(r.Context(), req.Identifier, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			a.audit(r.Context(), 0, "login_failed")
			log.Warn().Str("identifier", mask(req.Identifier)).Msg("login failed")
			server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		log.Error().Err(err).Msg("authentication error")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	sessionID, err := a.sessions.Create(r.Context(), userID, !requires2FA)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("session creation failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	a.setSessionCookie(w, sessionID)
	a.audit(r.Context(), userID, "login")

	if requires2FA {
		server.WriteJSON(w, http.StatusOK, map[string]string{"status": "2fa_required"})
		return
	}

	log.Info().Int64("user_id", userID).Msg("user logged in")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *authenticator) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	user, err := a.dbGetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	server.WriteJSON(w, http.StatusOK, profileFromUser(user))
}

func (a *authenticator) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req UpdateProfileRequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the error response
	}

	// Validate rank if provided
	if req.Rank != "" && !allowedRanks[req.Rank] {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rank"})
		return
	}

	if err := a.dbUpdateUserProfile(r.Context(), userID, &req); err != nil {
		if errors.Is(err, ErrUpdateConflict) {
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "An account with this email or WhatsApp number already exists."})
			return
		}
		if errors.Is(err, ErrInvalidRank) {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rank"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile update failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	a.audit(r.Context(), userID, "profile_update")
	log.Info().Int64("user_id", userID).Msg("profile updated")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *authenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	cookie, _ := r.Cookie(sessionCookieName)

	if cookie != nil {
		if err := a.sessions.Invalidate(r.Context(), cookie.Value); err != nil {
			log.Error().Err(err).Msg("session invalidation failed")
			// Continue to clear cookie client-side even if server invalidation fails
		}
	}

	a.clearSessionCookie(w)
	a.audit(r.Context(), userID, "logout")
	log.Info().Int64("user_id", userID).Msg("user logged out")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleLogoutAll invalidates every session for the authenticated user and
// clears the local cookie. Use after a suspected compromise.
func (a *authenticator) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	if err := a.sessions.InvalidateAll(r.Context(), userID); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("all-session invalidation failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	a.clearSessionCookie(w)
	a.audit(r.Context(), userID, "logout_all")
	log.Info().Int64("user_id", userID).Msg("all sessions invalidated")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// mask partially hides sensitive identifiers in logs.
// "test@example.com" → "t***************m"
// "+62812345678" → "+**********8"
func mask(s string) string {
	if len(s) <= 2 {
		return "***"
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}
