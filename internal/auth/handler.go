package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
)

func (a *authenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		return // decodeJSON writes the error response
	}

	if err := a.validate.Struct(req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "identifier and password are required"})
		return
	}

	userID, requires2FA, err := a.verifier.Verify(r.Context(), req.Identifier, req.Password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			log.Warn().Str("identifier", mask(req.Identifier)).Msg("login failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		log.Error().Err(err).Msg("authentication error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	sessionID, err := a.sessions.Create(r.Context(), userID, !requires2FA)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("session creation failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	a.setSessionCookie(w, sessionID)
	a.audit(r.Context(), userID, "login")

	if requires2FA {
		writeJSON(w, http.StatusOK, map[string]string{"status": "2fa_required"})
		return
	}

	log.Info().Int64("user_id", userID).Msg("user logged in")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *authenticator) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	user, err := a.dbGetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile fetch failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, profileFromUser(user))
}

func (a *authenticator) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req UpdateProfileRequest
	if err := decodeAndValidate(r, w, &req, a.validate); err != nil {
		return // decodeAndValidate writes the error response
	}

	// Validate rank if provided
	if req.Rank != "" && !allowedRanks[req.Rank] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rank"})
		return
	}

	if err := a.dbUpdateUserProfile(r.Context(), userID, &req); err != nil {
		if errors.Is(err, ErrUpdateConflict) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "An account with this email or WhatsApp number already exists."})
			return
		}
		if errors.Is(err, ErrInvalidRank) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rank"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile update failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	a.audit(r.Context(), userID, "profile_update")
	log.Info().Int64("user_id", userID).Msg("profile updated")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// mask partially hides sensitive identifiers in logs.
// "test@example.com" → "t***m"
// "+62812345678" → "+62*********8"
func mask(s string) string {
	if len(s) <= 2 {
		return "***"
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}
