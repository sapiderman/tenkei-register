package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/server"
	"golang.org/x/crypto/bcrypt"
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
			Audit(r.Context(), a.db, a.logger, 0, "login_failed")
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
	Audit(r.Context(), a.db, a.logger, userID, "login")

	if requires2FA {
		server.WriteJSON(w, http.StatusOK, map[string]string{"status": "2fa_required"})
		return
	}

	log.Info().Int64("user_id", userID).Msg("user logged in")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *authenticator) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	server.WriteJSON(w, http.StatusOK, ProfileFromUser(user))
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

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("profile fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Email is the login identifier. Changing it requires re-proving account
	// ownership with the current password — a stolen session cookie must not
	// be able to silently re-point the account to an attacker-controlled
	// address (lockout + persistence).
	emailChanged := req.Email != "" && req.Email != user.Email
	if emailChanged {
		if req.CurrentPassword == "" {
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "current_password is required to change email"})
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
			Audit(r.Context(), a.db, a.logger, userID, "email_change_rejected")
			log.Warn().Int64("user_id", userID).Msg("email change rejected: password verification failed")
			server.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "current password verification failed"})
			return
		}
	}

	if err := ApplyProfileUpdate(r.Context(), a.db, user, &req); err != nil {
		if errors.Is(err, ErrUpdateConflict) {
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "An account with this email already exists."})
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

	if emailChanged {
		// Containment: kill every session, then reissue one to the requester
		// so they stay logged in while all other devices (and any stolen
		// cookie) are logged out. Uses the two existing SessionStore methods
		// — no new interface seam for a single call site. A failure here does
		// not undo the update; log it and report success.
		if err := a.sessions.InvalidateAll(r.Context(), userID); err != nil {
			log.Error().Err(err).Int64("user_id", userID).Msg("email change: session invalidation failed")
		} else if newSession, err := a.sessions.Create(r.Context(), userID, true); err != nil {
			log.Error().Err(err).Int64("user_id", userID).Msg("email change: session reissue failed")
		} else {
			a.setSessionCookie(w, newSession)
		}
		Audit(r.Context(), a.db, a.logger, userID, "email_change")
	}

	Audit(r.Context(), a.db, a.logger, userID, "profile_update")
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
	Audit(r.Context(), a.db, a.logger, userID, "logout")
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
	Audit(r.Context(), a.db, a.logger, userID, "logout_all")
	log.Info().Int64("user_id", userID).Msg("all sessions invalidated")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleChangePassword implements POST /v1/auth/password: verify the current
// password, rotate the hash, and kill every other session. Like the email
// change path, the requester's own session is reissued so they stay logged
// in. Forgot-password is deliberately out of scope until a mailer exists —
// the PasswordResetter seam in interfaces.go is its documented place.
func (a *authenticator) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req PasswordChangeRequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the error response
	}

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("password change: user fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// The session already identifies the user, so there is nothing to
	// enumerate here: a plain wrong-password 403 is correct.
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
		Audit(r.Context(), a.db, a.logger, userID, "password_change_rejected")
		log.Warn().Int64("user_id", userID).Msg("password change rejected: wrong current password")
		server.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "current password verification failed"})
		return
	}

	// Length is validated (8..72); bcrypt.GenerateFromPassword cannot fail
	// on a valid-length input. DefaultCost matches the registration path.
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("password hashing failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	if err := UpdateUserPassword(r.Context(), a.db, userID, string(hash)); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("password update failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// All other sessions (including any stolen cookie) must die; reissue one
	// to the requester so they stay logged in. Mirrors the email-change path.
	if err := a.sessions.InvalidateAll(r.Context(), userID); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("password change: session invalidation failed")
	} else if newSession, err := a.sessions.Create(r.Context(), userID, true); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("password change: session reissue failed")
	} else {
		a.setSessionCookie(w, newSession)
	}

	Audit(r.Context(), a.db, a.logger, userID, "password_change")
	log.Info().Int64("user_id", userID).Msg("password changed")
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
