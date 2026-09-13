// TOTP login step 2 (otp-plan.md Phase 3): the only endpoint a pending
// (unverified) session cookie can reach. Everything here assumes the
// pendingSessionRequired middleware already proved the cookie belongs to an
// unexpired, unverified session.
package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/totp"
	"github.com/sapiderman/tenkei-register/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// Verify2FARequest is the inbound payload for POST /v1/auth/2fa/verify.
type Verify2FARequest struct {
	Code string `json:"code" validate:"required,numeric,len=6"` // #nosec G117 — write-only, never logged
}

// handleVerify2FA completes a 2FA login: check the code against the user's
// secret (with skew), atomically advance the replay counter, and promote the
// pending session. Every rejection is a 401 with one of two bodies —
// "invalid code" or "too many attempts" — regardless of why the code failed,
// so the endpoint offers no oracle beyond what the client already knows.
func (a *authenticator) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())
	cookie, _ := r.Cookie(sessionCookieName) // middleware guaranteed it exists

	var req Verify2FARequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the error response
	}

	fail := func() {
		a.recordVerifyFailure(w, r, userID, cookie.Value)
	}

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			fail() // account vanished mid-login — same posture as a wrong code
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: user fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// An unreadable or missing enrollment fails closed as an invalid code —
	// the member re-logs-in (password-only if enrollment is truly gone).
	secret, err := totp.DecryptSecret(a.totpKey, user.TOTPSecret)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: secret decrypt failed")
		fail()
		return
	}

	counter, ok := totp.VerifyCode(secret, req.Code, time.Now())
	if !ok {
		fail()
		return
	}

	// Replay guard: accept the counter only if strictly greater than the
	// stored one. Two concurrent submits of the same code cannot both win.
	accepted, err := AcceptTOTPCounter(r.Context(), a.db, userID, counter)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: counter update failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if !accepted {
		fail() // replayed code
		return
	}

	if err := a.sessions.MarkVerified(r.Context(), cookie.Value); err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			// The pending session is gone or already promoted (logout, expiry,
			// a concurrent duplicate verify that won): the counter is already
			// burned, so the member logs in again for a fresh code. The plan's
			// "second promotion is a no-op" — never a 500.
			a.clearSessionCookie(w)
			server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		// Genuine infra failure — the counter is already burned; the member
		// must log in again and use a fresh code. Loud log, clean 500.
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: session promotion failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	Audit(r.Context(), a.db, a.logger, userID, "login_2fa")
	log.Info().Int64("user_id", userID).Msg("2fa login complete")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// recordVerifyFailure bumps the pending session's attempt counter. At the
// limit the session is deleted and the cookie cleared: re-entry costs a
// fresh password login (plus Turnstile), which ends the brute-force path.
func (a *authenticator) recordVerifyFailure(w http.ResponseWriter, r *http.Request, userID int64, sessionID string) {
	attempts, err := a.sessions.RecordTOTPFailure(r.Context(), sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			// Deleted or expired between middleware and here — treat as expired.
			a.clearSessionCookie(w)
			server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired"})
			return
		}
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: failure recording failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	Audit(r.Context(), a.db, a.logger, userID, "2fa_verify_failed")

	if attempts >= maxTOTPAttempts {
		if err := a.sessions.Invalidate(r.Context(), sessionID); err != nil {
			log.Error().Err(err).Int64("user_id", userID).Msg("2fa verify: lockout invalidation failed")
		}
		a.clearSessionCookie(w)
		Audit(r.Context(), a.db, a.logger, userID, "2fa_locked_out")
		log.Warn().Int64("user_id", userID).Msg("2fa verify: too many attempts, session locked")
		server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "too many attempts, login again"})
		return
	}

	server.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
}

// --- Enrollment lifecycle (otp-plan.md Phase 4) ---
// All three handlers sit behind sessionRequired (a fully verified session)
// and are mounted only while the kill switch is on.

// Enroll2FAResponse is the outbound payload for POST /v1/auth/2fa/enroll.
// The secret appears exactly once, here — the member scans the QR (or types
// the secret) and it is never retrievable again.
type Enroll2FAResponse struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

// Confirm2FARequest is the inbound payload for POST /v1/auth/2fa/confirm:
// the first code from the member's authenticator plus the account password
// (a stolen cookie must not be able to finish arming 2FA — same rule as
// the email-change path).
type Confirm2FARequest struct {
	Code            string `json:"code" validate:"required,numeric,len=6"`      // #nosec G117 — never logged
	CurrentPassword string `json:"current_password" validate:"required,max=72"` // #nosec G117 — never logged
}

// Disable2FARequest is the inbound payload for POST /v1/auth/2fa/disable.
// Both factors are required: the password alone must not disarm the second
// lock, and the code alone must not suffice without account knowledge.
type Disable2FARequest struct {
	Code            string `json:"code" validate:"required,numeric,len=6"`      // #nosec G117 — never logged
	CurrentPassword string `json:"current_password" validate:"required,max=72"` // #nosec G117 — never logged
}

const totpIssuer = "Tenkei Aikidojo"

// handleEnroll2FA starts (or restarts) enrollment: store a fresh encrypted
// secret with totp_enabled still FALSE and hand the secret back once. An
// already-enabled account gets 409 — no silent secret swaps.
func (a *authenticator) handleEnroll2FA(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa enroll: user fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	secret, otpauthURL, err := totp.NewSecret(totpIssuer, user.Email)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa enroll: secret generation failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	enc, err := totp.EncryptSecret(a.totpKey, secret)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa enroll: secret encryption failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// The totp_enabled = FALSE guard is the whole race story: an enabled
	// account matches zero rows → 409, and two concurrent enrolls simply
	// leave whichever row committed last (each with its own fresh secret,
	// confirmed only by whoever holds the matching authenticator).
	res, err := a.db.NewRaw(
		`UPDATE users SET totp_secret = ?, totp_enabled = FALSE, totp_last_counter = 0
		  WHERE id = ? AND totp_enabled = FALSE`,
		enc, userID,
	).Exec(r.Context())
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa enroll: store failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "2FA is already enabled; disable it first"})
		return
	}

	Audit(r.Context(), a.db, a.logger, userID, "2fa_enrolled")
	log.Info().Int64("user_id", userID).Msg("2fa enrollment started")
	server.WriteJSON(w, http.StatusOK, Enroll2FAResponse{Secret: secret, OtpauthURL: otpauthURL})
}

// handleConfirm2FA finishes enrollment: re-prove the password (stolen-cookie
// containment), verify the first code against the stored secret, and flip
// totp_enabled. From this request on, the account's next login demands 2FA.
func (a *authenticator) handleConfirm2FA(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req Confirm2FARequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the error response
	}

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa confirm: user fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// The session identifies the user, but finishing an enrollment arms a
	// new lock on the account — that takes the password too.
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
		Audit(r.Context(), a.db, a.logger, userID, "2fa_confirm_rejected")
		log.Warn().Int64("user_id", userID).Msg("2fa confirm rejected: wrong password")
		server.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "current password verification failed"})
		return
	}

	if !a.acceptTOTPCode(r.Context(), user, req.Code, time.Now()) {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
		return
	}

	res, err := a.db.NewRaw(
		`UPDATE users SET totp_enabled = TRUE WHERE id = ? AND totp_secret IS NOT NULL AND totp_enabled = FALSE`,
		userID,
	).Exec(r.Context())
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa confirm: enable failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Enrollment vanished between the fetch and here (superseded, disabled).
		server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "no pending enrollment; enroll again"})
		return
	}

	Audit(r.Context(), a.db, a.logger, userID, "2fa_enabled")
	log.Info().Int64("user_id", userID).Msg("2fa enabled")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleDisable2FA turns 2FA off: both factors required, then the enrollment
// is wiped (secret NULL, counter reset). Lockout recovery is deliberately
// NOT this endpoint — lost-phone recovery is the operator SQL runbook.
func (a *authenticator) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r.Context())

	var req Disable2FARequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the error response
	}

	user, err := GetUserByID(r.Context(), a.db, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa disable: user fetch failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)) != nil {
		Audit(r.Context(), a.db, a.logger, userID, "2fa_disable_rejected")
		log.Warn().Int64("user_id", userID).Msg("2fa disable rejected: wrong password")
		server.WriteJSON(w, http.StatusForbidden, map[string]string{"error": "current password verification failed"})
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == "" {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "2FA is not enabled"})
		return
	}

	if !a.acceptTOTPCode(r.Context(), user, req.Code, time.Now()) {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
		return
	}

	if _, err := a.db.NewRaw(
		`UPDATE users SET totp_secret = NULL, totp_enabled = FALSE, totp_last_counter = 0 WHERE id = ?`,
		userID,
	).Exec(r.Context()); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("2fa disable: wipe failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	Audit(r.Context(), a.db, a.logger, userID, "2fa_disabled")
	log.Info().Int64("user_id", userID).Msg("2fa disabled")
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// acceptTOTPCode decrypts the user's stored secret, verifies the code with
// skew, and atomically advances the replay counter. Shared by confirm and
// disable (session-authenticated endpoints; a plain bool answer is enough).
func (a *authenticator) acceptTOTPCode(ctx context.Context, user *types.User, code string, at time.Time) bool {
	if user.TOTPSecret == "" {
		return false
	}
	secret, err := totp.DecryptSecret(a.totpKey, user.TOTPSecret)
	if err != nil {
		log.Error().Err(err).Int64("user_id", user.ID).Msg("2fa: secret decrypt failed")
		return false
	}
	counter, ok := totp.VerifyCode(secret, code, at)
	if !ok {
		return false
	}
	accepted, err := AcceptTOTPCounter(ctx, a.db, user.ID, counter)
	if err != nil {
		log.Error().Err(err).Int64("user_id", user.ID).Msg("2fa: counter update failed")
		return false
	}
	return accepted
}
