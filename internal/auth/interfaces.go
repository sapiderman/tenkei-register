package auth

import "context"

// Verifier verifies credentials and returns the authenticated user's ID.
// Today: BcryptVerifier checks email + bcrypt password and returns
// requires2FA = (TOTP kill switch on) && user.TOTPEnabled. The decorator
// idea from earlier plans was dropped — one boolean read needed no wrapper.
type Verifier interface {
	Verify(ctx context.Context, identifier, password string) (userID int64, requires2FA bool, err error)
}

// SessionStore manages session lifecycle.
// Today: DBSessionStore uses the sessions table.
// Future: can be swapped for Redis-backed sessions in tests or for horizontal scaling.
type SessionStore interface {
	// Create stores a new session. The verified parameter controls whether
	// the session is immediately authenticated (true for password-only login,
	// false when pending 2FA verification).
	Create(ctx context.Context, userID int64, verified bool) (sessionID string, err error)

	// Validate checks whether a session ID is valid, not expired, and verified.
	// Returns the associated user ID and the user's current role (resolved per
	// request from the joined user row, so a role change takes effect on the
	// next request without reissuing the session).
	Validate(ctx context.Context, sessionID string) (userID int64, role string, err error)

	// Invalidate destroys a single session (logout).
	Invalidate(ctx context.Context, sessionID string) error

	// InvalidateAll destroys every session for a user (forced logout,
	// password change, security event).
	InvalidateAll(ctx context.Context, userID int64) error

	// ValidatePending admits only an unexpired, NOT-yet-verified session —
	// the pending 2FA login state. It is the mirror of Validate (which
	// admits only verified sessions): normal endpoints reject pending
	// sessions, the 2FA verify endpoint accepts only them, so a half-
	// authenticated cookie can reach exactly one endpoint.
	ValidatePending(ctx context.Context, sessionID string) (userID int64, err error)

	// MarkVerified promotes a pending session to verified and extends its
	// lifetime to the full session TTL — the single statement that completes
	// a 2FA login. Returns ErrSessionNotFound when the row is gone, expired,
	// or already verified (idempotence check is the caller's 401 path).
	MarkVerified(ctx context.Context, sessionID string) error

	// RecordTOTPFailure increments the failed-code counter on a pending
	// session and returns the new count, so the verify handler can delete
	// the row after too many attempts (maxTOTPAttempts).
	RecordTOTPFailure(ctx context.Context, sessionID string) (attempts int, err error)
}

// PasswordResetter manages the forgot-password flow.
// Define now, implement later. This is the seam for future work:
// email tokens, SMS OTP, etc.
type PasswordResetter interface {
	// RequestReset generates and delivers a reset token for the given identifier.
	// The implementation decides delivery method (email, SMS).
	RequestReset(ctx context.Context, identifier string) error

	// ConfirmReset verifies a reset token and sets the new password.
	ConfirmReset(ctx context.Context, token, newPassword string) error
}
