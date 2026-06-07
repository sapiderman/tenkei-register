package auth

import "context"

// Verifier verifies credentials and returns the authenticated user's ID.
// Today: BcryptVerifier checks email/WhatsApp + bcrypt password.
// Future: when 2FA is added, BcryptAnd2FAVerifier decorates BcryptVerifier
// and returns requires2FA=true for users with TOTP enabled.
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
	// Returns the associated user ID.
	Validate(ctx context.Context, sessionID string) (userID int64, err error)

	// Invalidate destroys a single session (logout).
	Invalidate(ctx context.Context, sessionID string) error

	// InvalidateAll destroys every session for a user (forced logout,
	// password change, security event).
	InvalidateAll(ctx context.Context, userID int64) error
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
