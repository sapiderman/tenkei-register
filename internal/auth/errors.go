package auth

import "errors"

var (
	// ErrInvalidCredentials is returned when login credentials don't match.
	// The same error is used for "user not found" and "wrong password"
	// to prevent user enumeration.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrSessionNotFound is returned when a session ID is invalid or expired.
	ErrSessionNotFound = errors.New("session not found or expired")

	// ErrUserNotFound is returned when a user lookup by ID fails.
	ErrUserNotFound = errors.New("user not found")

	// ErrUpdateConflict is returned when an update violates a unique constraint.
	ErrUpdateConflict = errors.New("conflict with existing user data")

	// ErrInvalidRank is returned when rank is not in the allowed list.
	ErrInvalidRank = errors.New("invalid rank")
)
