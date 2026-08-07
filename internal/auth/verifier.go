package auth

import (
	"context"
	"database/sql"
	"errors"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// BcryptVerifier authenticates users by email + bcrypt password.
type BcryptVerifier struct {
	db *bun.DB
}

// NewBcryptVerifier creates a Verifier that checks credentials against
// the users table using bcrypt.
func NewBcryptVerifier(db *bun.DB) Verifier {
	return &BcryptVerifier{db: db}
}

// dummyHash is a precomputed bcrypt hash used to equalize login response time
// between the "user not found" and "wrong password" paths. Without it, the
// not-found path skips bcrypt and returns in microseconds while the wrong-
// password path costs ~50ms — a timing side channel that reveals whether an
// identifier exists (user enumeration). The plaintext is a throwaway string;
// only its cost profile matters.
const dummyHash = "$2a$10$oSZtgXPD6IB81wO8lrIbdulYN7cIawVnkgvcgd0InAI/9WSY8XeH6"

func (v *BcryptVerifier) Verify(ctx context.Context, identifier, password string) (int64, bool, error) {
	user, err := v.findUserByEmail(ctx, identifier)
	if err != nil {
		// Only mask not-found as invalid credentials; propagate DB errors upstream
		// so the handler can respond 500 for infrastructure failures.
		if errors.Is(err, ErrInvalidCredentials) {
			// Burn one bcrypt compare so this path takes the same time as the
			// wrong-password path — response time must not reveal existence.
			_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return 0, false, ErrInvalidCredentials
		}
		return 0, false, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		log.Warn().Int64("user_id", user.ID).Msg("login failed: wrong password")
		return 0, false, ErrInvalidCredentials
	}

	// 2FA is not yet implemented; always return false for requires2FA.
	return user.ID, false, nil
}

// findUserByEmail looks up a user by email. WhatsApp is deliberately NOT a
// login identifier (PRD: email is the sole login key), so a WhatsApp number
// can never resolve to an account or be used to probe one.
// Returns ErrInvalidCredentials when the user is not found (prevents enumeration).
// Returns the raw error for all other failures (DB connectivity, timeouts, etc.)
// so the caller can surface them as 500 instead of masking outages.
func (v *BcryptVerifier) findUserByEmail(ctx context.Context, identifier string) (*types.User, error) {
	var user types.User
	err := v.db.NewSelect().
		Model(&user).
		Where("email = ?", identifier).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	return &user, nil
}
