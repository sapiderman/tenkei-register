package auth

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
	"golang.org/x/crypto/bcrypt"
)

// BcryptVerifier authenticates users by email or WhatsApp + bcrypt password.
type BcryptVerifier struct {
	db *bun.DB
}

// NewBcryptVerifier creates a Verifier that checks credentials against
// the users table using bcrypt.
func NewBcryptVerifier(db *bun.DB) Verifier {
	return &BcryptVerifier{db: db}
}

func (v *BcryptVerifier) Verify(ctx context.Context, identifier, password string) (int64, bool, error) {
	user, err := v.findUserByIdentifier(ctx, identifier)
	if err != nil {
		return 0, false, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		log.Warn().Int64("user_id", user.ID).Msg("login failed: wrong password")
		return 0, false, ErrInvalidCredentials
	}

	// 2FA is not yet implemented; always return false for requires2FA.
	return user.ID, false, nil
}

// findUserByIdentifier looks up a user by email OR WhatsApp number.
// Returns ErrInvalidCredentials (not ErrUserNotFound) to prevent user enumeration.
func (v *BcryptVerifier) findUserByIdentifier(ctx context.Context, identifier string) (*types.User, error) {
	var user types.User
	err := v.db.NewSelect().
		Model(&user).
		Where("email = ? OR whatsapp_number = ?", identifier, identifier).
		Scan(ctx)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return &user, nil
}
