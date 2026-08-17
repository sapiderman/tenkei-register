package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/uptrace/bun"
)

// DBSessionStore implements SessionStore using the PostgreSQL sessions table.
type DBSessionStore struct {
	db *bun.DB
}

// NewDBSessionStore creates a SessionStore backed by PostgreSQL.
func NewDBSessionStore(db *bun.DB) SessionStore {
	return &DBSessionStore{db: db}
}

func (s *DBSessionStore) Create(ctx context.Context, userID int64, verified bool) (string, error) {
	id, err := generateSessionID()
	if err != nil {
		return "", err
	}

	session := &Session{
		ID:        id,
		UserID:    userID,
		ExpiresAt: time.Now().Add(sessionMaxAge),
		Verified:  verified,
	}

	_, err = s.db.NewInsert().Model(session).Exec(ctx)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *DBSessionStore) Validate(ctx context.Context, sessionID string) (int64, string, error) {
	// One query: join the session row to its user so the role is always the
	// current value (a role change need not invalidate sessions to take
	// effect on the next request). expires_at and the 2FA verified flag are
	// enforced here exactly as before.
	var row struct {
		UserID   int64  `bun:"user_id"`
		Verified bool   `bun:"verified"`
		Role     string `bun:"role"`
	}
	err := s.db.NewRaw(
		`SELECT s.user_id, s.verified, u.role
		   FROM sessions s
		   JOIN users u ON u.id = s.user_id
		  WHERE s.id = ? AND s.expires_at > NOW()`,
		sessionID,
	).Scan(ctx, &row)
	if err != nil {
		return 0, "", ErrSessionNotFound
	}

	// 2FA seam: if the session is not yet verified (pending 2FA),
	// reject it from accessing protected resources.
	if !row.Verified {
		return 0, "", ErrSessionNotFound
	}

	return row.UserID, row.Role, nil
}

func (s *DBSessionStore) Invalidate(ctx context.Context, sessionID string) error {
	_, err := s.db.NewDelete().
		Model((*Session)(nil)).
		Where("id = ?", sessionID).
		Exec(ctx)
	return err
}

func (s *DBSessionStore) InvalidateAll(ctx context.Context, userID int64) error {
	_, err := s.db.NewDelete().
		Model((*Session)(nil)).
		Where("user_id = ?", userID).
		Exec(ctx)
	return err
}

// generateSessionID creates a cryptographically random session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, sessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
