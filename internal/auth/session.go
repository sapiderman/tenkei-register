package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
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

	// Opportunistic purge of expired sessions, piggy-backed on login cadence.
	// Best-effort: a failure here must never block a login. Cloud Run forbids
	// background tickers (AGENTS.md AI Rule 8), so login is the trigger.
	// ponytail: fixed single DELETE — if login QPS grows enough that this
	// per-login delete matters, move to an external Cloud Scheduler endpoint.
	if _, err := s.db.NewDelete().
		Model((*Session)(nil)).
		Where("expires_at < NOW()").
		Exec(ctx); err != nil {
		// Best-effort only; a later login retries. Never block a login on this.
	}

	session := &Session{
		// Only the SHA-256 of the token is persisted: a DB read/leak (backup,
		// SQL injection elsewhere, provider compromise) must not yield usable
		// session tokens.
		ID:     hashSessionID(id),
		UserID: userID,
		// Unverified (2FA-pending) sessions live for pendingSessionTTL only;
		// RotatePending issues the full sessionMaxAge once the code checks out.
		ExpiresAt: time.Now().Add(sessionTTL(verified)),
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
		hashSessionID(sessionID),
	).Scan(ctx, &row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrSessionNotFound
		}
		// A DB outage must surface as 500, not masquerade as "session expired"
		// (a 401 that lies about the cause and hides auth incidents).
		return 0, "", fmt.Errorf("session store: %w", err)
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
		Where("id = ?", hashSessionID(sessionID)).
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

// sessionTTL returns the lifetime of a newly created session: the full
// sessionMaxAge once verified, pendingSessionTTL while a TOTP code is still
// owed.
func sessionTTL(verified bool) time.Duration {
	if verified {
		return sessionMaxAge
	}
	return pendingSessionTTL
}

// ValidatePending admits only unexpired, unverified sessions. Verified
// sessions are rejected here just as pending ones are rejected by Validate —
// the two methods partition sessions so the 2FA verify endpoint is the only
// place a pending cookie works, and a promoted cookie can never be replayed
// against it.
func (s *DBSessionStore) ValidatePending(ctx context.Context, sessionID string) (int64, error) {
	var row struct {
		UserID int64 `bun:"user_id"`
	}
	err := s.db.NewRaw(
		`SELECT s.user_id
		   FROM sessions s
		  WHERE s.id = ? AND s.expires_at > NOW() AND s.verified = FALSE`,
		hashSessionID(sessionID),
	).Scan(ctx, &row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrSessionNotFound
		}
		return 0, fmt.Errorf("session store: pending validate: %w", err)
	}
	return row.UserID, nil
}

// RotatePending deletes a pending session and mints a fresh verified one
// for the user, returning the new token — session-ID rotation on the
// pending→verified privilege change (OWASP session management): the token
// that lived minutes as half a credential never becomes a full one.
// One statement, atomically: the verified=FALSE + expiry guards keep the
// old MarkVerified semantics — a concurrent double-rotation, an expired
// pending, or a logout in flight deletes nothing, the INSERT selects zero
// rows, and the caller sees ErrSessionNotFound. No opportunistic purge
// here: login step 1 ran it seconds ago on the same cadence.
func (s *DBSessionStore) RotatePending(ctx context.Context, sessionID string, userID int64) (string, error) {
	newToken, err := generateSessionID()
	if err != nil {
		return "", err
	}

	res, err := s.db.NewRaw(
		`WITH killed AS (
		   DELETE FROM sessions WHERE id = ? AND verified = FALSE AND expires_at > NOW() RETURNING id
		 )
		 INSERT INTO sessions (id, user_id, verified, expires_at)
		 SELECT ?, ?, TRUE, NOW() + ? * INTERVAL '1 microsecond'
		   FROM killed`,
		hashSessionID(sessionID),
		hashSessionID(newToken), userID, sessionMaxAge.Microseconds(),
	).Exec(ctx)
	if err != nil {
		return "", fmt.Errorf("session store: rotate: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrSessionNotFound
	}
	return newToken, nil
}

// RecordTOTPFailure bumps the failed-code counter on a pending session and
// returns the new count. The conditional UPDATE cannot resurrect a deleted
// or expired row: zero rows affected means the session is already gone.
func (s *DBSessionStore) RecordTOTPFailure(ctx context.Context, sessionID string) (int, error) {
	var attempts int
	err := s.db.NewRaw(
		`UPDATE sessions SET totp_attempts = totp_attempts + 1
		  WHERE id = ? AND verified = FALSE AND expires_at > NOW()
		  RETURNING totp_attempts`,
		hashSessionID(sessionID),
	).Scan(ctx, &attempts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrSessionNotFound
		}
		return 0, fmt.Errorf("session store: record totp failure: %w", err)
	}
	return attempts, nil
}

// generateSessionID creates a cryptographically random session ID.
func generateSessionID() (string, error) {
	bytes := make([]byte, sessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashSessionID maps a bearer token to its at-rest form. SHA-256 (not bcrypt)
// because session IDs are 256 bits of CSPRNG output — unguessable, so a
// fast hash is sufficient (bcrypt's slowness buys nothing here and would
// add latency to every request). Output is 64 hex chars: same width as
// the raw token, so the sessions.id column needs no migration.
func hashSessionID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
