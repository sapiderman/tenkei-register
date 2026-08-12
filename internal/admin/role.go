package admin

import (
	"context"
	"database/sql"
	"errors"

	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// roleLockKey is the advisory-lock tag shared by every role-change
// transaction. Taking it serializes the last-superuser guard so two concurrent
// superusers cannot demote each other to zero superusers (check-then-act made
// safe under the lock).
//
// ponytail: a single global advisory lock is correct and cheap at dojo scale
// (role changes are rare, manual operations). If throughput ever mattered,
// downgrade contention by locking the (superuser) cohort more narrowly — but
// the last-superuser invariant inherently needs cross-user serialization.
const roleLockKey = 9102

// ErrLastSuperuser is returned when a demotion would leave zero superusers.
// Maps to 409.
var ErrLastSuperuser = errors.New("cannot demote the last superuser")

// setRole changes targetID's role to newRole. The role change and, on a
// demotion (level decrease), the invalidation of all the target's sessions run
// in a single transaction. The last-superuser guard is enforced inside that
// transaction under a serializing advisory lock, so it is race-free.
//
// Returns the previous role and whether the change was a demotion. newRole is
// assumed already validated against the allow-list by the caller.
func setRole(ctx context.Context, db *bun.DB, targetID int64, newRole string) (oldRole string, demoted bool, err error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return "", false, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Serialize the guard across concurrent role changes.
	if _, err = tx.NewRaw(`SELECT pg_advisory_xact_lock(?)`, roleLockKey).Exec(ctx); err != nil {
		return "", false, err
	}

	// Current role of the target (also proves existence).
	if err = tx.NewRaw(`SELECT role FROM users WHERE id = ?`, targetID).Scan(ctx, &oldRole); err != nil {
		return "", false, ErrMemberNotFound
	}

	// Last-superuser guard: demoting the only superuser is refused.
	if oldRole == types.RoleSuperuser && newRole != types.RoleSuperuser {
		var n int
		if err = tx.NewRaw(`SELECT COUNT(*) FROM users WHERE role = 'superuser'`).Scan(ctx, &n); err != nil {
			return "", false, err
		}
		if n <= 1 {
			return "", false, ErrLastSuperuser
		}
	}

	if _, err = tx.NewUpdate().
		Model((*types.User)(nil)).
		Set("role = ?", newRole).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("id = ?", targetID).
		Exec(ctx); err != nil {
		return "", false, err
	}

	// Demotion (level decrease) revokes the target's active sessions in the
	// same transaction. Promotions and same-level changes leave sessions.
	demoted = types.RoleLevel(newRole) < types.RoleLevel(oldRole)
	if demoted {
		if _, err = tx.NewRaw(`DELETE FROM sessions WHERE user_id = ?`, targetID).Exec(ctx); err != nil {
			return "", false, err
		}
	}

	if err = tx.Commit(); err != nil {
		return "", false, err
	}
	committed = true
	return oldRole, demoted, nil
}
