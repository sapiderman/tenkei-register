package admin

import (
	"context"
	"database/sql"

	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// roleVisibleToViewer reports whether a target role is within a viewer's
// scope: superusers see everyone; admins see only new/user. The single
// predicate shared by get/verify/update scoping.
func roleVisibleToViewer(viewerLevel int, role string) bool {
	if viewerLevel >= types.RoleLevel(types.RoleSuperuser) {
		return true
	}
	return role == types.RoleNew || role == types.RoleUser
}

// getMemberForViewer fetches a member for a read-only admin action, enforcing
// viewer scope. Out-of-scope is reported as not-found (anti-enumeration): an
// admin must not learn that an admin/superuser id exists.
func getMemberForViewer(ctx context.Context, db *bun.DB, viewerLevel int, targetID int64) (*types.User, error) {
	user, err := auth.GetUserByID(ctx, db, targetID)
	if err != nil {
		return nil, ErrMemberNotFound
	}
	if !roleVisibleToViewer(viewerLevel, user.Role) {
		return nil, ErrMemberNotFound
	}
	return user, nil
}

// updateMemberForViewer applies a profile edit to an in-scope target as one
// atomic step. The target row is locked (SELECT ... FOR UPDATE) for the
// duration of the transaction, so the scope check and the write cannot be
// separated by a concurrent role change: an admin cannot edit a target that a
// superuser promotes to admin/superuser in the window between check and update.
// This is also a single round-trip group (one locked fetch, then the write),
// honoring the "one query per intent" resource rule.
func updateMemberForViewer(ctx context.Context, db *bun.DB, viewerLevel int, targetID int64, req *auth.UpdateProfileRequest) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	var user types.User
	if err = tx.NewSelect().Model(&user).Where("id = ?", targetID).For("UPDATE").Scan(ctx); err != nil {
		return ErrMemberNotFound
	}
	if !roleVisibleToViewer(viewerLevel, user.Role) {
		return ErrMemberNotFound
	}

	if err := auth.ApplyProfileUpdate(ctx, tx, &user, req); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// verifyMember transitions an in-scope target from new to user. It returns:
//   - nil on a successful new -> user transition
//   - ErrMemberNotFound if the target does not exist or is out of scope
//   - ErrNotPending if the in-scope target is not in the 'new' role
//
// The UPDATE is conditional on role='new', so a concurrent role change is a
// no-op surfaced as ErrNotPending. Verification does NOT invalidate sessions —
// it is an upgrade within the soft-gated self-service tier (the member keeps
// self-serving exactly as before, now with role='user').
func verifyMember(ctx context.Context, db *bun.DB, viewerLevel int, targetID int64) error {
	member, err := getMemberForViewer(ctx, db, viewerLevel, targetID)
	if err != nil {
		return ErrMemberNotFound
	}
	if member.Role != types.RoleNew {
		return ErrNotPending
	}

	res, err := db.NewUpdate().
		Model((*types.User)(nil)).
		Set("role = ?", types.RoleUser).
		Set("updated_at = CURRENT_TIMESTAMP").
		Where("id = ? AND role = ?", targetID, types.RoleNew).
		Exec(ctx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Flipped by a concurrent request between our fetch and update.
		return ErrNotPending
	}
	return nil
}
