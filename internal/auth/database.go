package auth

import (
	"context"
	"strings"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// GetUserByID fetches a user by primary key. Shared by self-profile and admin.
func GetUserByID(ctx context.Context, db *bun.DB, userID int64) (*types.User, error) {
	var user types.User
	err := db.NewSelect().
		Model(&user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// ApplyProfileUpdate applies the non-zero fields of req to an already-loaded
// user and persists the change via db (a *bun.DB or a *bun.Tx), enforcing
// email uniqueness. The caller owns loading the user — self-profile loads by
// id; admin loads with SELECT ... FOR UPDATE inside a scoped transaction, so
// the scope check and the write are one atomic step (no check-then-act gap).
// Immutable fields (id, role, password_hash, created_at) are structurally
// absent from UpdateProfileRequest, so role can never be set here.
func ApplyProfileUpdate(ctx context.Context, db bun.IDB, user *types.User, req *UpdateProfileRequest) error {
	userID := user.ID

	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Email != "" && req.Email != user.Email {
		// WhatsApp is no longer unique; only email is checked for conflicts.
		count, err := db.NewSelect().
			Model((*types.User)(nil)).
			Where("email = ? AND id != ?", req.Email, userID).
			Count(ctx)
		if err != nil {
			return err
		}
		if count > 0 {
			return ErrUpdateConflict
		}
		user.Email = req.Email
	}
	if req.WhatsApp != "" {
		// WhatsApp is not unique and not a login identifier — no conflict check.
		user.WhatsApp = req.WhatsApp
	}
	if req.Dojo != "" {
		user.Dojo = req.Dojo
	}
	if req.Rank != "" {
		if !allowedRanks[req.Rank] {
			return ErrInvalidRank
		}
		user.Rank = req.Rank
	}
	if req.DateOfBirth != "" {
		dob, err := types.ParseDate(req.DateOfBirth)
		if err != nil {
			return err
		}
		user.DateOfBirth = dob
	}
	if req.LastGradingDate != "" {
		lgd, err := types.ParseDate(req.LastGradingDate)
		if err != nil {
			return err
		}
		user.LastGradingDate = lgd
	}
	if req.MedicalConditions != "" {
		user.MedicalConditions = req.MedicalConditions
	}
	if req.EmergencyContactName != "" {
		user.EmergencyContactName = req.EmergencyContactName
	}
	if req.EmergencyContactNumber != "" {
		user.EmergencyContactNumber = req.EmergencyContactNumber
	}
	if req.ConsentDataStore != nil {
		user.ConsentDataStore = *req.ConsentDataStore
	}
	if req.ConsentMarketing != nil {
		user.ConsentMarketingEmails = *req.ConsentMarketing
	}

	_, err := db.NewUpdate().
		Model(user).
		Where("id = ?", userID).
		Exec(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			return ErrUpdateConflict
		}
		return err
	}
	return nil
}

// UpdateUserProfile loads a user by id and applies a partial update. This is
// the self-profile path (no scope guard, no row lock).
func UpdateUserProfile(ctx context.Context, db *bun.DB, userID int64, req *UpdateProfileRequest) error {
	var user types.User
	err := db.NewSelect().
		Model(&user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return ErrUserNotFound
	}
	return ApplyProfileUpdate(ctx, db, &user, req)
}

// TODO(audit-cleanup): implement opportunistic audit self-cleanup when audit
// approaches ~50k rows — reltuples gate → keep-newest-N DELETE → Warn log
// (event=table_cleanup) + Audit{action:"cleanup"}. Deferred (YAGNI); full
// design + trigger in AGENTS.md "Resource Constraints".

// Audit records an action in the audit table. Shared by auth and admin.
func Audit(ctx context.Context, db *bun.DB, logger zerolog.Logger, userID int64, action string) {
	if db == nil {
		return
	}
	_, err := db.NewInsert().
		Model(&types.Audit{UserID: userID, Action: action}).
		Exec(ctx)
	if err != nil {
		logger.Error().Err(err).Int64("user_id", userID).Str("action", action).Msg("failed to write audit record")
	}
}
