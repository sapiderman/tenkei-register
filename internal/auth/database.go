package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &user, nil
}

// ApplyProfileUpdate applies the non-zero fields of req to an already-loaded
// user and persists the change via db (a *bun.DB or a *bun.Tx), enforcing
// email uniqueness. The caller owns loading the user — self-profile loads by
// id; admin loads with SELECT ... FOR UPDATE inside a scoped transaction, so
// the scope check and the write are one atomic step (no check-then-act gap).
// The write uses an explicit column whitelist: immutable columns (id, role,
// password_hash, created_at, join_date) can never be touched even if the
// struct grows new fields, so a concurrent role change can't be clobbered
// by a full-row rewrite from this path.
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
	if req.Faculty != "" {
		user.Faculty = req.Faculty
	}
	if req.Major != "" {
		user.Major = req.Major
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

	// Post-state invariant: a member of the UI campus dojo always carries
	// faculty and major. Checked after applying req so switching dojo to/from
	// the campus dojo is judged on the resulting row, not the payload.
	if types.FacultyMajorMissing(user.Dojo, user.Faculty, user.Major) {
		return ErrFacultyMajorRequired
	}

	_, err := db.NewUpdate().
		Model(user).
		// Explicit whitelist of the editable columns. Everything else on the
		// struct (role, password_hash, id, created_at, join_date) is excluded
		// from the UPDATE, so this path can never clobber a concurrent role or
		// credential change that happened after the caller loaded the row.
		Column(
			"name", "email", "whatsapp_number",
			"dojo", "faculty", "major", "rank", "date_of_birth", "last_grading_date",
			"medical_conditions", "emergency_contact_name", "emergency_contact_number",
			"consent_datastore", "consent_marketing",
		).
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

// UpdateUserPassword sets a user's password hash by id (self-service
// password change). Column-explicit, like ApplyProfileUpdate.
func UpdateUserPassword(ctx context.Context, db *bun.DB, userID int64, passwordHash string) error {
	_, err := db.NewUpdate().
		Model((*types.User)(nil)).
		Set("password_hash = ?", passwordHash).
		Where("id = ?", userID).
		Exec(ctx)
	return err
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
