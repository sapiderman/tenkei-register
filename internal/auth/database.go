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
		// Emails are stored lowercase and compared case-insensitively
		// (migrations/000010), so lowercase the request value before the
		// conflict check and the assignment — "New@Example.com" must collide
		// with "new@example.com", not slip past the count and then fail (or
		// worse, succeed against a pre-migration mixed-case row).
		email := strings.ToLower(req.Email)
		// WhatsApp is no longer unique; only email is checked for conflicts.
		count, err := db.NewSelect().
			Model((*types.User)(nil)).
			Where("lower(email) = ? AND id != ?", email, userID).
			Count(ctx)
		if err != nil {
			return err
		}
		if count > 0 {
			return ErrUpdateConflict
		}
		user.Email = email
	}
	if req.WhatsApp != "" {
		// WhatsApp is not unique and not a login identifier — no conflict check.
		// Stored in E.164 international format regardless of input shape.
		whatsapp, err := types.NormalizePhone(req.WhatsApp)
		if err != nil {
			return ErrInvalidPhone
		}
		// Separator-only input (" - ") normalizes to "", and "" means "no change"
		// for every other field here. Assigning it would silently wipe the number.
		if whatsapp != "" {
			user.WhatsApp = whatsapp
		}
	}
	if req.Dojo != "" {
		user.Dojo = req.Dojo
	}
	// Atomic category block: unlike every other field (non-zero-only apply,
	// so nothing can ever be cleared), a present category makes the whole
	// block authoritative — category switch student -> regular must be able
	// to wipe university/faculty/major/school/guardian. An empty category
	// leaves the entire block untouched (backwards compatible).
	if req.Category != "" {
		user.Category = req.Category
		user.University = req.University
		user.Faculty = req.Faculty
		user.Major = req.Major
		user.SchoolName = req.SchoolName
		user.GuardianName = req.GuardianName
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
		emergencyNumber, err := types.NormalizePhone(req.EmergencyContactNumber)
		if err != nil {
			return ErrInvalidPhone
		}
		// Same rule as WhatsApp above: separator-only input is a no-op, not a wipe.
		if emergencyNumber != "" {
			user.EmergencyContactNumber = emergencyNumber
		}
	}
	if req.ConsentDataStore != nil {
		user.ConsentDataStore = *req.ConsentDataStore
	}
	if req.ConsentMarketing != nil {
		user.ConsentMarketingEmails = *req.ConsentMarketing
	}

	// Post-state invariant: the merged row must satisfy the category rules.
	// Checked after applying req (so a category switch is judged on the
	// resulting row) and on the whole block, so legacy rows with stray
	// faculty/major are rejected on their next edit until the member (or an
	// admin) resubmits the block for their category. Fail-closed by design.
	if types.CategoryFieldsMissing(user.Category, types.CategoryFields{
		University:   user.University,
		Faculty:      user.Faculty,
		Major:        user.Major,
		SchoolName:   user.SchoolName,
		GuardianName: user.GuardianName,
	}) {
		return ErrCategoryFields
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
			"category", "university", "school_name", "guardian_name",
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

// AcceptTOTPCounter advances the replay guard to `counter`, succeeding only
// if the stored counter is strictly lower. Two concurrent submits of the
// same TOTP code resolve the same counter; exactly one UPDATE matches, the
// loser is told the code was replayed.
func AcceptTOTPCounter(ctx context.Context, db *bun.DB, userID, counter int64) (bool, error) {
	res, err := db.NewRaw(
		`UPDATE users SET totp_last_counter = ? WHERE id = ? AND totp_last_counter < ?`,
		counter, userID, counter,
	).Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("accept totp counter: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
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
