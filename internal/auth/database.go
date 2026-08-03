package auth

import (
	"context"
	"strings"

	"github.com/sapiderman/tenkei-register/internal/types"
)

// dbGetUserByID fetches a user by primary key.
func (a *authenticator) dbGetUserByID(ctx context.Context, userID int64) (*types.User, error) {
	var user types.User
	err := a.db.NewSelect().
		Model(&user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return &user, nil
}

// dbUpdateUserProfile applies partial updates from UpdateProfileRequest.
// Only non-zero/non-nil fields are updated. Immutable fields (id, role,
// password_hash, created_at) are structurally absent from UpdateProfileRequest.
func (a *authenticator) dbUpdateUserProfile(ctx context.Context, userID int64, req *UpdateProfileRequest) error {
	// Fetch current user to check for conflicts on email/WhatsApp
	var user types.User
	err := a.db.NewSelect().
		Model(&user).
		Where("id = ?", userID).
		Scan(ctx)
	if err != nil {
		return ErrUserNotFound
	}

	// Apply partial updates
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Email != "" {
		// Check for duplicate email
		if req.Email != user.Email {
			var count int
			count, err = a.db.NewSelect().
				Model((*types.User)(nil)).
				Where("email = ? AND id != ?", req.Email, userID).
				Count(ctx)
			if err != nil {
				return err
			}
			if count > 0 {
				return ErrUpdateConflict
			}
		}
		user.Email = req.Email
	}
	if req.WhatsApp != "" {
		// Check for duplicate WhatsApp
		if req.WhatsApp != user.WhatsApp {
			var count int
			count, err = a.db.NewSelect().
				Model((*types.User)(nil)).
				Where("whatsapp_number = ? AND id != ?", req.WhatsApp, userID).
				Count(ctx)
			if err != nil {
				return err
			}
			if count > 0 {
				return ErrUpdateConflict
			}
		}
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

	_, err = a.db.NewUpdate().
		Model(&user).
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

// TODO(audit-cleanup): implement opportunistic audit self-cleanup when audit
// approaches ~50k rows — reltuples gate → keep-newest-N DELETE → Warn log
// (event=table_cleanup) + Audit{action:"cleanup"}. Deferred (YAGNI); full
// design + trigger in AGENTS.md "Resource Constraints".
//
// audit records an action in the audit table.
func (a *authenticator) audit(ctx context.Context, userID int64, action string) {
	if a.db == nil {
		return
	}
	_, err := a.db.NewInsert().
		Model(&types.Audit{UserID: userID, Action: action}).
		Exec(ctx)
	if err != nil {
		a.logger.Error().Err(err).Int64("user_id", userID).Str("action", action).Msg("failed to write audit record")
	}
}
