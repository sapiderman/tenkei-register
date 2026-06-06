package auth

import (
	"github.com/sapiderman/tenkei-register/internal/types"
)

// profileFromUser maps a database User to a safe ProfileResponse.
// password_hash is never included.
func profileFromUser(user *types.User) ProfileResponse {
	var dob, lgd string
	if !user.DateOfBirth.IsZero() {
		dob = user.DateOfBirth.Format("2006-01-02")
	}
	if !user.LastGradingDate.IsZero() {
		lgd = user.LastGradingDate.Format("2006-01-02")
	}

	return ProfileResponse{
		ID:                     user.ID,
		Name:                   user.Name,
		Email:                  user.Email,
		WhatsApp:               user.WhatsApp,
		Dojo:                   user.Dojo,
		Rank:                   user.Rank,
		DateOfBirth:            dob,
		JoinDate:               user.JoinDate.Format("2006-01-02"),
		LastGradingDate:        lgd,
		Role:                   user.Role,
		ConsentDataStore:       user.ConsentDataStore,
		ConsentMarketing:       user.ConsentMarketingEmails,
		MedicalConditions:      user.MedicalConditions,
		EmergencyContactName:   user.EmergencyContactName,
		EmergencyContactNumber: user.EmergencyContactNumber,
	}
}