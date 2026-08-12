package admin

import "github.com/sapiderman/tenkei-register/internal/types"

// memberSummaryFromUser maps a full user row to the viewer-safe summary.
// PII (DOB, medical, emergency contact, consent) is dropped.
func memberSummaryFromUser(u *types.User) MemberSummary {
	return MemberSummary{
		ID:       u.ID,
		Name:     u.Name,
		Email:    u.Email,
		WhatsApp: u.WhatsApp,
		Dojo:     u.Dojo,
		Role:     u.Role,
	}
}
