package types

import (
	"time"

	"github.com/uptrace/bun"
)

// User is the shared database model for the users table.
// Both register and auth packages use this type.
type User struct {
	bun.BaseModel `bun:"table:users"`

	ID        int64     `bun:"id,pk,autoincrement"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp"`

	Name            string    `bun:"name,notnull"`
	Email           string    `bun:"email,notnull"`
	WhatsApp        string    `bun:"whatsapp_number"`
	PasswordHash    string    `bun:"password_hash,notnull"`
	JoinDate        time.Time `bun:"join_date,notnull,default:current_timestamp"`
	Dojo            string    `bun:"dojo"`
	Faculty         string    `bun:"faculty"`
	Major           string    `bun:"major"`
	Category        string    `bun:"category,notnull,default:'regular'"`
	University      string    `bun:"university"`
	SchoolName      string    `bun:"school_name"`
	GuardianName    string    `bun:"guardian_name"`
	DateOfBirth     time.Time `bun:"date_of_birth"`
	Rank            string    `bun:"rank"`
	LastGradingDate time.Time `bun:"last_grading_date"`

	Role                   string `bun:"role,notnull"`
	ConsentDataStore       bool   `bun:"consent_datastore,notnull,default:false"`
	ConsentMarketingEmails bool   `bun:"consent_marketing,notnull,default:false"`

	MedicalConditions      string `bun:"medical_conditions"`
	EmergencyContactName   string `bun:"emergency_contact_name"`
	EmergencyContactNumber string `bun:"emergency_contact_number"`

	// TOTP second factor (otp-plan.md). TOTPSecret is AES-256-GCM encrypted
	// (internal/totp) — never logged, never serialized in any response; the
	// nullzero tag keeps "never enrolled" as SQL NULL, never ''.
	TOTPSecret      string `bun:"totp_secret,nullzero"`
	TOTPEnabled     bool   `bun:"totp_enabled,notnull,default:false"`
	TOTPLastCounter int64  `bun:"totp_last_counter,notnull,default:0"` // replay guard: highest accepted TOTP step
}

// User categories (new-category.prd). One per user, chosen at registration,
// editable via profile/admin updates, independent of dojo.
const (
	CategoryRegular = "regular"
	CategoryStudent = "student"
	CategoryKids    = "kids"
)

// ValidCategory reports whether c is one of the three user categories.
func ValidCategory(c string) bool {
	switch c {
	case CategoryRegular, CategoryStudent, CategoryKids:
		return true
	}
	return false
}

// CategoryFields holds the category-conditional columns; the zero value
// means "all empty".
type CategoryFields struct {
	University, Faculty, Major, SchoolName, GuardianName string
}

// CategoryFieldsMissing reports whether the category's required fields are
// absent or disallowed fields are filled. Unknown category → true
// (fail-closed). Single source of the rule for registration, self-profile,
// and admin updates.
func CategoryFieldsMissing(category string, f CategoryFields) bool {
	filled := func(s string) bool { return s != "" }
	switch category {
	case CategoryRegular:
		return filled(f.University) || filled(f.Faculty) || filled(f.Major) ||
			filled(f.SchoolName) || filled(f.GuardianName)
	case CategoryStudent:
		// Exactly one path: university+faculty+major, or school_name alone.
		universityPath := filled(f.University) && filled(f.Faculty) && filled(f.Major) &&
			!filled(f.SchoolName) && !filled(f.GuardianName)
		schoolPath := filled(f.SchoolName) && !filled(f.University) && !filled(f.Faculty) &&
			!filled(f.Major) && !filled(f.GuardianName)
		return !(universityPath || schoolPath)
	case CategoryKids:
		return !filled(f.GuardianName) || filled(f.University) || filled(f.Faculty) ||
			filled(f.Major) || filled(f.SchoolName)
	default:
		return true
	}
}
