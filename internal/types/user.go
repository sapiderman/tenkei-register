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
	DateOfBirth     time.Time `bun:"date_of_birth"`
	Rank            string    `bun:"rank"`
	LastGradingDate time.Time `bun:"last_grading_date"`

	Role                   string `bun:"role,notnull"`
	ConsentDataStore       bool   `bun:"consent_datastore,notnull,default:false"`
	ConsentMarketingEmails bool   `bun:"consent_marketing,notnull,default:false"`

	MedicalConditions      string `bun:"medical_conditions"`
	EmergencyContactName   string `bun:"emergency_contact_name"`
	EmergencyContactNumber string `bun:"emergency_contact_number"`
}

// UIDojo is the canonical name of the Universitas Indonesia campus dojo.
// Members of this dojo must record their faculty and major (see
// FacultyMajorMissing). The spelling matches the university's own branding:
// it calls itself "Universitas Indonesia" in every language.
const UIDojo = "Tenkei Universitas Indonesia"

// FacultyMajorMissing reports whether the faculty/major-required rule is
// violated for this dojo: members of UIDojo must have both fields filled.
// It is the single source of the rule, shared by registration, self-profile
// updates, and admin updates.
func FacultyMajorMissing(dojo, faculty, major string) bool {
	return dojo == UIDojo && (faculty == "" || major == "")
}
