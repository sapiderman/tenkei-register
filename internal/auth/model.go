package auth

import (
	"time"

	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// Session represents a server-side session stored in PostgreSQL.
type Session struct {
	bun.BaseModel `bun:"table:sessions"`

	ID        string    `bun:"id,pk"`
	UserID    int64     `bun:"user_id,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	Verified  bool      `bun:"verified,notnull"`
}

// LoginRequest is the inbound payload for POST /v1/auth/login.
type LoginRequest struct {
	Identifier          string `json:"identifier" validate:"required"` // email
	Password            string `json:"password" validate:"required"`   // #nosec G117 — never logged
	CfTurnstileResponse string `json:"cf_turnstile_response"`          // optional here; required by the handler when Turnstile is enabled
}

// ProfileResponse is the safe outbound shape for GET /v1/auth/profile.
// password_hash is structurally absent — it can never leak into JSON.
type ProfileResponse struct {
	ID                     int64  `json:"id"`
	Name                   string `json:"name"`
	Email                  string `json:"email"`
	WhatsApp               string `json:"whatsapp"`
	Dojo                   string `json:"dojo"`
	Rank                   string `json:"rank"`
	DateOfBirth            string `json:"date_of_birth,omitempty"`
	JoinDate               string `json:"join_date"`
	LastGradingDate        string `json:"last_grading_date,omitempty"`
	Role                   string `json:"role"`
	ConsentDataStore       bool   `json:"consent_datastore"`
	ConsentMarketing       bool   `json:"consent_marketing"`
	MedicalConditions      string `json:"medical_conditions,omitempty"`
	EmergencyContactName   string `json:"emergency_contact_name,omitempty"`
	EmergencyContactNumber string `json:"emergency_contact_number,omitempty"`
}

// UpdateProfileRequest holds updatable fields only.
// Immutable fields (id, role, password_hash, created_at) are structurally absent,
// which prevents mass-assignment attacks at the type level.
// Pointer booleans distinguish "not sent" (nil) from "set to false".
type UpdateProfileRequest struct {
	Name                   string `json:"name,omitempty" validate:"omitempty,min=1,max=255"`
	Email                  string `json:"email,omitempty" validate:"omitempty,email"`
	CurrentPassword        string `json:"current_password,omitempty" validate:"omitempty,max=72"` // #nosec G117 — write-only, never logged; required only when email changes
	WhatsApp               string `json:"whatsapp,omitempty" validate:"omitempty,max=20"`
	DateOfBirth            string `json:"date_of_birth,omitempty" validate:"omitempty,datetime=2006-01-02"`
	Dojo                   string `json:"dojo,omitempty" validate:"omitempty,max=255"`
	Rank                   string `json:"rank,omitempty"`
	LastGradingDate        string `json:"last_grading_date,omitempty" validate:"omitempty,datetime=2006-01-02"`
	MedicalConditions      string `json:"medical_conditions,omitempty" validate:"omitempty,max=2000"`
	EmergencyContactName   string `json:"emergency_contact_name,omitempty" validate:"omitempty,max=255"`
	EmergencyContactNumber string `json:"emergency_contact_number,omitempty" validate:"omitempty,max=50"`
	ConsentDataStore       *bool  `json:"consent_datastore,omitempty"`
	ConsentMarketing       *bool  `json:"consent_marketing,omitempty"`
}

// PasswordChangeRequest is the inbound payload for POST /v1/auth/password.
// Both fields are write-only and never logged (AGENTS.md rule 3).
type PasswordChangeRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,max=72"`   // #nosec G117 — never logged
	NewPassword     string `json:"new_password" validate:"required,min=8,max=72"` // #nosec G117 — never logged
}

// allowedRanks delegates to the shared single source of truth in types.
var allowedRanks = types.AllowedRanks

const (
	sessionCookieName = "tenkei_session"
	sessionMaxAge     = 12 * time.Hour
	sessionIDLength   = 32 // bytes of randomness, hex-encoded to 64 chars
)
