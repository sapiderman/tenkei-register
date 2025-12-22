package register

import (
	"time"

	"github.com/uptrace/bun"
)

type User struct {
	bun.BaseModel `bun:"table:users"`

	ID        int64     `bun:"id,pk,autoincrement"`
	CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt time.Time `bun:"updated_at,notnull,default:current_timestamp"`

	Name            string    `bun:"name,notnull"`
	Email           string    `bun:"email"`
	WhatsApp        string    `bun:"whatsapp_number,notnull"`
	PasswordHash    string    `bun:"password_hash,notnull"`
	JoinDate        time.Time `bun:"join_date,notnull,default:current_timestamp"`
	Dojo            string    `bun:"dojo"`
	DateOfBirth     time.Time `bun:"date_of_birth"`
	Rank            string    `bun:"rank"`
	LastGradingDate time.Time `bun:"last_grading_date"`

	Role                   string `bun:"role,notnull"`
	ConsentDataStore       bool   `bun:"consent_datastore,notnull,default:false"`
	ConsentMarketingEmails bool   `bun:"consent_marketingemails,notnull,default:false"`

	MedicalConditions      string `bun:"medical_conditions"`
	EmergencyContactName   string `bun:"emergency_contact_name"`
	EmergencyContactNumber string `bun:"emergency_contact_number"`
}
