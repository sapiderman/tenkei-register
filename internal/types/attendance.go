package types

import (
	"time"

	"github.com/uptrace/bun"
)

// Attendance statuses (prd/attendance.prd): a member's entry starts pending;
// an admin's decision moves it to confirmed or rejected.
const (
	AttendancePending   = "pending"
	AttendanceConfirmed = "confirmed"
	AttendanceRejected  = "rejected"
)

// Attendance is the database model for the attendance table.
type Attendance struct {
	bun.BaseModel `bun:"table:attendance"`

	ID                int64      `bun:"id,pk,autoincrement"`
	UserID            int64      `bun:"user_id,notnull"`
	Dojo              string     `bun:"dojo,notnull"`
	Instructor        string     `bun:"instructor,notnull"`
	Latitude          *float64   `bun:"latitude"`
	Longitude         *float64   `bun:"longitude"`
	LocationAccuracyM *int64     `bun:"location_accuracy_m"`
	LoggedAt          time.Time  `bun:"logged_at,notnull,default:current_timestamp"`
	Status            string     `bun:"status,notnull,default:'pending'"`
	ConfirmedBy       *int64     `bun:"confirmed_by,nullzero"`
	ConfirmedAt       *time.Time `bun:"confirmed_at,nullzero"`
}
