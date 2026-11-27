package attendance

import "time"

// LogRequest is the body of POST /v1/attendance. Location is optional: a
// member may decline the browser's GPS prompt. When present, latitude and
// longitude come together (validateLocation).
type LogRequest struct {
	Dojo              string   `json:"dojo" validate:"required,max=255"`
	Instructor        string   `json:"instructor" validate:"required,max=255"`
	Latitude          *float64 `json:"latitude"`
	Longitude         *float64 `json:"longitude"`
	LocationAccuracyM *int64   `json:"location_accuracy_m"`
}

// LogResponse is the 201 body of POST /v1/attendance.
type LogResponse struct {
	ID          int64     `json:"id"`
	LoggedAt    time.Time `json:"logged_at"`
	Dojo        string    `json:"dojo"`
	Instructor  string    `json:"instructor"`
	Status      string    `json:"status"`
	HasLocation bool      `json:"has_location"`
}

// Record is one attendance row as a member sees it: the same facts an admin
// sees, minus the raw coordinates.
type Record struct {
	ID                int64      `json:"id"`
	UserID            int64      `json:"user_id"`
	UserName          string     `json:"user_name"`
	LoggedAt          time.Time  `json:"logged_at"`
	Dojo              string     `json:"dojo"`
	Instructor        string     `json:"instructor"`
	HasLocation       bool       `json:"has_location"`
	LocationAccuracyM *int64     `json:"location_accuracy_m"`
	Status            string     `json:"status"`
	ConfirmedByName   *string    `json:"confirmed_by_name"`
	ConfirmedAt       *time.Time `json:"confirmed_at"`
}

// AdminRecord is a Record plus the raw coordinates — admins only.
type AdminRecord struct {
	Record
	Latitude  *float64 `json:"latitude"`
	Longitude *float64 `json:"longitude"`
}

// MyListResponse wraps one page of the member's own records.
type MyListResponse struct {
	Items []Record `json:"items"`
	Total int64    `json:"total"`
	Page  int      `json:"page"`
	Size  int      `json:"size"`
}

// AdminListResponse wraps one page of the admin list.
type AdminListResponse struct {
	Items []AdminRecord `json:"items"`
	Total int64         `json:"total"`
	Page  int           `json:"page"`
	Size  int           `json:"size"`
}

// InstructorRoster is the GET /v1/attendance/instructors body. All holds the
// instructors whose dojo is ” (teaches everywhere); Instructors groups the
// dojo-specific ones. The client offers sorted unique All + Instructors[dojo].
type InstructorRoster struct {
	All         []string            `json:"all"`
	Instructors map[string][]string `json:"instructors"`
}
