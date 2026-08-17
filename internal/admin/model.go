package admin

// MemberSummary is the viewer-safe row for GET /v1/admin/users: no PII (no
// DOB, medical, or emergency contact). role lets the UI distinguish pending
// from verified and lets superusers see responsibilities.
type MemberSummary struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	WhatsApp string `json:"whatsapp"`
	Dojo     string `json:"dojo"`
	Role     string `json:"role"`
}

// ListUsersResponse wraps a page of summaries with pagination metadata.
type ListUsersResponse struct {
	Members []MemberSummary `json:"members"`
	Total   int64           `json:"total"`
	Page    int             `json:"page"`
	Size    int             `json:"size"`
}

// RoleRequest is the body for PUT /v1/admin/users/:id/role. Only the four
// allow-listed values are accepted (validated in the handler).
type RoleRequest struct {
	Role string `json:"role"`
}
