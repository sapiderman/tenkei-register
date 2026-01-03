// Package register provides functionalities for user registration
package register

import (
	"html"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// RegistrationFormData holds form data and validation state for template rendering.
type RegistrationFormData struct {
	// Form values
	Email                  string
	Name                   string
	WhatsApp               string
	DateOfBirth            string
	Dojo                   string
	Rank                   string
	LastGradingDate        string
	Role                   string
	ConsentDataStore       bool
	ConsentMarketingEmails bool
	MedicalConditions      string
	EmergencyContactName   string
	EmergencyContactNumber string

	// Error message for display
	Error string
}

// sanitizeInput trims whitespace and escapes HTML to prevent XSS attacks.
func sanitizeInput(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

// parseDate safely parses a date string in YYYY-MM-DD format.
// Returns zero time if parsing fails.
func parseDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseCheckbox returns true if the checkbox value indicates it was checked.
func parseCheckbox(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "on" || v == "1"
}

// allowedRanks defines the valid rank values for validation.
var allowedRanks = map[string]bool{
	"":         true, // empty is allowed
	"10th Kyu": true,
	"9th Kyu":  true,
	"8th Kyu":  true,
	"7th Kyu":  true,
	"6th Kyu":  true,
	"5th Kyu":  true,
	"4th Kyu":  true,
	"3rd Kyu":  true,
	"2nd Kyu":  true,
	"1st Kyu":  true,
	"Shodan":   true,
	"Nidan":    true,
	"Sandan":   true,
	"Yondan":   true,
	"Godan":    true,
}

// allowedRoles defines the valid role values for validation.
var allowedRoles = map[string]bool{
	"student":    true,
	"instructor": true,
	"admin":      true,
}

func (r *registrar) handleSubmission(w http.ResponseWriter, req *http.Request) {
	// Parse form data
	if err := req.ParseForm(); err != nil {
		r.logger.Debug().Caller().Err(err).Msg("failed to parse form")
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract and sanitize all form values
	formData := RegistrationFormData{
		Name:                   sanitizeInput(req.FormValue("name")),
		Email:                  sanitizeInput(req.FormValue("email")),
		WhatsApp:               sanitizeInput(req.FormValue("whatsapp")),
		DateOfBirth:            sanitizeInput(req.FormValue("date_of_birth")),
		Dojo:                   sanitizeInput(req.FormValue("dojo")),
		Rank:                   sanitizeInput(req.FormValue("rank")),
		LastGradingDate:        sanitizeInput(req.FormValue("last_grading_date")),
		Role:                   sanitizeInput(req.FormValue("role")),
		MedicalConditions:      sanitizeInput(req.FormValue("medical_conditions")),
		EmergencyContactName:   sanitizeInput(req.FormValue("emergency_contact_name")),
		EmergencyContactNumber: sanitizeInput(req.FormValue("emergency_contact_number")),
		ConsentDataStore:       parseCheckbox(req.FormValue("consent_datastore")),
		ConsentMarketingEmails: parseCheckbox(req.FormValue("consent_marketing")),
	}

	password := req.FormValue("password")
	passwordConfirm := req.FormValue("password_confirm")

	// --- Validation ---

	// Required field: Name
	if formData.Name == "" {
		formData.Error = "Name is required."
		r.logger.Warn().Caller().Msg("Name is required")
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(formData.Name) > 255 {
		formData.Error = "Name is too long (max 255 characters)."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// Required field: WhatsApp
	if formData.WhatsApp == "" {
		formData.Error = "WhatsApp number is required."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(formData.WhatsApp) > 20 {
		formData.Error = "WhatsApp number is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// Validate email format (if provided)
	if formData.Email != "" {
		if err := r.validate.Var(formData.Email, "email"); err != nil {
			formData.Error = "Invalid email address."
			r.logger.Warn().Caller().Msg(formData.Error)
			r.renderRegistrationBlock(w, "register-form", formData)
			return
		}
	}

	// Required field: Password
	if password == "" {
		formData.Error = "Password is required."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(password) < 8 {
		formData.Error = "Password must be at least 8 characters."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(password) > 72 { // bcrypt limit
		formData.Error = "Password is too long (max 72 characters)."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if password != passwordConfirm {
		formData.Error = "Passwords do not match."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// Validate rank (must be from allowed list)
	if !allowedRanks[formData.Rank] {
		formData.Error = "Invalid rank selected."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// Required: Data storage consent
	if !formData.ConsentDataStore {
		formData.Error = "You must consent to data storage to register."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// Validate field lengths for security
	if len(formData.Dojo) > 255 {
		formData.Error = "Dojo name is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(formData.MedicalConditions) > 2000 {
		formData.Error = "Medical conditions text is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(formData.EmergencyContactName) > 255 {
		formData.Error = "Emergency contact name is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}
	if len(formData.EmergencyContactNumber) > 20 {
		formData.Error = "Emergency contact number is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	// --- Build User struct ---
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		r.logger.Error().Err(err).Msg("failed to hash password")
		formData.Error = "An error occurred. Please try again."
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	user := User{
		Name:                   formData.Name,
		Email:                  formData.Email,
		WhatsApp:               formData.WhatsApp,
		PasswordHash:           string(hashedPwd),
		DateOfBirth:            parseDate(formData.DateOfBirth),
		Dojo:                   formData.Dojo,
		Rank:                   formData.Rank,
		LastGradingDate:        parseDate(formData.LastGradingDate),
		Role:                   formData.Role,
		ConsentDataStore:       formData.ConsentDataStore,
		ConsentMarketingEmails: formData.ConsentMarketingEmails,
		MedicalConditions:      formData.MedicalConditions,
		EmergencyContactName:   formData.EmergencyContactName,
		EmergencyContactNumber: formData.EmergencyContactNumber,
	}

	// hard coded defaults
	user.Role = "user"

	// --- Insert into database ---
	if err := r.dbInsertUser(req.Context(), &user); err != nil {
		// Check for duplicate email/whatsapp
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			formData.Error = "An account with this email or WhatsApp number already exists."
		} else {
			formData.Error = "Registration failed. Please try again later."
		}
		r.logger.Error().Caller().Err(err).Msg(formData.Error)
		r.renderRegistrationBlock(w, "register-form", formData)
		return
	}

	r.logger.Info().Str("name", user.Name).Str("whatsapp", user.WhatsApp).Msg("user registered successfully")

	// --- Success ---
	r.renderRegistrationBlock(w, "register-success", formData)
}

func (r *registrar) showPage(w http.ResponseWriter, req *http.Request) {
	err := r.templates.ExecuteTemplate(w, "register.html", RegistrationFormData{})
	if err != nil {
		r.logger.Error().Caller().Err(err).Msg("failed to render register page")
		http.Error(w, "Template Error", http.StatusInternalServerError)
	}
}

// renderRegistrationBlock renders a specific template block for HTMX partial updates.
func (r *registrar) renderRegistrationBlock(w http.ResponseWriter, blockName string, data RegistrationFormData) {
	err := r.templates.ExecuteTemplate(w, blockName, data)
	if err != nil {
		http.Error(w, "Render Error", http.StatusInternalServerError)
	}
}

func (r *registrar) getUserCount(w http.ResponseWriter, req *http.Request) {
	// TODO: Implement user count endpoint
}
