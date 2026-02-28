// Package register provides functionalities for user registration
package register

import (
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sapiderman/tenkei-register/internal/server"
	"golang.org/x/crypto/bcrypt"
)

// RegistrationFormData holds form data and validation state for template rendering.
type RegistrationFormData struct {
	// Form values
	Email                  string `json:"email"`
	Name                   string `json:"name"`
	WhatsApp               string `json:"whatsapp"`
	DateOfBirth            string `json:"date_of_birth"`
	Dojo                   string `json:"dojo"`
	Rank                   string `json:"rank"`
	LastGradingDate        string `json:"last_grading_date"`
	Role                   string `json:"role"`
	ConsentDataStore       bool   `json:"consent_datastore"`
	ConsentMarketingEmails bool   `json:"consent_marketing"`
	MedicalConditions      string `json:"medical_conditions"`
	EmergencyContactName   string `json:"emergency_contact_name"`
	EmergencyContactNumber string `json:"emergency_contact_number"`
	CfTurnstileResponse    string `json:"cf_turnstile_response"`

	// Error message for display
	Error string
}

// sanitizeInput trims whitespace and escapes HTML to prevent XSS attacks.
func sanitizeInput(input string) string {
	return html.EscapeString(strings.TrimSpace(input))
}

// sanitizeFormData applies sanitizeInput to all string fields in RegistrationFormData.
func sanitizeFormData(d RegistrationFormData) RegistrationFormData {
	d.Email = sanitizeInput(d.Email)
	d.Name = sanitizeInput(d.Name)
	d.WhatsApp = sanitizeInput(d.WhatsApp)
	d.DateOfBirth = sanitizeInput(d.DateOfBirth)
	d.Dojo = sanitizeInput(d.Dojo)
	d.Rank = sanitizeInput(d.Rank)
	d.LastGradingDate = sanitizeInput(d.LastGradingDate)
	d.Role = sanitizeInput(d.Role)
	d.MedicalConditions = sanitizeInput(d.MedicalConditions)
	d.EmergencyContactName = sanitizeInput(d.EmergencyContactName)
	d.EmergencyContactNumber = sanitizeInput(d.EmergencyContactNumber)
	d.CfTurnstileResponse = sanitizeInput(d.CfTurnstileResponse)
	return d
}

// parseDate safely parses a date string in YYYY-MM-DD format.
// Returns zero time for empty input and an error for invalid formats.
func parseDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}, errors.New("invalid date format, use YYYY-MM-DD")
	}
	return t, nil
}

// parseCheckbox returns true if the checkbox value indicates it was checked.
func parseCheckbox(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "on" || v == "1"
}

// allowedRanks defines the valid rank values for validation.
var allowedRanks = map[string]bool{
	"":                 true, // empty is allowed
	"10th Kyu":         true,
	"9th Kyu":          true,
	"8th Kyu":          true,
	"7th Kyu":          true,
	"6th Kyu":          true,
	"5th Kyu":          true,
	"4th Kyu":          true,
	"3rd Kyu":          true,
	"2nd Kyu":          true,
	"1st Kyu":          true,
	"Shodan (1st Dan)": true,
	"Nidan (2nd Dan)":  true,
	"Sandan (3rd Dan)": true,
	"Yondan (4th Dan)": true,
	"Godan (5th Dan)":  true,
}

// wantsJSON checks if the client expects or sends JSON.
func wantsJSON(req *http.Request) bool {
	ct := strings.ToLower(req.Header.Get("Content-Type"))
	accept := strings.ToLower(req.Header.Get("Accept"))
	return strings.Contains(ct, "application/json") || strings.Contains(accept, "application/json")
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// RenderError implements server.ErrorResponder interface
func (r *registrar) RenderError(w http.ResponseWriter, blockName string, data interface{}) {
	formData, ok := data.(RegistrationFormData)
	if !ok {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	r.renderRegistrationBlock(w, blockName, formData)
}

func (r *registrar) verifyTurnstileResponse(req *http.Request, token string) error {
	// Check if turnstile verification is enabled first; bypass if disabled
	if !r.turnstileEnabled {
		r.logger.Info().Msg("Bypassing Turnstile verification")
		return nil
	}

	// If enabled, validate required fields
	if token == "" {
		r.logger.Warn().Msg("Turnstile token is empty")
		return errors.New("turnstile token is empty")
	}

	if r.turnstileSecret == "" {
		r.logger.Error().Msg("TURNSTILE_SECRET_KEY not configured")
		return errors.New("TURNSTILE_SECRET_KEY not configured")
	}

	form := url.Values{}
	form.Add("secret", r.turnstileSecret)
	form.Add("response", token)

	// Add trusted client IP for Turnstile verification.
	// Prefer CF-Connecting-IP when behind Cloudflare; otherwise fallback to RemoteAddr.
	var remoteIP string
	if cfIP := strings.TrimSpace(req.Header.Get("CF-Connecting-IP")); cfIP != "" {
		remoteIP = cfIP
	} else {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			remoteIP = host
		} else {
			remoteIP = req.RemoteAddr
		}
	}
	if remoteIP != "" {
		form.Add("remoteip", remoteIP)
	}

	r.logger.Debug().
		Str("remoteIP", remoteIP).
		Msg("Sending Turnstile verification request")

	resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", form)
	if err != nil {
		r.logger.Error().
			Err(err).
			Str("remoteIP", remoteIP).
			Msg("Turnstile HTTP request failed")
		return err
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		r.logger.Error().
			Int("statusCode", resp.StatusCode).
			Str("status", resp.Status).
			Msg("Turnstile API returned non-OK status")
		return errors.New("turnstile API returned non-OK status: " + resp.Status)
	}

	// Cloudflare Turnstile response structure
	// See: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
	var result struct {
		Success     bool     `json:"success"`
		ChallengeTS string   `json:"challenge_ts"` // ISO timestamp of challenge
		Hostname    string   `json:"hostname"`     // Hostname of site where challenge was solved
		ErrorCodes  []string `json:"error-codes"`  // Error codes if verification failed
		Action      string   `json:"action"`       // Action name (if configured)
		CData       string   `json:"cdata"`        // Custom data (if configured)
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		r.logger.Error().
			Err(err).
			Int("statusCode", resp.StatusCode).
			Msg("Failed to decode Turnstile response")
		return errors.New("failed to decode turnstile response: " + err.Error())
	}

	// Log the full response details for debugging
	logEvent := r.logger.Debug().
		Bool("success", result.Success).
		Str("hostname", result.Hostname).
		Str("challengeTS", result.ChallengeTS).
		Str("remoteIP", remoteIP)

	if result.Action != "" {
		logEvent = logEvent.Str("action", result.Action)
	}
	if result.CData != "" {
		logEvent = logEvent.Str("cdata", result.CData)
	}
	if len(result.ErrorCodes) > 0 {
		logEvent = logEvent.Strs("errorCodes", result.ErrorCodes)
	}
	logEvent.Msg("Turnstile verification response")

	if !result.Success {
		// Log error with detailed information from Cloudflare
		errLogger := r.logger.Error().
			Strs("errorCodes", result.ErrorCodes).
			Str("hostname", result.Hostname).
			Str("challengeTS", result.ChallengeTS).
			Str("remoteIP", remoteIP)

		// Provide human-readable error descriptions
		var errorDescriptions []string
		for _, code := range result.ErrorCodes {
			switch code {
			case "missing-input-secret":
				errorDescriptions = append(errorDescriptions, "The secret parameter was not passed")
			case "invalid-input-secret":
				errorDescriptions = append(errorDescriptions, "The secret parameter was invalid or did not exist")
			case "missing-input-response":
				errorDescriptions = append(errorDescriptions, "The response parameter was not passed")
			case "invalid-input-response":
				errorDescriptions = append(errorDescriptions, "The response parameter is invalid or has expired")
			case "bad-request":
				errorDescriptions = append(errorDescriptions, "The request was rejected because it was malformed")
			case "timeout-or-duplicate":
				errorDescriptions = append(errorDescriptions, "The response parameter has already been validated before or is too old")
			case "internal-error":
				errorDescriptions = append(errorDescriptions, "An internal error happened while validating the response (retry)")
			default:
				errorDescriptions = append(errorDescriptions, "Unknown error: "+code)
			}
		}

		if len(errorDescriptions) > 0 {
			errLogger = errLogger.Strs("errorDescriptions", errorDescriptions)
		}

		errLogger.Msg("Turnstile verification failed")
		return errors.New("turnstile verification failed: " + strings.Join(result.ErrorCodes, ", "))
	}

	r.logger.Info().
		Str("hostname", result.Hostname).
		Str("remoteIP", remoteIP).
		Msg("Turnstile verification successful")

	return nil
}

func (r *registrar) handleSubmission(w http.ResponseWriter, req *http.Request) {
	isJSON := wantsJSON(req)

	var formData RegistrationFormData
	var password string
	var passwordConfirm string

	if isJSON {
		// Decode JSON body
		type apiRegistrationRequest struct {
			RegistrationFormData `json:",inline"`
			Password             string `json:"password" validate:"required"`         // #nosec G117
			PasswordConfirm      string `json:"password_confirm" validate:"required"` // #nosec G117
		}

		req.Body = http.MaxBytesReader(w, req.Body, 1<<20)
		var payload apiRegistrationRequest
		decoder := json.NewDecoder(req.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			r.logger.Warn().Caller().Err(err).Msg("invalid JSON payload")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			r.logger.Warn().Caller().Err(err).Msg("invalid JSON payload")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
			return
		}

		// Ensure checkbox values are respected if coming as strings (already bool in JSON)
		formData = sanitizeFormData(payload.RegistrationFormData)
		password = payload.Password
		passwordConfirm = payload.PasswordConfirm
	} else {
		// Parse form data
		if err := req.ParseForm(); err != nil {
			r.logger.Debug().Caller().Err(err).Msg("failed to parse form")
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		// Extract and sanitize all form values
		formData = RegistrationFormData{
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
			CfTurnstileResponse:    req.FormValue("cf_turnstile_response"),
		}

		password = req.FormValue("password")
		passwordConfirm = req.FormValue("password_confirm")
	}

	// Verify Turnstile response
	turnstileToken := formData.CfTurnstileResponse
	err := r.verifyTurnstileResponse(req, turnstileToken)
	if err != nil {
		formData.Error = "Security verification failed. Please try again in a few minutes."
		r.logger.Error().Caller().Err(err).Msg("Turnstile verification failed")
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Required field: Name
	if formData.Name == "" {
		formData.Error = "Name is required."
		r.logger.Warn().Caller().Msg("Name is required")
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(formData.Name) > 255 {
		formData.Error = "Name is too long (max 255 characters)."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Required field: WhatsApp
	if formData.WhatsApp == "" {
		formData.Error = "WhatsApp number is required."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(formData.WhatsApp) > 20 {
		formData.Error = "WhatsApp number is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Validate email format (if provided)
	if formData.Email != "" {
		if err := r.validate.Var(formData.Email, "email"); err != nil {
			formData.Error = "Invalid email address."
			r.logger.Warn().Caller().Msg(formData.Error)
			server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
			return
		}
	}

	// Required field: Password
	if password == "" {
		formData.Error = "Password is required."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(password) < 8 {
		formData.Error = "Password must be at least 8 characters."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(password) > 72 { // bcrypt limit
		formData.Error = "Password is too long (max 72 characters)."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if password != passwordConfirm {
		formData.Error = "Passwords do not match."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Validate rank (must be from allowed list)
	if !allowedRanks[formData.Rank] {
		formData.Error = "Invalid rank selected."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Required: Data storage consent
	if !formData.ConsentDataStore {
		formData.Error = "You must consent to data storage to register."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	// Validate field lengths for security
	if len(formData.Dojo) > 255 {
		formData.Error = "Dojo name is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(formData.MedicalConditions) > 2000 {
		formData.Error = "Medical conditions text is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(formData.EmergencyContactName) > 255 {
		formData.Error = "Emergency contact name is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}
	if len(formData.EmergencyContactNumber) > 20 {
		formData.Error = "Emergency contact number is too long."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	dateOfBirth, err := parseDate(formData.DateOfBirth)
	if err != nil {
		formData.Error = "Date of birth must be in YYYY-MM-DD format."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
		return
	}

	lastGradingDate, err := parseDate(formData.LastGradingDate)
	if err != nil {
		formData.Error = "Last grading date must be in YYYY-MM-DD format."
		r.logger.Warn().Caller().Msg(formData.Error)
		server.SendError(w, isJSON, http.StatusBadRequest, formData.Error, r, "register-form", formData)
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
		DateOfBirth:            dateOfBirth,
		Dojo:                   formData.Dojo,
		Rank:                   formData.Rank,
		LastGradingDate:        lastGradingDate,
		Role:                   formData.Role,
		ConsentDataStore:       formData.ConsentDataStore,
		ConsentMarketingEmails: formData.ConsentMarketingEmails,
		MedicalConditions:      formData.MedicalConditions,
		EmergencyContactName:   formData.EmergencyContactName,
		EmergencyContactNumber: formData.EmergencyContactNumber,
	}

	// hard coded defaults for now
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
		server.SendError(w, isJSON, http.StatusConflict, formData.Error, r, "register-form", formData)
		return
	}

	r.logger.Info().Int64("user_id", user.ID).Msg("user registered successfully")

	server.SendResponse(w, isJSON, http.StatusCreated, r, "register-success", formData)
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
