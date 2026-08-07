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

	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// RegistrationFormData is the JSON request shape for POST /v1/register/.
type RegistrationFormData struct {
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

func (r *registrar) verifyTurnstileResponse(req *http.Request, token string) error {
	// Check if turnstile verification is enabled first; bypass if disabled
	if !r.turnstileEnabled {
		r.logger.Debug().Caller().Msg("Bypassing Turnstile verification")
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

	verifyURL := r.turnstileVerifyURL
	if verifyURL == "" {
		verifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	}
	resp, err := http.PostForm(verifyURL, form) // #nosec G107,G704 — verifyURL is config-derived (TENKEI_SERVER_TURNSTILE_*), never request-controlled
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
	// badRequest logs a client error at warn and writes a 400 JSON response.
	badRequest := func(msg string) {
		r.logger.Warn().Caller().Msg(msg)
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
	}
	// fail logs an unexpected error (with cause) and writes a JSON response.
	fail := func(code int, msg string, err error) {
		r.logger.Error().Caller().Err(err).Msg(msg)
		server.WriteJSON(w, code, map[string]string{"error": msg})
	}

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
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		r.logger.Warn().Caller().Err(err).Msg("invalid JSON payload")
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON payload"})
		return
	}

	formData := sanitizeFormData(payload.RegistrationFormData)
	password := payload.Password
	passwordConfirm := payload.PasswordConfirm

	// Verify Turnstile response (if enabled).
	if err := r.verifyTurnstileResponse(req, formData.CfTurnstileResponse); err != nil {
		fail(http.StatusBadRequest, "Security verification failed. Please try again in a few minutes.", err)
		return
	}

	// Required field: Name
	if formData.Name == "" {
		badRequest("Name is required.")
		return
	}
	if len(formData.Name) > 255 {
		badRequest("Name is too long (max 255 characters).")
		return
	}

	// Required field: Email (sole login identifier)
	if formData.Email == "" {
		badRequest("Email is required.")
		return
	}
	if err := r.validate.Var(formData.Email, "email"); err != nil {
		badRequest("Invalid email address.")
		return
	}

	// Optional field: WhatsApp (no longer a login identifier, no longer unique)
	if formData.WhatsApp != "" && len(formData.WhatsApp) > 20 {
		badRequest("WhatsApp number is too long.")
		return
	}

	// Required field: Password
	if password == "" {
		badRequest("Password is required.")
		return
	}
	if len(password) < 8 {
		badRequest("Password must be at least 8 characters.")
		return
	}
	if len(password) > 72 { // bcrypt limit
		badRequest("Password is too long (max 72 characters).")
		return
	}
	if password != passwordConfirm {
		badRequest("Passwords do not match.")
		return
	}

	// Validate rank (must be from allowed list)
	if !types.AllowedRanks[formData.Rank] {
		badRequest("Invalid rank selected.")
		return
	}

	// Required: Data storage consent
	if !formData.ConsentDataStore {
		badRequest("You must consent to data storage to register.")
		return
	}

	// Validate field lengths for security
	if len(formData.Dojo) > 255 {
		badRequest("Dojo name is too long.")
		return
	}
	if len(formData.MedicalConditions) > 2000 {
		badRequest("Medical conditions text is too long.")
		return
	}
	if len(formData.EmergencyContactName) > 255 {
		badRequest("Emergency contact name is too long.")
		return
	}
	if len(formData.EmergencyContactNumber) > 20 {
		badRequest("Emergency contact number is too long.")
		return
	}

	dateOfBirth, err := types.ParseDate(formData.DateOfBirth)
	if err != nil {
		badRequest("Date of birth must be in YYYY-MM-DD format.")
		return
	}

	lastGradingDate, err := types.ParseDate(formData.LastGradingDate)
	if err != nil {
		badRequest("Last grading date must be in YYYY-MM-DD format.")
		return
	}

	// --- Build User struct ---
	hashedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fail(http.StatusInternalServerError, "failed to hash password", err)
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
		Role:                   "new", // hard-coded default; client-supplied role is ignored
		ConsentDataStore:       formData.ConsentDataStore,
		ConsentMarketingEmails: formData.ConsentMarketingEmails,
		MedicalConditions:      formData.MedicalConditions,
		EmergencyContactName:   formData.EmergencyContactName,
		EmergencyContactNumber: formData.EmergencyContactNumber,
	}

	// --- Insert into database ---
	if err := r.dbInsertUser(req.Context(), &user); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			// Known duplicate: log a PII-free line and return 409. The raw error is
			// not logged because Postgres unique-violation messages can carry the
			// offending value / constraint name (AGENTS.md AI Rule 3).
			r.logger.Warn().Caller().Msg("registration rejected: duplicate email")
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "An account with this email already exists."})
		} else {
			fail(http.StatusInternalServerError, "Registration failed. Please try again later.", err)
		}
		return
	}

	r.logger.Info().Int64("user_id", user.ID).Msg("user registered successfully")
	server.WriteJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (r *registrar) getUserCount(w http.ResponseWriter, req *http.Request) {
	// TODO: Implement user count endpoint
}
