// Package register provides functionalities for user registration
package register

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/mailer"
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
	Faculty                string `json:"faculty"`
	Major                  string `json:"major"`
	Category               string `json:"category"`
	University             string `json:"university"`
	SchoolName             string `json:"school_name"`
	GuardianName           string `json:"guardian_name"`
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

// sanitizeInput trims surrounding whitespace. HTML escaping was removed
// deliberately: this is a JSON API, so XSS is the frontend renderer's job;
// escaping at storage corrupts data ("O'Brien" → "O&#39;Brien") and was
// applied inconsistently anyway (profile updates never escaped). If an HTML
// surface is ever added, escape at render time there.
func sanitizeInput(input string) string {
	return strings.TrimSpace(input)
}

// sanitizeFormData applies sanitizeInput to all string fields in RegistrationFormData.
func sanitizeFormData(d RegistrationFormData) RegistrationFormData {
	d.Email = sanitizeInput(d.Email)
	d.Name = sanitizeInput(d.Name)
	d.WhatsApp = sanitizeInput(d.WhatsApp)
	d.DateOfBirth = sanitizeInput(d.DateOfBirth)
	d.Dojo = sanitizeInput(d.Dojo)
	d.Faculty = sanitizeInput(d.Faculty)
	d.Major = sanitizeInput(d.Major)
	d.Category = sanitizeInput(d.Category)
	d.University = sanitizeInput(d.University)
	d.SchoolName = sanitizeInput(d.SchoolName)
	d.GuardianName = sanitizeInput(d.GuardianName)
	d.Rank = sanitizeInput(d.Rank)
	d.LastGradingDate = sanitizeInput(d.LastGradingDate)
	d.Role = sanitizeInput(d.Role)
	d.MedicalConditions = sanitizeInput(d.MedicalConditions)
	d.EmergencyContactName = sanitizeInput(d.EmergencyContactName)
	d.EmergencyContactNumber = sanitizeInput(d.EmergencyContactNumber)
	d.CfTurnstileResponse = sanitizeInput(d.CfTurnstileResponse)
	return d
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

	var payload apiRegistrationRequest
	if err := server.DecodeJSONWithMessage(w, req, &payload, "Invalid JSON payload"); err != nil {
		r.logger.Warn().Caller().Err(err).Msg("invalid JSON payload")
		return
	}

	formData := sanitizeFormData(payload.RegistrationFormData)
	// Email is the login identifier and must be case-insensitive. Store it
	// lowercase so Andi@Example.com and andi@example.com are one account and
	// every lookup matches (see migrations/000010 for the stored-data side).
	formData.Email = strings.ToLower(formData.Email)
	password := payload.Password
	passwordConfirm := payload.PasswordConfirm

	// Verify Turnstile response (if enabled).
	if err := r.turnstile.Verify(req, formData.CfTurnstileResponse); err != nil {
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

	// Optional field: WhatsApp (no longer a login identifier, no longer unique).
	// Stored in E.164 international format (+62...) regardless of input shape:
	// local "08...", country-coded "62..." and "+62..." all normalize to "+62...".
	whatsapp, err := types.NormalizePhone(formData.WhatsApp)
	if err != nil {
		badRequest("Invalid WhatsApp number. Use international format, e.g. +628123456789.")
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
	if len(formData.Faculty) > 100 {
		badRequest("Faculty is too long (max 100 characters).")
		return
	}
	if len(formData.Major) > 100 {
		badRequest("Major is too long (max 100 characters).")
		return
	}
	// Conditional requirement per user category (dojo-independent). One
	// shared rule (types.CategoryFieldsMissing) covers registration, profile,
	// and admin updates. Empty category defaults to regular so forms that
	// predate categories keep working; any other invalid value is rejected.
	if formData.Category == "" {
		formData.Category = types.CategoryRegular
	}
	if !types.ValidCategory(formData.Category) {
		badRequest("Invalid registration category.")
		return
	}
	if len(formData.University) > 255 {
		badRequest("University is too long (max 255 characters).")
		return
	}
	if len(formData.SchoolName) > 255 {
		badRequest("School name is too long (max 255 characters).")
		return
	}
	if len(formData.GuardianName) > 100 {
		badRequest("Guardian name is too long (max 100 characters).")
		return
	}
	if types.CategoryFieldsMissing(formData.Category, types.CategoryFields{
		University:   formData.University,
		Faculty:      formData.Faculty,
		Major:        formData.Major,
		SchoolName:   formData.SchoolName,
		GuardianName: formData.GuardianName,
	}) {
		switch formData.Category {
		case types.CategoryStudent:
			badRequest("University, department, and major are required for student registrations (or school name if still in school).")
		case types.CategoryKids:
			badRequest("Parent or guardian name is required for kids registrations.")
		default:
			badRequest("Regular registrations must not include student or guardian fields.")
		}
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
	emergencyNumber, err := types.NormalizePhone(formData.EmergencyContactNumber)
	if err != nil {
		badRequest("Invalid emergency contact number. Use international format, e.g. +628123456789.")
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
		WhatsApp:               whatsapp,
		PasswordHash:           string(hashedPwd),
		DateOfBirth:            dateOfBirth,
		Dojo:                   formData.Dojo,
		Faculty:                formData.Faculty,
		Major:                  formData.Major,
		Category:               formData.Category,
		University:             formData.University,
		SchoolName:             formData.SchoolName,
		GuardianName:           formData.GuardianName,
		Rank:                   formData.Rank,
		LastGradingDate:        lastGradingDate,
		Role:                   "new", // hard-coded default; client-supplied role is ignored
		ConsentDataStore:       formData.ConsentDataStore,
		ConsentMarketingEmails: formData.ConsentMarketingEmails,
		MedicalConditions:      formData.MedicalConditions,
		EmergencyContactName:   formData.EmergencyContactName,
		EmergencyContactNumber: emergencyNumber,
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
			// The wrapped driver error is not logged: Postgres can embed member
			// values in it. The query hook already records the SQLSTATE for triage.
			fail(http.StatusInternalServerError, "Registration failed. Please try again later.", nil)
		}
		return
	}

	r.logger.Info().Int64("user_id", user.ID).Msg("user registered successfully")

	// Side effects, never a gate: the insert already succeeded, so both emails
	// are attempted before the 201 regardless of their outcome.
	r.sendRegistrationEmails(req, &user)

	server.WriteJSON(w, http.StatusCreated, map[string]string{"status": "ok"})
}

func (r *registrar) getUserCount(w http.ResponseWriter, req *http.Request) {
	count, err := r.db.NewSelect().TableExpr("users").Count(req.Context())
	if err != nil {
		r.logger.Error().Err(err).Msg("user count query failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to get member count."})
		return
	}
	server.WriteJSON(w, http.StatusOK, map[string]int{"count": count})
}

// sendRegistrationEmails delivers the welcome and admin-notice emails after a
// successful registration insert.
//
// Concurrency contract (see email-notif-plan.md Phase 3):
//   - Sends run in parallel (two goroutines, sync.WaitGroup) and the handler
//     waits for both before responding 201 — bounded, request-lifetime
//     concurrency, not a background worker.
//   - Sends use context.WithoutCancel(req.Context()): a client disconnect
//     right after the insert can never abort delivery.
//   - Each goroutine carries a panic recovery so an SDK/template panic kills
//     only that send (wg.Done is deferred first, so it always runs).
//   - Race-free collection: goroutine i writes only errs[i]; both are read
//     strictly after wg.Wait() (happens-before per the Go memory model).
//   - Failures never affect the registration outcome: they are logged with a
//     masked recipient and audited as email_send_failed:{which}:{category}.
func (r *registrar) sendRegistrationEmails(req *http.Request, user *User) {
	ctx := context.WithoutCancel(req.Context())

	type pendingSend struct {
		which string // audit label: "welcome" | "notify_admin"
		msg   mailer.Message
	}

	var sends []pendingSend
	if welcome, err := r.tmpl.welcomeMessage(user); err != nil {
		// welcome is the zero value here; the intended recipient is user.Email.
		r.recordEmailFailure(ctx, user, "welcome", user.Email, err)
	} else {
		sends = append(sends, pendingSend{which: "welcome", msg: welcome})
	}
	if notice, err := r.tmpl.adminMessage(user, r.notifyEmail); err != nil {
		r.recordEmailFailure(ctx, user, "notify_admin", r.notifyEmail, err)
	} else {
		sends = append(sends, pendingSend{which: "notify_admin", msg: notice})
	}

	var wg sync.WaitGroup
	errs := make([]error, len(sends))
	for i, s := range sends {
		wg.Add(1)
		go func(i int, s pendingSend) {
			defer wg.Done() // registered first: runs last, even when recovering a panic
			defer func() {
				if rec := recover(); rec != nil {
					// Logged here (not in recordEmailFailure) because the panicking
					// frames exist only on this goroutine's stack right now.
					r.logger.Error().Stack().
						Str("email", s.which).
						Int64("user_id", user.ID).
						Interface("panic", rec).
						Msg("panic during email send")
					errs[i] = fmt.Errorf("panic during %s send: %v", s.which, rec)
				}
			}()
			// pi-lens-ignore: go-goroutine-map-write
			// pi-lens-ignore: go-shared-map-write-goroutine
			errs[i] = r.mailer.Send(ctx, s.msg)
		}(i, s)
	}
	wg.Wait()

	for i, s := range sends {
		if errs[i] != nil {
			r.recordEmailFailure(ctx, user, s.which, s.msg.To, errs[i])
		}
	}
}

// recordEmailFailure logs a masked send failure and writes the categorized
// audit row. Raw error text is deliberately kept out of logs: provider errors
// (see mailer.SendError) can embed the recipient address, so only the
// closed-set category is emitted. The audit action carries the same category —
// no error text, no addresses.
func (r *registrar) recordEmailFailure(ctx context.Context, user *User, which, to string, err error) {
	category := mailer.CategoryOf(err)
	r.logger.Error().
		Str("email", which).
		Str("to", server.Mask(to)).
		Str("category", category).
		Int64("user_id", user.ID).
		Msg("registration email send failed")
	auth.Audit(ctx, r.db, r.logger, user.ID, "email_send_failed:"+which+":"+category)
}
