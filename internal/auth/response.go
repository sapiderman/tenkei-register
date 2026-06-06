package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/sapiderman/tenkei-register/internal/types"
)

// profileFromUser maps a database User to a safe ProfileResponse.
// password_hash is never included.
func profileFromUser(user *types.User) ProfileResponse {
	var dob, lgd string
	if !user.DateOfBirth.IsZero() {
		dob = user.DateOfBirth.Format("2006-01-02")
	}
	if !user.LastGradingDate.IsZero() {
		lgd = user.LastGradingDate.Format("2006-01-02")
	}

	return ProfileResponse{
		ID:                     user.ID,
		Name:                   user.Name,
		Email:                  user.Email,
		WhatsApp:               user.WhatsApp,
		Dojo:                   user.Dojo,
		Rank:                   user.Rank,
		DateOfBirth:            dob,
		JoinDate:               user.JoinDate.Format("2006-01-02"),
		LastGradingDate:        lgd,
		Role:                   user.Role,
		ConsentDataStore:       user.ConsentDataStore,
		ConsentMarketing:       user.ConsentMarketingEmails,
		MedicalConditions:      user.MedicalConditions,
		EmergencyContactName:   user.EmergencyContactName,
		EmergencyContactNumber: user.EmergencyContactNumber,
	}
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads and decodes a JSON request body with size limit.
// It enforces MaxBytesReader (1 MiB) and disallows unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	// Ensure no trailing content
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return fmt.Errorf("trailing content after JSON body")
	}
	return nil
}

// decodeAndValidate decodes JSON, then validates with go-playground/validator.
func decodeAndValidate(r *http.Request, w http.ResponseWriter, v interface{}, validate *validator.Validate) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	if err := validate.Struct(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.ReplaceAll(err.Error(), "\n", "; ")})
		return err
	}
	return nil
}

// parseDate safely parses a YYYY-MM-DD date string.
// Returns zero time for empty input.
func parseDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date format, use YYYY-MM-DD")
	}
	return t, nil
}
