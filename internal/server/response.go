// Package server provides utilities for handling server actions/responses
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
)

// WriteJSON writes a JSON response with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// DecodeJSON reads and decodes a JSON request body with size limit.
// It enforces MaxBytesReader (1 MiB) and disallows unknown fields.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	return DecodeJSONWithMessage(w, r, v, "invalid JSON payload")
}

// DecodeJSONWithMessage is DecodeJSON with the caller's exact 400 message,
// so endpoints that already answer a different string keep their wire bytes.
func DecodeJSONWithMessage(w http.ResponseWriter, r *http.Request, v interface{}, message string) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": message})
		return err
	}
	// Ensure no trailing content
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": message})
		return err
	}
	return nil
}

// DecodeAndValidate decodes JSON, then validates with go-playground/validator.
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, v interface{}, validate *validator.Validate) error {
	if err := DecodeJSON(w, r, v); err != nil {
		return err
	}
	if err := validate.Struct(v); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": strings.ReplaceAll(err.Error(), "\n", "; ")})
		return err
	}
	return nil
}

// Mask partially hides sensitive identifiers in logs.
// "test@example.com" → "t**************m"
// "+62812345678" → "+**********8"
func Mask(s string) string {
	if len(s) <= 2 {
		return "***"
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}

// SendSimpleResponse writes a simple JSON message response.
func SendSimpleResponse(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, map[string]string{"message": message})
}
