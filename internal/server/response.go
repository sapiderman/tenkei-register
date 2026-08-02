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
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	// Ensure no trailing content
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	return nil
}

// DecodeAndValidate decodes JSON, then validates with go-playground/validator.
func DecodeAndValidate(w http.ResponseWriter, r *http.Request, v interface{}, validate *validator.Validate) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	// Ensure no trailing content
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON payload"})
		return err
	}
	if err := validate.Struct(v); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": strings.ReplaceAll(err.Error(), "\n", "; ")})
		return err
	}
	return nil
}

// SendSimpleResponse writes a simple JSON message response.
func SendSimpleResponse(w http.ResponseWriter, statusCode int, message string) {
	WriteJSON(w, statusCode, map[string]string{"message": message})
}
