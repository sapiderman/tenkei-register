package server

import (
	"encoding/json"
	"net/http"
)

// ErrorResponder handles both JSON and HTML error responses
type ErrorResponder interface {
	RenderError(w http.ResponseWriter, blockName string, data interface{})
}

// SendError sends an error response in JSON or HTML format based on client preference
func SendError(w http.ResponseWriter, isJSON bool, statusCode int, errorMsg string, responder ErrorResponder, blockName string, data interface{}) {
	if isJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errorMsg})
	} else {
		responder.RenderError(w, blockName, data)
	}
}

// SendSuccess sends a success response in JSON or HTML format based on client preference
func SendSuccess(w http.ResponseWriter, isJSON bool, statusCode int, responder ErrorResponder, blockName string, data interface{}) {
	if isJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		responder.RenderError(w, blockName, data)
	}
}
