// Package server provides utilities for handling server actions/responses
package server

import (
	"encoding/json"
	"net/http"
)

type ErrorResponder interface {
	RenderError(w http.ResponseWriter, blockName string, data interface{})
}

// SendError sends an error response in JSON or HTML format based on client preference
func SendError(w http.ResponseWriter, isJSON bool, statusCode int, errorMsg string, responder ErrorResponder, blockName string, data any) {
	if isJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errorMsg})
	} else {
		w.WriteHeader(statusCode)
		responder.RenderError(w, blockName, data)
	}
}

// SendResponse sends a success response in JSON or HTML format based on client preference
func SendResponse(w http.ResponseWriter, isJSON bool, statusCode int, responder ErrorResponder, blockName string, data any) {
	if isJSON {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	} else {
		w.WriteHeader(statusCode)
		responder.RenderError(w, blockName, data)
	}
}

func SendSimpleResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})

}
