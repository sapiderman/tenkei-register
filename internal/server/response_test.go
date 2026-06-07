package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected Content-Type to contain application/json, got %s", ct)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if result["status"] != "ok" {
		t.Errorf("expected status 'ok', got %s", result["status"])
	}
}

func TestDecodeJSON_MaxBytes(t *testing.T) {
	bigBody := strings.Repeat(`{"identifier":"a","password":"b","x":"y"}`, 50000)
	req := httptest.NewRequest("POST", "/test", strings.NewReader(bigBody))
	w := httptest.NewRecorder()

	var target map[string]string
	err := DecodeJSON(w, req, &target)
	if err == nil {
		t.Error("expected error for oversized body, got nil")
	}
}

func TestDecodeJSON_TrailingContent(t *testing.T) {
	body := `{"identifier":"a","password":"b"}extra`
	req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
	w := httptest.NewRecorder()

	var target map[string]string
	err := DecodeJSON(w, req, &target)
	if err == nil {
		t.Error("expected error for trailing content, got nil")
	}
}

func TestDecodeJSON_Valid(t *testing.T) {
	body := `{"identifier":"a","password":"b"}`
	req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
	w := httptest.NewRecorder()

	var target map[string]string
	err := DecodeJSON(w, req, &target)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if target["identifier"] != "a" {
		t.Errorf("expected identifier 'a', got %s", target["identifier"])
	}
}

func TestDecodeAndValidate(t *testing.T) {
	type testReq struct {
		Email string `json:"email" validate:"required,email"`
	}

	validate := validator.New()

	t.Run("valid input", func(t *testing.T) {
		body := `{"email":"test@example.com"}`
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		w := httptest.NewRecorder()

		var target testReq
		err := DecodeAndValidate(w, req, &target, validate)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("validation fails", func(t *testing.T) {
		body := `{"email":"not-an-email"}`
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		w := httptest.NewRecorder()

		var target testReq
		err := DecodeAndValidate(w, req, &target, validate)
		if err == nil {
			t.Error("expected validation error, got nil")
		}
	})

	t.Run("trailing content", func(t *testing.T) {
		body := `{"email":"test@example.com"}{"junk":true}`
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		w := httptest.NewRecorder()

		var target testReq
		err := DecodeAndValidate(w, req, &target, validate)
		if err == nil {
			t.Error("expected error for trailing content, got nil")
		}
	})

	t.Run("trailing text", func(t *testing.T) {
		body := `{"email":"test@example.com"}extra`
		req := httptest.NewRequest("POST", "/test", strings.NewReader(body))
		w := httptest.NewRecorder()

		var target testReq
		err := DecodeAndValidate(w, req, &target, validate)
		if err == nil {
			t.Error("expected error for trailing text, got nil")
		}
	})
}
