package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestSendSimpleResponse(t *testing.T) {
	w := httptest.NewRecorder()
	SendSimpleResponse(w, http.StatusTeapot, "hi there")

	if w.Code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, w.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if result["message"] != "hi there" {
		t.Errorf("expected message 'hi there', got %q", result["message"])
	}
}

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

	// Pin the wire bytes: both rejection paths answer 400 with the exact
	// decode error string, before validator output ever shapes the body.
	t.Run("wire string for oversized body and trailing content", func(t *testing.T) {
		cases := []struct{ name, body string }{
			{"oversized body", strings.Repeat(`{"email":"test@example.com"}`, 50000)},
			{"trailing content", `{"email":"test@example.com"}{"junk":true}`},
		}
		for _, tc := range cases {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tc.body))
			w := httptest.NewRecorder()

			var target testReq
			if err := DecodeAndValidate(w, req, &target, validate); err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: expected status 400, got %d", tc.name, w.Code)
			}
			var res map[string]string
			if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
				t.Fatalf("%s: failed to decode response: %v", tc.name, err)
			}
			if res["error"] != "invalid JSON payload" {
				t.Errorf("%s: expected error %q, got %q", tc.name, "invalid JSON payload", res["error"])
			}
		}
	})
}
