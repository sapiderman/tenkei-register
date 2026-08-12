package auth

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
)

func TestProfileFromUser_OmitsPasswordHash(t *testing.T) {
	now := time.Now()
	user := &types.User{
		ID:                     1,
		Name:                   "Test User",
		Email:                  "test@example.com",
		WhatsApp:               "+62812345678",
		PasswordHash:           "$2a$10$SUPERSECRETHASH",
		Dojo:                   "Tenkei",
		Rank:                   "6th Kyu",
		JoinDate:               now,
		ConsentDataStore:       true,
		ConsentMarketingEmails: false,
	}

	resp := ProfileFromUser(user)

	// Marshal to JSON and verify password_hash is absent
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	s := string(data)
	if strings.Contains(s, "password") {
		t.Errorf("ProfileResponse JSON must not contain 'password': %s", s)
	}
	if strings.Contains(s, "PasswordHash") {
		t.Errorf("ProfileResponse JSON must not contain 'PasswordHash': %s", s)
	}
	if resp.ID != 1 {
		t.Errorf("expected ID 1, got %d", resp.ID)
	}
	if resp.Name != "Test User" {
		t.Errorf("expected Name 'Test User', got %s", resp.Name)
	}
}

func TestProfileFromUser_DateFormatting(t *testing.T) {
	dob := time.Date(1990, 6, 15, 0, 0, 0, 0, time.UTC)
	lgd := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	user := &types.User{
		ID:              1,
		DateOfBirth:     dob,
		LastGradingDate: lgd,
		JoinDate:        dob,
	}

	resp := ProfileFromUser(user)
	if resp.DateOfBirth != "1990-06-15" {
		t.Errorf("expected DateOfBirth '1990-06-15', got %s", resp.DateOfBirth)
	}
	if resp.LastGradingDate != "2024-06-01" {
		t.Errorf("expected LastGradingDate '2024-06-01', got %s", resp.LastGradingDate)
	}
	if resp.JoinDate != "1990-06-15" {
		t.Errorf("expected JoinDate '1990-06-15', got %s", resp.JoinDate)
	}
}

func TestProfileFromUser_ZeroDateOmitted(t *testing.T) {
	user := &types.User{
		ID: 1,
		// DateOfBirth and LastGradingDate are zero values
	}

	resp := ProfileFromUser(user)
	if resp.DateOfBirth != "" {
		t.Errorf("expected empty DateOfBirth for zero time, got %s", resp.DateOfBirth)
	}
	if resp.LastGradingDate != "" {
		t.Errorf("expected empty LastGradingDate for zero time, got %s", resp.LastGradingDate)
	}
}

func TestDecodeJSON_MaxBytes(t *testing.T) {
	// Test that DecodeJSON rejects bodies larger than 1 MiB
	bigBody := strings.Repeat(`{"identifier":"a","password":"b","x":"y"}`, 50000) // way too big
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(bigBody))
	w := httptest.NewRecorder()

	var reqBody LoginRequest
	err := server.DecodeJSON(w, req, &reqBody)
	if err == nil {
		t.Error("expected error for oversized body, got nil")
	}
}

func TestDecodeJSON_TrailingContent(t *testing.T) {
	body := `{"identifier":"a","password":"b"}extra`
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	var reqBody LoginRequest
	err := server.DecodeJSON(w, req, &reqBody)
	if err == nil {
		t.Error("expected error for trailing content, got nil")
	}
}

func TestParseDate(t *testing.T) {
	// Valid date
	result, err := types.ParseDate("1990-06-15")
	if err != nil {
		t.Errorf("ParseDate(\"1990-06-15\") error: %v", err)
	}
	if result.Year() != 1990 || result.Month() != 6 || result.Day() != 15 {
		t.Errorf("expected 1990-06-15, got %v", result)
	}

	// Empty string → zero time
	result, err = types.ParseDate("")
	if err != nil {
		t.Errorf("ParseDate(\"\") error: %v", err)
	}
	if !result.IsZero() {
		t.Errorf("expected zero time for empty string, got %v", result)
	}

	// Invalid format
	_, err = types.ParseDate("15-06-1990")
	if err == nil {
		t.Error("expected error for invalid date format, got nil")
	}
}
