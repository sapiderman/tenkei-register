package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptVerifier_ValidCredentials(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(t, db, "verifier-test@example.com", "+62811111111", string(hash))

	v := NewBcryptVerifier(db)
	gotID, requires2FA, err := v.Verify(t.Context(), "verifier-test@example.com", "correctpassword")
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if gotID != userID {
		t.Errorf("expected userID %d, got %d", userID, gotID)
	}
	if requires2FA {
		t.Error("expected requires2FA=false, got true")
	}
}

func TestBcryptVerifier_WrongPassword(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	_ = insertTestUser(t, db, "verifier-wrong@example.com", "+62822222222", string(hash))

	v := NewBcryptVerifier(db)
	gotID, requires2FA, err := v.Verify(t.Context(), "verifier-wrong@example.com", "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
	if gotID != 0 {
		t.Errorf("expected userID 0, got %d", gotID)
	}
	if requires2FA {
		t.Error("expected requires2FA=false, got true")
	}
}

func TestBcryptVerifier_NonexistentUser(t *testing.T) {
	db := setupTestDB(t)

	v := NewBcryptVerifier(db)
	gotID, requires2FA, err := v.Verify(t.Context(), "nonexistent@example.com", "anypassword")
	if err == nil {
		t.Fatal("expected error for nonexistent user, got nil")
	}
	// CRITICAL: must be ErrInvalidCredentials (not ErrUserNotFound) to prevent user enumeration
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials (prevents user enumeration), got %v", err)
	}
	if gotID != 0 {
		t.Errorf("expected userID 0, got %d", gotID)
	}
	if requires2FA {
		t.Error("expected requires2FA=false, got true")
	}
}

func TestBcryptVerifier_LoginByWhatsApp(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(t, db, "verifier-wa@example.com", "+62833333333", string(hash))

	v := NewBcryptVerifier(db)
	gotID, requires2FA, err := v.Verify(t.Context(), "+62833333333", "correctpassword")
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if gotID != userID {
		t.Errorf("expected userID %d, got %d", userID, gotID)
	}
	if requires2FA {
		t.Error("expected requires2FA=false, got true")
	}
}

func TestBcryptVerifier_DatabaseError(t *testing.T) {
	db := setupTestDB(t)

	// Close the underlying SQL connection to simulate a DB failure.
	sqldb := db.DB
	sqldb.Close()

	v := NewBcryptVerifier(db)
	gotID, requires2FA, err := v.Verify(t.Context(), "verifier-dberr@example.com", "anypassword")
	if err == nil {
		t.Fatal("expected error for DB failure, got nil")
	}
	// Must NOT be ErrInvalidCredentials — DB errors must propagate so the handler returns 500.
	if err == ErrInvalidCredentials {
		t.Error("DB error must not be masked as ErrInvalidCredentials")
	}
	if gotID != 0 {
		t.Errorf("expected userID 0, got %d", gotID)
	}
	if requires2FA {
		t.Error("expected requires2FA=false, got true")
	}
}
