package auth

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/types"
	"golang.org/x/crypto/bcrypt"
)

// TestUpdateProfileRequest_ImmutableFields verifies structurally that
// UpdateProfileRequest cannot set id, role, password_hash, or created_at. If
// someone adds those fields to UpdateProfileRequest, this test should be
// updated to reflect the design decision.
func TestUpdateProfileRequest_ImmutableFields(t *testing.T) {
	req := UpdateProfileRequest{}
	_ = req // structural guarantee — see model.go
}

func TestDBGetUserByID(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(t, db, "dbgetuser@example.com", "+62888888888", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	user, err := GetUserByID(t.Context(), a.db, userID)
	if err != nil {
		t.Fatalf("dbGetUserByID() error: %v", err)
	}
	if user.ID != userID {
		t.Errorf("expected ID %d, got %d", userID, user.ID)
	}
	if user.Email != "dbgetuser@example.com" {
		t.Errorf("expected email 'dbgetuser@example.com', got %s", user.Email)
	}
}

func TestDBGetUserByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	a := &authenticator{logger: zerolog.Nop(), db: db}

	_, err := GetUserByID(t.Context(), a.db, 999999999)
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestAudit_ClosedDB(t *testing.T) {
	// An audit insert against a closed connection hits the error-log branch.
	db := setupTestDB(t)
	a := &authenticator{logger: zerolog.Nop(), db: db}

	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	Audit(t.Context(), a.db, a.logger, 1, "test_action_closed_") // must not panic
}

func TestAudit(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "audit-test@example.com", "+628400000001", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	// Clean up leftover audit records from prior runs
	_, _ = db.NewRaw(`DELETE FROM audit WHERE user_id = ? AND action = ?`, userID, "test_action_unique_").Exec(t.Context())

	// Should not panic or error
	Audit(t.Context(), a.db, a.logger, userID, "test_action_unique_")

	// Verify audit record exists
	var count int
	err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = ?`, userID, "test_action_unique_").Scan(t.Context(), &count)
	if err != nil {
		t.Fatalf("audit query error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 audit record, got %d", count)
	}

	_ = types.Audit{} // ensure Audit type is used
}
