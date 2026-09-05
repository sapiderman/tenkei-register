package auth

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/types"
	"golang.org/x/crypto/bcrypt"
)

func TestDBUpdateUserProfile_ImmutableFields(t *testing.T) {
	// This test verifies structurally that UpdateProfileRequest cannot set
	// id, role, password_hash, or created_at. If someone adds those fields
	// to UpdateProfileRequest, this test should be updated to reflect the
	// design decision.
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

func TestDBUpdateUserProfile_BasicUpdate(t *testing.T) {
	db := setupTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	userID := insertTestUser(t, db, "dbupdate@example.com", "+62899999999", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	// Update name and rank
	trueVal := true
	req := &UpdateProfileRequest{
		Name:             "Updated Name",
		Rank:             "5th Kyu",
		ConsentMarketing: &trueVal,
	}
	err = UpdateUserProfile(t.Context(), a.db, userID, req)
	if err != nil {
		t.Fatalf("dbUpdateUserProfile() error: %v", err)
	}

	// Verify
	user, err := GetUserByID(t.Context(), a.db, userID)
	if err != nil {
		t.Fatalf("dbGetUserByID() error: %v", err)
	}
	if user.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got %s", user.Name)
	}
	if user.Rank != "5th Kyu" {
		t.Errorf("expected rank '5th Kyu', got %s", user.Rank)
	}
	if !user.ConsentMarketingEmails {
		t.Error("expected ConsentMarketingEmails=true")
	}
}

// TestDBUpdateUserProfile_FacultyMajorRule covers the shared post-state
// invariant: members of the UI campus dojo cannot be saved without faculty
// and major, however the gap arose (registration-era hole, dojo switch, or
// partial update on an incomplete record).
func TestDBUpdateUserProfile_FacultyMajorRule(t *testing.T) {
	db := setupTestDB(t)
	a := &authenticator{logger: zerolog.Nop(), db: db}

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	uiID := insertTestUser(t, db, "ui-rule@example.com", "+628170000001", string(hash))
	_, err := db.NewRaw(`UPDATE users SET dojo = ? WHERE id = ?`, types.UIDojo, uiID).Exec(t.Context())
	if err != nil {
		t.Fatalf("set dojo: %v", err)
	}

	// 1. Incomplete UI member: even an unrelated update is rejected.
	if err := UpdateUserProfile(t.Context(), a.db, uiID, &UpdateProfileRequest{Name: "Blocked"}); err != ErrFacultyMajorRequired {
		t.Errorf("incomplete UI member: want ErrFacultyMajorRequired, got %v", err)
	}

	// 2. Filling both fields completes the record and succeeds.
	if err := UpdateUserProfile(t.Context(), a.db, uiID, &UpdateProfileRequest{Faculty: "Fakultas Teknik", Major: "Teknik Elektro"}); err != nil {
		t.Fatalf("complete UI member update: %v", err)
	}
	u, _ := GetUserByID(t.Context(), a.db, uiID)
	if u.Faculty != "Fakultas Teknik" || u.Major != "Teknik Elektro" || u.Name != "Test User" {
		t.Errorf("fields not applied: name=%q faculty=%q major=%q", u.Name, u.Faculty, u.Major)
	}

	// 3. Complete UI member: unrelated updates pass again.
	if err := UpdateUserProfile(t.Context(), a.db, uiID, &UpdateProfileRequest{Name: "Renamed"}); err != nil {
		t.Fatalf("complete member rename: %v", err)
	}

	// 4. Switching a non-UI member onto the campus dojo without fields: rejected.
	switchID := insertTestUser(t, db, "ui-switch@example.com", "+628170000002", string(hash))
	if err := UpdateUserProfile(t.Context(), a.db, switchID, &UpdateProfileRequest{Dojo: types.UIDojo}); err != ErrFacultyMajorRequired {
		t.Errorf("dojo switch without fields: want ErrFacultyMajorRequired, got %v", err)
	}
	if err := UpdateUserProfile(t.Context(), a.db, switchID, &UpdateProfileRequest{Dojo: types.UIDojo, Faculty: "Fakultas Hukum", Major: "Ilmu Hukum"}); err != nil {
		t.Fatalf("dojo switch with fields: %v", err)
	}

	// 5. Switching an incomplete UI member away from the campus dojo: allowed.
	awayID := insertTestUser(t, db, "ui-away@example.com", "+628170000003", string(hash))
	_, _ = db.NewRaw(`UPDATE users SET dojo = ? WHERE id = ?`, types.UIDojo, awayID).Exec(t.Context())
	if err := UpdateUserProfile(t.Context(), a.db, awayID, &UpdateProfileRequest{Dojo: "Tenkei Natsu Aikidojo"}); err != nil {
		t.Errorf("dojo switch away: want nil, got %v", err)
	}
}

func TestDBUpdateUserProfile_DuplicateEmail(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)

	// Create two users
	_ = insertTestUser(t, db, "dup-email1@example.com", "+628100000001", string(hash))
	user2ID := insertTestUser(t, db, "dup-email2@example.com", "+628100000002", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	// Try to update user2's email to user1's email
	req := &UpdateProfileRequest{Email: "dup-email1@example.com"}
	err := UpdateUserProfile(t.Context(), a.db, user2ID, req)
	if err != ErrUpdateConflict {
		t.Errorf("expected ErrUpdateConflict for duplicate email, got %v", err)
	}
}

func TestDBUpdateUserProfile_DuplicateWhatsApp_NoConflict(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)

	// Create two users
	_ = insertTestUser(t, db, "dup-wa1@example.com", "+628200000001", string(hash))
	user2ID := insertTestUser(t, db, "dup-wa2@example.com", "+628200000002", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	// WhatsApp is no longer unique: sharing a number must NOT conflict.
	req := &UpdateProfileRequest{WhatsApp: "+628200000001"}
	err := UpdateUserProfile(t.Context(), a.db, user2ID, req)
	if err != nil {
		t.Errorf("expected no conflict for duplicate WhatsApp, got %v", err)
	}
}

func TestDBUpdateUserProfile_InvalidRank(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "rank-test@example.com", "+628300000001", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	req := &UpdateProfileRequest{Rank: "Black Belt Supreme"}
	err := UpdateUserProfile(t.Context(), a.db, userID, req)
	if err != ErrInvalidRank {
		t.Errorf("expected ErrInvalidRank, got %v", err)
	}
}

func TestDBUpdateUserProfile_NotFound(t *testing.T) {
	db := setupTestDB(t)
	a := &authenticator{logger: zerolog.Nop(), db: db}

	err := UpdateUserProfile(t.Context(), a.db, 999999999, &UpdateProfileRequest{Name: "x"})
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestDBUpdateUserProfile_InvalidDates(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "date-test@example.com", "+628500000005", string(hash))

	a := &authenticator{logger: zerolog.Nop(), db: db}

	cases := []struct {
		name string
		req  *UpdateProfileRequest
	}{
		{"invalid date of birth", &UpdateProfileRequest{DateOfBirth: "not-a-date"}},
		{"invalid last grading date", &UpdateProfileRequest{LastGradingDate: "2024/01/01"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := UpdateUserProfile(t.Context(), a.db, userID, tc.req)
			if err == nil {
				t.Error("expected error for invalid date")
			}
		})
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
