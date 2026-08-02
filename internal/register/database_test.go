package register

import (
	"testing"
	"time"
)

func TestDbInsertUser_Success(t *testing.T) {
	db := setupTestDB(t)
	reg := &registrar{db: db}

	user := &User{
		Name:                   "DB Test User",
		Email:                  "db-test@example.com",
		WhatsApp:               "+6282000000001",
		PasswordHash:           "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ12",
		DateOfBirth:            time.Date(1990, 6, 15, 0, 0, 0, 0, time.UTC),
		Dojo:                   "Test Dojo",
		Rank:                   "5th Kyu",
		LastGradingDate:        time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC),
		Role:                   "new",
		ConsentDataStore:       true,
		ConsentMarketingEmails: false,
		MedicalConditions:      "none",
		EmergencyContactName:   "Jane Doe",
		EmergencyContactNumber: "+6282000000002",
	}
	wipeUsers(t, db, user.Email, user.WhatsApp)

	if err := reg.dbInsertUser(t.Context(), user); err != nil {
		t.Fatalf("dbInsertUser failed: %v", err)
	}
	if user.ID == 0 {
		t.Fatal("expected auto-generated ID, got 0")
	}

	// Verify stored fields round-trip.
	var stored User
	err := db.NewSelect().Model(&stored).Where("id = ?", user.ID).Scan(t.Context())
	if err != nil {
		t.Fatalf("fetch user failed: %v", err)
	}

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"name", stored.Name, user.Name},
		{"email", stored.Email, user.Email},
		{"whatsapp", stored.WhatsApp, user.WhatsApp},
		{"rank", stored.Rank, user.Rank},
		{"dojo", stored.Dojo, user.Dojo},
		{"role", stored.Role, user.Role},
		{"medical", stored.MedicalConditions, user.MedicalConditions},
		{"emergency_name", stored.EmergencyContactName, user.EmergencyContactName},
		{"emergency_number", stored.EmergencyContactNumber, user.EmergencyContactNumber},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
	if !stored.ConsentDataStore {
		t.Error("expected consent_datastore true")
	}
	if stored.ConsentMarketingEmails {
		t.Error("expected consent_marketing false")
	}
	if stored.DateOfBirth.IsZero() {
		t.Error("expected date_of_birth to be set")
	}
	if stored.LastGradingDate.IsZero() {
		t.Error("expected last_grading_date to be set")
	}
}

func TestDbInsertUser_DuplicateEmail(t *testing.T) {
	db := setupTestDB(t)
	reg := &registrar{db: db}

	const (
		email = "dup-db@example.com"
		wa1   = "+6282000000010"
		wa2   = "+6282000000011"
	)
	wipeUsers(t, db, email, wa1, wa2)

	user1 := &User{Name: "Dup Test 1", Email: email, WhatsApp: wa1, PasswordHash: "h1", Role: "new", ConsentDataStore: true}
	user2 := &User{Name: "Dup Test 2", Email: email, WhatsApp: wa2, PasswordHash: "h2", Role: "new", ConsentDataStore: true} // same email

	if err := reg.dbInsertUser(t.Context(), user1); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}
	if err := reg.dbInsertUser(t.Context(), user2); err == nil {
		t.Fatal("expected duplicate email error, got nil")
	}
}

func TestDbInsertUser_DuplicateWhatsApp(t *testing.T) {
	db := setupTestDB(t)
	reg := &registrar{db: db}

	const (
		wa     = "+6282000000020"
		email1 = "dup-wa-1@example.com"
		email2 = "dup-wa-2@example.com"
	)
	wipeUsers(t, db, wa, email1, email2)

	user1 := &User{Name: "Dup WA 1", Email: email1, WhatsApp: wa, PasswordHash: "h1", Role: "new", ConsentDataStore: true}
	user2 := &User{Name: "Dup WA 2", Email: email2, WhatsApp: wa, PasswordHash: "h2", Role: "new", ConsentDataStore: true} // same whatsapp

	if err := reg.dbInsertUser(t.Context(), user1); err != nil {
		t.Fatalf("first insert failed: %v", err)
	}
	if err := reg.dbInsertUser(t.Context(), user2); err == nil {
		t.Fatal("expected duplicate whatsapp error, got nil")
	}
}

func TestDbInsertUser_MinimalFields(t *testing.T) {
	db := setupTestDB(t)
	reg := &registrar{db: db}

	const wa = "+6282000000030"
	wipeUsers(t, db, wa)

	// Minimum the registrar accepts: name, whatsapp, password_hash, role, consent.
	user := &User{
		Name:             "Minimal User",
		WhatsApp:         wa,
		PasswordHash:     "hash",
		Role:             "new",
		ConsentDataStore: true,
	}

	if err := reg.dbInsertUser(t.Context(), user); err != nil {
		t.Fatalf("dbInsertUser failed: %v", err)
	}
	if user.ID == 0 {
		t.Fatal("expected auto-generated ID")
	}
}
