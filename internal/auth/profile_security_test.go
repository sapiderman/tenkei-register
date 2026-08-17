package auth

// Security-fix tests (findings.md #5, #6 — profile write integrity; #3 —
// password change). DB-backed tests skip cleanly without a DSN.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestApplyProfileUpdate_DoesNotClobberRole reproduces the #6 race: a user
// row is loaded, an admin promotes the user out-of-band, then the stale
// self-profile update runs. The write must not roll the role back.
func TestApplyProfileUpdate_DoesNotClobberRole(t *testing.T) {
	db := setupTestDB(t)

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "role-clobber@example.com", "+62877777771", string(hash))

	// Self-profile path loads the row (role='user' at this moment).
	user, err := GetUserByID(t.Context(), db, userID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}

	// Admin promotes out-of-band between the load and the write.
	if _, err := db.NewRaw(`UPDATE users SET role = 'admin' WHERE id = ?`, userID).Exec(t.Context()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	req := &UpdateProfileRequest{Name: "Updated Name", Dojo: "Honbu"}
	if err := ApplyProfileUpdate(t.Context(), db, user, req); err != nil {
		t.Fatalf("ApplyProfileUpdate: %v", err)
	}

	var role string
	if err := db.NewRaw(`SELECT role FROM users WHERE id = ?`, userID).Scan(t.Context(), &role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "admin" {
		t.Errorf("role = %q, want 'admin' — self-profile update clobbered a concurrent role change", role)
	}
}

// TestHandleUpdateProfile_EmailChangeRequiresPassword verifies #5: changing
// the login identifier without the current password yields 400.
func TestHandleUpdateProfile_EmailChangeRequiresPassword(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "email-guard@example.com", "+62877777772", string(hash))

	body := `{"email":"new-email@example.com"}` // no current_password
	req := withUserID(httptest.NewRequest(http.MethodPut, "/v1/auth/profile", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "current_password") {
		t.Errorf("error should name current_password, got %s", w.Body.String())
	}
}

// TestHandleUpdateProfile_EmailChangeWrongPassword verifies #5: a wrong
// current password yields 403 and the email is unchanged.
func TestHandleUpdateProfile_EmailChangeWrongPassword(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "email-wrong@example.com", "+62877777773", string(hash))

	body := `{"email":"new-email-wrong@example.com","current_password":"not-the-password"}`
	req := withUserID(httptest.NewRequest(http.MethodPut, "/v1/auth/profile", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var email string
	if err := db.NewRaw(`SELECT email FROM users WHERE id = ?`, userID).Scan(t.Context(), &email); err != nil {
		t.Fatalf("read email: %v", err)
	}
	if email != "email-wrong@example.com" {
		t.Errorf("email must be unchanged after a rejected change, got %q", email)
	}
}

// TestHandleUpdateProfile_EmailChangeSuccess verifies #5's happy path: with
// the right password the email changes, every other session dies, and the
// requester gets a fresh session cookie.
func TestHandleUpdateProfile_EmailChangeSuccess(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	a.sessions = NewDBSessionStore(db)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "email-ok@example.com", "+62877777774", string(hash))

	// Another "device" holds a live session that must die on email change.
	store := NewDBSessionStore(db)
	otherSession, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("seed other session: %v", err)
	}

	body := `{"email":"email-ok-new@example.com","current_password":"testpassword"}`
	req := withUserID(httptest.NewRequest(http.MethodPut, "/v1/auth/profile", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var email string
	if err := db.NewRaw(`SELECT email FROM users WHERE id = ?`, userID).Scan(t.Context(), &email); err != nil {
		t.Fatalf("read email: %v", err)
	}
	if email != "email-ok-new@example.com" {
		t.Errorf("email = %q, want the new address", email)
	}

	if _, _, err := store.Validate(t.Context(), otherSession); err == nil {
		t.Error("the other device's session must be invalidated on email change")
	}

	// The requester stays logged in: a fresh session cookie is set.
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			found = true
			if _, _, err := store.Validate(t.Context(), c.Value); err != nil {
				t.Errorf("reissued cookie must validate, got %v", err)
			}
		}
	}
	if !found {
		t.Error("expected a fresh session cookie on email change")
	}
}

// TestHandleUpdateProfile_EmailUnchangedNeedsNoPassword pins the back-compat
// contract: name-only updates keep working without current_password.
func TestHandleUpdateProfile_EmailUnchangedNeedsNoPassword(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "email-same@example.com", "+62877777775", string(hash))

	body := `{"name":"Just A Rename"}` // no email, no password
	req := withUserID(httptest.NewRequest(http.MethodPut, "/v1/auth/profile", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleUpdateProfile(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// --- Password change (#3) ---

func TestHandleChangePassword_WrongCurrent(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "pw-wrong@example.com", "+62877777776", string(hash))

	body := `{"current_password":"not-the-password","new_password":"newpassword1"}`
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/password", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleChangePassword(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var stored string
	if err := db.NewRaw(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(t.Context(), &stored); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("testpassword")) != nil {
		t.Error("password hash must be untouched after a rejected change")
	}
}

func TestHandleChangePassword_Success(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	a.sessions = NewDBSessionStore(db)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "pw-ok@example.com", "+62877777777", string(hash))

	store := NewDBSessionStore(db)
	otherSession, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("seed other session: %v", err)
	}

	body := `{"current_password":"testpassword","new_password":"brand-new-pass-1"}`
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/password", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// New password verifies; the old one no longer does.
	var stored string
	if err := db.NewRaw(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(t.Context(), &stored); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("brand-new-pass-1")) != nil {
		t.Error("new password must verify after change")
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte("testpassword")) == nil {
		t.Error("old password must be rejected after change")
	}

	// Other devices are logged out; the requester is reissued a session.
	if _, _, err := store.Validate(t.Context(), otherSession); err == nil {
		t.Error("the other device's session must be invalidated on password change")
	}
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected a fresh session cookie after password change")
	}
}

func TestHandleChangePassword_Validation(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "pw-valid@example.com", "+62877777778", string(hash))

	cases := []struct {
		name string
		body string
	}{
		{"short new password", `{"current_password":"testpassword","new_password":"short"}`},
		{"missing current", `{"new_password":"brand-new-pass-1"}`},
		{"missing new", `{"current_password":"testpassword"}`},
		{"over-long new", `{"current_password":"testpassword","new_password":"` + strings.Repeat("x", 73) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/password", strings.NewReader(tc.body)), userID)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			a.handleChangePassword(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}
