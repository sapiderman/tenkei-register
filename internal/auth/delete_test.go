package auth

// Tests for POST /v1/auth/delete (GDPR Art. 17 erasure). DB-backed tests
// skip cleanly without a DSN.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	libtotp "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/sapiderman/tenkei-register/internal/totp"
)

func TestHandleDeleteAccount_Success(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	a.sessions = NewDBSessionStore(db)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "gdpr-del@example.com", "+62877777781", string(hash))

	// A live session must die with the user row (ON DELETE CASCADE).
	store := NewDBSessionStore(db)
	session, err := store.Create(t.Context(), userID, true)
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	body := `{"current_password":"testpassword"}`
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleDeleteAccount(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// User row gone.
	if err := db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(t.Context(), new(int)); err == nil {
		t.Error("user row must be deleted")
	}

	// Session died with the account.
	if _, _, err := store.Validate(t.Context(), session); err == nil {
		t.Error("session must be invalidated by the user delete cascade")
	}

	// The audit row outlives the user and names the requester by email.
	var action string
	if err := db.NewRaw(`SELECT action FROM audit WHERE user_id = ?`, userID).Scan(t.Context(), &action); err != nil {
		t.Fatalf("read audit row: %v", err)
	}
	if !strings.Contains(action, "gdpr-del@example.com") || !strings.Contains(action, "requested deletion") {
		t.Errorf("audit action = %q, want it to name the email and the deletion request", action)
	}

	// Session cookie cleared client-side.
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expected the session cookie to be cleared after deletion")
	}
}

func TestHandleDeleteAccount_WrongPassword(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "gdpr-wrong@example.com", "+62877777782", string(hash))

	body := `{"current_password":"not-the-password"}`
	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete", strings.NewReader(body)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleDeleteAccount(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if err := db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(t.Context(), new(int)); err != nil {
		t.Error("user row must survive a rejected deletion")
	}
}

func TestHandleDeleteAccount_Validation(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "gdpr-valid@example.com", "+62877777783", string(hash))

	req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete", strings.NewReader(`{}`)), userID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handleDeleteAccount(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing password, got %d: %s", w.Code, w.Body.String())
	}
	if err := db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(t.Context(), new(int)); err != nil {
		t.Error("user row must survive a validation failure")
	}
}

// TestHandleDeleteAccount_TOTP tests the second factor: an enrolled member
// must supply the current code; with it, deletion succeeds.
func TestHandleDeleteAccount_TOTP(t *testing.T) {
	a, db := newDBTestAuthenticator(t)
	key := []byte(strings.Repeat("k", 32)) // raw AES-256-GCM key, as acceptTOTPCode expects
	a.totpKey = key

	hash, _ := bcrypt.GenerateFromPassword([]byte("testpassword"), bcrypt.DefaultCost)
	userID := insertTestUser(t, db, "gdpr-totp@example.com", "+62877777784", string(hash))

	totpKey, err := libtotp.Generate(libtotp.GenerateOpts{Issuer: "Tenkei Aikidojo", AccountName: "gdpr-totp@example.com"})
	if err != nil {
		t.Fatalf("generate totp key: %v", err)
	}
	enc, err := totp.EncryptSecret(key, totpKey.Secret())
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	if _, err := db.NewRaw(
		`UPDATE users SET totp_enabled = TRUE, totp_secret = ? WHERE id = ?`, enc, userID,
	).Exec(t.Context()); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	code, err := libtotp.GenerateCode(totpKey.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}

	post := func(body string) *httptest.ResponseRecorder {
		req := withUserID(httptest.NewRequest(http.MethodPost, "/v1/auth/delete", strings.NewReader(body)), userID)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.handleDeleteAccount(w, req)
		return w
	}

	// Missing code → 400, user intact.
	if w := post(`{"current_password":"testpassword"}`); w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without code, got %d: %s", w.Code, w.Body.String())
	}
	if err := db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(t.Context(), new(int)); err != nil {
		t.Fatal("user row must survive a missing-code rejection")
	}

	// Wrong code → 400.
	if w := post(`{"current_password":"testpassword","code":"000000"}`); w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 with wrong code, got %d: %s", w.Code, w.Body.String())
	}

	// Correct code → 200, user gone.
	if w := post(`{"current_password":"testpassword","code":"` + code + `"}`); w.Code != http.StatusOK {
		t.Errorf("expected 200 with valid code, got %d: %s", w.Code, w.Body.String())
	}
	if err := db.NewRaw(`SELECT 1 FROM users WHERE id = ?`, userID).Scan(t.Context(), new(int)); err == nil {
		t.Error("user row must be deleted after a valid request")
	}
}
