package register

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"database/sql"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// newTestRegistrar creates a registrar with turnstile disabled for unit testing.
func newTestRegistrar() *registrar {
	return &registrar{
		logger:           zerolog.Nop(),
		validate:         validator.New(),
		turnstileEnabled: false,
	}
}

// newTestRegistrarDB creates a registrar wired to a real (test) DB.
func newTestRegistrarDB(t *testing.T) *registrar {
	t.Helper()
	return &registrar{
		logger:           zerolog.Nop(),
		validate:         validator.New(),
		db:               setupTestDB(t),
		turnstileEnabled: false,
	}
}

// setupTestDB creates a test DB connection or skips if unavailable.
func setupTestDB(t *testing.T) *bun.DB {
	t.Helper()
	dsn := os.Getenv("TENKEI_DATABASE_CONNECTION_STRING")
	if dsn == "" {
		t.Skip("skipping: TENKEI_DATABASE_CONNECTION_STRING not set")
		return nil
	}
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db := bun.NewDB(sqldb, pgdialect.New())
	if err := db.Ping(); err != nil {
		t.Skipf("skipping: cannot connect to PostgreSQL: %v", err)
		return nil
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// wipeUsers deletes any user whose email or whatsapp matches one of keys.
// Called once per DB test: it pre-deletes (idempotency against leaked residue
// from a prior interrupted run) and registers a t.Cleanup to delete what this
// test inserted. Uses context.Background because t.Context() is already
// cancelled by the time t.Cleanup runs (Go 1.24+).
func wipeUsers(t *testing.T, db *bun.DB, keys ...string) {
	t.Helper()
	del := func() {
		for _, k := range keys {
			_, _ = db.NewRaw(
				"DELETE FROM users WHERE email = ? OR whatsapp_number = ?",
				k, k,
			).Exec(context.Background())
		}
	}
	del()
	t.Cleanup(del)
}

// validPayloadMap returns a valid registration payload as a mutable map.
func validPayloadMap() map[string]any {
	return map[string]any{
		"name":                     "Test User",
		"email":                    "test@example.com",
		"whatsapp":                 "+6281234567890",
		"date_of_birth":            "1990-01-15",
		"dojo":                     "Tokyo Dojo",
		"rank":                     "5th Kyu",
		"last_grading_date":        "2024-06-01",
		"role":                     "student",
		"consent_datastore":        true,
		"consent_marketing":        false,
		"medical_conditions":       "none",
		"emergency_contact_name":   "Jane Doe",
		"emergency_contact_number": "+6289876543210",
		"password":                 "securepass123",
		"password_confirm":         "securepass123",
	}
}

// doJSONRequest builds a POST request with JSON content type and runs handleSubmission.
func doJSONRequest(t *testing.T, reg *registrar, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/register/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	reg.handleSubmission(w, req)
	return w
}

// decodeError pulls the "error" field out of a JSON response body.
func decodeError(t *testing.T, body *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	_ = json.NewDecoder(body.Body).Decode(&resp)
	return resp["error"]
}

// --- Pure unit tests (no DB required) ---

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"trims whitespace", "  hello  ", "hello"},
		{"escapes HTML", "<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"empty string", "", ""},
		{"normal text", "John Doe", "John Doe"},
		{"escapes ampersand", "A & B", "A &amp; B"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeInput(tt.input); got != tt.want {
				t.Errorf("sanitizeInput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSanitizeFormData(t *testing.T) {
	d := RegistrationFormData{
		Name:  "  <b>Test</b>  ",
		Email: " test@example.com ",
	}
	d = sanitizeFormData(d)
	if d.Name != "&lt;b&gt;Test&lt;/b&gt;" {
		t.Errorf("expected sanitized name, got %q", d.Name)
	}
	if d.Email != "test@example.com" {
		t.Errorf("expected trimmed email, got %q", d.Email)
	}
}

// --- handleSubmission validation (table-driven) ---
//
// Each case starts from a valid payload, applies an optional mutation, and
// asserts the 400 status plus an error substring. "raw" overrides mutation for
// bodies that must be invalid at the JSON layer itself.

func TestHandleSubmission_Validation(t *testing.T) {
	reg := newTestRegistrar()

	cases := []struct {
		name    string
		raw     string // sent verbatim when non-empty
		mutate  func(map[string]any)
		wantErr string // required substring of resp["error"]; "" skips
		notErr  string // substring that must NOT appear (case-insensitive)
	}{
		// JSON-layer rejections.
		{name: "InvalidJSON", raw: `{bad json}`, wantErr: "Invalid JSON payload"},
		{name: "UnknownFields", mutate: func(m map[string]any) { m["unknown_field"] = "x" }, wantErr: "Invalid JSON payload"},
		{name: "TrailingJSON", raw: marshalJSON(validPayloadMap()) + `{"second":1}`, wantErr: "Invalid JSON payload"},
		{name: "BodyTooLarge", raw: oversizedJSON(), wantErr: "Invalid JSON payload"},

		// Required-field / length validations.
		{name: "MissingName", mutate: func(m map[string]any) { m["name"] = "" }, wantErr: "Name is required"},
		{name: "NameTooLong", mutate: func(m map[string]any) { m["name"] = strings.Repeat("a", 256) }, wantErr: "Name is too long"},
		{name: "MissingWhatsApp", mutate: func(m map[string]any) { m["whatsapp"] = "" }, wantErr: "WhatsApp number is required"},
		{name: "WhatsAppTooLong", mutate: func(m map[string]any) { m["whatsapp"] = "+" + strings.Repeat("1", 20) }, wantErr: "WhatsApp number is too long"},
		{name: "InvalidEmail", mutate: func(m map[string]any) { m["email"] = "not-an-email" }, wantErr: "Invalid email"},
		{name: "MissingPassword", mutate: func(m map[string]any) { m["password"] = ""; m["password_confirm"] = "" }, wantErr: "Password is required"},
		{name: "PasswordTooShort", mutate: func(m map[string]any) { m["password"] = "short"; m["password_confirm"] = "short" }, wantErr: "at least 8 characters"},
		{name: "PasswordTooLong", mutate: func(m map[string]any) { p := strings.Repeat("a", 73); m["password"] = p; m["password_confirm"] = p }, wantErr: "Password is too long"},
		{name: "PasswordMismatch", mutate: func(m map[string]any) { m["password_confirm"] = "differentpass" }, wantErr: "Passwords do not match"},
		{name: "InvalidRank", mutate: func(m map[string]any) { m["rank"] = "Black Belt Grandmaster" }, wantErr: "Invalid rank"},
		{name: "MissingConsent", mutate: func(m map[string]any) { m["consent_datastore"] = false }, wantErr: "consent to data storage"},
		{name: "DojoTooLong", mutate: func(m map[string]any) { m["dojo"] = strings.Repeat("a", 256) }, wantErr: "Dojo name is too long"},
		{name: "MedicalConditionsTooLong", mutate: func(m map[string]any) { m["medical_conditions"] = strings.Repeat("a", 2001) }, wantErr: "Medical conditions"},
		{name: "EmergencyNameTooLong", mutate: func(m map[string]any) { m["emergency_contact_name"] = strings.Repeat("a", 256) }, wantErr: "Emergency contact name"},
		{name: "EmergencyNumberTooLong", mutate: func(m map[string]any) { m["emergency_contact_number"] = "+" + strings.Repeat("1", 20) }, wantErr: "Emergency contact number"},
		{name: "InvalidDateOfBirth", mutate: func(m map[string]any) { m["date_of_birth"] = "not-a-date" }, wantErr: "Date of birth"},
		{name: "InvalidLastGradingDate", mutate: func(m map[string]any) { m["date_of_birth"] = "1990-01-01"; m["last_grading_date"] = "2024/06/01" }, wantErr: "Last grading date"},

		// Branch ordering: empty email must skip email validation.
		{name: "EmptyEmailSkipsEmailValidation", mutate: func(m map[string]any) { m["email"] = ""; m["consent_datastore"] = false }, wantErr: "consent", notErr: "email"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.raw
			if body == "" {
				m := validPayloadMap()
				if tc.mutate != nil {
					tc.mutate(m)
				}
				body = marshalJSON(m)
			}
			w := doJSONRequest(t, reg, body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
			got := decodeError(t, w)
			if tc.wantErr != "" && !strings.Contains(got, tc.wantErr) {
				t.Errorf("error: want substring %q, got %q", tc.wantErr, got)
			}
			if tc.notErr != "" && strings.Contains(strings.ToLower(got), strings.ToLower(tc.notErr)) {
				t.Errorf("error: did not want substring %q, got %q", tc.notErr, got)
			}
		})
	}
}

// marshalJSON marshals m, failing the test on error.
func marshalJSON(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic("marshal: " + err.Error())
	}
	return string(b)
}

// oversizedJSON returns a valid JSON payload exceeding the 1 MiB body limit,
// exercising the MaxBytesReader guard.
func oversizedJSON() string {
	m := validPayloadMap()
	m["name"] = strings.Repeat("a", 1<<20+100) // > 1 MiB
	return marshalJSON(m)
}

func TestHandleSubmission_TurnstileDisabledBypass(t *testing.T) {
	reg := newTestRegistrar()
	if reg.turnstileEnabled {
		t.Fatal("expected turnstile disabled")
	}
	// verifyTurnstileResponse should return nil when disabled.
	if err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), ""); err != nil {
		t.Errorf("expected nil when turnstile disabled, got %v", err)
	}
}

func TestHandleSubmission_TurnstileFailure(t *testing.T) {
	// Enabled turnstile with a failing fake siteverify: submission is rejected 400.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response"]}`))
	}))
	t.Cleanup(ts.Close)

	reg := &registrar{
		logger:             zerolog.Nop(),
		validate:           validator.New(),
		turnstileEnabled:   true,
		turnstileSecret:    "test-secret",
		turnstileVerifyURL: ts.URL,
	}

	m := validPayloadMap()
	m["cf_turnstile_response"] = "token"
	w := doJSONRequest(t, reg, marshalJSON(m))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if got := decodeError(t, w); !strings.Contains(got, "Security verification failed") {
		t.Errorf("expected security verification error, got %q", got)
	}
}

// --- verifyTurnstileResponse enabled-path ---
//
// The Cloudflare siteverify URL is injected via turnstileVerifyURL so the
// enabled path can be exercised against a fake server.

func TestVerifyTurnstileResponse_Enabled(t *testing.T) {
	// Pure branches: no network call.
	t.Run("empty token rejected", func(t *testing.T) {
		reg := &registrar{logger: zerolog.Nop(), turnstileEnabled: true, turnstileSecret: "s"}
		err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "")
		if err == nil || !strings.Contains(err.Error(), "token is empty") {
			t.Fatalf("want token-empty error, got %v", err)
		}
	})

	t.Run("empty secret rejected", func(t *testing.T) {
		reg := &registrar{logger: zerolog.Nop(), turnstileEnabled: true}
		err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("want not-configured error, got %v", err)
		}
	})

	// newFakeReg spins up a httptest.Server standing in for Cloudflare.
	newFakeReg := func(t *testing.T, handler http.HandlerFunc) *registrar {
		t.Helper()
		ts := httptest.NewServer(handler)
		t.Cleanup(ts.Close)
		return &registrar{
			logger:             zerolog.Nop(),
			turnstileEnabled:   true,
			turnstileSecret:    "test-secret",
			turnstileVerifyURL: ts.URL,
		}
	}

	t.Run("success returns nil", func(t *testing.T) {
		reg := newFakeReg(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"hostname":"example.com","challenge_ts":"2024-01-01T00:00:00Z","action":"register","cdata":"custom"}`))
		})
		if err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("failure surfaces error codes", func(t *testing.T) {
		reg := newFakeReg(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":false,"error-codes":["missing-input-secret","invalid-input-secret","missing-input-response","invalid-input-response","bad-request","timeout-or-duplicate","internal-error","unknown-code"]}`))
		})
		err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil {
			t.Fatal("want error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid-input-response") {
			t.Errorf("want error code in message, got %v", err)
		}
	})

	t.Run("non-200 status rejected", func(t *testing.T) {
		reg := newFakeReg(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		})
		err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "non-OK status") {
			t.Fatalf("want non-OK status error, got %v", err)
		}
	})

	t.Run("malformed body rejected", func(t *testing.T) {
		reg := newFakeReg(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{not json`))
		})
		err := reg.verifyTurnstileResponse(httptest.NewRequest("POST", "/", nil), "tok")
		if err == nil || !strings.Contains(err.Error(), "failed to decode") {
			t.Fatalf("want decode error, got %v", err)
		}
	})

	t.Run("prefers CF-Connecting-IP", func(t *testing.T) {
		var gotRemote string
		reg := newFakeReg(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotRemote = r.FormValue("remoteip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		})
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("CF-Connecting-IP", "203.0.113.7")
		req.RemoteAddr = "10.0.0.1:1234"
		if err := reg.verifyTurnstileResponse(req, "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		if gotRemote != "203.0.113.7" {
			t.Errorf("remoteip: want 203.0.113.7, got %q", gotRemote)
		}
	})

	t.Run("falls back to RemoteAddr host", func(t *testing.T) {
		var gotRemote string
		reg := newFakeReg(t, func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			gotRemote = r.FormValue("remoteip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		})
		req := httptest.NewRequest("POST", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		if err := reg.verifyTurnstileResponse(req, "tok"); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
		if gotRemote != "10.0.0.1" {
			t.Errorf("remoteip: want 10.0.0.1 (port stripped), got %q", gotRemote)
		}
	})
}

// --- Integration tests (require DB) ---

func TestHandleSubmission_Success(t *testing.T) {
	reg := newTestRegistrarDB(t)
	db := reg.db
	wipeUsers(t, db, "test@example.com", "+6281234567890")

	w := doJSONRequest(t, reg, marshalJSON(validPayloadMap()))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q (body: %s)", resp["status"], w.Body.String())
	}
	if resp["error"] != "" {
		t.Errorf("expected no error field, got %q", resp["error"])
	}
}

func TestHandleSubmission_DuplicateEmail(t *testing.T) {
	reg := newTestRegistrarDB(t)
	db := reg.db
	wipeUsers(t, db, "test@example.com", "+6281234567890")

	body := marshalJSON(validPayloadMap())

	if w := doJSONRequest(t, reg, body); w.Code != http.StatusCreated {
		t.Fatalf("first registration failed: %d: %s", w.Code, decodeError(t, w))
	}

	w2 := doJSONRequest(t, reg, body)
	if w2.Code != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate, got %d", w2.Code)
	}
	if err := decodeError(t, w2); !strings.Contains(err, "already exists") {
		t.Errorf("expected 'already exists' error, got %q", err)
	}
}

func TestHandleSubmission_XSSInName(t *testing.T) {
	reg := newTestRegistrarDB(t)
	db := reg.db
	wipeUsers(t, db, "xss-test@example.com", "+6281111111111")

	m := validPayloadMap()
	m["name"] = "<script>alert('xss')</script>"
	m["email"] = "xss-test@example.com"
	m["whatsapp"] = "+6281111111111"
	m["date_of_birth"] = "1990-01-01"
	m["rank"] = ""

	w := doJSONRequest(t, reg, marshalJSON(m))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var name string
	err := db.NewRaw(`SELECT name FROM users WHERE email = ?`, "xss-test@example.com").
		Scan(context.Background(), &name)
	if err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}
	const want = "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
	if name != want {
		t.Errorf("name: want sanitized %q, got %q", want, name)
	}
}

// TestHandleSubmission_RoleForcedToNew verifies the server ignores the
// client-supplied role and always stores "new" (register.go hardcode).
func TestHandleSubmission_RoleForcedToNew(t *testing.T) {
	reg := newTestRegistrarDB(t)
	db := reg.db
	wipeUsers(t, db, "role-test@example.com", "+628123459999")

	m := validPayloadMap()
	m["email"] = "role-test@example.com"
	m["whatsapp"] = "+628123459999"
	m["role"] = "student"

	w := doJSONRequest(t, reg, marshalJSON(m))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var role string
	err := db.NewRaw(`SELECT role FROM users WHERE email = ?`, "role-test@example.com").
		Scan(context.Background(), &role)
	if err != nil {
		t.Fatalf("fetch role: %v", err)
	}
	if role != "new" {
		t.Errorf("role: want %q (client role must be ignored), got %q", "new", role)
	}
}
