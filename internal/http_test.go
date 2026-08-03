package internal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sapiderman/tenkei-register/config"
	"github.com/sapiderman/tenkei-register/internal/database"
)

// testDB connects to the test database or skips.
func testDB(t *testing.T) *database.Database {
	t.Helper()
	dsn := os.Getenv("TENKEI_DATABASE_CONNECTION_STRING")
	if dsn == "" {
		t.Skip("skipping: TENKEI_DATABASE_CONNECTION_STRING not set")
	}
	db, err := database.New(dsn)
	if err != nil {
		t.Skipf("skipping: cannot connect to PostgreSQL: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestHandler builds the full HTTP stack (middleware + register + auth routes).
func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	db := testDB(t)
	cfg := &config.Config{
		Server:   config.ServerConfig{XCFBypass: "test-bypass", TurnstileEnabled: false, Mode: "test"},
		Database: config.DatabaseConfig{ConnectionString: "unused"},
	}
	h, err := NewHTTPHandler(context.Background(), db, cfg)
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}
	return h
}

func TestNewHTTPHandler_Health(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("GET /health: got %d, want 200", w.Code)
	}
}

func TestNewHTTPHandler_RegisterRequiresBypass(t *testing.T) {
	h := newTestHandler(t)
	body := `{"name":"Test User","whatsapp":"+6281200000001","password":"securepass123","password_confirm":"securepass123","consent_datastore":true,"rank":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/register/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	// No bypass header: rejected before reaching the route.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("no bypass header: got %d, want 404", w.Code)
	}

	// Wrong bypass key: also rejected.
	req.Header.Set("x-cf-bypass", "wrong-key")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("wrong bypass key: got %d, want 404", w.Code)
	}
}

func TestNewHTTPHandler_RegisterSuccess(t *testing.T) {
	db := testDB(t)
	cfg := &config.Config{
		Server:   config.ServerConfig{XCFBypass: "test-bypass", TurnstileEnabled: false, Mode: "test"},
		Database: config.DatabaseConfig{ConnectionString: "unused"},
	}
	h, err := NewHTTPHandler(context.Background(), db, cfg)
	if err != nil {
		t.Fatalf("NewHTTPHandler: %v", err)
	}

	const email = "http-test@example.com"
	const wa = "+6281200000002"
	// Idempotent cleanup: sweep before and after, with context.Background()
	// (t.Context() is already cancelled inside t.Cleanup on Go 1.24+).
	sweep := func() {
		_, _ = db.DB.NewRaw(`DELETE FROM users WHERE email = ? OR whatsapp_number = ?`, email, wa).
			Exec(context.Background())
	}
	sweep()
	t.Cleanup(sweep)

	body := `{"name":"HTTP Test","email":"` + email + `","whatsapp":"` + wa + `","password":"securepass123","password_confirm":"securepass123","consent_datastore":true,"rank":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/register/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-cf-bypass", "test-bypass")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("register: got %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
}

func TestNewHTTPHandler_AuthProfileRequiresSession(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/profile", nil)
	req.Header.Set("x-cf-bypass", "test-bypass")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("GET /v1/auth/profile without session: got %d, want 401", w.Code)
	}
}
