package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
)

// stubStore is a SessionStore whose Validate reports a fixed user/role, so the
// admin router can be exercised end-to-end (middleware + handler) without a DB.
type stubStore struct {
	userID    int64
	role      string // returned by Validate; empty + noSession forces ErrSessionNotFound
	noSession bool
}

func (s *stubStore) Create(context.Context, int64, bool) (string, error) { return "stub", nil }
func (s *stubStore) Validate(_ context.Context, _ string) (int64, string, error) {
	if s.noSession {
		return 0, "", auth.ErrSessionNotFound
	}
	return s.userID, s.role, nil
}
func (s *stubStore) Invalidate(context.Context, string) error   { return nil }
func (s *stubStore) InvalidateAll(context.Context, int64) error { return nil }

func newTestRouter(t *testing.T, store auth.SessionStore) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	mw := auth.NewMiddleware(store, false)
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), nil, mw)
	return r
}

func TestAdminRouter_NoSession_401(t *testing.T) {
	r := newTestRouter(t, &stubStore{noSession: true})

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("no session: got %d, want 401", w.Code)
	}
}

func TestAdminRouter_LowRole_403(t *testing.T) {
	for _, role := range []string{"new", "user"} {
		r := newTestRouter(t, &stubStore{userID: 1, role: role})

		req := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
		req.AddCookie(&http.Cookie{Name: "tenkei_session", Value: "x"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("role %q: got %d, want 403", role, w.Code)
		}
	}
}

// TestAdminRouter_AdminAndSuperuserAdmitted verifies both admin and superuser
// pass the gate and reach the handler, which returns 200 against a real DB.
func TestAdminRouter_AdminAndSuperuserAdmitted(t *testing.T) {
	db := setupTestDB(t)
	for _, role := range []string{"admin", "superuser"} {
		r := chi.NewRouter()
		mw := auth.NewMiddleware(&stubStore{userID: 1, role: role}, false)
		NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), db, mw)

		req := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
		req.AddCookie(&http.Cookie{Name: "tenkei_session", Value: "x"})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("role %q: got %d, want 200", role, w.Code)
		}
	}
}

// TestAdminRouter_RoleEndpointAdmin403 verifies the role-management endpoint
// is superuser-only: an authenticated admin is rejected with 403.
func TestAdminRouter_RoleEndpointAdmin403(t *testing.T) {
	db := setupTestDB(t)
	r := chi.NewRouter()
	mw := auth.NewMiddleware(&stubStore{userID: 1, role: "admin"}, false)
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), db, mw)

	req := httptest.NewRequest(http.MethodPut, "/v1/admin/users/1/role", nil)
	req.AddCookie(&http.Cookie{Name: "tenkei_session", Value: "x"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("admin on role endpoint: got %d, want 403", w.Code)
	}
}
