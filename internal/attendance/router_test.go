package attendance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// stubStore is a SessionStore whose Validate reports a fixed user/role, so the
// router can be exercised end-to-end (middleware + handler). Mirrors
// internal/admin/router_test.go.
type stubStore struct {
	userID    int64
	role      string
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

// Pending-session methods: attendance routes never carry pending sessions;
// these only satisfy the SessionStore interface.
func (s *stubStore) ValidatePending(context.Context, string) (int64, error) {
	return 0, auth.ErrSessionNotFound
}
func (s *stubStore) RotatePending(_ context.Context, _ string, _ int64) (string, error) {
	return "stub-session", nil
}
func (s *stubStore) RecordTOTPFailure(context.Context, string) (int, error) {
	return 0, auth.ErrSessionNotFound
}

func newTestRouter(t *testing.T, store *stubStore, db *bun.DB) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	mw := auth.NewMiddleware(store, false)
	NewRouter(t.Context(), r, zerolog.Nop(), validator.New(), db, mw)
	return r
}

func withCookie(r *http.Request) *http.Request {
	r.AddCookie(&http.Cookie{Name: "tenkei_session", Value: "x"})
	return r
}

var (
	memberRoutes = []struct{ method, path string }{
		{http.MethodPost, "/v1/attendance"},
		{http.MethodGet, "/v1/attendance/me"},
	}
	adminRoutes = []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/attendance"},
		{http.MethodPut, "/v1/admin/attendance/1/confirm"},
		{http.MethodPut, "/v1/admin/attendance/1/reject"},
	}
)

func TestRouter_NoSession_401(t *testing.T) {
	r := newTestRouter(t, &stubStore{noSession: true}, nil)
	for _, rt := range append(append([]struct{ method, path string }{}, memberRoutes...), adminRoutes...) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withCookie(newReq(rt.method, rt.path, "")))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without session: got %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestRouter_MemberRoutes(t *testing.T) {
	db := setupTestDB(t)

	// Unverified members are refused before touching the database.
	r := newTestRouter(t, &stubStore{role: types.RoleNew}, nil)
	for _, rt := range memberRoutes {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withCookie(newReq(rt.method, rt.path, `{"dojo":"d","instructor":"i"}`)))
		if w.Code != http.StatusForbidden {
			t.Errorf("role new on %s: got %d, want 403", rt.path, w.Code)
		}
	}

	// Every verified role reaches the handler, which answers 200 against a real DB.
	for _, role := range []string{types.RoleUser, types.RoleAdmin, types.RoleSuperuser} {
		member, _ := seedMember(t, db, role)
		r := newTestRouter(t, &stubStore{userID: member, role: role}, db)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withCookie(newReq(http.MethodGet, "/v1/attendance/me", "")))
		if w.Code != http.StatusOK {
			t.Errorf("role %s on /me: got %d, want 200; body: %s", role, w.Code, w.Body)
		}
	}
}

func TestRouter_AdminRoutes(t *testing.T) {
	db := setupTestDB(t)

	for _, role := range []string{types.RoleNew, types.RoleUser} {
		r := newTestRouter(t, &stubStore{role: role}, nil)
		for _, rt := range adminRoutes {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, withCookie(newReq(rt.method, rt.path, "")))
			if w.Code != http.StatusForbidden {
				t.Errorf("role %s on %s: got %d, want 403", role, rt.path, w.Code)
			}
		}
	}

	for _, role := range []string{types.RoleAdmin, types.RoleSuperuser} {
		r := newTestRouter(t, &stubStore{role: role}, db)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withCookie(newReq(http.MethodGet, "/v1/admin/attendance", "")))
		if w.Code != http.StatusOK {
			t.Errorf("role %s on list: got %d, want 200; body: %s", role, w.Code, w.Body)
		}
	}
}

// TestRouter_RateLimitPerUser verifies the log-in limit is 10 per minute per
// user, regardless of how many dojos are tried.
func TestRouter_RateLimitPerUser(t *testing.T) {
	db := setupTestDB(t)
	member, _ := seedMember(t, db, types.RoleUser)
	r := newTestRouter(t, &stubStore{userID: member, role: types.RoleUser}, db)

	post := func(i int) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, withCookie(newReq(http.MethodPost, "/v1/attendance", fmt.Sprintf(`{"dojo":"Rate Dojo %d","instructor":"A"}`, i))))
		return w
	}
	for i := 1; i <= 10; i++ {
		if w := post(i); w.Code != http.StatusCreated {
			t.Fatalf("request %d: got %d, want 201; body: %s", i, w.Code, w.Body)
		}
	}
	if w := post(11); w.Code != http.StatusTooManyRequests {
		t.Fatalf("request 11: got %d, want 429; body: %s", w.Code, w.Body)
	}
}
