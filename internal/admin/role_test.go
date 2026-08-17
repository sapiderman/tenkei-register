package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
)

func roleMux(t *testing.T) (*administrator, http.Handler) {
	t.Helper()
	a := &administrator{logger: zerolog.Nop(), db: setupTestDB(t), validate: validator.New()}
	r := chi.NewRouter()
	r.Put("/users/{id}/role", a.handleRoleMember)
	return a, r
}

func TestRole_SuperuserSetsAnyRole(t *testing.T) {
	a, r := roleMux(t)

	cases := []struct{ from, to string }{
		{types.RoleUser, types.RoleAdmin},
		{types.RoleAdmin, types.RoleNew},
		{types.RoleNew, types.RoleSuperuser},
		{types.RoleUser, types.RoleNew},
	}
	for i, tc := range cases {
		tid := insertUser(t, a.db, "Role Target", fmt.Sprintf("role-set-%d@example.com", i), tc.from)

		req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"`+tc.to+`"}`), 1, types.RoleSuperuser)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("%s->%s: got %d, want 200", tc.from, tc.to, w.Code)
			continue
		}
		u, _ := auth.GetUserByID(t.Context(), a.db, tid)
		if u.Role != tc.to {
			t.Errorf("%s->%s: role = %q", tc.from, tc.to, u.Role)
		}
		if !auditExists(t, a.db, 1, fmt.Sprintf("role_change:%s->%s:target=%d", tc.from, tc.to, tid)) {
			t.Errorf("%s->%s: missing audit record", tc.from, tc.to)
		}
	}
}

func TestRole_InvalidRole_400(t *testing.T) {
	a, r := roleMux(t)
	tid := insertUser(t, a.db, "Bad Role", "role-bad@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"wizard"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid role: got %d, want 400", w.Code)
	}
}

func TestRole_NotFound(t *testing.T) {
	_, r := roleMux(t)
	req := withViewer(newReq(http.MethodPut, "/users/999999999/role", `{"role":"user"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing id: got %d, want 404", w.Code)
	}
}

func TestRole_DemotionInvalidatesSessions(t *testing.T) {
	a, r := roleMux(t)
	tid := insertUser(t, a.db, "Demote Me", "role-demote@example.com", types.RoleAdmin)
	sid := seedSession(t, a.db, tid)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"user"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("demote: got %d, want 200", w.Code)
	}
	if sessionExists(t, a.db, sid) {
		t.Error("demotion must invalidate the target's sessions")
	}
}

func TestRole_PromotionPreservesSessions(t *testing.T) {
	a, r := roleMux(t)
	tid := insertUser(t, a.db, "Promote Me", "role-promote@example.com", types.RoleNew)
	sid := seedSession(t, a.db, tid)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"admin"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("promote: got %d, want 200", w.Code)
	}
	if !sessionExists(t, a.db, sid) {
		t.Error("promotion must not invalidate sessions")
	}
}

func TestRole_SameRolePreservesSessions(t *testing.T) {
	a, r := roleMux(t)
	tid := insertUser(t, a.db, "Same Role", "role-same@example.com", types.RoleUser)
	sid := seedSession(t, a.db, tid)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"user"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("same role: got %d, want 200", w.Code)
	}
	if !sessionExists(t, a.db, sid) {
		t.Error("same-level change must not invalidate sessions")
	}
}

func TestRole_LastSuperuserGuard_409(t *testing.T) {
	a, r := roleMux(t)
	cleanupRoleTestLeftovers(t, a.db)
	// A lone superuser (the target) — demoting them to anything else is refused.
	tid := insertUser(t, a.db, "Lone Superuser", "role-lone@example.com", types.RoleSuperuser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"admin"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("demote last superuser: got %d, want 409", w.Code)
	}
	// Role unchanged.
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Role != types.RoleSuperuser {
		t.Errorf("role changed to %q; guard must leave it superuser", u.Role)
	}
}

func TestRole_DemoteSuperuserWhenOthersExist_OK(t *testing.T) {
	a, r := roleMux(t)
	tid := insertUser(t, a.db, "Superuser A", "role-su-a@example.com", types.RoleSuperuser)
	insertUser(t, a.db, "Superuser B", "role-su-b@example.com", types.RoleSuperuser) // a second one

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", tid), `{"role":"admin"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("demote non-last superuser: got %d, want 200", w.Code)
	}
}

// TestRole_LastSuperuserGuard_RaceFree runs two concurrent demotions of two
// superusers. The advisory-lock guard must prevent both from succeeding,
// leaving at least one superuser. (The last demotion to commit must 409.)
func TestRole_LastSuperuserGuard_RaceFree(t *testing.T) {
	a, r := roleMux(t)
	cleanupRoleTestLeftovers(t, a.db)
	suA := insertUser(t, a.db, "Race A", "role-race-a@example.com", types.RoleSuperuser)
	suB := insertUser(t, a.db, "Race B", "role-race-b@example.com", types.RoleSuperuser)

	var wg sync.WaitGroup
	var codeA, codeB int
	wg.Add(2)
	go func() {
		defer wg.Done()
		req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", suA), `{"role":"admin"}`), 1, types.RoleSuperuser)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		codeA = w.Code
	}()
	go func() {
		defer wg.Done()
		req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d/role", suB), `{"role":"admin"}`), 1, types.RoleSuperuser)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		codeB = w.Code
	}()
	wg.Wait()

	// At least one must have been refused (409) so a superuser survives.
	if codeA == http.StatusOK && codeB == http.StatusOK {
		t.Fatal("both concurrent demotions succeeded: last-superuser invariant broken")
	}
	var n int
	if err := a.db.NewRaw(`SELECT COUNT(*) FROM users WHERE role = 'superuser'`).Scan(t.Context(), &n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n < 1 {
		t.Fatalf("no superusers left after concurrent demotions; got %d", n)
	}
}
