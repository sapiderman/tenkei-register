package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
)

func verifyMux(t *testing.T) (*administrator, http.Handler) {
	t.Helper()
	a := &administrator{logger: zerolog.Nop(), db: setupTestDB(t), validate: validator.New()}
	r := chi.NewRouter()
	r.Post("/users/{id}/verify", a.handleVerifyMember)
	return a, r
}

func TestVerify_AdminVerifiesNew(t *testing.T) {
	a, r := verifyMux(t)
	tid := insertUser(t, a.db, "Pending", "verify-new@example.com", types.RoleNew)
	sid := seedSession(t, a.db, tid)

	req := withViewer(newReq(http.MethodPost, fmt.Sprintf("/users/%d/verify", tid), ""), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("verify new: got %d, want 200", w.Code)
	}
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Role != types.RoleUser {
		t.Errorf("role after verify = %q, want user", u.Role)
	}
	if !auditExists(t, a.db, 1, fmt.Sprintf("admin_verify:target=%d", tid)) {
		t.Error("expected audit record for admin_verify")
	}
	// Sessions are NOT invalidated on verify (upgrade within the soft-gated tier).
	if !sessionExists(t, a.db, sid) {
		t.Error("verify must not invalidate sessions")
	}
}

func TestVerify_AlreadyUser_409(t *testing.T) {
	// Also pins the in-scope half of the RowsAffected==0 race mapping in
	// verifyMember: re-check finds the target in scope -> 409, not 404.
	a, r := verifyMux(t)
	tid := insertUser(t, a.db, "Verified", "verify-user@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPost, fmt.Sprintf("/users/%d/verify", tid), ""), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("verify user: got %d, want 409", w.Code)
	}
}

func TestVerify_AdminTargetingAdminSuperuser_404(t *testing.T) {
	a, r := verifyMux(t)
	for _, role := range []string{types.RoleAdmin, types.RoleSuperuser} {
		tid := insertUser(t, a.db, "Hidden", "verify-hidden-"+role+"@example.com", role)

		req := withViewer(newReq(http.MethodPost, fmt.Sprintf("/users/%d/verify", tid), ""), 1, types.RoleAdmin)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("admin verify %s: got %d, want 404 (anti-enumeration)", role, w.Code)
		}
	}
}

func TestVerify_SuperuserVerifiesNew(t *testing.T) {
	a, r := verifyMux(t)
	tid := insertUser(t, a.db, "Su Pending", "verify-su@example.com", types.RoleNew)

	req := withViewer(newReq(http.MethodPost, fmt.Sprintf("/users/%d/verify", tid), ""), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("superuser verify new: got %d, want 200", w.Code)
	}
}

func TestVerify_NotFound(t *testing.T) {
	_, r := verifyMux(t)
	req := withViewer(newReq(http.MethodPost, "/users/999999999/verify", ""), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing id: got %d, want 404", w.Code)
	}
}

// TestUpdateMemberForViewer_OutOfScopeNoMutation is the regression test for the
// PUT TOCTOU fix: a scoped update on an out-of-scope target returns
// ErrMemberNotFound and writes nothing. (Previously the scope check was a
// separate pre-read, so a target promoted between check and write was edited.)
func TestUpdateMemberForViewer_OutOfScopeNoMutation(t *testing.T) {
	a := newTestAdministrator(t)
	tid := insertUser(t, a.db, "Locked Admin", "toctou-admin@example.com", types.RoleAdmin)

	req := &auth.UpdateProfileRequest{Name: "Should Not Apply"}
	err := updateMemberForViewer(t.Context(), a.db, types.RoleLevel(types.RoleAdmin), tid, req)
	if err != ErrMemberNotFound {
		t.Fatalf("out-of-scope update: err = %v, want ErrMemberNotFound", err)
	}
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Name != "Locked Admin" {
		t.Errorf("out-of-scope update mutated the row: name = %q", u.Name)
	}
}

func TestUpdateMemberForViewer_NotFound(t *testing.T) {
	a := newTestAdministrator(t)
	err := updateMemberForViewer(t.Context(), a.db, types.RoleLevel(types.RoleSuperuser), 999999999, &auth.UpdateProfileRequest{Name: "x"})
	if err != ErrMemberNotFound {
		t.Errorf("missing target: err = %v, want ErrMemberNotFound", err)
	}
}

func TestUpdateMemberForViewer_SuperuserEditsAdmin(t *testing.T) {
	a := newTestAdministrator(t)
	tid := insertUser(t, a.db, "Admin Edit", "su-tx-edit@example.com", types.RoleAdmin)

	err := updateMemberForViewer(t.Context(), a.db, types.RoleLevel(types.RoleSuperuser), tid, &auth.UpdateProfileRequest{Name: "Edited"})
	if err != nil {
		t.Fatalf("superuser update admin: %v", err)
	}
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Name != "Edited" {
		t.Errorf("name = %q, want Edited", u.Name)
	}
}
