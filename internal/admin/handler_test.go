package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// newAdminMux builds an admin handler group over a real DB, skipping the
// session middleware: tests inject the viewer identity straight into the
// request context via auth.WithAuth, isolating handler + DB behavior.
func newAdminMux(t *testing.T) (*administrator, http.Handler) {
	t.Helper()
	a := &administrator{logger: zerolog.Nop(), db: setupTestDB(t), validate: validator.New()}
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Get("/users/{id}", a.handleGetMember)
		r.Put("/users/{id}", a.handleUpdateMember)
	})
	return a, r
}

func withViewer(r *http.Request, userID int64, role string) *http.Request {
	return r.WithContext(auth.WithAuth(r.Context(), userID, role))
}

func newReq(method, url, body string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, url, nil)
	} else {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

// auditExists reports whether an audit row for (userID, action) exists.
func auditExists(t *testing.T, db *bun.DB, userID int64, action string) bool {
	t.Helper()
	var n int
	if err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = ?`, userID, action).Scan(t.Context(), &n); err != nil {
		t.Fatalf("auditExists: %v", err)
	}
	return n > 0
}

// ---- GET /v1/admin/users/:id ----

func TestGetMember_AdminCanSeeNewUser(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Visible", "get-visible@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodGet, fmt.Sprintf("/users/%d", tid), ""), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("admin GET new/user: got %d, want 200", w.Code)
	}
	var prof auth.ProfileResponse
	_ = json.NewDecoder(w.Body).Decode(&prof)
	if prof.ID != tid || prof.Name != "Visible" {
		t.Errorf("profile = %+v", prof)
	}
}

func TestGetMember_AdminCannotSeeAdminSuperuser_404(t *testing.T) {
	a, r := newAdminMux(t)
	for _, role := range []string{types.RoleAdmin, types.RoleSuperuser} {
		tid := insertUser(t, a.db, "Hidden", "get-hidden-"+role+"@example.com", role)

		req := withViewer(newReq(http.MethodGet, fmt.Sprintf("/users/%d", tid), ""), 1, types.RoleAdmin)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("admin GET %s: got %d, want 404 (anti-enumeration)", role, w.Code)
		}
	}
}

func TestGetMember_SuperuserSeesAnyone(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Su Target", "su-target@example.com", types.RoleAdmin)

	req := withViewer(newReq(http.MethodGet, fmt.Sprintf("/users/%d", tid), ""), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("superuser GET admin: got %d, want 200", w.Code)
	}
}

func TestGetMember_NotFound(t *testing.T) {
	_, r := newAdminMux(t)
	req := withViewer(newReq(http.MethodGet, "/users/999999999", ""), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("missing id: got %d, want 404", w.Code)
	}
}

// ---- PUT /v1/admin/users/:id ----

func TestUpdateMember_AdminEditsNewUser(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Edit Me", "edit-me@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"name":"Edited","rank":"5th Kyu"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("admin PUT: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Name != "Edited" || u.Rank != "5th Kyu" {
		t.Errorf("update did not apply: name=%q rank=%q", u.Name, u.Rank)
	}
	if !auditExists(t, a.db, 1, fmt.Sprintf("admin_profile_update:target=%d", tid)) {
		t.Error("expected audit record for admin_profile_update")
	}
}

// TestUpdateMember_FacultyMajorRule: saving a UI-campus member without
// faculty/major maps ErrFacultyMajorRequired to a 400 with a clear error.
func TestUpdateMember_FacultyMajorRule(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "UI Member", "ui-put@example.com", types.RoleUser)
	if _, err := a.db.NewRaw(`UPDATE users SET dojo = ? WHERE id = ?`, types.UIDojo, tid).Exec(t.Context()); err != nil {
		t.Fatalf("set dojo: %v", err)
	}

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"name":"No Fields"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT without faculty/major: got %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "faculty and major are required") {
		t.Errorf("error text: got %s", w.Body.String())
	}

	// With both fields the same admin edit succeeds.
	ok := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid),
		`{"name":"Fixed","faculty":"Fakultas Teknik","major":"Teknik Elektro"}`), 1, types.RoleAdmin)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, ok)
	if w2.Code != http.StatusOK {
		t.Fatalf("PUT with faculty/major: got %d, want 200 (body=%s)", w2.Code, w2.Body.String())
	}
}

func TestUpdateMember_SuperuserEditsAdmin(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Admin Target", "su-edit@example.com", types.RoleAdmin)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"name":"SU-Edited"}`), 1, types.RoleSuperuser)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("superuser PUT admin: got %d, want 200", w.Code)
	}
}

func TestUpdateMember_AdminCannotEditAdminSuperuser_404(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "No Edit", "no-edit@example.com", types.RoleAdmin)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"name":"X"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("admin PUT admin: got %d, want 404", w.Code)
	}
}

func TestUpdateMember_RoleStructurallyAbsent(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "No Role", "no-role@example.com", types.RoleUser)

	// "role" is an unknown field; DecodeJSON disallows it -> 400. Either way,
	// the role cannot be set through this endpoint.
	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"role":"superuser"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("role in body: got %d, want 400", w.Code)
	}
	// Confirm the target's role is unchanged.
	u, _ := auth.GetUserByID(t.Context(), a.db, tid)
	if u.Role != types.RoleUser {
		t.Errorf("role mutated to %q; must be unchanged", u.Role)
	}
}

func TestUpdateMember_DuplicateEmail_409(t *testing.T) {
	a, r := newAdminMux(t)
	insertUser(t, a.db, "Owner", "dup-owner@example.com", types.RoleUser)
	tid := insertUser(t, a.db, "Target", "dup-target@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"email":"dup-owner@example.com"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate email: got %d, want 409", w.Code)
	}
}

func TestUpdateMember_InvalidRank_400(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Bad Rank", "bad-rank@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"rank":"Wizard"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid rank: got %d, want 400", w.Code)
	}
}

func TestUpdateMember_BadDate_400(t *testing.T) {
	a, r := newAdminMux(t)
	tid := insertUser(t, a.db, "Bad Date", "bad-date@example.com", types.RoleUser)

	req := withViewer(newReq(http.MethodPut, fmt.Sprintf("/users/%d", tid), `{"date_of_birth":"01/01/2000"}`), 1, types.RoleAdmin)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad date: got %d, want 400", w.Code)
	}
}
