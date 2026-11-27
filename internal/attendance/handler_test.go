package attendance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// newAttendanceMux mounts the handlers directly, without the session
// middleware; tests set the viewer with withViewer.
func newAttendanceMux(t *testing.T) (*attendanceService, http.Handler) {
	t.Helper()
	s := &attendanceService{logger: zerolog.Nop(), db: setupTestDB(t), validate: validator.New()}

	r := chi.NewRouter()
	r.Post("/v1/attendance", s.handleLog)
	r.Get("/v1/attendance/me", s.handleMine)
	r.Get("/v1/attendance/instructors", s.handleInstructors)
	r.Get("/v1/admin/attendance", s.handleList)
	r.Put("/v1/admin/attendance/{id}/confirm", s.handleConfirm)
	r.Put("/v1/admin/attendance/{id}/reject", s.handleReject)
	return s, r
}

// withViewer returns the request with a resolved session user/role in its context.
func withViewer(r *http.Request, userID int64, role string) *http.Request {
	return r.WithContext(auth.WithAuth(r.Context(), userID, role))
}

// newReq builds a JSON request with body ("" for none).
func newReq(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// auditExists reports whether an audit row (userID, action) is present.
func auditExists(t *testing.T, db *bun.DB, userID int64, action string) bool {
	t.Helper()
	var n int
	if err := db.NewRaw(`SELECT COUNT(*) FROM audit WHERE user_id = ? AND action = ?`, userID, action).Scan(t.Context(), &n); err != nil {
		t.Fatalf("auditExists: %v", err)
	}
	return n > 0
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", w.Body, err)
	}
	return v
}

func TestHandleLog(t *testing.T) {
	s, mux := newAttendanceMux(t)
	member, _ := seedMember(t, s.db, types.RoleUser)
	const dojo = "Tenkei Test Log"

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantLoc    bool // has_location in the 201
	}{
		{"with location", fmt.Sprintf(`{"dojo":%q,"instructor":"Sensei A","latitude":-6.36,"longitude":106.83,"location_accuracy_m":25}`, dojo+" 1"), http.StatusCreated, true},
		{"without location", fmt.Sprintf(`{"dojo":%q,"instructor":"Senpai B"}`, dojo+" 2"), http.StatusCreated, false},
		{"fields are trimmed", fmt.Sprintf(`{"dojo":"  %s 3  ","instructor":"  Senpai C "}`, dojo), http.StatusCreated, false},
		{"missing dojo", `{"instructor":"Sensei A"}`, http.StatusBadRequest, false},
		{"blank instructor", `{"dojo":"x","instructor":"   "}`, http.StatusBadRequest, false},
		{"latitude without longitude", fmt.Sprintf(`{"dojo":%q,"instructor":"A","latitude":1}`, dojo+" 4"), http.StatusBadRequest, false},
		{"longitude out of range", fmt.Sprintf(`{"dojo":%q,"instructor":"A","latitude":1,"longitude":200}`, dojo+" 5"), http.StatusBadRequest, false},
		{"negative accuracy", fmt.Sprintf(`{"dojo":%q,"instructor":"A","latitude":1,"longitude":2,"location_accuracy_m":-1}`, dojo+" 6"), http.StatusBadRequest, false},
		{"unknown field", fmt.Sprintf(`{"dojo":%q,"instructor":"A","role":"admin"}`, dojo+" 7"), http.StatusBadRequest, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, withViewer(newReq(http.MethodPost, "/v1/attendance", tc.body), member, types.RoleUser))
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body)
			}
			if tc.wantStatus != http.StatusCreated {
				return
			}
			got := decode[LogResponse](t, w)
			if got.ID == 0 || got.Status != types.AttendancePending || got.Dojo == "" || got.Instructor == "" || got.LoggedAt.IsZero() {
				t.Fatalf("unexpected 201 body: %+v", got)
			}
			if got.HasLocation != tc.wantLoc {
				t.Fatalf("has_location = %v, want %v", got.HasLocation, tc.wantLoc)
			}
		})
	}

	// Same member + dojo inside 10 minutes is refused.
	body := fmt.Sprintf(`{"dojo":%q,"instructor":"A"}`, dojo+" dup")
	for i, want := range []int{http.StatusCreated, http.StatusConflict} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, withViewer(newReq(http.MethodPost, "/v1/attendance", body), member, types.RoleUser))
		if w.Code != want {
			t.Fatalf("request %d: status = %d, want %d; body: %s", i+1, w.Code, want, w.Body)
		}
	}
}

func TestHandleMine(t *testing.T) {
	s, mux := newAttendanceMux(t)
	member, _ := seedMember(t, s.db, types.RoleUser)
	other, _ := seedMember(t, s.db, types.RoleUser)
	admin, _ := seedMember(t, s.db, types.RoleAdmin)
	const dojo = "Tenkei Test Mine"

	first := seedRecord(t, s.db, member, dojo, "Sensei A")
	seedRecord(t, s.db, member, dojo+" 2", "Sensei B")
	seedRecord(t, s.db, other, dojo, "Sensei C") // invisible to member
	if _, err := decideAttendance(t.Context(), s.db, first, admin, types.AttendanceConfirmed); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	get := func(query string) MyListResponse {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, withViewer(newReq(http.MethodGet, "/v1/attendance/me"+query, ""), member, types.RoleUser))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body: %s", w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "latitude") {
			t.Fatalf("member history must not carry coordinates: %s", w.Body)
		}
		return decode[MyListResponse](t, w)
	}

	got := get("")
	if got.Total != 2 || len(got.Items) != 2 || got.Page != 1 || got.Size != defaultPageSize {
		t.Fatalf("unexpected page: %+v", got)
	}
	// Newest first, so the confirmed row (inserted first) is last.
	last := got.Items[len(got.Items)-1]
	if last.ID != first || last.Status != types.AttendanceConfirmed || last.ConfirmedByName == nil || last.ConfirmedAt == nil {
		t.Fatalf("confirmed row not mapped: %+v", last)
	}

	got = get("?size=1&page=2")
	if got.Total != 2 || len(got.Items) != 1 || got.Page != 2 || got.Size != 1 || got.Items[0].ID != first {
		t.Fatalf("unexpected second page: %+v", got)
	}
}

func TestHandleList(t *testing.T) {
	s, mux := newAttendanceMux(t)
	admin, _ := seedMember(t, s.db, types.RoleAdmin)
	member, memberName := seedMember(t, s.db, types.RoleUser)
	const dojo = "Tenkei Test List"

	seedRecord(t, s.db, member, dojo, "Sensei A")
	seedRecord(t, s.db, member, dojo+" 2", "Sensei B")
	lat, lng, acc := -6.36, 106.83, int64(25)
	if _, err := insertAttendance(t.Context(), s.db, member, &LogRequest{Dojo: dojo + " 3", Instructor: "Sensei C", Latitude: &lat, Longitude: &lng, LocationAccuracyM: &acc}); err != nil {
		t.Fatalf("insert with location: %v", err)
	}

	get := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, withViewer(newReq(http.MethodGet, "/v1/admin/attendance?"+query, ""), admin, types.RoleAdmin))
		return w
	}
	byMember := "q=" + url.QueryEscape(memberName)

	tests := []struct {
		name      string
		query     string
		wantTotal int64
		wantLen   int
		wantLat   bool
	}{
		{"by member", byMember, 3, 3, true},
		{"status pending", byMember + "&status=pending", 3, 3, true},
		{"status confirmed", byMember + "&status=confirmed", 0, 0, false},
		{"dojo", byMember + "&dojo=" + url.QueryEscape(dojo), 1, 1, false},
		{"size", byMember + "&size=1", 3, 1, true},
		{"date range matches", byMember + "&from=2000-01-01&to=2100-12-31", 3, 3, true},
		{"date range empty", byMember + "&from=2000-01-01&to=2000-12-31", 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := get(tc.query)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body)
			}
			got := decode[AdminListResponse](t, w)
			if got.Total != tc.wantTotal || len(got.Items) != tc.wantLen {
				t.Fatalf("total/items = %d/%d, want %d/%d", got.Total, len(got.Items), tc.wantTotal, tc.wantLen)
			}
			if got.Items == nil {
				t.Fatalf("items must be an empty list, not null: %s", w.Body)
			}
			// Newest first, so a located row (seeded last) is on top when present.
			if len(got.Items) > 0 {
				if has := got.Items[0].Latitude != nil && got.Items[0].Longitude != nil && got.Items[0].LocationAccuracyM != nil && got.Items[0].HasLocation; has != tc.wantLat {
					t.Fatalf("newest row located = %v, want %v; row: %+v", has, tc.wantLat, got.Items[0])
				}
			}
		})
	}

	for _, tc := range []struct{ name, query, want string }{
		{"bad status", byMember + "&status=bogus", "status must be pending, confirmed or rejected"},
		{"bad date", byMember + "&from=yesterday", "from and to must be YYYY-MM-DD dates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := get(tc.query)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status = %d, body: %s", w.Code, w.Body)
			}
		})
	}
}

func TestHandleDecide(t *testing.T) {
	s, mux := newAttendanceMux(t)
	admin, _ := seedMember(t, s.db, types.RoleAdmin)
	member, _ := seedMember(t, s.db, types.RoleUser)
	const dojo = "Tenkei Test Decide"

	decide := func(idOrPath, action string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, withViewer(newReq(http.MethodPut, "/v1/admin/attendance/"+idOrPath+"/"+action, ""), admin, types.RoleAdmin))
		return w
	}

	id := seedRecord(t, s.db, member, dojo, "Sensei A")
	w := decide(fmt.Sprint(id), "confirm")
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: status = %d; body: %s", w.Code, w.Body)
	}
	got := decode[AdminRecord](t, w)
	if got.ID != id || got.UserID != member || got.UserName == "" || got.Status != types.AttendanceConfirmed ||
		got.ConfirmedByName == nil || got.ConfirmedAt == nil || got.HasLocation {
		t.Fatalf("unexpected confirmed row: %+v", got)
	}
	if !auditExists(t, s.db, admin, fmt.Sprintf("attendance_confirmed:id=%d", id)) {
		t.Fatal("confirm was not audited")
	}

	if w := decide(fmt.Sprint(id), "reject"); w.Code != http.StatusConflict {
		t.Fatalf("second decision: status = %d, want 409; body: %s", w.Code, w.Body)
	}
	if w := decide("999999999", "confirm"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: status = %d, want 404; body: %s", w.Code, w.Body)
	}
	if w := decide("abc", "confirm"); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed id: status = %d, want 400; body: %s", w.Code, w.Body)
	}

	id2 := seedRecord(t, s.db, member, dojo+" 2", "Sensei B")
	w = decide(fmt.Sprint(id2), "reject")
	if w.Code != http.StatusOK {
		t.Fatalf("reject: status = %d; body: %s", w.Code, w.Body)
	}
	if got := decode[AdminRecord](t, w); got.Status != types.AttendanceRejected {
		t.Fatalf("unexpected rejected row: %+v", got)
	}
	if !auditExists(t, s.db, admin, fmt.Sprintf("attendance_rejected:id=%d", id2)) {
		t.Fatal("reject was not audited")
	}
}

// TestHandlers_DatabaseDown_500 covers the infrastructure-failure branch of
// every handler: a closed connection must surface as a plain 500.
func TestHandlers_DatabaseDown_500(t *testing.T) {
	s, mux := newAttendanceMux(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	for _, rt := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/attendance", `{"dojo":"d","instructor":"i"}`},
		{http.MethodGet, "/v1/attendance/me", ""},
		{http.MethodGet, "/v1/admin/attendance", ""},
		{http.MethodPut, "/v1/admin/attendance/1/confirm", ""},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, withViewer(newReq(rt.method, rt.path, rt.body), 1, types.RoleAdmin))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s %s: got %d, want 500; body: %s", rt.method, rt.path, w.Code, w.Body)
		}
	}
}
