package attendance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/uptrace/bun"
)

// seedInstructorRows isolates its rows with a unique dojo name; the table is
// shared with whatever else the test DB holds. dojo "" seeds shared rows, so
// those are cleaned up by name as well.
func seedInstructorRows(t *testing.T, db *bun.DB, dojo string, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := db.NewRaw("INSERT INTO instructors (dojo, name) VALUES (?, ?)", dojo, name).Exec(context.Background()); err != nil {
			t.Fatalf("seed instructor %q: %v", name, err)
		}
		t.Cleanup(func() {
			_, _ = db.NewRaw("DELETE FROM instructors WHERE dojo = ? AND name = ?", dojo, name).Exec(context.Background())
		})
	}
}

func TestListInstructors(t *testing.T) {
	db := setupTestDB(t)
	dojo := "Test Dojo " + t.Name()
	seedInstructorRows(t, db, dojo, "C Sensei", "A Sensei", "B Sensei")
	seedInstructorRows(t, db, "", "Shared Z "+t.Name(), "Shared A "+t.Name())

	roster, err := listInstructors(t.Context(), db)
	if err != nil {
		t.Fatalf("listInstructors: %v", err)
	}
	got := roster.Instructors[dojo]
	if len(got) != 3 || got[0] != "A Sensei" || got[1] != "B Sensei" || got[2] != "C Sensei" {
		t.Fatalf("instructors[%q] = %v, want names sorted", dojo, got)
	}
	if _, ok := roster.Instructors[""]; ok {
		t.Fatal("dojo '' must not appear in instructors; it belongs in all")
	}
	// The shared list is global, so only check that our rows are in it, in order.
	first, last := -1, -1
	for i, name := range roster.All {
		if name == "Shared A "+t.Name() {
			first = i
		}
		if name == "Shared Z "+t.Name() {
			last = i
		}
	}
	if first == -1 || last == -1 || first > last {
		t.Fatalf("all = %v, want %q before %q", roster.All, "Shared A "+t.Name(), "Shared Z "+t.Name())
	}
}

func TestHandleInstructors(t *testing.T) {
	db := setupTestDB(t)
	dojo := "Test Dojo " + t.Name()
	seedInstructorRows(t, db, dojo, "A Sensei")
	seedInstructorRows(t, db, "", "Shared Sensei "+t.Name())
	_, handler := newAttendanceMux(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, withViewer(newReq(http.MethodGet, "/v1/attendance/instructors", ""), 1, "user"))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body struct {
		All         []string            `json:"all"`
		Instructors map[string][]string `json:"instructors"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if names := body.Instructors[dojo]; len(names) != 1 || names[0] != "A Sensei" {
		t.Fatalf("instructors[%q] = %v, want [A Sensei]", dojo, names)
	}
	if !slices.Contains(body.All, "Shared Sensei "+t.Name()) {
		t.Fatalf("all = %v, want the shared instructor", body.All)
	}

	// A dojo with no rows is absent, not an empty array.
	delete(body.Instructors, dojo)
	for other, names := range body.Instructors {
		if len(names) == 0 {
			t.Fatalf("instructors[%q] is empty; dojos without rows must be omitted", other)
		}
	}
}

func TestHandleInstructors_DatabaseDown_500(t *testing.T) {
	s, handler := newAttendanceMux(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, withViewer(newReq(http.MethodGet, "/v1/attendance/instructors", ""), 1, "user"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
