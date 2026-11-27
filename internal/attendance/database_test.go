package attendance

import (
	"errors"
	"testing"
	"time"

	"github.com/sapiderman/tenkei-register/internal/types"
)

func TestInsertAttendance(t *testing.T) {
	db := setupTestDB(t)
	member, _ := seedMember(t, db, types.RoleUser)
	other, _ := seedMember(t, db, types.RoleUser)
	const dojo = "Tenkei Test Insert"
	log := func(user int64, d string, mods ...func(*LogRequest)) (*types.Attendance, error) {
		req := &LogRequest{Dojo: d, Instructor: "Sensei A"}
		for _, mod := range mods {
			mod(req)
		}
		return insertAttendance(t.Context(), db, user, req)
	}

	lat, lng, acc := -6.36, 106.83, int64(25)
	rec, err := log(member, dojo, func(r *LogRequest) { r.Latitude, r.Longitude, r.LocationAccuracyM = &lat, &lng, &acc })
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if rec.ID == 0 || rec.Status != types.AttendancePending || time.Since(rec.LoggedAt) > time.Minute {
		t.Fatalf("unexpected row: %+v", rec)
	}

	if rec2, err := log(member, dojo+" 2"); err != nil || rec2.Latitude != nil {
		t.Fatalf("insert without location: %+v %v", rec2, err)
	}

	// Duplicate: same member, same dojo, within 10 minutes.
	if _, err = log(member, dojo); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: err = %v, want ErrDuplicate", err)
	}
	// Another dojo, or another member, is fine.
	if _, err = log(member, dojo+" 3"); err != nil {
		t.Fatalf("other dojo: %v", err)
	}
	if _, err = log(other, dojo); err != nil {
		t.Fatalf("other member: %v", err)
	}
	// A rejected entry does not block a fresh one.
	if _, err := db.NewRaw(`UPDATE attendance SET status = 'rejected', confirmed_at = CURRENT_TIMESTAMP WHERE id = ?`, rec.ID).Exec(t.Context()); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, err = log(member, dojo); err != nil {
		t.Fatalf("after reject: %v", err)
	}
}

func TestListAttendance(t *testing.T) {
	db := setupTestDB(t)
	member, memberName := seedMember(t, db, types.RoleUser)
	admin, adminName := seedMember(t, db, types.RoleAdmin)
	const dojo = "Tenkei Test List DB"

	// Three rows with pinned times so order and the Jakarta-day filter are
	// exact. a shares c's dojo, so it is aged past the 10-minute duplicate
	// guard before c is inserted: 2026-01-01 17:00 UTC is 2026-01-02 00:00 in
	// Jakarta.
	pin := func(id int64, at time.Time) {
		t.Helper()
		if _, err := db.NewRaw(`UPDATE attendance SET logged_at = ? WHERE id = ?`, at, id).Exec(t.Context()); err != nil {
			t.Fatalf("pin logged_at: %v", err)
		}
	}
	a := seedRecord(t, db, member, dojo, "A")
	pin(a, time.Date(2026, 1, 1, 17, 0, 0, 0, time.UTC))
	b := seedRecord(t, db, member, dojo+" 2", "B")
	pin(b, time.Now().Add(-time.Hour))
	c := seedRecord(t, db, member, dojo, "C")
	if _, err := decideAttendance(t.Context(), db, c, admin, types.AttendanceConfirmed); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	list := func(f listFilter) ([]attendanceRow, int64) {
		t.Helper()
		rows, total, err := listAttendance(t.Context(), db, f)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		return rows, total
	}
	mine := listFilter{userID: member}

	rows, total := list(mine)
	if total != 3 || len(rows) != 3 || rows[0].ID != c || rows[1].ID != b || rows[2].ID != a {
		t.Fatalf("newest first: total %d rows %+v", total, rows)
	}
	if confirmed := rows[0]; confirmed.Status != types.AttendanceConfirmed || confirmed.ConfirmedByName == nil || *confirmed.ConfirmedByName != adminName || confirmed.ConfirmedAt == nil || confirmed.UserName != memberName {
		t.Fatalf("joined names: %+v", confirmed)
	}
	if rows[1].ConfirmedByName != nil || rows[1].ConfirmedAt != nil {
		t.Fatalf("pending row must have no decider: %+v", rows[1])
	}

	if _, total = list(listFilter{userID: member, status: types.AttendanceConfirmed}); total != 1 {
		t.Fatalf("status confirmed: total %d", total)
	}
	if _, total = list(listFilter{userID: member, status: types.AttendancePending}); total != 2 {
		t.Fatalf("status pending: total %d", total)
	}
	if _, total = list(listFilter{userID: member, dojo: dojo}); total != 2 {
		t.Fatalf("dojo: total %d", total)
	}
	// Admin-style: no user filter, hermetic by the unique member name.
	if _, total = list(listFilter{search: memberName}); total != 3 {
		t.Fatalf("search by name: total %d", total)
	}
	if _, total = list(listFilter{search: "no such member name"}); total != 0 {
		t.Fatalf("search miss: total %d", total)
	}

	// Jakarta days: a sits exactly on the Jan 1 → Jan 2 boundary.
	for _, tc := range []struct {
		from, to string
		want     int64
	}{
		{"2026-01-01", "2026-01-01", 0},
		{"2026-01-02", "2026-01-02", 1},
		{"2026-01-01", "2026-01-02", 1},
	} {
		if _, total = list(listFilter{userID: member, from: tc.from, to: tc.to}); total != tc.want {
			t.Fatalf("from/to %s..%s: total %d, want %d", tc.from, tc.to, total, tc.want)
		}
	}

	rows, total = list(listFilter{userID: member, size: 2, page: 2})
	if total != 3 || len(rows) != 1 || rows[0].ID != a {
		t.Fatalf("page 2 size 2: total %d rows %+v", total, rows)
	}
	if rows, _ = list(listFilter{userID: member, page: -5, size: 0}); len(rows) != 3 {
		t.Fatalf("page/size clamped to defaults: %+v", rows)
	}
	if gotPage, gotSize := clampPage(maxPage+5, maxPageSize+5); gotPage != maxPage || gotSize != maxPageSize {
		t.Fatalf("upper clamp: %d/%d, want %d/%d", gotPage, gotSize, maxPage, maxPageSize)
	}
}

func TestDecideAttendance(t *testing.T) {
	db := setupTestDB(t)
	admin, adminName := seedMember(t, db, types.RoleAdmin)
	member, _ := seedMember(t, db, types.RoleUser)
	id := seedRecord(t, db, member, "Tenkei Test Decide DB", "A")

	got, err := decideAttendance(t.Context(), db, id, admin, types.AttendanceConfirmed)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got.ID != id || got.UserID != member || got.Status != types.AttendanceConfirmed || got.ConfirmedByName == nil || *got.ConfirmedByName != adminName || got.ConfirmedAt == nil {
		t.Fatalf("unexpected row: %+v", got)
	}

	var stored types.Attendance
	if err := db.NewSelect().Model(&stored).Where("id = ?", id).Scan(t.Context()); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.Status != types.AttendanceConfirmed || stored.ConfirmedBy == nil || *stored.ConfirmedBy != admin || stored.ConfirmedAt == nil {
		t.Fatalf("not persisted: %+v", stored)
	}

	if _, err = decideAttendance(t.Context(), db, id, admin, types.AttendanceRejected); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second decision: err = %v, want ErrNotPending", err)
	}
	if _, err = decideAttendance(t.Context(), db, 999999999, admin, types.AttendanceConfirmed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: err = %v, want ErrNotFound", err)
	}
}
