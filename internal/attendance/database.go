package attendance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/sapiderman/tenkei-register/internal/types"
	"github.com/uptrace/bun"
)

// Pagination bounds, same as the member list in internal/admin.
const (
	defaultPageSize = 25
	maxPageSize     = 100
	maxPage         = 1000000

	// dayZone is the day boundary for the admin list's from/to filters: the
	// dojo's local day, not UTC.
	dayZone = "Asia/Jakarta"
)

// clampPage applies the pagination bounds.
func clampPage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	} else if page > maxPage {
		page = maxPage
	}
	if size < 1 {
		size = defaultPageSize
	} else if size > maxPageSize {
		size = maxPageSize
	}
	return page, size
}

// insertAttendance writes the member's entry and returns the stored row. The
// duplicate guard (same member, same dojo, not rejected, last 10 minutes)
// runs inside the INSERT, so the happy path is one round-trip; zero rows
// inserted is ErrDuplicate. Two identical requests racing in the same
// instant can both pass NOT EXISTS under READ COMMITTED — the per-user rate
// limit and the UI's disabled button cover that window.
// listInstructors reads the instructors table. A row with dojo ” teaches at
// every dojo and lands in All; dojos without rows are absent from Instructors.
func listInstructors(ctx context.Context, db *bun.DB) (InstructorRoster, error) {
	var rows []struct {
		Dojo string `bun:"dojo"`
		Name string `bun:"name"`
	}
	if err := db.NewRaw("SELECT dojo, name FROM instructors ORDER BY dojo, name").Scan(ctx, &rows); err != nil {
		return InstructorRoster{}, err
	}
	roster := InstructorRoster{All: []string{}, Instructors: make(map[string][]string, len(rows))}
	for _, row := range rows {
		if row.Dojo == "" {
			roster.All = append(roster.All, row.Name)
			continue
		}
		roster.Instructors[row.Dojo] = append(roster.Instructors[row.Dojo], row.Name)
	}
	return roster, nil
}

func insertAttendance(ctx context.Context, db *bun.DB, userID int64, req *LogRequest) (*types.Attendance, error) {
	rec := &types.Attendance{
		UserID:            userID,
		Dojo:              req.Dojo,
		Instructor:        req.Instructor,
		Latitude:          req.Latitude,
		Longitude:         req.Longitude,
		LocationAccuracyM: req.LocationAccuracyM,
	}
	err := db.NewRaw(`
		INSERT INTO attendance (user_id, dojo, instructor, latitude, longitude, location_accuracy_m)
		SELECT ?, ?, ?, ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM attendance
			WHERE user_id = ? AND dojo = ? AND status <> 'rejected'
			  AND logged_at > CURRENT_TIMESTAMP - INTERVAL '10 minutes'
		)
		RETURNING id, logged_at, status`,
		userID, req.Dojo, req.Instructor, req.Latitude, req.Longitude, req.LocationAccuracyM,
		userID, req.Dojo,
	).Scan(ctx, rec)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDuplicate
	}
	if err != nil {
		return nil, fmt.Errorf("insert attendance: %w", err)
	}
	return rec, nil
}

// listFilter narrows listAttendance. Every field is optional; the member's
// own history sets userID to the session user.
type listFilter struct {
	userID int64
	dojo   string
	search string // member name, case-insensitive substring
	status string // pending, confirmed or rejected
	from   string // YYYY-MM-DD, inclusive, Asia/Jakarta days
	to     string
	page   int
	size   int
}

// validate rejects a status the database does not know and malformed dates;
// the SQL casts the dates for real, this only checks the shape.
func (f listFilter) validate() error {
	switch f.status {
	case "", types.AttendancePending, types.AttendanceConfirmed, types.AttendanceRejected:
	default:
		return errors.New("status must be pending, confirmed or rejected")
	}
	for _, d := range []string{f.from, f.to} {
		if d == "" {
			continue
		}
		if _, err := time.Parse("2006-01-02", d); err != nil {
			return errors.New("from and to must be YYYY-MM-DD dates")
		}
	}
	return nil
}

// attendanceRow is the joined read model: one attendance row plus the names
// of the member and of the admin who decided it (NULL while pending).
type attendanceRow struct {
	ID                int64      `bun:"id"`
	UserID            int64      `bun:"user_id"`
	UserName          string     `bun:"user_name"`
	Dojo              string     `bun:"dojo"`
	Instructor        string     `bun:"instructor"`
	Latitude          *float64   `bun:"latitude"`
	Longitude         *float64   `bun:"longitude"`
	LocationAccuracyM *int64     `bun:"location_accuracy_m"`
	LoggedAt          time.Time  `bun:"logged_at"`
	Status            string     `bun:"status"`
	ConfirmedByName   *string    `bun:"confirmed_by_name"`
	ConfirmedAt       *time.Time `bun:"confirmed_at"`
}

func (row attendanceRow) record() Record {
	return Record{
		ID:                row.ID,
		UserID:            row.UserID,
		UserName:          row.UserName,
		LoggedAt:          row.LoggedAt,
		Dojo:              row.Dojo,
		Instructor:        row.Instructor,
		HasLocation:       row.Latitude != nil,
		LocationAccuracyM: row.LocationAccuracyM,
		Status:            row.Status,
		ConfirmedByName:   row.ConfirmedByName,
		ConfirmedAt:       row.ConfirmedAt,
	}
}

func (row attendanceRow) adminRecord() AdminRecord {
	return AdminRecord{Record: row.record(), Latitude: row.Latitude, Longitude: row.Longitude}
}

// attendanceColumns is the page query's SELECT list: a = attendance,
// u = the member, c = the deciding admin.
const attendanceColumns = `a.id, a.user_id, u.name AS user_name, a.dojo, a.instructor,
	a.latitude, a.longitude, a.location_accuracy_m, a.logged_at, a.status,
	c.name AS confirmed_by_name, a.confirmed_at`

// listAttendance returns one page, newest first, and the total match count,
// in two queries (count + page) so the total matches the page.
func listAttendance(ctx context.Context, db *bun.DB, f listFilter) ([]attendanceRow, int64, error) {
	page, size := clampPage(f.page, f.size)

	applyConds := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.ModelTableExpr("attendance AS a").
			Join("LEFT JOIN users AS u ON u.id = a.user_id")
		if f.userID > 0 {
			q = q.Where("a.user_id = ?", f.userID)
		}
		if f.dojo != "" {
			q = q.Where("a.dojo = ?", f.dojo)
		}
		if f.search != "" {
			q = q.Where("u.name ILIKE ?", "%"+f.search+"%")
		}
		if f.status != "" {
			q = q.Where("a.status = ?", f.status)
		}
		if f.from != "" {
			q = q.Where("a.logged_at >= CAST(CAST(? AS DATE) AS TIMESTAMP) AT TIME ZONE ?", f.from, dayZone)
		}
		if f.to != "" {
			q = q.Where("a.logged_at < CAST(CAST(? AS DATE) + 1 AS TIMESTAMP) AT TIME ZONE ?", f.to, dayZone)
		}
		return q
	}

	total, err := applyConds(db.NewSelect().Model((*types.Attendance)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count attendance: %w", err)
	}

	var rows []attendanceRow
	err = applyConds(db.NewSelect().Model((*types.Attendance)(nil))).
		ColumnExpr(attendanceColumns).
		Join("LEFT JOIN users AS c ON c.id = a.confirmed_by").
		OrderExpr("a.logged_at DESC, a.id DESC").
		Limit(size).
		Offset((page-1)*size).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("list attendance: %w", err)
	}
	return rows, int64(total), nil
}

// decideAttendance applies the admin's decision to a pending record and
// returns the row as the admin list would show it. ErrNotPending when the
// record already carries a decision, ErrNotFound when it does not exist.
func decideAttendance(ctx context.Context, db *bun.DB, id, adminID int64, status string) (AdminRecord, error) {
	var row attendanceRow
	err := db.NewRaw(`
		WITH upd AS (
			UPDATE attendance
			SET status = ?, confirmed_by = ?, confirmed_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'pending'
			RETURNING id, user_id, dojo, instructor, latitude, longitude, location_accuracy_m,
			          logged_at, status, confirmed_by, confirmed_at
		)
		SELECT upd.id, upd.user_id, u.name AS user_name, upd.dojo, upd.instructor,
		       upd.latitude, upd.longitude, upd.location_accuracy_m, upd.logged_at, upd.status,
		       c.name AS confirmed_by_name, upd.confirmed_at
		FROM upd
		LEFT JOIN users AS u ON u.id = upd.user_id
		LEFT JOIN users AS c ON c.id = upd.confirmed_by`,
		status, adminID, id,
	).Scan(ctx, &row)
	if errors.Is(err, sql.ErrNoRows) {
		// Not updated: unknown id or already decided. One cheap read tells them apart.
		var current string
		if err := db.NewRaw(`SELECT status FROM attendance WHERE id = ?`, id).Scan(ctx, &current); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return AdminRecord{}, ErrNotFound
			}
			return AdminRecord{}, fmt.Errorf("read attendance %d: %w", id, err)
		}
		return AdminRecord{}, ErrNotPending
	}
	if err != nil {
		return AdminRecord{}, fmt.Errorf("decide attendance %d: %w", id, err)
	}
	return row.adminRecord(), nil
}
