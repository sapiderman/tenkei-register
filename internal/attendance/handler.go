package attendance

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
)

// handleInstructors handles GET /v1/attendance/instructors — the roster the
// log dialog offers. Dojos without rows are simply absent from the per-dojo
// map; the client offers All (dojo ”) + the dojo's own names, and treats an
// empty result as "no instructors listed yet".
func (s *attendanceService) handleInstructors(w http.ResponseWriter, r *http.Request) {
	roster, err := listInstructors(r.Context(), s.db)
	if err != nil {
		log.Error().Err(err).Msg("list instructors failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}
	server.WriteJSON(w, http.StatusOK, roster)
}

// handleLog handles POST /v1/attendance — a member records a practice.
//
// Body: dojo and instructor (trimmed, required, <=255) plus an optional
// location pair. 201 with the stored row; 409 when the same dojo was logged
// in the last 10 minutes.
func (s *attendanceService) handleLog(w http.ResponseWriter, r *http.Request) {
	var req LogRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		return // DecodeJSON writes the error response
	}
	req.Dojo = strings.TrimSpace(req.Dojo)
	req.Instructor = strings.TrimSpace(req.Instructor)
	if err := s.validate.Struct(req); err != nil {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "dojo and instructor are required"})
		return
	}
	if err := validateLocation(&req); err != nil {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rec, err := insertAttendance(r.Context(), s.db, auth.UserIDFromContext(r.Context()), &req)
	switch {
	case errors.Is(err, ErrDuplicate):
		server.WriteJSON(w, http.StatusConflict, map[string]string{"error": ErrDuplicate.Error()})
		return
	case err != nil:
		log.Error().Err(err).Msg("attendance log failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	server.WriteJSON(w, http.StatusCreated, LogResponse{
		ID:          rec.ID,
		LoggedAt:    rec.LoggedAt,
		Dojo:        rec.Dojo,
		Instructor:  rec.Instructor,
		Status:      rec.Status,
		HasLocation: rec.Latitude != nil,
	})
}

// validateLocation enforces the coordinate pair and their ranges (the
// database CHECKs repeat them).
func validateLocation(req *LogRequest) error {
	if (req.Latitude == nil) != (req.Longitude == nil) {
		return errors.New("latitude and longitude must be provided together")
	}
	if req.Latitude != nil && (*req.Latitude < -90 || *req.Latitude > 90 || *req.Longitude < -180 || *req.Longitude > 180) {
		return errors.New("latitude or longitude is out of range")
	}
	if req.LocationAccuracyM != nil && *req.LocationAccuracyM < 0 {
		return errors.New("location_accuracy_m must not be negative")
	}
	return nil
}

// handleMine handles GET /v1/attendance/me — the member's own history,
// newest first. Never returns coordinates.
func (s *attendanceService) handleMine(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))

	rows, total, err := listAttendance(r.Context(), s.db, listFilter{
		userID: auth.UserIDFromContext(r.Context()),
		page:   page,
		size:   size,
	})
	if err != nil {
		log.Error().Err(err).Msg("attendance history failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	page, size = clampPage(page, size)
	items := make([]Record, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.record())
	}
	server.WriteJSON(w, http.StatusOK, MyListResponse{Items: items, Total: total, Page: page, Size: size})
}

// handleList handles GET /v1/admin/attendance.
//
// Query params: dojo (exact), q (member name substring), status (pending,
// confirmed or rejected; absent = all), from/to (YYYY-MM-DD, inclusive,
// Asia/Jakarta days), page/size as for the member list. Not viewer-scoped:
// every admin sees every record.
func (s *attendanceService) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("size"))
	f := listFilter{
		dojo:   strings.TrimSpace(q.Get("dojo")),
		search: strings.TrimSpace(q.Get("q")),
		status: q.Get("status"),
		from:   q.Get("from"),
		to:     q.Get("to"),
		page:   page,
		size:   size,
	}
	if err := f.validate(); err != nil {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	rows, total, err := listAttendance(r.Context(), s.db, f)
	if err != nil {
		log.Error().Err(err).Msg("admin list attendance failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	page, size = clampPage(page, size)
	items := make([]AdminRecord, 0, len(rows))
	for _, row := range rows {
		items = append(items, row.adminRecord())
	}
	server.WriteJSON(w, http.StatusOK, AdminListResponse{Items: items, Total: total, Page: page, Size: size})
}

// handleConfirm handles PUT /v1/admin/attendance/:id/confirm.
func (s *attendanceService) handleConfirm(w http.ResponseWriter, r *http.Request) {
	s.handleDecide(w, r, types.AttendanceConfirmed)
}

// handleReject handles PUT /v1/admin/attendance/:id/reject.
func (s *attendanceService) handleReject(w http.ResponseWriter, r *http.Request) {
	s.handleDecide(w, r, types.AttendanceRejected)
}

// handleDecide is the shared confirm/reject handler: 200 with the updated
// row, 404 for an unknown id, 409 when the record already has a decision.
// The decision is audited as attendance_<status>:id=N.
func (s *attendanceService) handleDecide(w http.ResponseWriter, r *http.Request, status string) {
	id, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	adminID := auth.UserIDFromContext(r.Context())
	rec, err := decideAttendance(r.Context(), s.db, id, adminID, status)
	switch {
	case errors.Is(err, ErrNotFound):
		server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": ErrNotFound.Error()})
		return
	case errors.Is(err, ErrNotPending):
		server.WriteJSON(w, http.StatusConflict, map[string]string{"error": ErrNotPending.Error()})
		return
	case err != nil:
		log.Error().Err(err).Int64("attendance_id", id).Msg("attendance decide failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	auth.Audit(r.Context(), s.db, s.logger, adminID, fmt.Sprintf("attendance_%s:id=%d", status, id))
	server.WriteJSON(w, http.StatusOK, rec)
}

// parseIDParam extracts and validates the {id} URL param. On a malformed id
// it writes a 400 response and returns ok=false.
func parseIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id < 1 {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return id, true
}
