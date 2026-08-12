package admin

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"
	"github.com/sapiderman/tenkei-register/internal/auth"
	"github.com/sapiderman/tenkei-register/internal/server"
	"github.com/sapiderman/tenkei-register/internal/types"
)

// handleListUsers handles GET /v1/admin/users.
//
// Query params: page (1-based), size (capped 1..100, default 25), q (name/email
// substring, case-insensitive), pending=true (only role='new'). Results are
// viewer-scoped: admins see new/user only, superusers see all.
func (a *administrator) handleListUsers(w http.ResponseWriter, r *http.Request) {
	viewerLevel := types.RoleLevel(auth.RoleFromContext(r.Context()))

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("size"))
	search := r.URL.Query().Get("q")
	pendingOnly := r.URL.Query().Get("pending") == "true"

	members, total, err := a.dbListUsers(r.Context(), viewerLevel, search, pendingOnly, page, size)
	if err != nil {
		log.Error().Err(err).Msg("admin list users failed")
		server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	// Re-clamp page/size for the response so the client sees the effective values.
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = defaultPageSize
	}
	if size > maxPageSize {
		size = maxPageSize
	}

	server.WriteJSON(w, http.StatusOK, ListUsersResponse{
		Members: members,
		Total:   total,
		Page:    page,
		Size:    size,
	})
}

// parseIDParam extracts and validates the {id} URL param. On a malformed id
// it writes a 400 response and returns ok=false.
func parseIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

// handleGetMember handles GET /v1/admin/users/:id — the member's full profile.
// Out-of-scope targets (an admin requesting an admin/superuser) return 404 so
// existence is not leaked.
func (a *administrator) handleGetMember(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	viewerLevel := types.RoleLevel(auth.RoleFromContext(r.Context()))

	user, err := getMemberForViewer(r.Context(), a.db, viewerLevel, targetID)
	if err != nil {
		server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	server.WriteJSON(w, http.StatusOK, auth.ProfileFromUser(user))
}

// handleUpdateMember handles PUT /v1/admin/users/:id. It uses the same field
// whitelist and validation as self-profile (auth.UpdateProfileRequest has role
// structurally absent), so an admin corrects a member exactly as a member
// edits themselves. The scope check and the write run as one atomic
// transaction (updateMemberForViewer): out-of-scope targets return 404 and a
// concurrent role change cannot let an admin edit a promoted target.
func (a *administrator) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	viewerLevel := types.RoleLevel(auth.RoleFromContext(r.Context()))

	var req auth.UpdateProfileRequest
	if err := server.DecodeAndValidate(w, r, &req, a.validate); err != nil {
		return // DecodeAndValidate writes the response
	}

	if err := updateMemberForViewer(r.Context(), a.db, viewerLevel, targetID, &req); err != nil {
		switch {
		case errors.Is(err, auth.ErrUpdateConflict):
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "An account with this email already exists."})
		case errors.Is(err, auth.ErrInvalidRank):
			server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rank"})
		case errors.Is(err, ErrMemberNotFound):
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		default:
			log.Error().Err(err).Int64("target_id", targetID).Msg("admin profile update failed")
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		}
		return
	}

	auth.Audit(r.Context(), a.db, a.logger, auth.UserIDFromContext(r.Context()), fmt.Sprintf("admin_profile_update:target=%d", targetID))
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleVerifyMember handles POST /v1/admin/users/:id/verify — transitions an
// in-scope member from new to user. A regular user gets 403 (middleware); an
// admin targeting an admin/superuser gets 404 (anti-enumeration); an
// in-scope target that is already user returns 409. No sessions are
// invalidated: verify is an upgrade within the soft-gated self-service tier.
func (a *administrator) handleVerifyMember(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseIDParam(w, r)
	if !ok {
		return
	}
	viewerLevel := types.RoleLevel(auth.RoleFromContext(r.Context()))

	if err := verifyMember(r.Context(), a.db, viewerLevel, targetID); err != nil {
		switch {
		case errors.Is(err, ErrMemberNotFound):
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		case errors.Is(err, ErrNotPending):
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "member is not pending"})
		default:
			log.Error().Err(err).Int64("target_id", targetID).Msg("admin verify failed")
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		}
		return
	}

	auth.Audit(r.Context(), a.db, a.logger, auth.UserIDFromContext(r.Context()), fmt.Sprintf("admin_verify:target=%d", targetID))
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRoleMember handles PUT /v1/admin/users/:id/role — superuser-only. It
// sets any valid role (including to/from 'new'). The last-superuser guard is
// enforced atomically inside setRole (409 if it would leave zero superusers).
// A demotion invalidates the target's sessions in the same transaction; a
// promotion or same-level change does not.
func (a *administrator) handleRoleMember(w http.ResponseWriter, r *http.Request) {
	targetID, ok := parseIDParam(w, r)
	if !ok {
		return
	}

	var req RoleRequest
	if err := server.DecodeJSON(w, r, &req); err != nil {
		return // DecodeJSON writes the response
	}
	if !types.AllowedRoles[req.Role] {
		server.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
		return
	}

	oldRole, _, err := setRole(r.Context(), a.db, targetID, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, ErrMemberNotFound):
			server.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		case errors.Is(err, ErrLastSuperuser):
			server.WriteJSON(w, http.StatusConflict, map[string]string{"error": "cannot demote the last superuser"})
		default:
			log.Error().Err(err).Int64("target_id", targetID).Msg("admin role change failed")
			server.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		}
		return
	}

	auth.Audit(r.Context(), a.db, a.logger, auth.UserIDFromContext(r.Context()), fmt.Sprintf("role_change:%s->%s:target=%d", oldRole, req.Role, targetID))
	server.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
