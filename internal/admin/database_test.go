package admin

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/sapiderman/tenkei-register/internal/types"
)

// allRoles lists the four roles, used to seed a mixed roster for scoping tests.
var allRoles = []string{types.RoleNew, types.RoleUser, types.RoleAdmin, types.RoleSuperuser}

func newTestAdministrator(t *testing.T) *administrator {
	t.Helper()
	return &administrator{logger: zerolog.Nop(), db: setupTestDB(t)}
}

func TestDBListUsers_AdminSeesOnlyNewUser(t *testing.T) {
	a := newTestAdministrator(t)

	for _, r := range allRoles {
		insertUser(t, a.db, "admscope-"+r, "admscope-"+r+"@example.com", r)
	}

	// q isolates this test's rows from any other data in the shared DB.
	members, total, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleAdmin), "admscope", false, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers: %v", err)
	}

	// admin level: 2 new/user rows out of the 4-role roster.
	if total != 2 {
		t.Errorf("admin total = %d, want 2", total)
	}
	for _, m := range members {
		if m.Role != types.RoleNew && m.Role != types.RoleUser {
			t.Errorf("admin saw out-of-scope role %q", m.Role)
		}
	}
}

func TestDBListUsers_SuperuserSeesAll(t *testing.T) {
	a := newTestAdministrator(t)

	for _, r := range allRoles {
		insertUser(t, a.db, "suskope-"+r, "suskope-"+r+"@example.com", r)
	}

	members, total, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "suskope", false, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers: %v", err)
	}

	if total != 4 {
		t.Errorf("superuser total = %d, want 4", total)
	}
	seen := map[string]bool{}
	for _, m := range members {
		seen[m.Role] = true
	}
	for _, r := range allRoles {
		if !seen[r] {
			t.Errorf("superuser did not see role %q", r)
		}
	}
}

func TestDBListUsers_PendingFilter(t *testing.T) {
	a := newTestAdministrator(t)

	insertUser(t, a.db, "pendscope-new", "pendscope-a@example.com", types.RoleNew)
	insertUser(t, a.db, "pendscope-user", "pendscope-b@example.com", types.RoleUser)

	// superuser scope + q isolate to this test's two rows; pending keeps only new.
	_, total, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "pendscope", true, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers: %v", err)
	}
	if total != 1 {
		t.Errorf("pending total = %d, want 1 (only 'new')", total)
	}
}

func TestDBListUsers_SearchByNameAndEmail(t *testing.T) {
	a := newTestAdministrator(t)

	insertUser(t, a.db, "Alice UniqueSearchName", "alice-s@example.com", types.RoleUser)
	insertUser(t, a.db, "Bob", "bob-UniqueSearchEmail@example.com", types.RoleUser)
	insertUser(t, a.db, "Carol", "carol-s@example.com", types.RoleUser)

	// Match by name fragment.
	_, totalName, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "UniqueSearchName", false, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers name search: %v", err)
	}
	if totalName != 1 {
		t.Errorf("name search total = %d, want 1", totalName)
	}

	// Match by email fragment (case-insensitive).
	_, totalEmail, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "uniquesearchemail", false, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers email search: %v", err)
	}
	if totalEmail != 1 {
		t.Errorf("email search total = %d, want 1", totalEmail)
	}
}

func TestDBListUsers_PaginationClamps(t *testing.T) {
	a := newTestAdministrator(t)

	for i := 0; i < 5; i++ {
		insertUser(t, a.db, "page-user", pageEmail(i), types.RoleUser)
	}

	// Default size when size<=0.
	members, _, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "", false, 1, 0)
	if err != nil {
		t.Fatalf("dbListUsers default size: %v", err)
	}
	if len(members) > defaultPageSize {
		t.Errorf("default size returned %d rows, want <= %d", len(members), defaultPageSize)
	}

	// Cap above maxPageSize.
	members, _, err = a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "", false, 1, 9999)
	if err != nil {
		t.Fatalf("dbListUsers cap size: %v", err)
	}
	if len(members) > maxPageSize {
		t.Errorf("capped size returned %d rows, want <= %d", len(members), maxPageSize)
	}

	// Page 2 of size 2 returns offset rows. (At least 5 rows exist for this
	// search-uniqued prefix, so page 2 size 2 must return exactly 2.)
	members, _, err = a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "page-user", false, 2, 2)
	if err != nil {
		t.Fatalf("dbListUsers page 2: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("page 2 size 2 returned %d rows, want 2", len(members))
	}
}

func TestDBListUsers_SummaryFieldsOnly(t *testing.T) {
	a := newTestAdministrator(t)

	// A user with PII-bearing fields set; the summary must not surface them.
	id := insertUser(t, a.db, "Summary Fields", "summary-fields@example.com", types.RoleUser)
	_, _ = a.db.NewRaw(
		`UPDATE users SET medical_conditions='secret', emergency_contact_name='secret', date_of_birth='1990-01-01' WHERE id = ?`,
		id,
	).Exec(t.Context())

	members, _, err := a.dbListUsers(t.Context(), types.RoleLevel(types.RoleSuperuser), "summary-fields@example.com", false, 1, 100)
	if err != nil {
		t.Fatalf("dbListUsers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
	m := members[0]
	if m.Name != "Summary Fields" {
		t.Errorf("Name = %q", m.Name)
	}
	if m.Role != types.RoleUser {
		t.Errorf("Role = %q", m.Role)
	}
	// MemberSummary has no PII fields at the type level; this is a structural
	// guarantee. If a PII field is ever added to MemberSummary, add an explicit
	// assertion here.
}

// pageEmail produces a unique email per index for pagination tests.
func pageEmail(i int) string {
	return string(rune('a'+i)) + "-page@example.com"
}
