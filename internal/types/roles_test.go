package types

import "testing"

func TestAllowedRoles(t *testing.T) {
	for _, r := range []string{RoleNew, RoleUser, RoleAdmin, RoleSuperuser} {
		if !AllowedRoles[r] {
			t.Errorf("AllowedRoles[%q] = false, want true", r)
		}
	}
	for _, r := range []string{"", "root", "Admin", "USER", "super"} {
		if AllowedRoles[r] {
			t.Errorf("AllowedRoles[%q] = true, want false", r)
		}
	}
}

func TestRoleLevel(t *testing.T) {
	cases := []struct {
		role string
		want int
	}{
		{RoleNew, 0},
		{RoleUser, 1},
		{RoleAdmin, 2},
		{RoleSuperuser, 3},
		{"", -1},
		{"root", -1},
	}
	for _, tc := range cases {
		if got := RoleLevel(tc.role); got != tc.want {
			t.Errorf("RoleLevel(%q) = %d, want %d", tc.role, got, tc.want)
		}
	}
}

// TestRoleLevelMonotonic locks in the >= ordering the authorization
// middleware depends on: each role must outrank the one below it.
func TestRoleLevelMonotonic(t *testing.T) {
	if !(RoleLevel(RoleNew) < RoleLevel(RoleUser) &&
		RoleLevel(RoleUser) < RoleLevel(RoleAdmin) &&
		RoleLevel(RoleAdmin) < RoleLevel(RoleSuperuser)) {
		t.Fatal("role levels must be strictly increasing: new<user<admin<superuser")
	}
}
