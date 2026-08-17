package types

// User roles. Authorization uses numeric levels with >= semantics: a higher
// level grants every capability of the levels below it.
//
//	new        0  pending (just registered, not yet verified by an admin)
//	user       1  verified member
//	admin      2  member administration (list/view/edit/verify members)
//	superuser  3  full administration incl. role management
const (
	RoleNew       = "new"
	RoleUser      = "user"
	RoleAdmin     = "admin"
	RoleSuperuser = "superuser"
)

// AllowedRoles is the single source of truth for valid role values, parallel
// to AllowedRanks. Used by validation, the migration CHECK, and role-setting.
var AllowedRoles = map[string]bool{
	RoleNew:       true,
	RoleUser:      true,
	RoleAdmin:     true,
	RoleSuperuser: true,
}

// RoleLevels maps each role to its authorization level.
var RoleLevels = map[string]int{
	RoleNew:       0,
	RoleUser:      1,
	RoleAdmin:     2,
	RoleSuperuser: 3,
}

// RoleLevel returns the authorization level for a role, or -1 if unknown.
// roleRequired treats an unknown/empty role as below every threshold.
func RoleLevel(role string) int {
	if l, ok := RoleLevels[role]; ok {
		return l
	}
	return -1
}
