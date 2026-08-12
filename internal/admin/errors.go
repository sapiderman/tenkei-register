package admin

import "errors"

// ErrMemberNotFound is returned when a target member does not exist or is
// outside the viewer's scope. Both cases map to 404 for anti-enumeration:
// an admin must not learn that an admin/superuser id exists.
var ErrMemberNotFound = errors.New("member not found")

// ErrNotPending is returned by verify when the in-scope target is not in the
// 'new' role (already verified, or otherwise not pending). Maps to 409.
var ErrNotPending = errors.New("member is not pending")
