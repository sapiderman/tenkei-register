package attendance

import "errors"

var (
	// ErrDuplicate means the member already logged this dojo in the last 10
	// minutes; the handler maps it to 409.
	ErrDuplicate = errors.New("already logged at this dojo in the last 10 minutes")
	// ErrNotFound means no attendance row has that id; the handler maps it to 404.
	ErrNotFound = errors.New("attendance record not found")
	// ErrNotPending means the record already carries a decision; the handler
	// maps it to 409.
	ErrNotPending = errors.New("attendance record is not pending")
)
