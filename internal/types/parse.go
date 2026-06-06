package types

import (
	"fmt"
	"time"
)

// ParseDate safely parses a YYYY-MM-DD date string.
// Returns zero time for empty input.
func ParseDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid date format, use YYYY-MM-DD")
	}
	return t, nil
}