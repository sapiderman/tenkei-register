package types

import "testing"

func TestAllowedRanks(t *testing.T) {
	ranks := []string{"", "6th Kyu", "Shodan (1st Dan)", "Godan (5th Dan)"}
	for _, r := range ranks {
		if !AllowedRanks[r] {
			t.Errorf("expected rank %q to be in AllowedRanks", r)
		}
	}
	// Verify an invalid rank is not allowed
	if AllowedRanks["invalid rank"] {
		t.Error("expected invalid rank to not be in AllowedRanks")
	}
}

func TestParseDate(t *testing.T) {
	// Valid date
	result, err := ParseDate("1990-06-15")
	if err != nil {
		t.Errorf("ParseDate(\"1990-06-15\") error: %v", err)
	}
	if result.Year() != 1990 || result.Month() != 6 || result.Day() != 15 {
		t.Errorf("expected 1990-06-15, got %v", result)
	}

	// Empty string → zero time
	result, err = ParseDate("")
	if err != nil {
		t.Errorf("ParseDate(\"\") error: %v", err)
	}
	if !result.IsZero() {
		t.Errorf("expected zero time for empty string, got %v", result)
	}

	// Invalid format
	_, err = ParseDate("15-06-1990")
	if err == nil {
		t.Error("expected error for invalid date format, got nil")
	}
}
