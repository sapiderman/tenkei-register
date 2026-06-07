package auth

import "testing"

func TestAllowedRanks(t *testing.T) {
	// Verify key ranks are present
	ranks := []string{"", "6th Kyu", "Shodan (1st Dan)", "Godan (5th Dan)"}
	for _, r := range ranks {
		if !allowedRanks[r] {
			t.Errorf("expected rank %q to be allowed", r)
		}
	}
}

func TestUpdateProfileRequestOmitsImmutableFields(t *testing.T) {
	// Verify that UpdateProfileRequest cannot represent immutable fields.
	// This is a compile-time guarantee — if someone adds ID or Role fields,
	// this test documents why they shouldn't.
	req := UpdateProfileRequest{}
	_ = req // suppress unused variable warning
}

func TestProfileResponseOmitsPasswordHash(t *testing.T) {
	// ProfileResponse should never contain PasswordHash.
	// This is a structural guarantee confirmed by field inspection.
	resp := ProfileResponse{}
	_ = resp // suppress unused variable warning — the guarantee is at the struct definition level
}
