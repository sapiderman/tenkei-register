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

func TestNormalizePhone(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		// Accepted shapes, all normalizing to the same E.164 value.
		{name: "AlreadyE164", in: "+628123456789", want: "+628123456789"},
		{name: "CountryCodeNoPlus", in: "628123456789", want: "+628123456789"},
		{name: "LocalTrunkZero", in: "08123456789", want: "+628123456789"},
		{name: "Separators", in: "0812-3456-789", want: "+628123456789"},
		{name: "ParensAndSpaces", in: "+62 (812) 345-678", want: "+62812345678"},
		// Non-breaking space: pasted from a web page, Excel, or WhatsApp.
		{name: "NonBreakingSpace", in: "+62\u00a0812345678", want: "+62812345678"},
		// The trunk 0 is not part of an E.164 number: it must not survive next to
		// the country code. "+62 0812…" is the most common way users get this
		// wrong — it used to be stored as the undialable "+620812…".
		{name: "CountryCodePlusTrunkZero", in: "+620812345678", want: "+62812345678"},
		{name: "CountryCodePlusTrunkZeroSeparators", in: "+62 0812-3456-789", want: "+628123456789"},
		{name: "BareCountryCodePlusTrunkZero", in: "620812345678", want: "+62812345678"},
		{name: "LandlineTrunkZeroAfterCC", in: "62021234567", want: "+6221234567"},
		{name: "OtherCountryKept", in: "+14155551234", want: "+14155551234"},
		{name: "OtherCountrySeparators", in: "+1 415 555 1234", want: "+14155551234"},
		// Indonesian numbering plan: subscriber number starts 2-9, 8–12 digits.
		{name: "IDMaxLength", in: "0812345678901", want: "+62812345678901"},
		{name: "IDLandline", in: "021-12345678", want: "+622112345678"},
		// 0620–0628 are North Sumatra landline area codes, not a duplicated country
		// code. All three spellings of a Kabanjahe landline must converge — reading
		// "0628…" as a stray country code would yield "+6281234567", a real mobile
		// number belonging to someone else.
		{name: "IDAreaCode628Local", in: "0628 123 4567", want: "+626281234567"},
		{name: "IDAreaCode628CountryCodeTrunkZero", in: "+62 0628 123 4567", want: "+626281234567"},
		{name: "IDAreaCode628AlreadyE164", in: "+626281234567", want: "+626281234567"},
		{name: "IDAreaCode622Pematangsiantar", in: "0622-1234567", want: "+626221234567"},
		{name: "EmptyOptional", in: "", want: ""},
		{name: "SeparatorsOnly", in: " - ", want: ""},

		// Rejected shapes.
		{name: "BareMobileNoPrefix", in: "8123456789", wantErr: true},
		{name: "TooShort", in: "081234", wantErr: true},
		{name: "TooLong", in: "+621234567890123456", wantErr: true},
		{name: "Letters", in: "+62abc123456", wantErr: true},
		{name: "BareForeignCountryCode", in: "4412345678", wantErr: true},
		// E.164 country codes never start with 0; without this guard the number is
		// stored verbatim and is undialable forever.
		{name: "PlusZeroCountryCode", in: "+08123456789", wantErr: true},
		// "00" is an international access prefix, not a country code: guessing
		// would store a doubled one ("+62062...").
		{name: "InternationalAccessPrefix", in: "00628123456789", wantErr: true},
		{name: "InternationalAccessPrefixSpaced", in: "0062 812 3456 789", wantErr: true},
		// Two zeros after the country code: the second is not a trunk prefix, so
		// the number cannot be interpreted.
		{name: "DoubledTrunkZero", in: "6200212345678", wantErr: true},
		{name: "DoubledTrunkZeroWithPlus", in: "+6200212345678", wantErr: true},
		// Off the Indonesian numbering plan: subscriber number must start 2-9 and
		// be 8–12 digits (10–14 digits total, i.e. tighter than E.164's 15 cap).
		{name: "IDSubscriberStartsOne", in: "+621234567890", wantErr: true},
		{name: "IDSubscriberStartsZero", in: "+620123456789", wantErr: true},
		{name: "IDTooFewDigits", in: "+628123456", wantErr: true},
		{name: "IDFifteenDigits", in: "+628123456789012", wantErr: true},
		{name: "LocalTooShort", in: "0812345", wantErr: true},
		{name: "LocalOffPlan", in: "0112345678", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePhone(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Errorf("NormalizePhone(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Errorf("NormalizePhone(%q) error: %v", tc.in, err)
				return
			}
			if got != tc.want {
				t.Errorf("NormalizePhone(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
