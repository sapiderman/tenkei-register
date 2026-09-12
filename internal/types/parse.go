package types

import (
	"fmt"
	"regexp"
	"strings"
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

// phoneCleanup strips the characters users sprinkle into phone numbers for
// readability before validation. The non-breaking space is included because it
// rides along with a copy-paste from a web page, Excel, or WhatsApp, and it is
// invisible in the input field.
var phoneCleanup = strings.NewReplacer(" ", "", "\u00a0", "", "-", "", ".", "", "(", "", ")", "")

// E.164 patterns applied to the normalized value. An Indonesian number must fit
// the dojo's numbering plan — "+62", a subscriber number starting 2-9, and 8–12
// subscriber digits (10–14 digits total). Any other country code only needs the
// generic E.164 shape.
//
// These exact patterns are mirrored in the CASE guards of
// migrations/000007_phone_e164.up.sql — keep them in sync, or the app and the
// backfill will disagree on what counts as a valid number. A CHECK constraint on
// users.whatsapp_number / users.emergency_contact_number is planned but not yet
// added (blocked on the legacy-data count); when it is, it must embed these same
// regexes, or app-accepted input becomes a DB error (500) instead of a 400.
var (
	phoneIDPattern      = regexp.MustCompile(`^\+62[2-9]\d{7,11}$`)
	phoneGenericPattern = regexp.MustCompile(`^\+[1-9]\d{7,14}$`)
)

// NormalizePhone converts a phone number to E.164 international format
// ("+628123456789"), the storage standard for users.whatsapp_number and
// users.emergency_contact_number. Accepted shapes, after separator stripping
// (spaces — including non-breaking — dashes, dots, parentheses):
//
//   - "+62..." or "+<other country code>..." → kept as-is (already E.164)
//   - "62..."                                → "+" prepended
//   - "08..."                                → trunk 0 replaced with "62"
//   - "+62 08..." / "6208..."                → trunk 0 stripped (E.164 keeps no
//     trunk prefix after the country code, so this is the same as "+628...")
//
// The result is then checked against phoneIDPattern (Indonesian numbers, which
// must fit the dojo's numbering plan) or phoneGenericPattern (other countries).
// Empty input maps to "" (phone fields are optional); anything that fails both
// shapes is an error, including the ambiguous "00" international access prefix,
// a 0 left next to the country code, and a length outside 10–14 digits for
// Indonesian numbers.
func NormalizePhone(s string) (string, error) {
	s = phoneCleanup.Replace(s)
	if s == "" {
		return "", nil
	}

	digits := s
	switch {
	case strings.HasPrefix(s, "+"):
		digits = s[1:]
	case strings.HasPrefix(s, "0"):
		// A single leading 0 is Indonesia's national trunk prefix. "00..." is the
		// international access prefix — a dialing prefix, not a country code — and
		// guessing at it would store a doubled one ("0062..." → "+62062...").
		if strings.HasPrefix(s, "00") {
			return "", fmt.Errorf("phone must be in international format, e.g. +628123456789")
		}
		// The rest is the national number even when it starts with "62": 0620–0628
		// are real North Sumatra landline area codes (Kabanjahe, Tebing Tinggi,
		// Pematangsiantar, …). So "0628 123 4567" is "+62 628 123 4567" — do NOT
		// read it as a stray country code, "+6281234567" is a different (mobile)
		// number that belongs to someone else.
		digits = "62" + s[1:]
	case !strings.HasPrefix(s, "62"):
		return "", fmt.Errorf("phone must be in international format, e.g. +628123456789")
	}
	// The trunk 0 is not part of an E.164 number: "+62 0812..." and "620812..."
	// are the same number as "+62812...". Strip exactly one; a subscriber number
	// that still starts with 0 is rejected by the pattern check below.
	if strings.HasPrefix(digits, "620") {
		digits = "62" + digits[3:]
	}

	e164 := "+" + digits
	pattern := phoneGenericPattern
	if strings.HasPrefix(e164, "+62") {
		pattern = phoneIDPattern
	}
	if !pattern.MatchString(e164) {
		return "", fmt.Errorf("phone must be in international format, e.g. +628123456789")
	}
	return e164, nil
}
