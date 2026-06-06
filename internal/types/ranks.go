package types

// AllowedRanks defines the valid rank values for validation.
// Both register and auth packages use this single source of truth.
var AllowedRanks = map[string]bool{
	"":                 true, // empty is allowed
	"10th Kyu":         true,
	"9th Kyu":          true,
	"8th Kyu":          true,
	"7th Kyu":          true,
	"6th Kyu":          true,
	"5th Kyu":          true,
	"4th Kyu":          true,
	"3rd Kyu":          true,
	"2nd Kyu":          true,
	"1st Kyu":          true,
	"Shodan (1st Dan)": true,
	"Nidan (2nd Dan)":  true,
	"Sandan (3rd Dan)": true,
	"Yondan (4th Dan)": true,
	"Godan (5th Dan)":  true,
}