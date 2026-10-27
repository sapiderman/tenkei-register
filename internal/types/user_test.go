package types

import "testing"

func TestValidCategory(t *testing.T) {
	for _, c := range []string{CategoryRegular, CategoryStudent, CategoryKids} {
		if !ValidCategory(c) {
			t.Errorf("ValidCategory(%q) = false, want true", c)
		}
	}
	for _, c := range []string{"", "alumni", "STUDENT", "student ", "regular\n"} {
		if ValidCategory(c) {
			t.Errorf("ValidCategory(%q) = true, want false", c)
		}
	}
}

func TestCategoryFieldsMissing(t *testing.T) {
	filled := CategoryFields{
		University:   "Universitas Indonesia",
		Faculty:      "Fakultas Teknik",
		Major:        "Teknik Elektro",
		SchoolName:   "SMA Negeri 1",
		GuardianName: "Ibu Sri",
	}
	schoolOnly := CategoryFields{SchoolName: "SMA Negeri 1"}
	guardianOnly := CategoryFields{GuardianName: "Ibu Sri"}

	tests := []struct {
		name     string
		category string
		fields   CategoryFields
		want     bool
	}{
		// regular: every field empty is the only OK state.
		{"regular all empty", CategoryRegular, CategoryFields{}, false},
		{"regular with university", CategoryRegular, CategoryFields{University: "UI"}, true},
		{"regular with faculty", CategoryRegular, CategoryFields{Faculty: "Teknik"}, true},
		{"regular with major", CategoryRegular, CategoryFields{Major: "Elektro"}, true},
		{"regular with school", CategoryRegular, schoolOnly, true},
		{"regular with guardian", CategoryRegular, guardianOnly, true},

		// student university path: university+faculty+major set, rest empty.
		{"student university path", CategoryStudent, CategoryFields{University: "UI", Faculty: "Fakultas Teknik", Major: "Teknik Elektro"}, false},
		{"student missing university", CategoryStudent, CategoryFields{Faculty: "Fakultas Teknik", Major: "Teknik Elektro"}, true},
		{"student missing faculty", CategoryStudent, CategoryFields{University: "UI", Major: "Teknik Elektro"}, true},
		{"student missing major", CategoryStudent, CategoryFields{University: "UI", Faculty: "Fakultas Teknik"}, true},
		{"student nothing", CategoryStudent, CategoryFields{}, true},

		// student school path: school_name set, university fields empty.
		{"student school path", CategoryStudent, schoolOnly, false},
		{"student school plus university (both paths)", CategoryStudent, CategoryFields{University: "UI", Faculty: "Fakultas Teknik", Major: "Teknik Elektro", SchoolName: "SMA Negeri 1"}, true},
		{"student school plus major", CategoryStudent, CategoryFields{SchoolName: "SMA Negeri 1", Major: "Teknik Elektro"}, true},
		{"student university path with guardian", CategoryStudent, CategoryFields{University: "UI", Faculty: "Fakultas Teknik", Major: "Teknik Elektro", GuardianName: "Ibu Sri"}, true},
		{"student school path with guardian", CategoryStudent, CategoryFields{SchoolName: "SMA Negeri 1", GuardianName: "Ibu Sri"}, true},

		// kids: guardian set, all student fields empty.
		{"kids with guardian", CategoryKids, guardianOnly, false},
		{"kids missing guardian", CategoryKids, CategoryFields{}, true},
		{"kids with university", CategoryKids, CategoryFields{GuardianName: "Ibu Sri", University: "UI"}, true},
		{"kids with school", CategoryKids, CategoryFields{GuardianName: "Ibu Sri", SchoolName: "SMA Negeri 1"}, true},
		{"kids guardian only via full struct", CategoryKids, CategoryFields{GuardianName: "Ibu Sri"}, false},

		// unknown/empty category: fail-closed.
		{"unknown category", "alumni", CategoryFields{}, true},
		{"unknown category filled", "alumni", filled, true},
		{"empty category", "", CategoryFields{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CategoryFieldsMissing(tt.category, tt.fields); got != tt.want {
				t.Errorf("CategoryFieldsMissing(%q, %+v) = %v, want %v", tt.category, tt.fields, got, tt.want)
			}
		})
	}
}
