package demo

import (
	"strings"
	"testing"
)

func TestWithinValidity(t *testing.T) {
	tests := []struct {
		name, date, from, until, wantErr string
	}{
		{"inside", "2027-01-01", "2026-10-01", "2027-09-30", ""},
		{"without end", "2099-01-01", "2026-10-01", "", ""},
		{"before start", "2026-09-30", "2026-10-01", "2027-09-30", "valid from 2026-10-01"},
		{"after end", "2027-10-01", "2026-10-01", "2027-09-30", "ended on 2027-09-30"},
		{"unparsable end", "2027-01-01", "2026-10-01", "30.09.2027", `validity_period_valid_until "30.09.2027" is not a date`},
		{"unparsable start", "2027-01-01", "next week", "2027-09-30", `validity_period_valid_from "next week" is not a date`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := withinValidity(test.date, test.from, test.until)
			switch {
			case test.wantErr == "" && err != nil:
				t.Errorf("error %v, want none", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Errorf("error %v, want one with %q", err, test.wantErr)
			}
		})
	}
}
