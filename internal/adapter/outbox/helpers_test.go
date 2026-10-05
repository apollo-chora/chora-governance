// helpers_test.go — cover the small string helpers in store.go so the
// package coverage clears the 85% gate per `.claude/rules/development-execution.md`.
package outbox

import "testing"

func TestTruncate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"short stays short", "abc", 10, "abc"},
		{"exact cap stays", "abcdef", 6, "abcdef"},
		{"longer trims", "hello world", 5, "hello"},
		{"empty stays empty", "", 5, ""},
		{"zero cap returns empty", "abc", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tc.in, tc.n)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q; want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	if isUniqueViolation(nil) {
		t.Errorf("nil err is not a unique violation")
	}
	// raw SQLSTATE prefix
	if !isUniqueViolation(errFromString("ERROR: 23505 unique violation")) {
		t.Errorf("23505 should be detected")
	}
	// pgx-style phrasing
	if !isUniqueViolation(errFromString("duplicate key value violates unique constraint")) {
		t.Errorf("phrasing should be detected")
	}
}

type stringErr string

func (s stringErr) Error() string { return string(s) }

func errFromString(s string) error { return stringErr(s) }

func TestIndexOfAndContains(t *testing.T) {
	t.Parallel()
	if !contains("23505 unique violation", "23505") {
		t.Errorf("contains should find substring")
	}
	if contains("abc", "xyz") {
		t.Errorf("contains should not find missing substring")
	}
	if !contains("", "") {
		t.Errorf("empty sub matches anything")
	}
	if indexOf("abcdef", "cd") != 2 {
		t.Errorf("indexOf cd in abcdef = %d; want 2", indexOf("abcdef", "cd"))
	}
	if indexOf("abc", "z") != -1 {
		t.Errorf("indexOf z in abc = %d; want -1", indexOf("abc", "z"))
	}
}
