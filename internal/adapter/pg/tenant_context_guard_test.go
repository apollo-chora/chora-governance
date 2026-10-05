package pg

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// funcBody returns the source of the function starting at from, ending at its
// brace-matched close. Braces inside strings are rare enough in this package
// that a simple depth count is sound, and an unbalanced read falls back to the
// remainder, which can only over-report.
func funcBody(text string, from int) string {
	open := strings.IndexByte(text[from:], '{')
	if open < 0 {
		return text[from:]
	}
	depth, i := 0, from+open
	for ; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return text[from : i+1]
			}
		}
	}
	return text[from:]
}

// Every write in this package must establish tenant context before it runs.
//
// WHY A SOURCE-SCANNING TEST RATHER THAN A BEHAVIOURAL ONE. This defect class
// has recurred three times on this platform in two days (payments-audit, the
// egress audit_log, the observability familiar_growth ledger), and it is
// invisible to ordinary tests: chora_governance's tables are RLS-protected on
// the chora.tenant_id GUC, so a write on a bare pool raises 42501 only when a
// real row is attempted against a real policy. A repo whose table has never
// taken a production row therefore stays green for months, which is exactly how
// audit_log carried a latent 42501 while its own godoc named the gap.
//
// Requirement G5 asked for an audit. An audit is a snapshot; this keeps it
// true. The check is deliberately crude and local: any function in this package
// that contains a write statement must also mention a tenant-context helper.
// False positives are cheap to fix by naming the helper; the failure it exists
// to prevent is not.
func TestEveryWriteEstablishesTenantContext(t *testing.T) {
	writeStmt := regexp.MustCompile(`(?i)\b(INSERT INTO|UPDATE\s+\w+\s+SET|DELETE FROM)\b`)
	tenantCtx := regexp.MustCompile(
		`WithTenantTx|RunInTenantTx|ApplySession|setTenantContext|SET LOCAL chora\.tenant_id|WithRLSBypass`)
	funcStart := regexp.MustCompile(`(?m)^func (\([^)]*\) )?(\w+)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	var offenders []string
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		locs := funcStart.FindAllStringSubmatchIndex(text, -1)
		for _, loc := range locs {
			// Take the function's OWN body, brace-matched, rather than
			// everything up to the next func. Package-level SQL consts often
			// sit between two functions, and attributing one to the function
			// above it produced a false positive on a constructor that runs no
			// SQL at all (closure_repository.NewClosureRepository), while its
			// real caller was properly wrapped.
			body := funcBody(text, loc[0])
			if !writeStmt.MatchString(body) {
				continue
			}
			scanned++
			if tenantCtx.MatchString(body) {
				continue
			}
			fname := text[loc[4]:loc[5]]
			offenders = append(offenders, name+"::"+fname)
		}
	}

	// Positive control. A zero here must mean "every write is wrapped", never
	// "the scanner matched nothing"; without this a broken regex reads as a
	// clean pass, which is the failure mode the audit itself was checking for.
	if scanned == 0 {
		t.Fatal("scanned zero write-bearing functions; the scanner is broken, not the package clean")
	}
	control := "func (r *X) bare() error { return r.db.Exec(`INSERT INTO t (a) VALUES (1)`) }"
	if !writeStmt.MatchString(control) || tenantCtx.MatchString(control) {
		t.Fatal("positive control failed: this scanner could not flag a bare write")
	}

	if len(offenders) > 0 {
		t.Errorf("%d write(s) reachable without tenant context (RLS is enforced on chora.tenant_id, "+
			"so these raise 42501 the first time a real row is attempted):\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
	t.Logf("G5 guard: %d write-bearing functions scanned, all establish tenant context", scanned)
}
