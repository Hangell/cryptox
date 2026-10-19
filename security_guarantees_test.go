package cryptox

import (
	"os"
	"strings"
	"testing"
)

// TestSecurityGuaranteesDocumented verifies that SECURITY.md states both the
// supported guarantees and the explicit non-guarantees required by Phase 0.
// Keeping these checks in sync with the public policy prevents unsupported
// security claims from being silently introduced.
func TestSecurityGuaranteesDocumented(t *testing.T) {
	b, err := os.ReadFile("SECURITY.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)

	for _, want := range []string{
		"## Supported guarantees",
		"## Known limitations",
		"whole-file integrity",
		"replay",
		"erasure of secrets from memory",
		"trusted destination directory",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("SECURITY.md is missing required statement %q", want)
		}
	}
}

// TestPrivateReportingPathDocumented verifies that SECURITY.md names a concrete,
// non-conditional confidential channel and a triage workflow, so reporters do
// not need to discover at reporting time whether a path exists.
func TestPrivateReportingPathDocumented(t *testing.T) {
	b, err := os.ReadFile("SECURITY.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)

	for _, want := range []string{
		"security/advisories/new",
		"rodrigo@hangell.org",
		"[CryptoX security]",
		"CVSS",
		"proof-of-concept publicly",
		"Never post",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("SECURITY.md is missing required statement %q", want)
		}
	}
}
