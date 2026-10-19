package verification

import (
	"strings"
	"testing"

	"github.com/Hangell/cryptox/keys/signatures"
)

func TestFingerprintStableAndUnique(t *testing.T) {
	pubA, _, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	fa := FingerprintOf(pubA)
	if fa != FingerprintOf(pubA) {
		t.Fatal("fingerprint is not deterministic")
	}
	if fa == FingerprintOf(pubB) {
		t.Fatal("distinct keys produced identical fingerprints")
	}
	if !fa.Equal(fa) {
		t.Fatal("Equal rejected identical fingerprints")
	}
	if fa.Equal(FingerprintOf(pubB)) {
		t.Fatal("Equal accepted distinct fingerprints")
	}

	s := fa.String()
	if len(s) != 16*4+15 { // 16 groups of 4 hex digits, 15 separators
		t.Fatalf("unexpected fingerprint string length %d: %q", len(s), s)
	}
	if strings.ContainsAny(s, "abcdef") {
		t.Fatalf("fingerprint string not uppercase: %q", s)
	}
}
