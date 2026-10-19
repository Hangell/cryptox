package devices

import (
	"bytes"
	"testing"
	"time"

	"github.com/Hangell/cryptox/identity/credentials"
	"github.com/Hangell/cryptox/keys/signatures"
)

func anchorKey(t *testing.T) signatures.PrivateKey {
	t.Helper()
	_, priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func deviceKey(t *testing.T) signatures.PublicKey {
	t.Helper()
	pub, _, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func enrollCredential(t *testing.T, anchorPriv signatures.PrivateKey, device signatures.PublicKey) credentials.Credential {
	t.Helper()
	now := time.Now()
	cred, err := credentials.New(anchorPriv, device, credentials.PurposeDeviceIdentity, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestEnrollRequiresTrustAnchor(t *testing.T) {
	anchor := anchorKey(t)
	anchorPub, err := anchor.Public()
	if err != nil {
		t.Fatal(err)
	}
	device := deviceKey(t)

	// Valid enrollment.
	rec, err := Enroll(anchorPub, enrollCredential(t, anchor, device), time.Now())
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if rec.State != StateActive || rec.Seq != 1 || rec.Key() != device {
		t.Fatalf("unexpected record: %+v", rec)
	}

	// A different anchor's credential must be rejected.
	otherAnchor := anchorKey(t)
	if _, err := Enroll(anchorPub, enrollCredential(t, otherAnchor, device), time.Now()); err != ErrUntrustedIssuer {
		t.Fatalf("untrusted issuer: got %v, want ErrUntrustedIssuer", err)
	}

	// Wrong purpose must be rejected.
	now := time.Now()
	agentCred, err := credentials.New(anchor, device, credentials.PurposeAgentIdentity, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(anchorPub, agentCred, now); err != ErrInvalidCredential {
		t.Fatalf("wrong purpose: got %v, want ErrInvalidCredential", err)
	}

	// Expired credential must be rejected.
	expired, err := credentials.New(anchor, device, credentials.PurposeDeviceIdentity, uint64(now.Add(-2*time.Hour).Unix()), uint64(now.Add(-time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(anchorPub, expired, now); err != ErrInvalidCredential {
		t.Fatalf("expired: got %v, want ErrInvalidCredential", err)
	}
}

func TestReplace(t *testing.T) {
	anchor := anchorKey(t)
	anchorPub, err := anchor.Public()
	if err != nil {
		t.Fatal(err)
	}
	oldKey := deviceKey(t)
	newKey := deviceKey(t)
	now := time.Now()

	rec, err := Enroll(anchorPub, enrollCredential(t, anchor, oldKey), now)
	if err != nil {
		t.Fatal(err)
	}

	old, next, err := Replace(anchorPub, rec, enrollCredential(t, anchor, newKey), now)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if old.State != StateRetired || old.Key() != oldKey {
		t.Fatalf("old record not retired correctly: %+v", old)
	}
	if next.State != StateActive || next.Key() != newKey || next.Seq != rec.Seq+1 {
		t.Fatalf("new record incorrect: %+v", next)
	}

	// Replacing with the same key must fail.
	if _, _, err := Replace(anchorPub, next, enrollCredential(t, anchor, newKey), now); err != ErrInvalidCredential {
		t.Fatalf("same-key replace: got %v, want ErrInvalidCredential", err)
	}

	// Replacing a retired record must fail.
	if _, _, err := Replace(anchorPub, old, enrollCredential(t, anchor, deviceKey(t)), now); err != ErrInvalidState {
		t.Fatalf("retired replace: got %v, want ErrInvalidState", err)
	}

	// A replacement credential from a non-anchor must fail.
	forger := anchorKey(t)
	if _, _, err := Replace(anchorPub, rec, enrollCredential(t, forger, deviceKey(t)), now); err != ErrUntrustedIssuer {
		t.Fatalf("forged replace: got %v, want ErrUntrustedIssuer", err)
	}
}

func TestRevocation(t *testing.T) {
	anchor := anchorKey(t)
	anchorPub, err := anchor.Public()
	if err != nil {
		t.Fatal(err)
	}
	devicePub := deviceKey(t)
	rec, err := Enroll(anchorPub, enrollCredential(t, anchor, devicePub), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Anchor-authorized revocation.
	rev, err := NewRevocation(anchor, rec.Key(), rec.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := Revoke(rec, rev, anchorPub)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked.State != StateRevoked || revoked.Seq != rec.Seq+1 {
		t.Fatalf("unexpected revoked record: %+v", revoked)
	}
	if _, err := Revoke(revoked, rev, anchorPub); err != ErrInvalidState {
		t.Fatalf("double revoke: got %v, want ErrInvalidState", err)
	}

	// Revoking a different key must fail.
	rec2, err := Enroll(anchorPub, enrollCredential(t, anchor, deviceKey(t)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(rec2, rev, anchorPub); err != ErrWrongKey {
		t.Fatalf("wrong key: got %v, want ErrWrongKey", err)
	}

	// Stale sequence must be rejected.
	rec3, err := Enroll(anchorPub, enrollCredential(t, anchor, deviceKey(t)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stale, err := NewRevocation(anchor, rec3.Key(), rec3.Seq) // not newer
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(rec3, stale, anchorPub); err != ErrStaleSequence {
		t.Fatalf("stale seq: got %v, want ErrStaleSequence", err)
	}
}

func TestSelfRevocationAndThirdPartyRejection(t *testing.T) {
	anchor := anchorKey(t)
	anchorPub, err := anchor.Public()
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Enroll(anchorPub, enrollCredential(t, anchor, pub), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Self-revocation.
	self, err := NewRevocation(priv, pub, rec.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := Revoke(rec, self, anchorPub)
	if err != nil {
		t.Fatalf("self-revoke: %v", err)
	}
	if revoked.State != StateRevoked {
		t.Fatalf("state %v, want revoked", revoked.State)
	}

	// Third-party revocation must be rejected.
	rec2, err := Enroll(anchorPub, enrollCredential(t, anchor, deviceKey(t)), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	thirdParty := anchorKey(t)
	bad, err := NewRevocation(thirdParty, rec2.Key(), rec2.Seq+1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(rec2, bad, anchorPub); err != ErrInvalidRevocation {
		t.Fatalf("third-party revoke: got %v, want ErrInvalidRevocation", err)
	}
}

func TestRecordPersistenceAndRecovery(t *testing.T) {
	anchor := anchorKey(t)
	anchorPub, err := anchor.Public()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Enroll(anchorPub, enrollCredential(t, anchor, deviceKey(t)), time.Now())
	if err != nil {
		t.Fatal(err)
	}

	enc, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRecord(enc)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	if dec != rec {
		t.Fatal("record round-trip mismatch")
	}
	// Recovery with the right anchor passes; with a different anchor it must
	// fail, so recovery cannot bypass authorization.
	if err := dec.Verify(anchorPub, time.Now()); err != nil {
		t.Fatalf("recovery verify: %v", err)
	}
	otherPub, _, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := dec.Verify(otherPub, time.Now()); err != ErrUntrustedIssuer {
		t.Fatalf("wrong-anchor recovery: got %v, want ErrUntrustedIssuer", err)
	}

	// Malformed record lengths.
	if _, err := DecodeRecord(nil); err != ErrMalformed {
		t.Fatalf("nil record: got %v, want ErrMalformed", err)
	}
	if _, err := DecodeRecord(enc[:len(enc)-1]); err != ErrMalformed {
		t.Fatalf("truncated record: got %v, want ErrMalformed", err)
	}
}

func TestRevocationPersistence(t *testing.T) {
	anchor := anchorKey(t)
	rev, err := NewRevocation(anchor, deviceKey(t), 42)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := rev.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeRevocation(enc)
	if err != nil {
		t.Fatalf("DecodeRevocation: %v", err)
	}
	if dec != rev {
		t.Fatal("revocation round-trip mismatch")
	}
	if _, err := DecodeRevocation(nil); err != ErrMalformed {
		t.Fatalf("nil revocation: got %v, want ErrMalformed", err)
	}
	if _, err := DecodeRevocation(enc[:len(enc)-1]); err != ErrMalformed {
		t.Fatalf("truncated revocation: got %v, want ErrMalformed", err)
	}
}

func FuzzDecodeRecord(f *testing.F) {
	anchor := anchorKeyForFuzz(f)
	pub, _, err := signatures.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	cred, err := credentials.New(anchor, pub, credentials.PurposeDeviceIdentity, 1000, 2000)
	if err != nil {
		f.Fatal(err)
	}
	seed := Record{Credential: cred, State: StateActive, Seq: 1}
	seedBytes, _ := seed.Encode()

	f.Add([]byte{})
	f.Add(seedBytes)
	f.Fuzz(func(t *testing.T, b []byte) {
		rec, err := DecodeRecord(b)
		if err != nil {
			return
		}
		_ = rec.Verify(signatures.PublicKey{}, time.Unix(0, 0))
		re, err := rec.Encode()
		if err == nil && !bytes.Equal(re, b) {
			t.Fatalf("re-encode of decoded record differs")
		}
	})
}

func FuzzDecodeRevocation(f *testing.F) {
	anchor := anchorKeyForFuzz(f)
	rev, err := NewRevocation(anchor, signatures.PublicKey{}, 1)
	if err != nil {
		f.Fatal(err)
	}
	seed, _ := rev.Encode()

	f.Add([]byte{})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRevocation(b)
		if err != nil {
			return
		}
		_ = r.Verify(signatures.PublicKey{})
		re, err := r.Encode()
		if err == nil && !bytes.Equal(re, b) {
			t.Fatalf("re-encode of decoded revocation differs")
		}
	})
}

// anchorKeyForFuzz mirrors anchorKey but accepts *testing.F for seed setup.
func anchorKeyForFuzz(f *testing.F) signatures.PrivateKey {
	_, priv, err := signatures.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	return priv
}
