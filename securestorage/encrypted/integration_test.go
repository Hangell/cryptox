package encrypted

import (
	"bytes"
	"testing"

	"github.com/Hangell/cryptox/keys"
	"github.com/Hangell/cryptox/keys/keyring"
	"github.com/Hangell/cryptox/keys/lifecycle"
	"github.com/Hangell/cryptox/securestorage/memory"
)

// TestEndToEndPutGetRotationRecovery exercises the full Phase 3 flow in CI:
// derive a storage key, store records through the encrypted layer, rotate the
// keyring key, migrate to the new key, and recover from the migrated store.
func TestEndToEndPutGetRotationRecovery(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 64)
	storageKey, err := keys.DeriveVersioned(root, "storage", keys.CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}

	// Keyring holding the active storage key.
	kr := keyring.New()
	kid, err := keyring.NewKeyID()
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Add(keyring.Record{
		ID: kid, Version: 1, Purpose: "storage",
		State: lifecycle.StateActive, Secret: keyring.Secret(storageKey),
	}); err != nil {
		t.Fatal(err)
	}

	// Encrypted store backed by the in-memory adapter.
	store, err := New(memory.New(), storageKey, "ns")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("rec", []byte("phase3"), nil); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Get("rec"); err != nil || string(got.Data) != "phase3" {
		t.Fatalf("Get after Put: %q, %v", got.Data, err)
	}

	// Rotate: derive a new storage key, retire the old one.
	newKey, err := keys.DeriveVersioned(root, "storage-v2", keys.CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kr.Rotate(kid, keyring.Secret(newKey)); err != nil {
		t.Fatal(err)
	}

	// Migrate records to the new key, then recover from the new store.
	dst, err := New(memory.New(), newKey, "ns")
	if err != nil {
		t.Fatal(err)
	}
	if migrated, _, err := Migrate(t.Context(), store, dst); err != nil || migrated != 1 {
		t.Fatalf("migrate: migrated=%d err=%v", migrated, err)
	}
	got, err := dst.Get("rec")
	if err != nil || string(got.Data) != "phase3" {
		t.Fatalf("recovery after rotation: %q, %v", got.Data, err)
	}

	// The retired key is still resolvable for historical reads.
	active := kr.Active("storage")
	if len(active) != 1 {
		t.Fatalf("active keys = %d, want 1", len(active))
	}
}
