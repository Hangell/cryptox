package encrypted

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

func TestMigrateCopiesAndIsIdempotent(t *testing.T) {
	src, _ := newTestStore(t)
	innerDst := newFakeStore()
	dst, err := New(innerDst, bytes.Repeat([]byte{0x77}, 32), "test-ns")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := src.Put("a", []byte("payload-a"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Put("b", []byte("payload-b"), nil); err != nil {
		t.Fatal(err)
	}

	migrated, skipped, err := Migrate(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 2 || skipped != 0 {
		t.Fatalf("migrated=%d skipped=%d, want 2/0", migrated, skipped)
	}

	// dst decrypts with its own key.
	got, err := dst.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "payload-a" {
		t.Fatalf("dst payload = %q", got.Data)
	}

	// Second run is a no-op (idempotent).
	migrated, skipped, err = Migrate(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 0 || skipped != 2 {
		t.Fatalf("second run migrated=%d skipped=%d, want 0/2", migrated, skipped)
	}
}

func TestMigrateDoesNotModifySource(t *testing.T) {
	src, _ := newTestStore(t)
	dst, _ := newTestStore(t)

	if _, err := src.Put("a", []byte("keep"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Migrate(context.Background(), src, dst); err != nil {
		t.Fatal(err)
	}
	// Source still decrypts with its original key.
	got, err := src.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "keep" {
		t.Fatalf("source changed: %q", got.Data)
	}
}

func TestMigrateResumableAfterCancellation(t *testing.T) {
	src, _ := newTestStore(t)
	dst, _ := newTestStore(t)

	for i := 0; i < 5; i++ {
		if _, err := src.Put(interfaces.RecordID(string(rune('a'+i))), []byte("data"), nil); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: Migrate returns before copying anything
	if _, _, err := Migrate(ctx, src, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled migrate: got %v, want context.Canceled", err)
	}

	// Resume with a live context: everything copies.
	migrated, skipped, err := Migrate(context.Background(), src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if migrated != 5 || skipped != 0 {
		t.Fatalf("resumed migrated=%d skipped=%d, want 5/0", migrated, skipped)
	}
}
