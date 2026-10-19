package encrypted

import (
	"context"
	"errors"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

// Migrate re-encrypts records from src into dst, which use different keys
// and/or namespaces. It is resumable and idempotent:
//
//   - It never modifies src, so the old key remains usable until the operator
//     validates the migration and rotates it.
//   - A record already present in dst is skipped, so an interrupted migration
//     resumes without rewriting or duplicating records.
//   - ctx cancellation stops the loop; already-migrated records remain in dst.
//
// The source and destination are independent stores; do not pass the same
// Store for both. migrated counts records copied, skipped counts records that
// were already present in dst.
func Migrate(ctx context.Context, src, dst *Store) (migrated, skipped int, err error) {
	ids, err := src.List()
	if err != nil {
		return 0, 0, err
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return migrated, skipped, err
		}
		if _, getErr := dst.Get(id); getErr == nil {
			skipped++
			continue
		} else if !errors.Is(getErr, interfaces.ErrNotFound) {
			return migrated, skipped, getErr
		}
		rec, err := src.Get(id)
		if err != nil {
			return migrated, skipped, err
		}
		if _, err := dst.Put(id, rec.Data, nil); err != nil {
			return migrated, skipped, err
		}
		migrated++
	}
	return migrated, skipped, nil
}
