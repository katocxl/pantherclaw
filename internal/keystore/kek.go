// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// unwrapStored unwraps a stored key. The row's kek_id must name the KEK
// in the wrapped value's envelope, so a row whose two columns disagree
// fails closed instead of being routed by either one (D157, HR-486).
func unwrapStored(ctx context.Context, kp keys.KeyProvider, kekID string, wrapped, aad []byte) ([]byte, error) {
	inner, err := keys.KEKOf(wrapped)
	if err != nil {
		return nil, err
	}
	if !keys.SameKEK(kekID, inner) {
		return nil, keys.ErrUnwrap
	}
	return kp.Unwrap(ctx, wrapped, aad)
}

// KEKRouter reports whether a stored kek_id has a provider (keys.Router).
type KEKRouter interface {
	Routes(kekID string) bool
}

// CheckStoredKEKs fails with a configuration error when org has a stored
// key whose KEK no configured provider holds, for example file KEKs after
// key_service moved to openbao without kek_files (D165). Without the check
// the server would fail later, at the first unwrap.
func CheckStoredKEKs(ctx context.Context, pool *db.Pool, org ids.OrgID, r KEKRouter) error {
	var stored []string
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		stored, err = dbq.New(tx).ListStoredKEKIDs(ctx, org)
		return err
	}, db.ReadOnly())
	if err != nil {
		return err
	}
	var missing []string
	for _, id := range stored {
		if !r.Routes(id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("keystore: stored keys are wrapped by KEKs that no configured provider holds (%s): "+
			"keep their kek_files (or the key_service.openbao settings) configured until the re-wrap job has moved them",
			strings.Join(missing, ", "))
	}
	return nil
}
