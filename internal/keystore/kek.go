// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"

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
