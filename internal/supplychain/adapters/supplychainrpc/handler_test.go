// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package supplychainrpc

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestD281_AReasonIsServed: the reason a flag was stored with reaches the API.
// Covers: T-252, F869
func TestD281_AReasonIsServed(t *testing.T) {
	f := flagOf(dbq.PcSupplychainFlag{Detail: []byte(`{"note":"n","spans":[],"reason":"digest_unknown"}`)})
	if f.GetReason() != "digest_unknown" || f.GetNote() != "n" {
		t.Errorf("%v", f)
	}
}
