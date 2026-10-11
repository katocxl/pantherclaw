// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import "testing"

func TestChecksum(t *testing.T) {
	// RFC 1071 §3 example words 0001 f203 f4f5 f6f7: sum ddf2, checksum 220d.
	if got := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Fatalf("checksum %#04x", got)
	}
}
