// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestAReasonIsAuditedWhole: a written reason of up to 1,000 characters
// is kept whole in audit details of at most 512 bytes each.
func TestAReasonIsAuditedWhole(t *testing.T) {
	for _, reason := range []string{"Accepted for the pilot.", strings.Repeat("é", 1000), strings.Repeat("😀", 1000)} {
		d := auditReason(map[string]string{"kind": "credential_overreach"}, reason)
		var whole strings.Builder
		for i := 1; ; i++ {
			part, ok := d["reason_"+strconv.Itoa(i)]
			if !ok {
				break
			}
			if len(part) > 512 || !utf8.ValidString(part) {
				t.Fatalf("part %d: %d bytes", i, len(part))
			}
			whole.WriteString(part)
		}
		if whole.String() != reason || len(d) > 16 {
			t.Fatalf("a reason of %d bytes kept as %d bytes in %d details", len(reason), whole.Len(), len(d))
		}
	}
}
