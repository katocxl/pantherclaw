// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"fmt"
	"maps"
	"testing"

	"buf.build/go/protovalidate"

	"github.com/katocxl/pantherclaw/internal/gateway/broker"
)

// TestHR203_AWiderGrantIsRecordedWithinTheReceiptsSchema (#313 review
// follow-up): a refused wider grant may name anything GitHub likes; what the
// execution record carries keeps only well-formed permissions, at most 32,
// so the record is accepted and the transaction is not left UNKNOWN
// although nothing was sent.
func TestHR203_AWiderGrantIsRecordedWithinTheReceiptsSchema(t *testing.T) {
	granted := map[string]string{"contents": "write", "Bad-Name": "write", "issues": "READ", "x": "a very long level name"}
	for i := range 40 {
		granted[fmt.Sprintf("perm_%02d", i)] = "read"
	}
	a := accessOf(broker.Access{
		Installation: 7, Repository: "acme/payments", Requested: map[string]string{"contents": "read"}, Granted: granted, Revocation: "revoked",
	})
	if err := protovalidate.Validate(a); err != nil {
		t.Fatalf("the record is refused: %v", err)
	}
	g := a.GetGranted()
	if len(g) != maxGrant || g["contents"] != "write" || g["Bad-Name"] != "" || g["issues"] != "" || g["x"] != "" {
		t.Fatalf("granted %v", g)
	}
	if small := map[string]string{"contents": "write", "metadata": "read"}; !maps.Equal(clampGrant(small), small) {
		t.Fatal("a well-formed grant changed")
	}
}
