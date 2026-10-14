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
	if !a.GetGrantedIncomplete() {
		t.Fatal("a cut grant is not marked incomplete")
	}
	if small := map[string]string{"contents": "write", "metadata": "read"}; !maps.Equal(must(clampGrant(small, nil)), small) {
		t.Fatal("a well-formed grant changed")
	}

	// What made the grant wider is kept, however it sorts (#353 review):
	// forty permissions as requested, and workflows:write beyond them.
	requested, wide := map[string]string{}, map[string]string{"workflows": "write"}
	for i := range 40 {
		n := fmt.Sprintf("perm_%02d", i)
		requested[n], wide[n] = "read", "read"
	}
	b := accessOf(broker.Access{Installation: 7, Repository: "acme/payments", Requested: requested, Granted: wide, Revocation: "revoked"})
	if b.GetGranted()["workflows"] != "write" || len(b.GetGranted()) != maxGrant || !b.GetGrantedIncomplete() {
		t.Fatalf("the widening permission was dropped: %v %v", b.GetGranted(), b.GetGrantedIncomplete())
	}
	if c := accessOf(broker.Access{Installation: 7, Repository: "acme/payments", Granted: map[string]string{"contents": "read"}}); c.GetGrantedIncomplete() {
		t.Fatal("a whole grant is marked incomplete")
	}
}

func must(m map[string]string, _ bool) map[string]string { return m }
