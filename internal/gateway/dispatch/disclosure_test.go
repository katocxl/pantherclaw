// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// memoRefund maps a refund carrying memo through
// the mock payments package with memo added as a disclosure param.
func memoRefund(t *testing.T, memo string) (*defs.Definition, actionir.Parsed) {
	t.Helper()
	raw, err := os.ReadFile("../../../packages/mock-payments/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	enum := "        values: [duplicate, fraudulent, requested_by_customer]\n"
	call := "            reason: input.reason\n    dispatch:"
	if !strings.Contains(text, enum) || !strings.Contains(text, call) {
		t.Fatal("the refund moved; update the fixture")
	}
	text = strings.Replace(text, enum, enum+"      memo:\n        type: text\n        disclosure: true\n        max_bytes: 512\n", 1)
	text = strings.Replace(text, call, "            reason: input.reason\n            memo: input.memo\n    dispatch:", 1)
	pkg, err := manifest.Decode([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	input := `{"charge":"ch_1","amount":"10.00","currency":"USD","reason":"duplicate","memo":"` + memo + `"`
	p, err := m.MCP(context.Background(), mapping.Context{
		Org: ids.NewV7().String(), Env: ids.NewV7().String(), RunID: ids.NewV7().String(), ActionID: ids.NewV7().String(),
		AgentInstance: ids.NewV7().String(), Connection: ids.NewV7().String(),
	}, "create_refund", []byte(input+"}"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == "payments.refund.create" {
			return &pkg.Definitions[i], p
		}
	}
	t.Fatal("no refund definition")
	return nil, p
}

// diverse is n printable ASCII bytes cycling through 92 symbols: about 6.5
// bits per byte, the shape of an encoded secret.
func diverse(n int) string {
	var b strings.Builder
	for i := range n {
		c := byte('!' + i%94)
		if c == '"' || c == 0x5c { // no JSON escapes

			c = 'x'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// TestT017_DisclosureOverItsLimitsIsNotDispatched: before dispatch the
// gateway checks a disclosure_limits obligation (HR-079, M10 half): a
// value over the byte limit, or under it but denser than the entropy
// limit (an encoded secret), is refused as an obligation failure and
// nothing is dispatched; ordinary text and an absent param pass, and the
// action is not changed; a malformed limit is unsupported, never ignored.
func TestT017_DisclosureOverItsLimitsIsNotDispatched(t *testing.T) {
	limits := []*pb.Obligation{{
		Rule: "HR-079", Kind: string(defs.ConstraintDisclosureLimits), Param: "memo", Max: "512", MaxEntropy: "6",
		Timing: "before_execution",
	}}
	if defs.Entropy([]byte(diverse(300))) <= 6 || defs.Entropy([]byte(strings.Repeat("ab", 100))) != 1 {
		t.Fatal("entropy fixture")
	}
	for _, c := range []struct {
		name string
		memo string
		want error
	}{
		{"ordinary text", "the customer was charged twice for one order", nil},
		{"over the byte limit", strings.Repeat("a", 513), errDisclosure},
		{"dense like a secret", diverse(300), errDisclosure},
	} {
		def, p := memoRefund(t, c.memo)
		eff, err := effective(def, p, limits)
		if !errors.Is(err, c.want) || (err == nil && eff.HashHex() != p.HashHex()) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	def, p := memoRefund(t, "fine")
	// A limit on a param the action does not set discloses nothing.
	absent := []*pb.Obligation{{Kind: string(defs.ConstraintDisclosureLimits), Param: "note", Max: "1", MaxEntropy: "0.5"}}
	if _, err := effective(def, p, absent); err != nil {
		t.Fatalf("absent param: %v", err)
	}
	for _, bad := range []*pb.Obligation{
		{Kind: string(defs.ConstraintDisclosureLimits), Param: "memo", Max: "x", MaxEntropy: "6"},
		{Kind: string(defs.ConstraintDisclosureLimits), Param: "memo", Max: "512", MaxEntropy: "9"},
		{Kind: string(defs.ConstraintDisclosureLimits), Param: "memo", Max: "512", MaxEntropy: "6", Timing: "after_dispatch"},
	} {
		if _, err := effective(def, p, []*pb.Obligation{bad}); !errors.Is(err, errUnsupported) {
			t.Errorf("malformed %+v: %v", bad, err)
		}
	}
	if CodeObligationFailed != "obligation_failed" {
		t.Fatal("the refusal code changed")
	}
}
