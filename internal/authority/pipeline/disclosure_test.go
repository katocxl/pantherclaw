// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"slices"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// withMemo adds a disclosure-capable memo (text, at most 64 bytes, default
// entropy) to the refund and maps it from the MCP tool's input.
func withMemo(t *testing.T) *fx {
	t.Helper()
	return newFxWith(t, func(raw []byte) []byte {
		enum := []byte("        values: [duplicate, fraudulent, requested_by_customer]\n")
		if !bytes.Contains(raw, enum) {
			t.Fatal("the refund's reason param moved; update the fixture")
		}
		return bytes.Replace(raw, enum, append(enum, []byte("      memo:\n        type: text\n        disclosure: true\n        max_bytes: 64\n")...), 1)
	}, "            reason: input.reason\n            memo: input.memo")
}

func memoRefund(memo string) string {
	return `{"charge":"ch_1","amount":"10.00","currency":"USD","reason":"duplicate","memo":"` + memo + `"}`
}

// TestHR079_DisclosureParamsCarrySizeAndEntropyLimits (M10 half): an
// action toward a public destination carries a disclosure_limits
// obligation for each disclosure param it sets (the definition's byte
// limit, the default 6 bits per byte), decided ALLOW_WITH_OBLIGATIONS; the
// same action through an internal connection carries none. The class is
// the connection record's.
func TestHR079_DisclosureParamsCarrySizeAndEntropyLimits(t *testing.T) {
	f := withMemo(t)
	gw := ids.NewV7()
	public, internal := connection(gw), connection(gw)
	public.DestinationClass, internal.DestinationClass = "public", "internal"
	f.w.PutConnection(public)
	f.w.PutConnection(internal)

	ev := f.on(gw, public.ID, "create_refund", memoRefund("thanks"))
	if ev.Decision != adomain.AllowWithObligations {
		t.Fatalf("public: %s %+v", ev.Decision, ev.Checklist)
	}
	i := slices.IndexFunc(ev.Obligations, func(o pdomain.Obligation) bool { return o.Kind == pdomain.DisclosureLimits })
	if i < 0 {
		t.Fatalf("no disclosure obligation: %+v", ev.Obligations)
	}
	o := ev.Obligations[i]
	if o.Param != "memo" || o.Max != "64" || o.MaxEntropy != "6" || o.Rule != pipeline.DisclosureRule ||
		o.Timing != pdomain.TimingBeforeExecution || o.ByAuthority() {
		t.Fatalf("obligation: %+v", o)
	}
	if !slices.ContainsFunc(ev.Checklist, func(it pipeline.Item) bool { return it.Code == pipeline.ReasonDisclosureLimits }) {
		t.Fatal("the checklist does not say why")
	}

	in := f.on(gw, internal.ID, "create_refund", memoRefund("thanks"))
	expect(t, in, adomain.Allow, pipeline.ReasonGrantCovers)
	if slices.ContainsFunc(in.Obligations, func(o pdomain.Obligation) bool { return o.Kind == pdomain.DisclosureLimits }) {
		t.Fatal("an internal destination carries disclosure limits")
	}
}
