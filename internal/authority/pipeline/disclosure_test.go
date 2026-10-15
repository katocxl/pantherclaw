// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// withMemo adds a disclosure-capable memo (text, the default 4096 bytes
// and 6 bits per byte) to the refund and maps it from the MCP tool's input.
func withMemo(t *testing.T) *fx {
	t.Helper()
	return newFxWith(t, func(raw []byte) []byte {
		enum := []byte("        values: [duplicate, fraudulent, requested_by_customer]\n")
		if !bytes.Contains(raw, enum) {
			t.Fatal("the refund's reason param moved; update the fixture")
		}
		return bytes.Replace(raw, enum, append(enum, []byte("      memo:\n        type: text\n        disclosure: true\n")...), 1)
	}, "            reason: input.reason\n            memo: input.memo")
}

func memoRefund(memo string) string {
	return `{"charge":"ch_1","amount":"10.00","currency":"USD","reason":"duplicate","memo":"` + memo + `"}`
}

func disclosureObligation(ev *pipeline.Evaluation) (pdomain.Obligation, bool) {
	i := slices.IndexFunc(ev.Obligations, func(o pdomain.Obligation) bool { return o.Kind == pdomain.DisclosureLimits })
	if i < 0 {
		return pdomain.Obligation{}, false
	}
	return ev.Obligations[i], true
}

// dense is n printable ASCII bytes cycling through 92 symbols, about 6.5
// bits per byte.
func dense(n int) string {
	var b strings.Builder
	for i := range n {
		c := byte('!' + i%94)
		if c == '"' || c == 0x5c {
			c = 'x'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// TestHR079_DisclosureParamsCarrySizeAndEntropyLimits (M10 half, D56,
// D73): toward a public destination the Authority checks each disclosure
// param it holds. Over its byte limit, or denser than its entropy limit,
// the action is denied DISCLOSURE_LIMIT. Within them, a route the gateway
// mediates carries a disclosure_limits obligation it checks again, and
// the decision is ALLOW_WITH_OBLIGATIONS (a route the agent runs itself is
// covered in TestHR079_GitHubPullRequestBodyIsChecked). Toward an internal
// destination nothing is attached. The byte cap
// is the control: base64 and hex stay under the entropy limit by
// construction (their alphabets carry at most 6 and 4 bits per byte), and
// pass when they fit; so does prose.
func TestHR079_DisclosureParamsCarrySizeAndEntropyLimits(t *testing.T) {
	f := withMemo(t)
	gw := ids.NewV7()
	public, internal := connection(gw), connection(gw)
	public.DestinationClass, internal.DestinationClass = "public", "internal"
	for _, c := range []pipeline.Connection{public, internal} {
		f.w.PutConnection(c)
	}

	ev := f.on(gw, public.ID, "create_refund", memoRefund("thanks"))
	if ev.Decision != adomain.AllowWithObligations {
		t.Fatalf("public: %s %+v", ev.Decision, ev.Checklist)
	}
	o, ok := disclosureObligation(ev)
	if !ok || o.Param != "memo" || o.Max != "4096" || o.MaxEntropy != "6" || o.Rule != pipeline.DisclosureRule ||
		o.Timing != pdomain.TimingBeforeExecution || o.ByAuthority() {
		t.Fatalf("obligation: %+v %v", o, ok)
	}
	if !slices.ContainsFunc(ev.Checklist, func(it pipeline.Item) bool { return it.Code == pipeline.ReasonDisclosureLimits }) {
		t.Fatal("the checklist does not say why")
	}

	for _, memo := range map[string]string{
		"over the byte limit": strings.Repeat("a", 4097),
		"dense raw bytes":     dense(400),
	} {
		expect(t, f.on(gw, public.ID, "create_refund", memoRefund(memo)), adomain.Deny, pipeline.ReasonDisclosureLimit)
	}
	for name, memo := range map[string]string{
		"base64 that fits": base64.StdEncoding.EncodeToString(random(3000)),
		"hex that fits":    hex.EncodeToString(random(2000)),
		"prose":            strings.Repeat("The customer was charged twice for the same order and asked for one refund. ", 40),
	} {
		ev := f.on(gw, public.ID, "create_refund", memoRefund(memo))
		if ev.Decision != adomain.AllowWithObligations {
			t.Fatalf("%s: %s (%s)", name, ev.Decision, ev.Decisive().Code)
		}
	}

	in := f.on(gw, internal.ID, "create_refund", memoRefund(dense(400)))
	expect(t, in, adomain.Allow, pipeline.ReasonGrantCovers)
	if _, ok := disclosureObligation(in); ok {
		t.Fatal("an internal destination carries disclosure limits")
	}
}
