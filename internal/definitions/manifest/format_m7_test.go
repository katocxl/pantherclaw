// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR124_VerifierFieldsAreReviewedAndStrict: the M7 verifier fields
// decode into the definition (and so into its digest), and every malformed
// or unsafe form is refused (G0 M7 design decision 5).
func TestHR124_VerifierFieldsAreReviewedAndStrict(t *testing.T) {
	raw := readMock(t)
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := p.Definition("payments.refund.create")
	v := create.Verifier
	if !v.Extended() || v.Reaches() != domain.LevelFollowUp || v.RequiredLevel() != domain.LevelAcceptance ||
		v.Reference.FromResponse != "/id" || v.Lookup.Operation != "payments.refund.list" || v.Lookup.List.Correlate != "/idempotency_key" ||
		len(v.Expect) != 3 || v.States.Field != "/status" || v.Limits == "" {
		t.Fatalf("verifier %+v", v)
	}
	if t0 := p.TargetLogs[0]; t0.Operation != "payments.refund.recent" || t0.EffectOf != "payments.refund.create" ||
		t0.SinceParam != "created_gte" || t0.List.Created != "/created" {
		t.Fatalf("target log %+v", t0)
	}
	if list, _ := p.Definition("payments.refund.list"); len(list.Mappings) != 0 || list.Dispatch.HTTP.Query["charge"] != "target.id" {
		t.Fatalf("payments.refund.list %+v", list)
	}

	for name, change := range map[string][2]string{
		"not a pointer":              {"from_response: /id", "from_response: id"},
		"a pointer with a space":     {"correlate: /idempotency_key\n          more", "correlate: /idempotency key\n          more"},
		"an unknown level":           {"level: follow_up", "level: settled"},
		"required above the level":   {"level: follow_up", "level: follow_up\n      required: domain_effect"},
		"an unknown verifier field":  {"level: follow_up", "level: follow_up\n      retries: 3"},
		"expect from untrusted text": {"equals: target.id", "equals: params.note"},
		"expect a whole money param": {"equals: params.amount.value", "equals: params.amount"},
		"one field expected twice":   {"field: /amount", "field: /charge"},
		"no confirmed status":        {"confirmed: [succeeded]", "confirmed: []"},
		"a status in two lists":      {"pending: [pending]", "pending: [succeeded]"},
		"a lookup that is a write":   {"operation: payments.refund.list\n        list:", "operation: payments.refund.create\n        list:"},
		"a lookup of another target": {"operation: payments.refund.list\n        list:", "operation: payments.refund.get\n        list:"},
		"a required page param":      {"      starting_after:\n        type: identifier\n        pattern: '^re_[A-Za-z0-9-]{1,64}$'\n    effects:\n      - kind: none\n        description: Reads only\n    reversibility: reversible\n    retry:\n      safe: true\n      on_unknown: fail\n    assurance:\n      basis: declared\n      reviewed_by: [pantherclaw-maintainers]\n      valid_until: 2027-10-08\n    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds\n        query:\n          charge", "      starting_after:\n        type: identifier\n        required: true\n        pattern: '^re_[A-Za-z0-9-]{1,64}$'\n    effects:\n      - kind: none\n        description: Reads only\n    reversibility: reversible\n    retry:\n      safe: true\n      on_unknown: fail\n    assurance:\n      basis: declared\n      reviewed_by: [pantherclaw-maintainers]\n      valid_until: 2027-10-08\n    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds\n        query:\n          charge"},
		"a page param without more":  {"more: /has_more\n          page_param: starting_after\n      expect", "page_param: starting_after\n      expect"},
		"a bad query name":           {"charge: target.id\n          starting_after", "charge-id: target.id\n          starting_after"},
		"money in a query":           {"charge: target.id\n          starting_after", "charge: params.amount.value\n          starting_after"},
		"a target log of a charge":   {"type: pc.connection", "type: payments.charge"},
		"a target log of a read":     {"effect_of: payments.refund.create", "effect_of: payments.refund.get"},
		"a since param in no unit":   {"since_param: created_gte", "since_param: starting_after"},
		"a target log without dates": {"      created: /created\n", ""},
		"an unused internal read":    {"target_logs:\n  - operation: payments.refund.recent", "target_logs:\n  - operation: payments.refund.list"},
	} {
		if _, err := Decode(mutate(t, raw, change[0], change[1])); !errors.Is(err, domain.ErrInvalid) && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR124_PackagesBeforeM7StayValid: format 1 changes are additive. A
// verifier without the M7 fields is checked as before, even when its read
// has no dispatch template or reads another kind of target, and runs
// nothing (its effects are UNVERIFIABLE).
func TestHR124_PackagesBeforeM7StayValid(t *testing.T) {
	raw := readMock(t)
	const m7 = "      level: follow_up\n"
	start := indexOf(t, raw, m7)
	end := indexOf(t, raw, "    approval:")
	old := append(append([]byte{}, raw[:start]...), raw[end:]...)
	// Without the lookup the internal list read is unused: drop it and the
	// target log with it, as a pre-M7 package would not have them.
	old = old[:indexOf(t, old, "\n  # Internal reads")+1]
	p, err := Decode(old)
	if err != nil {
		t.Fatal(err)
	}
	create, _ := p.Definition("payments.refund.create")
	if create.Verifier.Extended() || create.Verifier.Operation != "payments.refund.get" {
		t.Fatalf("verifier %+v", create.Verifier)
	}
}

// TestHR190_APackagesHTTPReadsAreTheReadsAGatewayCanMake: a connection to
// a package serves, for a verifier, exactly its reads with an HTTP GET
// template, never a write (G0 M7 design decision 2, F497).
func TestHR190_APackagesHTTPReadsAreTheReadsAGatewayCanMake(t *testing.T) {
	p, err := Decode(readMock(t))
	if err != nil {
		t.Fatal(err)
	}
	got := p.HTTPReads()
	want := []string{"payments.refund.get", "payments.refund.list", "payments.refund.recent"}
	if len(got) != len(want) {
		t.Fatalf("reads %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reads %v, want %v", got, want)
		}
	}
}

func indexOf(t *testing.T, raw []byte, s string) int {
	t.Helper()
	for i := 0; i+len(s) <= len(raw); i++ {
		if string(raw[i:i+len(s)]) == s {
			return i
		}
	}
	t.Fatalf("the package has no %q", s)
	return -1
}
