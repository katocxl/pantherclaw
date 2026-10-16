// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const sample = `
apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: Refund small tickets from Support.
work_kind: AGENT_WORK
review_by: "2026-12-01"
when:
  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
authority:
  principal: self
  ceiling:
    agents: [0192f000-0000-7000-8000-000000000003]
    bounds:
      operations: [payments.refund]
    per_grant:
      ttl: 1h
    per_day:
      grants: 5
      runs: 5
      budget:
        - currency: USD
          amount: "250.00"
do:
  - id: launch
    step: launch_run
    with:
      agent: 0192f000-0000-7000-8000-000000000003
      task_ref: "ticket {{params.ticket}}"
  - id: wait
    step: wait_run
    with:
      step: launch
    timeout: 2h
finish_when:
  - step: wait
    condition: RUN_ENDED
limits:
  deadline: 1d
`

func TestParseYAMLAndDigest(t *testing.T) {
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if d.When.Kind() != autodomain.TriggerInbound || d.Authority.Ceiling == nil || len(d.Do) != 2 {
		t.Fatalf("parsed %+v", d)
	}
	if got := d.Limits.DeadlineOrDefault(); got != 24*time.Hour {
		t.Errorf("deadline %s", got)
	}
	w, err := d.Do[0].DecodeWith()
	if err != nil {
		t.Fatal(err)
	}
	if lr, ok := w.(*autodomain.LaunchRunWith); !ok || lr.TaskRef != "ticket {{params.ticket}}" {
		t.Errorf("launch_run with = %#v", w)
	}
	c, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	// The canonical form parses back to the same digest.
	again, err := autodomain.Parse(c)
	if err != nil {
		t.Fatalf("canonical form: %v\n%s", err, c)
	}
	d1, _ := d.Digest()
	d2, _ := again.Digest()
	if !bytes.Equal(d1, d2) || len(d1) != 32 {
		t.Errorf("digest changed after a round trip: %x vs %x", d1, d2)
	}
}

func TestParseRefusesUnknownAndLooseInput(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field":      strings.Replace(sample, "purpose:", "color: red\npurpose:", 1),
		"unknown with field": strings.Replace(sample, "task_ref:", "shell: rm\n      task_ref:", 1),
		"wrong kind":         strings.Replace(sample, "kind: Automation", "kind: Workflow", 1),
		"anchor":             strings.Replace(sample, "purpose: Refund", "purpose: &a Refund", 1),
		"bad duration":       strings.Replace(sample, "ttl: 1h", "ttl: forever", 1),
		"bad uuid":           strings.Replace(sample, "source: 0192f000-0000-7000-8000-000000000002", "source: alice", 1),
	} {
		if _, err := autodomain.Parse([]byte(doc)); !errors.Is(err, autodomain.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestCatalogIsClosedAndConsistent: every D3 kind decodes an empty with,
// names only catalog permissions, and the finish vocabulary is reachable.
func TestCatalogIsClosedAndConsistent(t *testing.T) {
	if n := len(autodomain.Kinds()); n != 25 {
		t.Errorf("catalog has %d kinds, want 25", n)
	}
	reach := map[autodomain.FinishCondition]bool{}
	for _, k := range autodomain.Kinds() {
		spec := autodomain.Catalog[k]
		if spec.Kind != k {
			t.Errorf("%s: spec names %s", k, spec.Kind)
		}
		if _, err := spec.DecodeWith(nil); err != nil {
			t.Errorf("%s: empty with: %v", k, err)
		}
		if _, err := spec.DecodeWith([]byte(`{"nope":1}`)); err == nil {
			t.Errorf("%s: unknown with member accepted", k)
		}
		for _, p := range spec.ConfirmerPermissions {
			if !td.Permission(p).Known() {
				t.Errorf("%s: confirmer permission %q is not in the catalog", k, p)
			}
		}
		if spec.DeciderPermission != "" && !td.Permission(spec.DeciderPermission).Known() {
			t.Errorf("%s: decider permission %q unknown", k, spec.DeciderPermission)
		}
		if (len(spec.ConfirmerPermissions) == 0) != (spec.ConfirmAt == autodomain.ConfirmNone) {
			t.Errorf("%s: confirmer permissions without a scope, or a scope without them", k)
		}
		for _, c := range spec.Finishes {
			reach[c] = true
		}
	}
	for _, c := range autodomain.FinishConditions() {
		if !reach[c] {
			t.Errorf("finish condition %s is satisfied by no kind", c)
		}
	}
	if autodomain.Catalog[autodomain.KindContain].Edition != autodomain.EditionBusiness {
		t.Error("contain must need Business (F562)")
	}
}

func TestParamConvert(t *testing.T) {
	str := autodomain.ParamSpec{Type: autodomain.ParamString, Pattern: "T-[0-9]+"}
	if v, err := str.Convert("t", "T-12"); err != nil || v.Text() != "T-12" {
		t.Errorf("string: %v %v", v, err)
	}
	for _, bad := range []any{"T-12; drop", 12.0, true, strings.Repeat("T-1", 30)} {
		if _, err := str.Convert("t", bad); !errors.Is(err, autodomain.ErrParam) {
			t.Errorf("string %v accepted", bad)
		}
	}
	dec := autodomain.ParamSpec{Type: autodomain.ParamDecimal, Min: "0", Max: "50.00"}
	if v, err := dec.Convert("a", "12.50"); err != nil || v.Decimal != "12.5" && v.Decimal != "12.50" {
		t.Errorf("decimal: %v %v", v, err)
	}
	if _, err := dec.Convert("a", "50.01"); !errors.Is(err, autodomain.ErrParam) {
		t.Error("decimal above max accepted")
	}
	enum := autodomain.ParamSpec{Type: autodomain.ParamEnum, Values: []string{"low", "high"}}
	if _, err := enum.Convert("e", "medium"); !errors.Is(err, autodomain.ErrParam) {
		t.Error("enum outside values accepted")
	}
	id := autodomain.ParamSpec{Type: autodomain.ParamUUID}
	if _, err := id.Convert("u", "not-a-uuid"); !errors.Is(err, autodomain.ErrParam) {
		t.Error("bad uuid accepted")
	}
}

func TestDuration(t *testing.T) {
	var d autodomain.Duration
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "90s": 90 * time.Second, "24h": 24 * time.Hour} {
		if err := d.UnmarshalText([]byte(in)); err != nil || d.D() != want {
			t.Errorf("%s: %v %v", in, d.D(), err)
		}
	}
	for _, bad := range []string{"0d", "-1h", "1.5d", "x"} {
		if err := d.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	b, _ := autodomain.Duration(48 * time.Hour).MarshalText()
	if string(b) != "2d" {
		t.Errorf("48h marshals as %s", b)
	}
}
