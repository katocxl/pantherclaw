// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

func routeDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/v2_route.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestV2ParsesToNodes: a v2 document parses, its steps are in execution
// order, and its stored form holds nodes only and parses to the same digest.
//
// Covers: F678
func TestV2ParsesToNodes(t *testing.T) {
	d, err := autodomain.Parse([]byte(routeDoc(t)))
	if err != nil {
		t.Fatal(err)
	}
	if !d.IsV2() || len(d.Nodes) != 9 || d.Flow().Entry != "route" {
		t.Fatalf("parsed %+v", d)
	}
	var steps []string
	for _, s := range d.Do {
		steps = append(steps, s.ID)
	}
	if !slices.Equal(steps, []string{"approve", "log", "tell", "record", "file"}) {
		t.Errorf("steps %v", steps)
	}
	if n := d.Flow().Node("route"); n.Kind() != autodomain.NodeKindSwitch || len(n.Edges()) != 3 || n.Edges()[2].Label != "default" {
		t.Errorf("route = %+v", n)
	}
	c, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(c, []byte(`"do":[]`)) {
		t.Errorf("canonical %s", c)
	}
	again, err := autodomain.Parse(c)
	if err != nil {
		t.Fatalf("canonical form: %v\n%s", err, c)
	}
	d1, _ := d.Digest()
	d2, _ := again.Digest()
	if !bytes.Equal(d1, d2) {
		t.Fatal("the stored form parses to another digest")
	}
	if len(again.Do) != 5 {
		t.Errorf("reparsed steps %d", len(again.Do))
	}
}

// TestV1IsLiftedToALine: a v1 definition reads as a line of its steps to
// one terminal holding finish_when, in memory only.
//
// Covers: F678
func TestV1IsLiftedToALine(t *testing.T) {
	d, err := autodomain.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	f := d.Flow()
	if f.Entry != "launch" || len(f.Nodes) != 3 || f.Node("launch").Next != "wait" || f.Node("wait").Next != autodomain.EndNode {
		t.Fatalf("flow %+v", f)
	}
	end := f.Node(autodomain.EndNode)
	if end.Kind() != autodomain.NodeKindTerminal || len(end.FinishWhen) != 1 || end.Outcome != autodomain.OutcomeSucceeded {
		t.Errorf("end %+v", end)
	}
	if c, _ := d.Canonical(); bytes.Contains(c, []byte("nodes")) {
		t.Errorf("the lift reached the stored form: %s", c)
	}
}

// TestHR530_FormatsStayApart: v1 refuses what only v2 has, as it always
// refused unknown fields, and v2 refuses v1's sections.
//
// Covers: F678
func TestHR530_FormatsStayApart(t *testing.T) {
	route := routeDoc(t)
	for _, tc := range []struct{ name, doc string }{
		{"nodes in v1", strings.Replace(sample, "limits:\n", "nodes:\n  - id: a\n    outcome: FAILED\nlimits:\n", 1)},
		{"compensates in v1", strings.Replace(sample, "limits:\n", "if_fails:\n  compensate:\n    - id: u\n      step: revoke_grant\n      compensates: launch\nlimits:\n", 1)},
		{"do in v2", route + "do:\n  - id: a\n    step: wait\n"},
		{"finish_when in v2", route + "finish_when:\n  - step: approve\n    condition: APPROVAL_RESOLVED\n"},
		{"two kinds in one node", strings.Replace(route, "    next: approved\n", "    next: approved\n    outcome: FAILED\n", 1)},
		{"step field on a switch", strings.Replace(route, "  - id: route\n", "  - id: route\n    timeout: 1h\n", 1)},
		{"unknown node field", strings.Replace(route, "  - id: route\n", "  - id: route\n    loop: true\n", 1)},
		{"unknown version", strings.Replace(route, "dev/v2", "dev/v3", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := autodomain.Parse([]byte(tc.doc)); !errors.Is(err, autodomain.ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
