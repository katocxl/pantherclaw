// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pack

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/detection/rules"
)

// TestHR711_ConfigChangedRaisesOneAlertOnly: pc.agent.config_changed fires
// on agent.config_changed, as an alert on an observed fact (a digest
// changed) that contains nothing, in Community; a discovery change does
// not fire it (G0 M30 D941, founder answer C).
func TestHR711_ConfigChangedRaisesOneAlertOnly(t *testing.T) {
	changed := rules.TestEvent{
		Kind: "audit.agent.config_changed", Subjects: map[string]string{"agent": "a1"},
		Attrs: map[string]string{"client": "claude_code", "scope": "project", "path_class": "hooks", "old_digest": "1", "new_digest": "2"},
	}
	if !fires(t, "pc.agent.config_changed", changed) {
		t.Error("a changed digest did not fire")
	}
	if fires(t, "pc.agent.config_changed", rules.TestEvent{Kind: "audit.agent.discovery_changed", Subjects: map[string]string{"agent": "a1"}}) {
		t.Error("a discovery change fired")
	}
	p, err := Load(env(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Rules {
		if c.Rule.ID != "pc.agent.config_changed" {
			continue
		}
		if r := c.Rule; r.Attention != "ALERT" || r.Basis != "OBSERVED" || r.Edition != "community" {
			t.Fatalf("rule %s: attention %s, basis %s, edition %s", r.ID, r.Attention, r.Basis, r.Edition)
		}
		return
	}
	t.Fatal("pc.agent.config_changed is not in the pack")
}
