// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestHR684_SignalCarriesTheRulesTechniques: a firing's signal carries the
// rule's ATLAS and ATT&CK techniques, which the raiser stores on the alert
// (G0 M28 D718). Covers: F964, HR-684
func TestHR684_SignalCarriesTheRulesTechniques(t *testing.T) {
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rules.Parse([]byte("id: org.kill\nversion: \"1\"\ntitle: Kill\ndescription: Custom.\nseverity: LOW\nattention: ALERT\n" +
		"basis: INFERRED\nedition: business\natlas: [AML.T0053]\nattack: [T1552.001, T1078]\n" +
		"on: [audit.security.kill_switch_engaged]\ntests: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := engine.Compile(env, r, "d", "")
	if err != nil {
		t.Fatal(err)
	}
	e := feed.Event{Org: ids.New[ids.Org](), Kind: "audit.security.kill_switch_engaged", OccurredAt: time.Now()}
	s := engine.Signal(c, e, engine.Firing{Count: 1})
	if !slices.Equal(s.ATLAS, []string{"AML.T0053"}) || !slices.Equal(s.ATTACK, []string{"T1552.001", "T1078"}) {
		t.Errorf("signal atlas %v attack %v", s.ATLAS, s.ATTACK)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("signal: %v", err)
	}
}
