// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestHR640_ACustomRuleRaisesInferenceAtMost: whatever basis an older
// custom rule declared, its alerts are raised as INFERRED, so no automation
// contains on them; a built-in rule keeps its basis (D526 P6). Covers: F933
func TestHR640_ACustomRuleRaisesInferenceAtMost(t *testing.T) {
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	e := feed.Event{Org: ids.New[ids.Org](), Kind: "audit.security.kill_switch_engaged", OccurredAt: time.Now()}
	for _, tc := range []struct {
		id, edition string
		declared    reflexdomain.Basis
		want        reflexdomain.Basis
	}{
		{"org.kill", "business", reflexdomain.BasisObserved, reflexdomain.BasisInferred},
		{"org.kill", "business", reflexdomain.BasisRuleMatch, reflexdomain.BasisInferred},
		{"org.kill", "business", reflexdomain.BasisHypothesis, reflexdomain.BasisHypothesis},
		{"pc.test.kill", "community", reflexdomain.BasisObserved, reflexdomain.BasisObserved},
	} {
		none := "" // a built-in rule says techniques_none (G0 M28 D714)
		if strings.HasPrefix(tc.id, "pc.") {
			none = "techniques_none: A test rule.\n"
		}
		r, err := rules.Parse([]byte("id: " + tc.id + "\nversion: \"1\"\ntitle: Kill\ndescription: Custom.\nseverity: LOW\nattention: ALERT\n" +
			"basis: " + string(tc.declared) + "\nedition: " + tc.edition + "\n" + none + "on: [audit.security.kill_switch_engaged]\ntests: []\n"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := engine.Compile(env, r, "d", "")
		if err != nil {
			t.Fatal(err)
		}
		if got := engine.Signal(c, e, engine.Firing{Count: 1}).Basis; got != tc.want {
			t.Errorf("%s declaring %s raised %s, want %s", tc.id, tc.declared, got, tc.want)
		}
	}
}
