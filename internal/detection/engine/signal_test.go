// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"crypto/sha256"
	"encoding/hex"
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
		r, err := rules.Parse([]byte("id: " + tc.id + "\nversion: \"1\"\ntitle: Kill\ndescription: Custom.\nseverity: LOW\nattention: ALERT\n" +
			"basis: " + string(tc.declared) + "\nedition: " + tc.edition + "\non: [audit.security.kill_switch_engaged]\ntests: []\n"))
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

// TestHR666_OnlyAConfirmedVersionRaisesRuleMatch: a custom rule raises
// RULE_MATCH only when its content matches the digest of the open two-person
// confirmation of its running version; without one, or with a confirmation
// of other content, it stays INFERRED (HR-640). Covers: F951
func TestHR666_OnlyAConfirmedVersionRaisesRuleMatch(t *testing.T) {
	env, err := engine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	src := "id: org.kill\nversion: \"1\"\ntitle: Kill\ndescription: Custom.\nseverity: LOW\nattention: ALERT\n" +
		"basis: INFERRED\nedition: business\non: [audit.security.kill_switch_engaged]\ntests: []\n"
	sum := sha256.Sum256([]byte(src))
	other := sha256.Sum256([]byte(src + "# edited"))
	e := feed.Event{Org: ids.New[ids.Org](), Kind: "audit.security.kill_switch_engaged", OccurredAt: time.Now()}
	for _, tc := range []struct {
		name      string
		confirmed []byte
		want      reflexdomain.Basis
	}{
		{"confirmed", sum[:], reflexdomain.BasisRuleMatch},
		{"unconfirmed", nil, reflexdomain.BasisInferred},
		{"confirmation of other content", other[:], reflexdomain.BasisInferred},
	} {
		c, err := engine.CustomRule(env, src, engine.Recorded{
			Stored: sum[:], Published: sum[:], LedgerPresent: true, Ledger: hex.EncodeToString(sum[:]), Confirmed: tc.confirmed,
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := engine.Signal(c, e, engine.Firing{Count: 1}).Basis; got != tc.want {
			t.Errorf("%s: raised %s, want %s", tc.name, got, tc.want)
		}
	}
	// A confirmation is the only way up: a rule that declares a confirmed
	// basis and has no confirmation stays INFERRED.
	declared := strings.Replace(src, "basis: INFERRED", "basis: RULE_MATCH", 1)
	ds := sha256.Sum256([]byte(declared))
	c, err := engine.CustomRule(env, declared, engine.Recorded{Stored: ds[:], Published: ds[:], LedgerPresent: true, Ledger: hex.EncodeToString(ds[:])})
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Signal(c, e, engine.Firing{Count: 1}).Basis; got != reflexdomain.BasisInferred {
		t.Errorf("a declared RULE_MATCH without a confirmation raised %s", got)
	}
}
