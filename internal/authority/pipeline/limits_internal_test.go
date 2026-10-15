// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestConsequenceLimitsFollowTheConfiguration: consequence rules use the
// decision policy's CEL limits, else the configured ones, else the
// defaults (G0 M4 decision 4), and each set of limits has its own
// evaluator.
func TestConsequenceLimitsFollowTheConfiguration(t *testing.T) {
	configured := celenv.Limits{MaxExpressionBytes: 512, MaxCost: 500, MaxComprehensionNesting: 1, EstimatedCollectionSize: 16}
	if got := (&Pipeline{}).consequenceLimits(&state{}); got != celenv.DefaultLimits {
		t.Errorf("unconfigured: %+v, want the defaults", got)
	}
	if got := (&Pipeline{Limits: configured}).consequenceLimits(&state{}); got != configured {
		t.Errorf("configured, no policy: %+v, want %+v", got, configured)
	}
	ofPolicy := celenv.Limits{MaxExpressionBytes: 1024, MaxCost: 2000, MaxComprehensionNesting: 2, EstimatedCollectionSize: 64}
	c, err := (&papp.Engine{Limits: ofPolicy}).Compile(&pdomain.Bundle{ID: "org-policy", Version: 1, Rules: []pdomain.Rule{{
		ID: "no-refunds", Kind: pdomain.Forbid, Summary: "no refunds", Operations: []string{"payments.refund.create"}, When: `true`, Reason: "NO_REFUNDS",
	}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &state{policy: &Policy{Compiled: c, Version: "org-policy@1"}}
	if got := (&Pipeline{Limits: configured}).consequenceLimits(s); got != ofPolicy {
		t.Errorf("with a policy: %+v, want the policy's %+v", got, ofPolicy)
	}
	first := evaluatorFor(configured)
	if first == evaluatorFor(ofPolicy) || first != evaluatorFor(configured) {
		t.Error("evaluators are not kept per set of limits")
	}
}
