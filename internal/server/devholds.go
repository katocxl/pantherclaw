// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// devHoldReason is the reason of the seeded hold (S02).
const devHoldReason = "REFUND_NEEDS_APPROVAL"

// devHoldBundle is the development policy: refunds over limit need one
// approver (G0 M5 part 2, S02).
func devHoldBundle(limit money.Money) *pdomain.Bundle {
	amount, _ := strings.CutSuffix(limit.String(), " "+string(limit.Currency))
	return &pdomain.Bundle{ID: "dev-holds", Version: 1, Rules: []pdomain.Rule{{
		ID: "approve-large-refunds", Kind: pdomain.RequireApproval, Summary: "refunds over " + limit.String() + " need an approver",
		Operations: []string{"payments.refund.create"},
		When:       fmt.Sprintf("action.params.amount > money(%q, %q)", amount, string(limit.Currency)),
		Reason:     devHoldReason, Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}}}
}

// seedHoldPolicy publishes devHoldBundle for org through the publish gate
// like any version (G0 M11.1 design decision 10): compiled, validated and
// tested against its active definitions. dev seed is the author and
// publisher of record.
func seedHoldPolicy(ctx context.Context, pool *db.Pool, org ids.OrgID, limit money.Money) (ids.UUID, error) {
	id, err := newPolicyVersions(pool, nil, "").Seed(ctx, org, devHoldBundle(limit), devSeedActor)
	if err != nil {
		return ids.UUID{}, fmt.Errorf("dev seed: hold policy: %w", err)
	}
	return id, nil
}

// approverSteps tells how a person becomes the org's approver through the
// ordinary flows: dev seed never creates a person or a role binding. The
// approval cooldowns (account, role and key ages) apply as everywhere.
func approverSteps(publicURL string, org ids.OrgID) string {
	return fmt.Sprintf(`an approver approves in the browser at %s/approvals?org=%s; to make one:
  pantherclaw-server org admin-invite --org %s           # then sign in as alice with: pclaw login --invitation <token>
  pclaw invite create --email bob@example.test --role approver   # bob signs in with that token, then adds a security key at /account
approvals count only from people whose account is 7 days old and whose role and key are 1 day old (G0 M5 part 2, decision 5)
`, publicURL, org, org)
}
