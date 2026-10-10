// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"strings"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
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

// seedHoldPolicy publishes devHoldBundle for org, compiled against its
// active definitions like any version. dev seed is the author and
// publisher of record.
func seedHoldPolicy(ctx context.Context, pool *db.Pool, org ids.OrgID, limit money.Money) (ids.UUID, error) {
	b := devHoldBundle(limit)
	catalog, err := (&factspg.Store{Pool: pool}).Catalog(ctx, org)
	if err != nil {
		return ids.UUID{}, err
	}
	ds, err := (&defspg.Store{Pool: pool}).ActiveDefinitions(ctx, org)
	if err != nil {
		return ids.UUID{}, err
	}
	if _, err := (&policyapp.Engine{Limits: celenv.DefaultLimits, Facts: catalog}).Compile(b, ds); err != nil {
		return ids.UUID{}, fmt.Errorf("dev seed: hold policy: %w", err)
	}
	store := &polpg.Store{Pool: pool}
	object := &audit.Object{Type: "policy", ID: b.ID}
	id, _, err := store.CreateVersion(ctx, org, b, devSeedActor.ID, &audit.Event{
		Name: "policy.version_created", Actor: devSeedActor, Outcome: audit.Success, Object: object,
	})
	if err != nil {
		return ids.UUID{}, fmt.Errorf("dev seed: hold policy: %w", err)
	}
	if err := store.Publish(ctx, org, id, devSeedActor.ID, &audit.Event{
		Name: "policy.published", Actor: devSeedActor, Outcome: audit.Success, Object: object,
	}); err != nil {
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
