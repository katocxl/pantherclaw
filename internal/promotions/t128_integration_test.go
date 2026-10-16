// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package promotions_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/promotions/promotionsrpc"
	"github.com/katocxl/pantherclaw/internal/promotions/promotiontest"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// TestT128_TheAPICannotPromote: PromoteAgent over the API carries no
// step-up, so it is refused STEP_UP_REQUIRED even for a person holding
// fleet_manager on a browser session whose checks all pass (D53).
func TestT128_TheAPICannotPromote(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	_, err := promotionsrpc.New(w.svc).PromoteAgent(p.Ctx, &pantherclawv1.PromoteAgentRequest{
		AgentId: w.agent.String(), EnvironmentId: w.prod.String(), Operations: []string{refund},
		FailureBehavior: pantherclawv1.FailureBehavior_FAILURE_BEHAVIOR_FAIL_CLOSED,
	})
	if !stepup.Is(err) {
		t.Fatalf("PromoteAgent over the API: %v, want STEP_UP_REQUIRED", err)
	}
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "after the API call", err)
}

// TestT128_OnlyTheAgentsOwnActivePromotionCovers: a promotion of another
// agent, of another org's agent, a revoked one, or one of a narrower
// prefix never covers a production grant.
func TestT128_OnlyTheAgentsOwnActivePromotionCovers(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	w, other := newOrg(t, p), newOrg(t, p)
	promotiontest.Promote(t, other.scope, refund)
	_, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "another org's agent is promoted", err)

	sibling := promotiontest.Scope{Pool: p, Org: w.org, Agent: ids.NewV7(), Env: w.prod, Connection: w.conn}
	w.exec(`INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		SELECT org_id, $2, 'sibling', team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at
		FROM pc.agents WHERE org_id = $1 AND id = $3`, w.org, sibling.Agent, w.agent)
	w.exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'discovery')`, w.org, ids.NewV7(), sibling.Agent, strings.Repeat("s", 43))
	promotiontest.Promote(t, sibling, refund)
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "another agent of the org is promoted", err)

	promotiontest.Record(t, w.scope, refund)
	ps := promotiontest.Promote(t, w.scope, "payments.refund.*")
	_, err = w.issue(w.agent, `{"operations": ["payments.*"]}`)
	notPromoted(t, "a grant wider than the promoted prefix", err)
	if _, err := w.issue(w.agent, `{"operations": ["payments.refund.create"]}`); err != nil {
		t.Fatalf("an operation under the promoted prefix: %v", err)
	}
	pr := promotiontest.NewPromoter(t, w.scope)
	if _, err := w.svc.RevokePromotion(pr.Ctx, ps[0].ID, "incident"); err != nil {
		t.Fatal(err)
	}
	_, err = w.issue(w.agent, `{"operations": ["payments.refund.create"]}`)
	notPromoted(t, "a revoked promotion", err)
}

// compromised marks every person compromised.
type compromised struct{}

func (compromised) Compromised(context.Context, db.TenantTx, ids.OrgID, ids.UUID) (bool, error) {
	return true, nil
}

// TestT128_ACompromisedPersonCannotPromote: a person marked compromised is
// refused even with a fresh step-up and passing checks (D43).
func TestT128_ACompromisedPersonCannotPromote(t *testing.T) {
	w := newWorld(t)
	promotiontest.Record(t, w.scope, refund)
	p := promotiontest.NewPromoter(t, w.scope)
	svc := &promotions.Service{Pool: w.pool, Compromise: compromised{}}
	_, err := svc.PromoteAgent(p.Ctx, promotions.PromoteInput{
		Agent: w.agent, Environment: w.prod, Operations: []string{refund}, FailureBehavior: promotions.FailClosed,
	}, p.StepUp())
	if !errors.Is(err, promotions.ErrCompromised) {
		t.Fatalf("a compromised promoter: %v", err)
	}
}
