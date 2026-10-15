// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// restore lifts the run's DENY_ALL and a HOLD_WRITES on its agent through a
// two-stage restoration plan (Team, F564, F568, HR-250). The requester may
// not decide it; an independent reviewer approves it, and each stage's test
// actions are replayed by the server's replay engine (a dry run, never
// dispatched) before its controls are lifted. It runs in-process: over the
// API the decision needs a browser step-up (D58).
func (r *reflexStack) restore(t *testing.T, response pantherclawv1connect.ResponseServiceClient, runAction, refundTxn string) {
	t.Helper()
	ctx, s := context.Background(), r.s
	held, err := response.Contain(ctx, &pantherclawv1.ContainRequest{
		Scope: &pantherclawv1.ResponseSubject{Type: "agent", Id: r.agent.String()}, Control: "HOLD_WRITES", Reason: "hold writes while restoring",
	})
	if err != nil {
		t.Fatalf("hold the agent's writes: %v", err)
	}
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	// The replay engine as the server wires it (wiring_replay.go).
	engine := &replay.Engine{
		Source: &pgauthority.ReplaySource{Pool: s.pool, Definitions: &defspg.Store{Pool: s.pool}, FactStore: &factspg.Store{Pool: s.pool}},
		Inputs: recording.NewSealer(pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp))),
	}
	c := &rapp.Containment{Pool: s.pool, Raiser: &alerts.Raiser{}, Failures: &failures.Sink{}, Editions: ents{billing.Team}}
	reviewer := s.person(t, "reviewer", td.RoleSecurityAdmin)
	reviewerID := mustUUID(t, s.row(t, "SELECT user_id::text FROM pc.webauthn_credentials WHERE id = $1", reviewer.key))
	control := func(ctx context.Context, tx db.TenantTx, action string) (ids.UUID, error) {
		cs, err := dbq.New(tx).ControlsOfAction(ctx, s.org, mustUUID(t, action))
		if err != nil {
			return ids.UUID{}, err
		}
		if len(cs) != 1 {
			return ids.UUID{}, errors.New("the action holds no single control")
		}
		return cs[0].ID, nil
	}
	refund := mustUUID(t, refundTxn)
	var plan ids.UUID
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		runCtl, err := control(ctx, tx, runAction)
		if err != nil {
			return err
		}
		agentCtl, err := control(ctx, tx, held.GetActionId())
		if err != nil {
			return err
		}
		plan, _, err = c.RequestRestorationIn(ctx, tx, rapp.RestorationRequest{
			Controls: []ids.UUID{runCtl, agentCtl}, Reason: "investigated", Requester: r.aliceID,
			Stages: []rapp.StageSpec{
				// Stage 1 lifts the hold: the refund stays refused while the run
				// is still contained.
				{Controls: []ids.UUID{agentCtl}, Tests: []rapp.TestAction{{Transaction: refund, Evaluation: 1, Expect: rapp.ExpectProhibited}}},
				// Stage 2 lifts the run's control: the refund is allowed again.
				{Controls: []ids.UUID{runCtl}, Tests: []rapp.TestAction{{Transaction: refund, Evaluation: 1, Expect: rapp.ExpectPermitted}}},
			},
		})
		return err
	}); err != nil {
		t.Fatalf("request restoration: %v", err)
	}
	decide := func(reviewer ids.UUID) error {
		return s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			_, _, err := c.DecideRestorationIn(ctx, tx, plan, reviewer, true)
			if errors.Is(err, rapp.ErrPreconditions) {
				return nil
			}
			return err
		})
	}
	if err := decide(r.aliceID); !errors.Is(err, rapp.ErrReviewerNotIndependent) {
		t.Fatalf("the requester decides their own restoration: %v", err)
	}
	if err := decide(reviewerID); err != nil {
		t.Fatalf("approve the plan: %v", err)
	}
	active := func() string {
		return s.row(t, "SELECT count(*)::text FROM pc.containment_controls WHERE lifted_at IS NULL AND scope_id IN ($1, $2)",
			s.run, r.agent.String())
	}
	if n := active(); n != "2" {
		t.Fatalf("approving a staged plan lifted controls before its stages: %s left", n)
	}
	apply := func(ordinal int32) string {
		var sp rapp.StagePlan
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			sp, err = c.StageToApply(ctx, tx, plan, ordinal)
			return err
		}); err != nil {
			t.Fatalf("stage %d: %v", ordinal, err)
		}
		results, passed, err := rapp.RunStageTests(ctx, engine, s.org, sp)
		if err != nil || !passed {
			t.Fatalf("stage %d tests: %+v %v", ordinal, results, err)
		}
		var state string
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			state, err = c.ApplyStageIn(ctx, tx, sp, reviewerID, results, passed)
			return err
		}); err != nil {
			t.Fatalf("apply stage %d: %v", ordinal, err)
		}
		return state
	}
	if state := apply(1); state != rapp.PlanStaging || active() != "1" {
		t.Fatalf("after stage 1: %s, %s controls left", state, active())
	}
	if state := apply(2); state != rapp.PlanCompleted || active() != "0" {
		t.Fatalf("after stage 2: %s, %s controls left", state, active())
	}
	// The run acts again.
	if code, rep := s.refund(t, ids.NewV7(), "1.00"); code != http.StatusOK {
		t.Fatalf("a refund after restoration: %d %+v", code, rep)
	}
}
