// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/server"
)

// The UI phase's range steps (G0 UI D16; RT-062..RT-064): the stack runs
// with hosted plans (billing.mode external, the plan gate on) and the
// org starts on an active Business plan.

const capBilling = app.Capability("billing")

// uiStep runs plan.event, person.rpc and config.check; ok is false for
// any other kind.
func (d *rangeDriver) uiStep(st domain.Step) (domain.Observation, bool, error) {
	switch st.Do {
	case "plan.event":
		obs, err := d.planEvent(st)
		return obs, true, err
	case "person.rpc":
		obs, err := d.personRPC(st)
		return obs, true, err
	case "config.check":
		obs, err := d.configCheck(st)
		return obs, true, err
	case "api.flood":
		obs, err := d.apiFlood(st)
		return obs, true, err
	}
	return domain.Observation{}, false, nil
}

// plans is the plan writer the billing extension gets, over the stack's
// database.
func (d *rangeDriver) plans() *entitlements.Service { return hostedPlans(d.t, d.s.pool) }

func hostedPlans(t *testing.T, pool *db.Pool) *entitlements.Service {
	t.Helper()
	s, err := entitlements.New(pool, entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) {
		return billing.CommunityEntitlements(), nil
	}), entitlements.ModeExternal, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// activePlan gives org an active Business plan, as a completed checkout
// would, before anything of the stack calls the API.
func activePlan(t *testing.T, pool *db.Pool, org ids.OrgID) {
	t.Helper()
	if err := hostedPlans(t, pool).ApplyPlan(context.Background(), org, entitlements.Snapshot{
		PlanID: "business", Edition: "business", Status: entitlements.StatusActive,
		EventID: "evt_range_setup", EventAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
}

// setupBilling starts the scenario's plan events afresh.
func (d *rangeDriver) setupBilling() { d.planEvents = 0 }

// planEvent reports one plan event as the billing extension does.
func (d *rangeDriver) planEvent(st domain.Step) (domain.Observation, error) {
	var w struct {
		Status  string `json:"status"`
		Edition string `json:"edition"`
		Age     string `json:"age"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if w.Edition == "" {
		w.Edition = "business"
	}
	d.planEvents++
	at := time.Now()
	if w.Age == "older" {
		at = at.Add(-time.Hour)
	}
	svc := d.plans()
	ctx := context.Background()
	err := svc.ApplyPlan(ctx, d.s.org, entitlements.Snapshot{
		PlanID: w.Edition, Edition: w.Edition, Status: entitlements.Status(w.Status),
		EventID: fmt.Sprintf("evt_range_%s_%d", st.ID, d.planEvents), EventAt: at,
	})
	if err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: pcerr.ReasonOf(err), Detail: err.Error()}, nil
	}
	p, err := svc.Plan(ctx, d.s.org)
	if err != nil {
		return domain.Observation{}, err
	}
	if string(p.Status) == w.Status {
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "plan " + string(p.Status)}, nil
	}
	var kind string
	d.s.query(d.t, "SELECT kind FROM pc.entitlement_events WHERE org_id = $1 ORDER BY received_at DESC LIMIT 1", []any{d.s.org}, &kind)
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: kind, Detail: "plan stays " + string(p.Status)}, nil
}

// personRPC asks the plan gate about a person's call, as the server's
// authentication layer does after the permission check (HR-356). A
// procedure no proto declares is not served at all.
func (d *rangeDriver) personRPC(st domain.Step) (domain.Observation, error) {
	var w struct {
		Procedure string `json:"procedure"`
		As        string `json:"as"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	declared, err := protoperms.Declared(filepath.Join("..", "..", "proto"))
	if err != nil {
		return domain.Observation{}, err
	}
	if _, ok := declared[w.Procedure]; !ok {
		return domain.Observation{Outcome: domain.OutcomeNotFound, Detail: "not served"}, nil
	}
	gate := entitlements.NewGate(d.plans(), true, server.ProcedureClass)
	if err := gate.Check(context.Background(), d.s.org, w.Procedure); err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: pcerr.ReasonOf(err), Detail: err.Error()}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: server.ProcedureClass(w.Procedure).String()}, nil
}

// configCheck validates a server configuration as start-up does.
func (d *rangeDriver) configCheck(st domain.Step) (domain.Observation, error) {
	var w struct {
		Deployment  string `json:"deployment"`
		BillingMode string `json:"billing_mode"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	c := server.DefaultConfig()
	c.DB.AppPasswordFile, c.KEKFiles = "pw", []string{"kek"}
	c.Deployment, c.Billing.Mode = w.Deployment, w.BillingMode
	switch err := c.Validate(); {
	case err == nil:
		return domain.Observation{Outcome: domain.OutcomeAllow}, nil
	case strings.Contains(err.Error(), "DEPLOYMENT_CONFIG"):
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "DEPLOYMENT_CONFIG", Detail: err.Error()}, nil
	default:
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "INVALID_CONFIG", Detail: err.Error()}, nil
	}
}
