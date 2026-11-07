// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/runs/app"
)

// instancePrincipal reads grants as the store does, but names an
// instance as their principal: the schema allows only users and service
// accounts, so this is the store returning what it must not.
type instancePrincipal struct{ s *grantspg.Store }

func (g instancePrincipal) GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id gdomain.GrantID) (gdomain.Grant, bool, error) {
	gr, found, err := g.s.GrantInTx(ctx, tx, org, id)
	gr.Principal = gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: ids.NewV7()}
	return gr, found, err
}

// TestHR744_APodRunActsOnlyForAUserOrAServiceAccount: a run grant whose
// principal is an instance starts no pod run, K8S_RUN_GRANT_PRINCIPAL
// (D973a, D1218 L3), and writes no run.
func TestHR744_APodRunActsOnlyForAUserOrAServiceAccount(t *testing.T) {
	w := newWorld(t)
	svc := app.New(w.pool).WithGrants(instancePrincipal{&grantspg.Store{Pool: w.pool}})
	agent := w.agent(t)
	inst := w.instance(t, agent, "ADMITTED")
	none := ids.UUID{}
	g := w.grant(t, agent, w.owner, none, none, "-1 hour", "2 hours", false)
	err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := svc.StartForWorkloadTx(ctx, tx, app.WorkloadStart{
			Org: w.org, AgentID: agent, Instance: inst.Instance, IssuerRevision: ids.NewV7(), IssuerEntry: ids.NewV7(),
			RunGrant: g, PodName: "probe-1",
		})
		return err
	})
	wantCode(t, "an instance principal", err, pcerr.FailedPrecondition, "K8S_RUN_GRANT_PRINCIPAL")
	if n := w.count(t, "SELECT count(*)::int FROM pc.runs WHERE org_id = $1", w.org); n != 0 {
		t.Errorf("%d runs written", n)
	}
}
