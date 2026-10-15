// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// viewer sees the listed agents, and credential rights only at org scope.
type viewer struct {
	agents map[ids.UUID]bool
	org    bool
}

func (v viewer) Agent(_ context.Context, a ids.UUID) (bool, error) { return v.agents[a], nil }
func (v viewer) Org() bool                                         { return v.org }

func recompute(t *testing.T, o *exposuretest.Org) app.Recomputed {
	t.Helper()
	var rec app.Recomputed
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rec, err = app.Recompute(ctx, tx, "manual", 0)
		return err
	})
	return rec
}

func current(t *testing.T, o *exposuretest.Org, v app.Viewer, f domain.Filter) app.View {
	t.Helper()
	var out app.View
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = app.Current(ctx, tx, v, f)
		return err
	})
	return out
}

func has(rs []domain.Right, view domain.View, agent *ids.UUID, op string, verb domain.Verb) (domain.Right, bool) {
	i := slices.IndexFunc(rs, func(r domain.Right) bool {
		return r.View == view && r.Operation == op && r.Verb == verb &&
			((agent == nil) == (r.Agent == nil)) && (agent == nil || *agent == *r.Agent)
	})
	if i < 0 {
		return domain.Right{}, false
	}
	return rs[i], true
}

// TestIntRecomputeStoresThreeViews: a recomputation over the org's grants,
// connections, credential and dispatches stores the three views apart,
// with the credential's unknown scope as UNCERTAIN; a read returns the
// same rights; a change recorded afterwards marks the snapshot stale.
func TestIntRecomputeStoresThreeViews(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 1, "", "payments.*")
	o.Credential(t, "1 day")
	o.Dispatch(t, "payments.refund.get")

	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := app.Current(ctx, tx, viewer{org: true}, domain.Filter{})
		if !errors.Is(err, app.ErrNoSnapshot) {
			t.Errorf("before any snapshot: %v", err)
		}
		return nil
	})
	rec := recompute(t, o)
	if rec.Snapshot.Rights != len(rec.Rights) || rec.Snapshot.Truncated || len(rec.Snapshot.Digest) != 32 {
		t.Fatalf("snapshot: %+v", rec.Snapshot)
	}
	all := current(t, o, viewer{org: true, agents: map[ids.UUID]bool{o.Agent: true, o.Other: true}}, domain.Filter{})
	if len(all.Rights) != len(rec.Rights) || all.Snapshot.ID != rec.Snapshot.ID || all.Snapshot.Stale || all.Restricted {
		t.Fatalf("read back %d of %d rights, %+v", len(all.Rights), len(rec.Rights), all.Snapshot)
	}
	if !slices.Equal(app.Digest(all.Rights), rec.Snapshot.Digest) {
		t.Fatal("stored rights differ from the computed ones")
	}
	r, ok := has(all.Rights, domain.Effective, &o.Agent, "payments.refund.create", domain.VerbTransfer)
	if !ok || r.Label != domain.Usable || r.Coverage != domain.CoverageUnknown || r.Grant == nil {
		t.Fatalf("effective refund: %+v %v", r, ok)
	}
	if _, ok := has(all.Rights, domain.Effective, &o.Agent, "", domain.VerbDelegate); !ok {
		t.Fatal("delegable grant has no delegate right")
	}
	if r, ok := has(all.Rights, domain.Observed, &o.Agent, "payments.refund.get", domain.VerbRead); !ok || r.Observations != 1 {
		t.Fatalf("observed: %+v %v", r, ok)
	}
	if r, ok := has(all.Rights, domain.Credential, nil, "", domain.VerbDelete); !ok || r.Label != domain.Uncertain ||
		r.ResourceGroup != "credential:payments" {
		t.Fatalf("credential scope unknown: %+v %v", r, ok)
	}
	if _, ok := has(all.Rights, domain.Effective, &o.Other, "payments.refund.create", domain.VerbTransfer); ok {
		t.Fatal("an agent without a grant has effective reach")
	}

	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).RecordExposureChange(ctx, o.Org, 7)
	})
	if s := current(t, o, viewer{org: true}, domain.Filter{}).Snapshot; !s.Stale || s.ChangedAt == nil {
		t.Fatalf("not stale after a change: %+v", s)
	}
	if s := recompute(t, o).Snapshot; s.Digest == nil {
		t.Fatal("recompute")
	}
	if s := current(t, o, viewer{org: true}, domain.Filter{}).Snapshot; s.Stale {
		t.Fatal("still stale after a recomputation")
	}
}

// TestHR254_ExposureReadsFilterBeforeCounting: a viewer limited to one
// agent reads only that agent's rights, no credential right and nothing of
// the other agent, and the view says it is restricted; the matrix and
// ranking built from it never count the hidden agent.
func TestHR254_ExposureReadsFilterBeforeCounting(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.refund.get")
	o.Grant(t, o.Other, 0, "", "payments.*")
	o.Credential(t, "1 day")
	recompute(t, o)
	v := current(t, o, viewer{agents: map[ids.UUID]bool{o.Agent: true}}, domain.Filter{})
	if !v.Restricted || len(v.Rights) == 0 {
		t.Fatalf("restricted view: %v %d", v.Restricted, len(v.Rights))
	}
	for _, r := range v.Rights {
		if r.Agent == nil || *r.Agent != o.Agent {
			t.Fatalf("hidden right read: %+v", r)
		}
	}
	m := domain.BuildMatrix(v.Rights)
	if len(m.Agents) != 1 || *m.Agents[0] != o.Agent {
		t.Fatalf("matrix agents: %v", m.Agents)
	}
	if ranked := domain.Rank(v.Rights, nil, nil); len(ranked) != 1 {
		t.Fatalf("ranking: %d", len(ranked))
	}
	// Asking for the hidden agent directly gives nothing, the same as an
	// agent with no reach.
	if h := current(t, o, viewer{agents: map[ids.UUID]bool{o.Agent: true}}, domain.Filter{Agent: &o.Other}); len(h.Rights) != 0 {
		t.Fatalf("hidden agent's rights: %d", len(h.Rights))
	}
}

// TestIntPreviewRevokeCascades: revoking a grant previews the loss of its
// reach and of every grant delegated from it, while the live data stays as
// it was.
func TestIntPreviewRevokeCascades(t *testing.T) {
	o := exposuretest.New(t)
	root := o.Grant(t, o.Agent, 1, "", "payments.*")
	child := o.Grant(t, o.Other, 0, "", "payments.refund.get")
	o.Exec(t, `INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $3, 1)`, o.Org, child, root)
	o.Dispatch(t, "payments.refund.get")
	var d domain.Diff
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		d, err = app.Preview(ctx, tx, domain.Change{RevokeGrants: []ids.UUID{root}})
		return err
	})
	if d.After[domain.Effective] != 0 || d.Before[domain.Effective] == 0 || len(d.Disruption) != 1 {
		t.Fatalf("preview: before %v after %v disruption %d", d.Before, d.After, len(d.Disruption))
	}
	if !slices.ContainsFunc(d.Removed, func(r domain.Right) bool { return r.Agent != nil && *r.Agent == o.Other }) {
		t.Fatal("the delegated grant's reach is not removed")
	}
	if rec := recompute(t, o); !slices.ContainsFunc(rec.Rights, func(r domain.Right) bool { return r.View == domain.Effective }) {
		t.Fatal("a preview changed the live grants")
	}
}

// TestTenancy_exposure_snapshots: another org reads none of an org's
// snapshots, rights or changes and cannot write any into it.
func TestTenancy_exposure_snapshots(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	rec := recompute(t, o)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return dbq.New(tx).RecordExposureChange(ctx, o.Org, 1) })
	them := exposuretest.NewIn(t, o.D, o.P)
	for _, c := range []struct {
		table, where string
	}{{"exposure_snapshots", "id = $1"}, {"exposure_rights", "snapshot_id = $1"}, {"exposure_changes", "$1::uuid IS NOT NULL"}} {
		var n int
		them.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM pc."+c.table+" WHERE "+c.where, rec.Snapshot.ID).Scan(&n)
		})
		if n != 0 {
			t.Errorf("%s: another org reads %d rows", c.table, n)
		}
	}
	err := them.P.InTenantTx(context.Background(), them.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.exposure_snapshots (org_id, id, cause, rights, rights_sha256)
			VALUES ($1, $2, 'manual', 0, $3)`, o.Org, ids.NewV7(), make([]byte, 32))
		return err
	})
	if err == nil {
		t.Error("a snapshot written into another org")
	}
	var mine app.View
	them.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		mine, err = app.Current(ctx, tx, viewer{org: true}, domain.Filter{})
		if !errors.Is(err, app.ErrNoSnapshot) {
			t.Errorf("their current: %v", err)
		}
		return nil
	})
	if len(mine.Rights) != 0 {
		t.Fatal("rights across orgs")
	}
}
