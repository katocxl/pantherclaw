// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package recompute_test

import (
	"context"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

func audited(t *testing.T, o *exposuretest.Org, name string) {
	t.Helper()
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{Name: name, Actor: evdomain.Actor{Type: "user", ID: "alice"}, Outcome: audit.Success})
		return err
	})
	// The chainer links only entries older than every running transaction
	// on the cluster; under a parallel test run that can take a moment.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := ledger.ChainOrg(context.Background(), o.P, o.Org, 100); err != nil {
			t.Fatal(err)
		}
		if count(t, o, "SELECT count(*) FROM pc.ledger_entries e WHERE NOT EXISTS "+
			"(SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)") == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("ledger entries not chained within 30 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func count(t *testing.T, o *exposuretest.Org, sql string) int {
	t.Helper()
	var n int
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error { return tx.QueryRow(ctx, sql).Scan(&n) })
	return n
}

// TestIntRecomputeFollowsTheFeed: the first run computes a snapshot; a
// run with nothing new does nothing; an event that moves reach (a grant
// issued) is recorded and recomputed, an unrelated one is only read; on
// Business the posture findings follow; on Community the job stops and
// records one failure.
func TestIntRecomputeFollowsTheFeed(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	svc := &recompute.Service{Pool: o.P, Ents: edition(billing.Business), Failures: &failures.Sink{}}
	ctx := context.Background()

	res, err := svc.Run(ctx, o.Org)
	if err != nil || !res.Recomputed || res.Posture == nil {
		t.Fatalf("first run: %+v %v", res, err)
	}
	if res, err = svc.Run(ctx, o.Org); err != nil || res.Recomputed {
		t.Fatalf("nothing new: %+v %v", res, err)
	}
	audited(t, o, "licence.installed")
	if res, err = svc.Run(ctx, o.Org); err != nil || res.Recomputed || res.Read == 0 || res.Changed {
		t.Fatalf("unrelated event: %+v %v", res, err)
	}
	audited(t, o, "grant.issued")
	if res, err = svc.Run(ctx, o.Org); err != nil || !res.Recomputed || !res.Changed {
		t.Fatalf("grant issued: %+v %v", res, err)
	}
	if n := count(t, o, "SELECT count(*) FROM pc.exposure_snapshots"); n != 2 {
		t.Fatalf("snapshots: %d", n)
	}
	if n := count(t, o, "SELECT count(*) FROM pc.posture_findings"); n == 0 {
		t.Fatal("no posture findings on Business")
	}

	svc.Ents = edition(billing.Community)
	audited(t, o, "grant.issued")
	for range 2 {
		if res, err = svc.Run(ctx, o.Org); err != nil || res.Recomputed {
			t.Fatalf("community: %+v %v", res, err)
		}
	}
	if n := count(t, o, "SELECT count(*) FROM pc.operational_failures WHERE kind = 'exposure.edition_lapsed'"); n != 1 {
		t.Fatalf("lapse failures: %d", n)
	}
}

func TestMoves(t *testing.T) {
	for kind, want := range map[string]bool{
		"audit.grant.issued": true, "audit.grant_revoked": true, "audit.policy.published": true, "coverage.snapshot": true,
		"audit.connection.quarantined": true, "audit.credential.revoked": true, "receipt.decision": false,
		"audit.licence.installed": false, "audit.policy.simulation_requested": false, "audit.grantee": false,
	} {
		if recompute.Moves(kind) != want {
			t.Errorf("%s: %v", kind, !want)
		}
	}
}
