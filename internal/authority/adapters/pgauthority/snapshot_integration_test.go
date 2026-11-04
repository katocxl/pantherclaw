// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
)

// TestReaderSnapshotIsOneSnapshot: every read of one evaluation sees the
// org as it was when its snapshot began, whatever commits meanwhile.
func TestReaderSnapshotIsOneSnapshot(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	g := w.grant("500")
	snap := w.auth.Pipeline.Reader.(pipeline.Snapshotter)
	if err := snap.Snapshot(ctx, w.org, func(ctx context.Context, r pipeline.Reader) error {
		before, err := r.Containment(ctx, w.org)
		if err != nil {
			return err
		}
		// Meanwhile, in other transactions: the grant is revoked and the
		// kill switch engaged.
		if _, err := w.grants.Revoke(w.human, g.ID, "done"); err != nil { //nolint:contextcheck // another transaction, outside the snapshot
			t.Fatal(err)
		}
		w.db.AdminExec(t, "UPDATE pc.org_containment SET epoch = epoch + 1, kill_switch = true, engaged_at = now(), engaged_by = 'test' WHERE org_id = $1", w.org) //nolint:contextcheck // another transaction, outside the snapshot
		after, err := r.Containment(ctx, w.org)
		if err != nil {
			return err
		}
		chain, err := r.Chain(ctx, w.org, g.ID)
		if err != nil {
			return err
		}
		if after.Epoch != before.Epoch || after.KillSwitch || len(chain) != 1 || chain[0].State != gdomain.StateActive {
			t.Errorf("the snapshot changed: containment %+v then %+v, grant %s", before, after, chain[0].State)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if cur, err := w.auth.Pipeline.Reader.Containment(ctx, w.org); err != nil || !cur.KillSwitch {
		t.Fatalf("a new read sees the change: %+v %v", cur, err)
	}
}

// TestAuthorizeOnOneConnection: a whole refund completes on a pool of one
// connection. No read of an evaluation, and not the lookup before it, takes
// a second connection while the snapshot holds one: under load, requests
// that each held one connection and waited for another could wait forever.
func TestAuthorizeOnOneConnection(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	cfg := w.db.App
	cfg.MaxConns = 1
	one := w.db.Pool(t, cfg)
	defs := &defpg.Store{Pool: one}
	auth := *w.auth
	auth.Pipeline = &pipeline.Pipeline{Reader: &pgauthority.Reader{
		Pool: one, Definitions: defs, Policies: &polpg.Store{Pool: one}, FactStore: &factpg.Store{Pool: one},
		Grants: &gpg.Store{Pool: one}, Limits: celenv.DefaultLimits,
	}}
	auth.Store = &pgauthority.Store{Pool: one}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := auth.Authorize(ctx, w.gw, w.request(run, ids.NewV7(), "ch_1", "30.00"))
	if err != nil || r.Decision != adomain.Allow || r.Permit == "" || r.Receipt == "" {
		t.Fatalf("authorize: %+v %v", r, err)
	}
	if _, err := auth.BeginDispatch(ctx, w.gw, r.PermitID, r.Epoch, finalize.Outbound{}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Accepted, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if again, err := auth.Authorize(ctx, w.gw, w.request(run, ids.NewV7(), "ch_1", "30.00")); err != nil || decisive(again) != pipeline.ReasonReconciliation {
		t.Fatalf("a repeat after success: %s %v", decisive(again), err)
	}
}
