// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// TestHR220_RangeMarkIsImmutable (D1): the mark is set when the agent is
// created; pc_app cannot change it afterwards, so a real agent never
// becomes a range agent or the reverse.
func TestHR220_RangeMarkIsImmutable(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	real, err := w.inv.Create(ctx, w.details())
	if err != nil || real.RangeAgent {
		t.Fatalf("real agent: %+v, %v", real, err)
	}
	d := w.details()
	d.RangeAgent = true
	rng, err := w.inv.Create(ctx, d)
	if err != nil || !rng.RangeAgent {
		t.Fatalf("range agent: %+v, %v", rng, err)
	}
	for _, c := range []struct {
		id   string
		to   bool
		what string
	}{{real.ID.String(), true, "real to range"}, {rng.ID.String(), false, "range to real"}} {
		err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, "UPDATE pc.agents SET range_agent = $1 WHERE org_id = $2 AND id = $3", c.to, w.org, c.id)
			return err
		})
		if err == nil {
			t.Errorf("%s: the update succeeded, want permission denied", c.what)
		}
	}
	for _, a := range []app.Agent{real, rng} {
		got, err := w.inv.Get(ctx, a.ID)
		if err != nil || got.RangeAgent != a.RangeAgent {
			t.Errorf("agent %s read back range=%v, %v, want %v", a.ID, got.RangeAgent, err, a.RangeAgent)
		}
		// Ordinary changes keep the mark.
		if _, err := w.inv.Update(ctx, a.ID, ptr("renamed"), nil); err != nil {
			t.Fatal(err)
		}
		if got, _ := w.inv.Get(ctx, a.ID); got.RangeAgent != a.RangeAgent {
			t.Errorf("after an edit, agent %s range=%v, want %v", a.ID, got.RangeAgent, a.RangeAgent)
		}
	}
}

func ptr(s string) *string { return &s }

// TestHR220_RangeAgentsAreCappedAtFivePerOrg (D1): a sixth live range agent
// is refused in every edition; retiring one frees a slot.
func TestHR220_RangeAgentsAreCappedAtFivePerOrg(t *testing.T) {
	for _, edition := range []billing.Edition{"", billing.Business} {
		w := newWorld(t)
		w.ents.edition = edition
		ctx := w.teamOwner()
		d := w.details()
		d.RangeAgent = true
		var first app.Agent
		for i := range app.MaxRangeAgents {
			a, err := w.inv.Create(ctx, d)
			if err != nil {
				t.Fatalf("%q: range agent %d: %v", edition, i, err)
			}
			if i == 0 {
				first = a
			}
		}
		_, err := w.inv.Create(ctx, d)
		wantCode(t, string(edition)+" sixth range agent", err, pcerr.FailedPrecondition, "RANGE_AGENT_LIMIT")
		if _, err := w.inv.Retire(ctx, first.ID, "frees a slot"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.inv.Create(ctx, d); err != nil {
			t.Fatalf("%q: after retiring one: %v", edition, err)
		}
	}
}

// TestHR220_RangeAgentsDoNotCountTowardTheEditionLimit (D1): five range
// agents leave all five Community slots for real agents, and real agents
// never use up the range cap.
func TestHR220_RangeAgentsDoNotCountTowardTheEditionLimit(t *testing.T) {
	w := newWorld(t)
	w.ents.edition = "" // Community: 5 governed agents
	ctx := w.teamOwner()
	rd := w.details()
	rd.RangeAgent = true
	for i := range app.MaxRangeAgents {
		if _, err := w.inv.Create(ctx, rd); err != nil {
			t.Fatalf("range agent %d: %v", i, err)
		}
	}
	for i := range 5 {
		if _, err := w.inv.Create(ctx, w.details()); err != nil {
			t.Fatalf("real agent %d after five range agents: %v", i, err)
		}
	}
	_, err := w.inv.Create(ctx, w.details())
	wantCode(t, "sixth real agent", err, pcerr.FailedPrecondition, "AGENT_LIMIT")
	_, err = w.inv.Create(ctx, rd)
	wantCode(t, "sixth range agent", err, pcerr.FailedPrecondition, "RANGE_AGENT_LIMIT")
	if n := w.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND range_agent", w.org); n != 5 {
		t.Fatalf("%d range agents stored, want 5", n)
	}
}

// TestRace_RangeAgentCapHoldsUnderConcurrentCreates: the org's limit lock
// lets exactly five range agents through.
func TestRace_RangeAgentCapHoldsUnderConcurrentCreates(t *testing.T) {
	w := newWorld(t)
	ctx := w.teamOwner()
	d := w.details()
	d.RangeAgent = true
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := w.inv.Create(ctx, d); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != app.MaxRangeAgents {
		t.Fatalf("%d range agents created, want %d", ok, app.MaxRangeAgents)
	}
}
