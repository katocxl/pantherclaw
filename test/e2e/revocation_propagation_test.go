// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// propagationBound is the fail-closed bound: a gateway whose containment
// view is older than this refuses every dispatch on its own (HR-010), so a
// change that took longer to arrive would not have been the gateway's view.
const propagationBound = control.MaxStaleness

// TestPN0113_RevocationPropagation measures how fast a containment change
// reaches every connected gateway (PN-011.3; docs/perf/M13.md). Four
// gateways share one identity, the most one certificate may stream
// (MaxStreamsPerCert). Each event starts on the test's wall clock right
// after the call that committed it returned, and ends for each gateway when
// its own containment view, polled every millisecond, shows the change. The
// event's sample is the latest gateway's. Two kinds of event:
//   - the kill switch engaged (the view refuses with ErrKillSwitch), then
//     restored by a second person before the next cycle;
//   - an agent suspended, which raises the org's containment epoch (the
//     gateway's Epoch reaches the committed epoch). Each cycle suspends a
//     new agent.
//
// The normal e2e run takes 30 cycles and asserts only the fail-closed
// bound. With PC_PERF_REVOCATION=1 (task perf:revocation) it takes 200 and
// writes the percentiles to bin/perf/out/revocation-<date>.json.
//
// Covers: PN-011.3
func TestPN0113_RevocationPropagation(t *testing.T) {
	cycles, perf := 30, os.Getenv("PC_PERF_REVOCATION") == "1"
	if perf {
		cycles = 200
	}
	s := start(t, options{budget: "1000.00"})
	gws := []*gateway.Gateway{s.gw}
	for len(gws) < gwapp.MaxStreamsPerCert {
		gws = append(gws, s.watchingGateway(t))
	}
	alice, bob := s.person(t, "alice", td.RoleEmergency), s.person(t, "bob", td.RoleEmergency)
	ks := rapp.New(s.pool, nil, s.apiURL)
	now := func(p person) rapp.StepUp { return rapp.StepUp{Credential: p.key, At: time.Now()} }

	var engaged []time.Duration
	for i := range cycles {
		if _, err := ks.Engage(alice.ctx, now(alice), "propagation measurement"); err != nil {
			t.Fatal(err)
		}
		engaged = append(engaged, reaches(t, gws, time.Now(), control.ErrKillSwitch))
		p, err := ks.ProposeRestore(alice.ctx, now(alice), "propagation measurement")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ks.ConfirmRestore(bob.ctx, now(bob), p.ID); err != nil {
			t.Fatal(err)
		}
		// The clear is not a revocation; the next cycle starts once every
		// gateway dispatches again.
		reaches(t, gws, time.Now(), nil)
		if i == 0 {
			t.Logf("first cycle: kill switch reached %d gateways in %s", len(gws), engaged[0])
		}
	}

	suspended := s.suspensions(t, gws, cycles)

	ksp := percentilesMS(engaged)
	t.Logf("kill switch engage, %d events, %d gateways: p50 %.1f ms, p95 %.1f ms, p99 %.1f ms, max %.1f ms",
		len(engaged), len(gws), ksp["p50"], ksp["p95"], ksp["p99"], ksp["max"])
	sp := percentilesMS(suspended)
	t.Logf("agent suspension, %d events, %d gateways: p50 %.1f ms, p95 %.1f ms, p99 %.1f ms, max %.1f ms",
		len(suspended), len(gws), sp["p50"], sp["p95"], sp["p99"], sp["max"])
	if !perf {
		return
	}
	out := os.Getenv("PC_PERF_OUT")
	if out == "" {
		out = filepath.Join("..", "..", "bin", "perf", "out")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(map[string]any{
		"test": "TestPN0113_RevocationPropagation", "date": time.Now().UTC().Format(time.RFC3339), "gateways": len(gws),
		"poll_every_ms": 1, "bound_ms": propagationBound.Milliseconds(),
		"kill_switch":      map[string]any{"events": len(engaged), "percentiles_ms": ksp, "samples_ms": msOf(engaged)},
		"agent_suspension": map[string]any{"events": len(suspended), "percentiles_ms": sp, "samples_ms": msOf(suspended)},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(out, "revocation-"+time.Now().UTC().Format("2006-01-02")+".json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// suspensions suspends n new agents one after another and returns, for
// each, how long until every gateway's epoch reached the one the
// suspension committed.
func (s *stack) suspensions(t *testing.T, gws []*gateway.Gateway, n int) []time.Duration {
	t.Helper()
	var team, env, owner ids.UUID
	s.query(t, `SELECT team_id, environment_id, owner_user_id FROM pc.agents
		WHERE team_id IS NOT NULL AND environment_id IS NOT NULL AND owner_user_id IS NOT NULL LIMIT 1`, nil, &team, &env, &owner)
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: owner},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: team}}},
	}, Credential: tapp.CredAccessToken})
	inv := aapp.NewInventory(s.pool, unlimited{})
	agents := make([]ids.UUID, n)
	for i := range agents {
		a, err := inv.Create(ctx, adomain.Details{
			Name: fmt.Sprintf("propagation-%03d", i), TeamID: team, EnvironmentID: env, OwnerUserID: owner, Context: adomain.ContextCI,
		})
		if err != nil {
			t.Fatal(err)
		}
		agents[i] = a.ID
	}
	var took []time.Duration
	for _, a := range agents {
		var before, committed int64
		s.query(t, "SELECT epoch FROM pc.org_containment", nil, &before)
		if _, err := inv.Suspend(ctx, a, "propagation measurement"); err != nil {
			t.Fatal(err)
		}
		since := time.Now()
		// Nothing else raises this org's epoch meanwhile: the suspension
		// committed before+1, checked below.
		d := reachesWhen(t, gws, since, func(g *gateway.Gateway) bool { return g.Epoch() > before })
		s.query(t, "SELECT epoch FROM pc.org_containment", nil, &committed)
		if committed != before+1 {
			t.Fatalf("epoch %d after one suspension from %d", committed, before)
		}
		took = append(took, d)
	}
	return took
}

// watchingGateway starts one more gateway from the saved identity, serving
// nothing: only its containment view is watched.
func (s *stack) watchingGateway(t *testing.T) *gateway.Gateway {
	t.Helper()
	cfg := s.gatewayCfg
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	id, err := gateway.LoadOrEnroll(ctx, &cfg, s.gatewayEnroll, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(ctx, &cfg, id, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Run(ctx) }()
	if err := g.WaitReady(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	return g
}

// reaches polls every gateway's containment view every millisecond from
// since until it shows want, and returns how long the latest gateway took.
// It fails t when a gateway still shows the old view after the fail-closed
// bound.
func reaches(t *testing.T, gws []*gateway.Gateway, since time.Time, want error) time.Duration {
	t.Helper()
	return reachesWhen(t, gws, since, func(g *gateway.Gateway) bool { return errors.Is(g.Contained(), want) })
}

func reachesWhen(t *testing.T, gws []*gateway.Gateway, since time.Time, shows func(*gateway.Gateway) bool) time.Duration {
	t.Helper()
	took := make([]time.Duration, len(gws))
	left := len(gws)
	for left > 0 {
		for i, g := range gws {
			if took[i] == 0 && shows(g) {
				took[i] = max(time.Since(since), time.Nanosecond)
				left--
			}
		}
		if left > 0 && time.Since(since) > propagationBound {
			t.Fatalf("%d of %d gateways still had the old view %s after the change, over the %s bound",
				left, len(gws), time.Since(since), propagationBound)
		}
		time.Sleep(time.Millisecond)
	}
	return slices.Max(took)
}

// percentilesMS are the nearest-rank percentiles in ms, as pantherclaw-sim
// load reports them (internal/sim/load.go).
func percentilesMS(ds []time.Duration) map[string]float64 {
	xs := msOf(ds)
	slices.Sort(xs)
	at := func(p float64) float64 { return xs[min(len(xs)-1, int(p*float64(len(xs))))] }
	return map[string]float64{"p50": at(0.50), "p95": at(0.95), "p99": at(0.99), "max": xs[len(xs)-1]}
}

func msOf(ds []time.Duration) []float64 {
	xs := make([]float64, len(ds))
	for i, d := range ds {
		xs[i] = float64(d.Microseconds()) / 1000
	}
	return xs
}
