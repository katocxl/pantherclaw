// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"errors"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/app"
	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

const modelHost = "model.provider.test"

// modelWorld has an open campaign of the twin through its relay on gateway gw.
func modelWorld(t *testing.T) (*world, domain.Campaign, ids.UUID, ids.UUID) {
	t.Helper()
	w := newWorld(t, billing.Business)
	gw := ids.NewV7()
	w.f.relays[w.relay] = app.RelayRef{Gateway: gw, Simulated: true, ModelRelay: true, Active: true}
	c, err := w.svc.StartCampaign(w.ctx, w.input("RT-140"))
	if err != nil {
		t.Fatal(err)
	}
	w.step(t, c, "RT-140")
	return w, c, gw, w.run(c)
}

func (w *world) org() ids.OrgID {
	c, _ := tenancy.CallerFrom(w.ctx)
	return c.Org
}

// TestHR614_TheModelRouteOpensOnlyForAnOpenCampaignsTwinRun: the server allows
// a model call only through a simulated model relay this gateway serves, for a
// simulated run of a range agent made during its open campaign, to its model
// host; every other case, a closed campaign included, is refused alike and
// counts nothing (D313).
// Covers: F906
func TestHR614_TheModelRouteOpensOnlyForAnOpenCampaignsTwinRun(t *testing.T) {
	w, c, gw, run := modelWorld(t)
	call := func() app.ModelCall {
		return app.ModelCall{Gateway: gw, Connection: w.relay, Run: run, ModelHost: modelHost, BytesToModel: 10}
	}
	got, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call())
	if err != nil || got != c.ID {
		t.Fatalf("the open campaign's call: %v %v", got, err)
	}

	prod := ids.NewV7()
	w.f.agents[prod] = app.AgentRef{ID: prod, Path: w.f.agents[w.agent].Path}
	realRun := ids.NewV7()
	w.f.runs[realRun] = domain.RunRecord{ID: realRun, Agent: prod, Simulated: false, Created: c.Started}
	oldRun := ids.NewV7()
	w.f.runs[oldRun] = domain.RunRecord{ID: oldRun, Agent: w.agent, Simulated: true, Created: c.Started.Add(-time.Hour)}
	realConn := ids.NewV7()
	w.f.relays[realConn] = app.RelayRef{Gateway: gw, ModelRelay: true, Active: true}
	twinConn := ids.NewV7()
	w.f.relays[twinConn] = app.RelayRef{Gateway: gw, Simulated: true, Active: true}

	for name, edit := range map[string]func(*app.ModelCall){
		"a real connection":               func(m *app.ModelCall) { m.Connection = realConn },
		"a simulated connection, no mark": func(m *app.ModelCall) { m.Connection = twinConn },
		"an unknown connection":           func(m *app.ModelCall) { m.Connection = ids.NewV7() },
		"another gateway":                 func(m *app.ModelCall) { m.Gateway = ids.NewV7() },
		"a real agent's run":              func(m *app.ModelCall) { m.Run = realRun },
		"a run from before the campaign":  func(m *app.ModelCall) { m.Run = oldRun },
		"an unknown run":                  func(m *app.ModelCall) { m.Run = ids.NewV7() },
		"another model host":              func(m *app.ModelCall) { m.ModelHost = "api.other.test" },
		"a body past the cap":             func(m *app.ModelCall) { m.BytesToModel = app.MaxModelBytes + 1 },
	} {
		m := call()
		edit(&m)
		if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), m); !errors.Is(err, app.ErrModelRoute) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A quarantined relay, then a closed campaign: the route is off.
	r := w.f.relays[w.relay]
	r.Active = false
	w.f.relays[w.relay] = r
	if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call()); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("a quarantined relay: %v", err)
	}
	r.Active = true
	w.f.relays[w.relay] = r
	if _, err := w.svc.FinishCampaign(w.ctx, c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call()); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("a closed campaign: %v", err)
	}
	if u := w.f.usage[run]; u[0] != 1 || u[1] != 10 {
		t.Fatalf("usage %v: a refused call was counted", u)
	}
}

// TestHR614_AStaleCampaignAndTheRunTotalCloseTheRoute: a campaign past 24
// hours and a run past its total are refused (D313). Each request reserves
// room for its answer (MaxModelBytes, D525 L2), so requests whose answers
// have not come back cannot pass the total either; an answer settles its
// reservation.
// Covers: F906
func TestHR614_AStaleCampaignAndTheRunTotalCloseTheRoute(t *testing.T) {
	w, c, gw, run := modelWorld(t)
	call := app.ModelCall{Gateway: gw, Connection: w.relay, Run: run, ModelHost: modelHost, BytesToModel: app.MaxModelBytes}
	for range app.RunModelTotal / (2 * app.MaxModelBytes) {
		if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("past the run total with the answers reserved: %v", err)
	}
	if w.f.reserved[run] != app.RunModelTotal/2 {
		t.Fatalf("reserved %d", w.f.reserved[run])
	}
	// One-byte answers settle their reservations, which opens room again.
	for range app.RunModelTotal / (2 * app.MaxModelBytes) {
		if err := w.svc.ReportModelUsage(w.ctx, w.org(), gw, c.ID, run, 1); err != nil {
			t.Fatal(err)
		}
	}
	if w.f.reserved[run] != 0 {
		t.Fatalf("reserved %d after the answers", w.f.reserved[run])
	}
	if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), call); err != nil {
		t.Fatalf("after the answers settled: %v", err)
	}
	w2, _, gw2, run2 := modelWorld(t)
	w2.svc.Now = func() time.Time { return c.Started.Add(app.MaxCampaignAge) }
	if _, err := w2.svc.AuthorizeModelCall(w2.ctx, w2.org(), app.ModelCall{Gateway: gw2, Connection: w2.relay, Run: run2, ModelHost: modelHost}); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("a stale campaign: %v", err)
	}
}

// TestHR613_OnlyTheRelaysGatewayReportsUsage: the answer's size is added for
// the relay's gateway, never for another one.
// Covers: F906
func TestHR613_OnlyTheRelaysGatewayReportsUsage(t *testing.T) {
	w, c, gw, run := modelWorld(t)
	if _, err := w.svc.AuthorizeModelCall(w.ctx, w.org(), app.ModelCall{Gateway: gw, Connection: w.relay, Run: run, ModelHost: modelHost, BytesToModel: 5}); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.ReportModelUsage(w.ctx, w.org(), ids.NewV7(), c.ID, run, 7); !errors.Is(err, app.ErrModelRoute) {
		t.Fatalf("another gateway: %v", err)
	}
	if err := w.svc.ReportModelUsage(w.ctx, w.org(), gw, c.ID, run, 7); err != nil {
		t.Fatal(err)
	}
	if u := w.f.usage[run]; u != [3]int64{1, 5, 7} {
		t.Fatalf("usage %v", u)
	}
}
