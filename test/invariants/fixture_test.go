// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package invariants holds the property tests of the twelve product
// invariants (ARCHITECTURE §1), at what each milestone can show. M4 shows
// them through the decision pipeline and the finalization with in-memory
// stores; later milestones extend them (approvals M5, coverage M9,
// automations M11).
package invariants_test

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"os"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

var (
	org = ids.MustParse[ids.Org]("01920000-0000-7000-8000-0000000000a1")
	now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
)

// world is one org with the mock-payments package (plus an untrusted note
// on refunds), one agent and helpers to issue grants and start runs.
// fataler is what the fixture needs from a test: *testing.T or *rapid.T.
type fataler interface {
	Helper()
	Fatal(args ...any)
}

type world struct {
	tb       fataler
	w        *pipelinetest.World
	p        *pipeline.Pipeline
	mapper   *mapping.Mapper
	agent    ids.UUID
	instance ids.UUID
	env      ids.UUID
	team     ids.UUID
	alice    gdomain.Principal
	// gateway serves conn, an enforce-mode HTTP connection to the package
	// that every request goes through (PAP-1 §6).
	gateway, conn ids.UUID
}

func newWorld(tb fataler) *world { return newWorldWith(tb, nil) }

// newWorldWith is newWorld with the package edited first.
func newWorldWith(tb fataler, edit func(string) string) *world {
	tb.Helper()
	raw, err := os.ReadFile("../../packages/mock-payments/package.yaml")
	if err != nil {
		tb.Fatal(err)
	}
	if edit != nil {
		raw = []byte(edit(string(raw)))
	}
	// An untrusted note on refunds (text is never material, HR-023).
	raw = bytes.Replace(raw, []byte("    effects:"), []byte("      note:\n        type: text\n    effects:"), 1)
	// The MCP refund mapping is the refund definition's last mapping, right
	// before its dispatch template.
	mcp := []byte("            reason: input.reason\n    dispatch:")
	if !bytes.Contains(raw, mcp) {
		tb.Fatal("the MCP refund mapping moved; update the fixture")
	}
	raw = bytes.Replace(raw, mcp, []byte("            reason: input.reason\n            note: input.note\n    dispatch:"), 1)
	pkg, err := manifest.Decode(raw)
	if err != nil {
		tb.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		tb.Fatal(err)
	}
	w := &world{
		tb: tb, w: pipelinetest.New(org, pkg, now), mapper: m,
		agent: ids.NewV7(), instance: ids.NewV7(), env: ids.NewV7(), team: ids.NewV7(),
		alice: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()}, gateway: ids.NewV7(), conn: ids.NewV7(),
	}
	w.w.PutConnection(pipeline.Connection{
		ID: w.conn, Gateway: w.gateway, Kind: "http", Package: pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	w.p = &pipeline.Pipeline{Reader: w.w}
	w.w.AddAgent(w.agent, pipeline.Agent{State: "VERIFIED", TeamID: w.team, BusinessUnitID: ids.NewV7()})
	for _, ch := range []string{"ch_1", "ch_2", "ch_3"} {
		w.w.PutFact(fdomain.Fact{
			Name: "payments.charge.refundable", SubjectType: "payments.charge", SubjectID: ch,
			Value: fdomain.Value{Type: fdomain.TypeBoolean, Bool: true}, ObservedAt: now.Add(-time.Minute), ProviderID: ids.NewV7(),
		})
	}
	return w
}

const rootBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"prefixes": ["re_"]}},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}
}`

func (w *world) grant(bounds string, p gdomain.Principal) gdomain.Grant {
	w.tb.Helper()
	b, err := gdomain.DecodeBounds([]byte(bounds))
	if err != nil {
		w.tb.Fatal(err)
	}
	g := gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: org, Revision: 1, State: gdomain.StateActive,
		AgentID: w.agent, Principal: p, EnvironmentID: w.env, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour),
		Bounds: b, Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 10}, Grantor: w.alice, Basis: "test",
	}
	w.w.Grants.Put(g)
	return g
}

func (w *world) run(g gdomain.GrantID, p gdomain.Principal) ids.UUID {
	id := ids.NewV7()
	w.w.AddRun(id, pipeline.Run{AgentID: w.agent, InstanceID: w.instance, Launcher: p, Principal: p, EnvironmentID: w.env, GrantID: g, Active: true})
	return id
}

func (w *world) request(run ids.UUID, tool, input string) pipeline.Request {
	w.tb.Helper()
	p, err := w.mapper.MCP(context.Background(), mapping.Context{
		Org: org.String(), Env: w.env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: w.instance.String(),
		Connection: w.conn.String(),
	}, tool, jsontext.Value(input))
	if err != nil {
		w.tb.Fatal(err)
	}
	return pipeline.Request{
		Org: org, Action: p, Identity: pipeline.Identity{InstanceID: w.instance, AgentID: w.agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}, Gateway: w.gateway.String(),
	}
}

func (w *world) eval(req pipeline.Request) *pipeline.Evaluation {
	w.tb.Helper()
	ev, err := w.p.Evaluate(context.Background(), req)
	if err != nil {
		w.tb.Fatal(err)
	}
	return ev
}

func refundInput(charge, amount, note string) string {
	return `{"charge":"` + charge + `","amount":"` + amount + `","currency":"USD","reason":"duplicate","note":` + jsonString(note) + `}`
}

func jsonString(s string) string {
	b, _ := jsontext.AppendQuote(nil, s)
	return string(b)
}

func auditEvent() audit.Event { return audit.Event{Name: "test.event", Outcome: audit.Success} }

func mustMoney(s string) money.Decimal { return money.MustParse(s) }
