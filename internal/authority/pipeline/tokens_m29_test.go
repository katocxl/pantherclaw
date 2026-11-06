// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR693_AModelCallPastTheRunsTokenCapIsTokenBudgetExhausted: the
// budgets step reserves a model call's tokens (max_tokens plus a third of
// input_bytes) against the run's token cap; a call that fits is allowed and
// one past it is denied TOKEN_BUDGET_EXHAUSTED, naming the run's token
// budget (G0 M29 D821, D822, D1214).
//
// Covers: HR-693
func TestHR693_AModelCallPastTheRunsTokenCapIsTokenBudgetExhausted(t *testing.T) {
	raw, err := os.ReadFile("../../../packages/pc-anthropic/package.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	var def *defs.Definition
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == "anthropic.messages.create" {
			def = &pkg.Definitions[i]
		}
	}
	if def == nil {
		t.Fatal("no anthropic.messages.create")
	}
	w := pipelinetest.New(org, pkg, now)
	agent, instance, env, gateway, conn := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	alice := gdomain.Principal{Kind: gdomain.PrincipalUser, ID: ids.NewV7()}
	w.PutConnection(pipeline.Connection{
		ID: conn, Gateway: gateway, Kind: "model", Package: pkg.Name, State: "ACTIVE", AccessMode: "none",
		DefaultMode: pipeline.ModeEnforce, Modes: map[string]string{},
	})
	w.AddAgent(agent, pipeline.Agent{State: "VERIFIED", TeamID: ids.NewV7(), BusinessUnitID: ids.NewV7()})
	b, err := gdomain.DecodeBounds([]byte(`{"operations": ["anthropic.messages.create"], "targets": {"model": {"ids": ["sim-model"]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	grant := gdomain.Grant{
		ID: gdomain.NewGrantID(), Org: org, Revision: 1, State: gdomain.StateActive,
		AgentID: agent, Principal: alice, EnvironmentID: env, TaskRef: "chat",
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(48 * time.Hour), Bounds: b,
		Delegation: gdomain.Delegation{Depth: 2, MaxChildren: 3}, Grantor: alice, Basis: "test",
	}
	w.Grants.Put(grant)
	run := ids.NewV7()
	capTokens := int64(1000)
	w.AddRun(run, pipeline.Run{
		AgentID: agent, InstanceID: instance, Launcher: alice, Principal: alice, EnvironmentID: env, GrantID: grant.ID, Active: true,
		MaxTokens: &capTokens, TokenCapRunID: run,
	})
	p := &pipeline.Pipeline{Reader: w}
	call := func(maxTokens, inputBytes int64) *pipeline.Evaluation {
		t.Helper()
		params, err := def.EncodeParams(defs.Values{
			"model":       {Type: defs.TypeIdentifier, Str: "sim-model"},
			"max_tokens":  {Type: defs.TypeInteger, Int: maxTokens},
			"stream":      {Type: defs.TypeBoolean, Bool: false},
			"input_bytes": {Type: defs.TypeInteger, Int: inputBytes},
			"body_sha256": {Type: defs.TypeIdentifier, Str: strings.Repeat("a", 64)},
		})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := actionir.Encode(actionir.ActionIR{
			V: actionir.Version, Org: org.String(), Env: env.String(), RunID: run.String(), ActionID: ids.NewV7().String(),
			AgentInstance: instance.String(), Connection: conn.String(), Operation: def.Operation,
			Definition: actionir.Definition{Package: pkg.Name, Version: pkg.Version, Digest: def.Digest},
			Channel:    string(defs.ChannelHTTP), Route: "anthropic-messages",
			Target: actionir.Target{Type: "model", ID: "sim-model"}, Params: params,
		})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := p.Evaluate(context.Background(), pipeline.Request{
			Org: org, Action: parsed, Gateway: gateway.String(),
			Identity: pipeline.Identity{InstanceID: instance, AgentID: agent, AttestationLevel: 1, JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	// 900 + ceil(300/3) = 1000 tokens: exactly the cap.
	expect(t, call(900, 300), adomain.Allow, pipeline.ReasonGrantCovers)
	// 900 + ceil(301/3) = 1001 tokens: one past it.
	ev := call(900, 301)
	expect(t, ev, adomain.Deny, gdomain.ReasonTokenBudgetExhausted)
	if d := ev.Decisive().Detail; !strings.Contains(d, "token budget") {
		t.Fatalf("the explanation names the token budget: %q", d)
	}
}
