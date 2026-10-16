// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// noGrants fails a test that reaches the grants port.
type noGrants struct{ t *testing.T }

func (g noGrants) IssueForAutomation(context.Context, pgx.Tx, LaunchIssue) (ids.UUID, error) {
	g.t.Fatal("issued a grant")
	return ids.UUID{}, nil
}

func (g noGrants) RevokeForAutomation(context.Context, pgx.Tx, GrantRevoke) ([]ids.UUID, error) {
	g.t.Fatal("revoked grants")
	return nil, nil
}

// TestHR279_StepsActOnlyWithinTheDeclaredPlatformScope: a revoke_grant or
// notify whose scope the version's `platform` section does not list is
// refused before any port is called; the registry holds exactly the
// engine's catalog kinds.
func TestHR279_StepsActOnlyWithinTheDeclaredPlatformScope(t *testing.T) {
	reg := Generic(Deps{Grants: noGrants{t}})
	var engineKinds []string
	for _, k := range autodomain.Kinds() {
		if autodomain.Catalog[k].Owner == autodomain.OwnerEngine {
			engineKinds = append(engineKinds, k)
		}
	}
	var got []string
	for k := range reg {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, engineKinds) {
		t.Fatalf("registry %v, want the engine's catalog kinds %v", got, engineKinds)
	}
	def := &autodomain.Definition{Authority: autodomain.Authority{
		Platform: []autodomain.PlatformScope{{Step: autodomain.KindRevokeGrant, Scopes: []string{autodomain.ScopeExecution}}},
	}}
	sc := autodomain.StepContext{
		Def: def, Mode: autodomain.ModeLive, With: &autodomain.RevokeGrantWith{Scope: autodomain.RevokeCeilingAgents},
		Spec: autodomain.StepSpec{ID: "revoke", Step: autodomain.KindRevokeGrant},
	}
	res, err := reg[autodomain.KindRevokeGrant].Run(context.Background(), nil, sc)
	if err != nil || res.State != autodomain.StepFailed || res.Reason != ReasonOutsideScope {
		t.Fatalf("revoke outside its scope: %+v %v", res, err)
	}
	sc.With = &autodomain.NotifyWith{To: []string{autodomain.ScopeConfirmers}, Message: autodomain.NotifyMessage{Title: "x"}}
	sc.Spec.Step = autodomain.KindNotify
	res, err = reg[autodomain.KindNotify].Run(context.Background(), nil, sc)
	if err != nil || res.State != autodomain.StepFailed || res.Reason != ReasonOutsideScope {
		t.Fatalf("notify outside its scope: %+v %v", res, err)
	}
}

// TestHR279_UnwiredPortsRefuseRatherThanPretend: without its port a step
// fails UNSUPPORTED_CAPABILITY; a LIVE launch without the rollout port never
// skips the cohort check (D84 E9).
func TestHR279_UnwiredPortsRefuseRatherThanPretend(t *testing.T) {
	reg := Generic(Deps{})
	for _, k := range []string{autodomain.KindLaunchRun, autodomain.KindGate, autodomain.KindRevokeGrant, autodomain.KindDeliver} {
		res, err := reg[k].Run(context.Background(), nil, autodomain.StepContext{
			Def: &autodomain.Definition{}, Mode: autodomain.ModeLive, Spec: autodomain.StepSpec{ID: "s", Step: k},
		})
		if err != nil || res.State != autodomain.StepFailed || res.Reason != engine.ReasonUnsupported {
			t.Errorf("%s: %+v %v", k, res, err)
		}
	}
}

// TestHR279_TheServerNeverDispatchesAToolCall (F3): the engine and its
// steps import nothing that reaches a tool — no gateway, connection
// dispatcher, MCP or HTTP client — so tool calls happen only through an
// enrolled agent's run.
func TestHR279_TheServerNeverDispatchesAToolCall(t *testing.T) {
	forbidden := []string{
		"/internal/gateway", "/internal/connections", "/internal/sandbox", "/internal/pclaw", "net/http", "/mcp",
	}
	for _, dir := range []string{".", "../engine", "../engine/adapters/pgengine"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range parsed.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				for _, bad := range forbidden {
					if strings.Contains(path, bad) {
						t.Errorf("%s imports %s", f, path)
					}
				}
			}
		}
	}
}
