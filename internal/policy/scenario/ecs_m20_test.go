// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scenario

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
)

const (
	ecsDeploy   = "aws.ecs.service.deploy"
	ecsRevision = "arn:aws:ecs:us-east-1:111122223333:task-definition/web:2"
)

func ecsWorld(t *testing.T) *packageWorld {
	t.Helper()
	pkg, err := manifest.Decode(pcawsecs.Package)
	if err != nil {
		t.Fatal(err)
	}
	w := &packageWorld{world: world{catalog: map[string]fdomain.Type{}}, pkgs: []*defs.Package{pkg}}
	for i := range pkg.Definitions {
		w.defs = append(w.defs, &pkg.Definitions[i])
	}
	return w
}

// verifyDeploys has every deploy verified at the level ECS's read reaches.
func verifyDeploys() pdomain.Rule {
	return pdomain.Rule{
		ID: "verify-deploys", Kind: pdomain.Constrain, Summary: "deploys are verified", Operations: []string{ecsDeploy},
		When: "true", Reason: "DEPLOYS_VERIFIED", Constraint: &pdomain.Constraint{Kind: pdomain.Verify, Level: defs.LevelDomainEffect},
	}
}

func deployCase(expect pdomain.TestExpect) pdomain.TestCase {
	return pdomain.TestCase{
		ID: "deploy", Summary: "a deploy whose effect must be verified",
		Action: pdomain.TestAction{
			Operation: ecsDeploy, Target: &actionir.Target{Type: "aws_ecs_service", ID: "prod/web", Account: "111122223333"},
			Params: jsontext.Value(`{"task_definition":"` + ecsRevision + `","deployment_controller":"ECS"}`),
		},
		Given: &pdomain.TestGiven{Facts: map[string]pdomain.TestFact{
			"aws.ecs.service.controller": {Value: jsontext.Value(`{"object":{"type":"ECS"}}`), AgeSeconds: 5},
		}},
		Expect: expect,
	}
}

func runDeploy(t *testing.T, w *packageWorld, expect pdomain.TestExpect) pdomain.CaseResult {
	t.Helper()
	r := newRunner(&w.world, papp.DefaultBudget)
	r.pkgs = w
	res := runOK(t, r, bundle([]pdomain.Rule{verifyDeploys()}, deployCase(expect)))
	if len(res.Cases) != 1 {
		t.Fatalf("result %+v", res)
	}
	return res.Cases[0]
}

// TestHR190_APolicyTestSeesTheReadsProductionHas: the promotion gate takes a
// connection's verifier reads from the active packages, as the Authority
// does: a verify obligation at domain_effect on a pc.aws.ecs deploy is
// satisfied there too, so a policy test agrees with production (D291).
// Covers: HR-190, HR-191
func TestHR190_APolicyTestSeesTheReadsProductionHas(t *testing.T) {
	c := runDeploy(t, ecsWorld(t), pdomain.TestExpect{Decision: "ALLOW_WITH_OBLIGATIONS", Reason: "DEPLOYS_VERIFIED"})
	if !c.Passed {
		t.Fatalf("case %+v", c)
	}
}

// TestHR190_AnOrgPackageGetsNoPOSTReadInAPolicyTest: the same definitions
// from any other package have no such read, in a policy test as in
// production: the obligation cannot be met (D290, D291).
// Covers: HR-190, HR-191
func TestHR190_AnOrgPackageGetsNoPOSTReadInAPolicyTest(t *testing.T) {
	w := ecsWorld(t)
	w.pkgs[0].Name = "acme.ecs"
	c := runDeploy(t, w, pdomain.TestExpect{Decision: "CANNOT_AUTHORIZE", Reason: "VERIFIER_UNSUPPORTED"})
	if !c.Passed {
		t.Fatalf("case %+v", c)
	}
}

// TestHR190_NoPackagesMeansNoPOSTRead: a reader that serves no packages
// knows no identity, so only GET reads count, never a read by its shape.
// Covers: HR-190
func TestHR190_NoPackagesMeansNoPOSTRead(t *testing.T) {
	w := ecsWorld(t)
	reads := httpReads(w.defs, nil)
	if len(reads) != 0 {
		t.Fatalf("reads %v", reads)
	}
	if got := httpReads(w.defs, w.pkgs); len(got) != 2 {
		t.Fatalf("reads %v", got)
	}
}
