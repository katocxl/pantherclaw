// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcawsecs_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
)

const (
	describe = "AmazonEC2ContainerServiceV20141113.DescribeServices"
	account  = "111122223333"
	txn      = "01920000-0000-7000-8000-000000000009"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcawsecs.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcawsecs.Name || p.Version != pcawsecs.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	return p
}

func deployArgs(taskDefinition string) string {
	b, _ := json.Marshal(map[string]string{"account_id": account, "cluster": "prod", "service": "web", "task_definition": taskDefinition})
	return string(b)
}

// TestHR526_TheDeployIsAnMCPToolFixedByThePackage: the deploy is reached only
// through its MCP tool (D284), its ECS operation and its resource come from
// the package and the decision's target, and the session it gets names that
// one action on that one service (D270).
// Covers: HR-526, HR-525, F756
func TestHR526_TheDeployIsAnMCPToolFixedByThePackage(t *testing.T) {
	p := decode(t)
	if _, ok := p.TestRead(); ok {
		t.Fatal("an ECS connection has no test read (D284)")
	}
	d, ok := p.Definition("aws.ecs.service.deploy")
	if !ok || len(d.Mappings) != 1 || d.Mappings[0].Channel != domain.ChannelMCP {
		t.Fatalf("mappings %+v", d)
	}
	if a, ok := d.AWSAction(); !ok || a != "UpdateService" {
		t.Fatalf("action %q", a)
	}
	for _, op := range []string{"aws.ecs.service.rollout", "aws.ecs.service.read", "aws.ecs.service.deployments.read"} {
		if r, ok := p.Definition(op); !ok || len(r.Mappings) != 0 {
			t.Errorf("%s: agents do not reach it", op)
		}
	}

	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := m.MCP(context.Background(), tc, "aws_ecs_deploy_service", []byte(deployArgs(awssim.TaskDefinition(2))))
	if err != nil {
		t.Fatal(err)
	}
	a := parsed.Action
	if a.Operation != d.Operation || a.Target.ID != awssim.ServiceTarget || a.Target.Account != account {
		t.Fatalf("action %+v", a)
	}
	r, err := egress.Build("https://ecs.us-east-1.amazonaws.com", d, a, txn)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"cluster":"prod","service":"web","taskDefinition":"` + awssim.TaskDefinition(2) + `"}`
	if string(r.Body) != want || r.Method != http.MethodPost || r.URL.Path != "/" || r.ContentType != domain.AWSJSONContentType ||
		r.Headers["X-Amz-Target"] != "AmazonEC2ContainerServiceV20141113.UpdateService" {
		t.Fatalf("request %s %s %s %v", r.Method, r.URL, r.Body, r.Headers)
	}
	arn, err := d.AWSResourceARN(a.Target, account, "us-east-1", "aws")
	if err != nil || arn != "arn:aws:ecs:us-east-1:"+account+":service/prod/web" {
		t.Fatalf("resource %q %v", arn, err)
	}
}

// TestHR526_AnAgentNamesOneRevisionAndNeverTheController: a family without a
// revision means whatever is latest and is refused, and an agent cannot name
// the controller the mapping fixes (D284).
// Covers: HR-526, F756
func TestHR526_AnAgentNamesOneRevisionAndNeverTheController(t *testing.T) {
	p := decode(t)
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for name, arg := range map[string]string{
		"a family":     "arn:aws:ecs:us-east-1:" + account + ":task-definition/web",
		"a short name": "web:2",
		"a wildcard":   "arn:aws:ecs:us-east-1:" + account + ":task-definition/*:2",
		"revision 0":   "arn:aws:ecs:us-east-1:" + account + ":task-definition/web:0",
	} {
		if _, err := m.MCP(context.Background(), tc, "aws_ecs_deploy_service", []byte(deployArgs(arg))); err == nil {
			t.Errorf("%s was mapped", name)
		}
	}
	extra := strings.TrimSuffix(deployArgs(awssim.TaskDefinition(2)), "}") + `,"deployment_controller":"CODE_DEPLOY"}`
	if _, err := m.MCP(context.Background(), tc, "aws_ecs_deploy_service", []byte(extra)); err == nil {
		t.Fatal("an agent named the controller")
	}
	parsed, err := m.MCP(context.Background(), tc, "aws_ecs_deploy_service", []byte(deployArgs(awssim.TaskDefinition(2))))
	if err != nil {
		t.Fatal(err)
	}
	var params map[string]any
	if err := json.Unmarshal(parsed.Action.Params, &params); err != nil || params["deployment_controller"] != "ECS" {
		t.Fatalf("params %s %v", parsed.Action.Params, err)
	}
	d, _ := p.Definition("aws.ecs.service.deploy")
	if b := d.Prerequisites[0].Binds; d.Prerequisites[0].Fact != "aws.ecs.service.controller" || b.Member != "type" ||
		b.Param != "deployment_controller" || b.Reason != "VERIFIER_UNSUPPORTED" {
		t.Fatalf("prerequisite %+v", d.Prerequisites[0])
	}
}

// TestHR190_DescribeServicesIsSentAsAListOfTheTarget: the verification reads
// are the D283 exception, send the target and nothing else, and the rollout
// is a consequence found by the revision the deploy's verifier captures.
// Covers: HR-190, F756
func TestHR190_DescribeServicesIsSentAsAListOfTheTarget(t *testing.T) {
	p := decode(t)
	for _, op := range []string{"aws.ecs.service.read", "aws.ecs.service.deployments.read"} {
		d, _ := p.Definition(op)
		if !d.PostVerificationRead() || d.Target.Account != domain.PresenceNone {
			t.Fatalf("%s: %+v", op, d.Dispatch.HTTP)
		}
		a := actionir.ActionIR{Operation: op, Target: actionir.Target{Type: "aws_ecs_service", ID: awssim.ServiceTarget}, Params: []byte(`{}`)}
		r, err := egress.Build("https://ecs.us-east-1.amazonaws.com", d, a, txn)
		if err != nil {
			t.Fatal(err)
		}
		if string(r.Body) != `{"cluster":"prod","services":["web"]}` || r.Headers["X-Amz-Target"] != describe {
			t.Fatalf("%s: %s %v", op, r.Body, r.Headers)
		}
	}
	reads := strings.Join(p.HTTPReads(), " ")
	if !strings.Contains(reads, "aws.ecs.service.read") || !strings.Contains(reads, "aws.ecs.service.deployments.read") {
		t.Fatalf("a gateway must serve the reads: %s", reads)
	}
	deploy, _ := p.Definition("aws.ecs.service.deploy")
	rollout, _ := p.Definition("aws.ecs.service.rollout")
	if deploy.Verifier.Capture["task_definition"] != "/services/0/taskDefinition" || rollout.Verifier.Lookup == nil ||
		rollout.Verifier.Lookup.IDParam != "" || len(p.Consequences) != 1 || p.Consequences[0].Consequence.Operation != rollout.Operation {
		t.Fatalf("deploy %+v rollout %+v", deploy.Verifier, rollout.Verifier)
	}
}

// TestHR190_NoOtherPOSTIsAVerificationRead: at package validation, the
// exception is exact: UpdateService declared as a read, a near-match target,
// and the same target in another encoding are all refused, and a matched
// lookup without id_param is valid on no other read (D283, D284).
// Covers: HR-190
func TestHR190_NoOtherPOSTIsAVerificationRead(t *testing.T) {
	read := func(header string) []byte {
		return bytes.ReplaceAll(pcawsecs.Package, []byte("X-Amz-Target: "+describe), []byte(header))
	}
	for name, raw := range map[string][]byte{
		"UpdateService as a read": read("X-Amz-Target: AmazonEC2ContainerServiceV20141113.UpdateService"),
		"a longer target":         read("X-Amz-Target: " + describe + "X"),
		"another version":         read("X-Amz-Target: AmazonEC2ContainerServiceV20141114.DescribeServices"),
		"another case":            read("X-Amz-Target: AmazonEC2ContainerServiceV20141113.describeservices"),
		"another service":         read("X-Amz-Target: AWSCodeDeploy_20141006.DescribeServices"),
		"a second target":         read("X-Amz-Target: " + describe + "\n          x-amz-target: AmazonEC2ContainerServiceV20141113.UpdateService"),
	} {
		if _, err := manifest.Decode(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Only the last read declares a param, so the change goes there.
	lastBody := func(line string) []byte {
		at := bytes.LastIndex(pcawsecs.Package, []byte("          services[]: target.id.service\n"))
		return slices.Concat(pcawsecs.Package[:at], []byte(line+"\n"), pcawsecs.Package[at:])
	}
	for name, raw := range map[string][]byte{
		"an extra header":       read("X-Amz-Target: " + describe + "\n          X-HTTP-Method-Override: DELETE"),
		"a param in the body":   lastBody("          cmd: params.task_definition"),
		"a literal in the body": lastBody("          cmd: literal.drop-all-tables"),
		"a query": bytes.Replace(lastBody(""), []byte("        body:\n          cluster: target.id.cluster\n\n"),
			[]byte("        query:\n          force: target.id.cluster\n        body:\n          cluster: target.id.cluster\n"), 1),
		"an org package":    bytes.Replace(pcawsecs.Package, []byte("\nname: pc.aws.ecs\n"), []byte("\nname: acme.ecs\n"), 1),
		"another publisher": bytes.Replace(pcawsecs.Package, []byte("\npublisher: pantherclaw\n"), []byte("\npublisher: acme\n"), 1),
	} {
		if bytes.Equal(raw, pcawsecs.Package) {
			t.Fatalf("%s changed nothing", name)
		}
		if _, err := manifest.Decode(raw); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// An org key cannot claim the name: it is PantherClaw's namespace.
	if !trust.Reserved(pcawsecs.Name) || pcawsecs.Name != domain.ECSPackage {
		t.Fatalf("%s is not reserved", pcawsecs.Name)
	}
	noDisagreement := bytes.Replace(pcawsecs.Package, []byte("reconcile: [FAILED, disagreement]"), []byte("reconcile: [FAILED]"), 1)
	if _, err := manifest.Decode(noDisagreement); err == nil || !strings.Contains(err.Error(), "disagreement") {
		t.Fatalf("a lookup without id_param whose items may differ: %v", err)
	}
}
