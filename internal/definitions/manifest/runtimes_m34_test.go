// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package manifest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	pcawsagentcore "github.com/katocxl/pantherclaw/packages/pc-aws-agentcore"
	pcawsssm "github.com/katocxl/pantherclaw/packages/pc-aws-ssm"
	pcazurecompute "github.com/katocxl/pantherclaw/packages/pc-azure-compute"
	pcazurefoundry "github.com/katocxl/pantherclaw/packages/pc-azure-foundry"
	pcvertexagentengine "github.com/katocxl/pantherclaw/packages/pc-vertex-agent-engine"
)

// The M34 packages (G0 M34 D993, D993a, D1002; HR-763, HR-525, T-347,
// T-348).

// goldenM34 pins a package's canonical form and every definition digest
// (HR-124).
func goldenM34(t *testing.T, base string, raw []byte, name, version string) *domain.Package {
	t.Helper()
	p, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != name || p.Version != version {
		t.Fatalf("decoded %s %s, want %s %s", p.Name, p.Version, name, version)
	}
	canon, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, base+".canonical.json", append(canon, '\n'))
	var digests strings.Builder
	for _, d := range p.Definitions {
		fmt.Fprintf(&digests, "%s %s\n", d.Operation, d.Digest)
	}
	golden(t, base+".digests", []byte(digests.String()))
	return p
}

type m34Pkg struct {
	base, name, version string
	raw                 []byte
}

var m34Packages = []m34Pkg{
	{"pc-aws-agentcore", pcawsagentcore.Name, pcawsagentcore.Version, pcawsagentcore.Package},
	{"pc-aws-ssm", pcawsssm.Name, pcawsssm.Version, pcawsssm.Package},
	{"pc-azure-compute", pcazurecompute.Name, pcazurecompute.Version, pcazurecompute.Package},
	{"pc-azure-foundry", pcazurefoundry.Name, pcazurefoundry.Version, pcazurefoundry.Package},
	{"pc-vertex-agent-engine", pcvertexagentengine.Name, pcvertexagentengine.Version, pcvertexagentengine.Package},
}

// TestHR124_M34PackagesGolden pins the reviewed meaning of the M34
// packages.
func TestHR124_M34PackagesGolden(t *testing.T) {
	for _, p := range m34Packages {
		t.Run(p.base, func(t *testing.T) { goldenM34(t, p.base, p.raw, p.name, p.version) })
	}
}

// m34Writes are HR-763's writes: each operation's effect.
var m34Writes = map[string]string{
	"vertex.reasoning_engine.create":  "agent.deploy",
	"vertex.reasoning_engine.patch":   "agent.deploy",
	"foundry.agent.create":            "agent.deploy",
	"foundry.agent.update":            "agent.deploy",
	"aws.ssm.send_command":            "code.execute",
	"aws.ssm.send_powershell_command": "code.execute",
	"azure.vm.run_command":            "code.execute",
}

// TestHR763_DeployAndAdminCommandsAreReviewedIrreversibleWrites: every
// write of the M34 packages is one of HR-763's, with its agent.deploy or
// code.execute effect, irreversible, never retried, and named by no policy
// pack (template grant); pc.aws-agentcore is reads only. A command's
// command id is a closed enum and its commands or script at most 8192
// bytes.
func TestHR763_DeployAndAdminCommandsAreReviewedIrreversibleWrites(t *testing.T) {
	seen := map[string]bool{}
	for _, pk := range m34Packages {
		p, err := Decode(pk.raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range p.Definitions {
			if d.Access != domain.AccessWrite {
				continue
			}
			if pk.name == pcawsagentcore.Name {
				t.Errorf("pc.aws-agentcore has the write %s (reads only in M34)", d.Operation)
			}
			effect, ok := m34Writes[d.Operation]
			if !ok {
				t.Errorf("%s: a write HR-763 does not name", d.Operation)
				continue
			}
			seen[d.Operation] = true
			if len(d.Effects) != 1 || d.Effects[0].Kind != effect || d.Reversibility != domain.Irreversible || d.Retry.Safe ||
				d.Assurance.Basis == "" || len(d.Assurance.ReviewedBy) == 0 {
				t.Errorf("%s: effects %+v reversibility %s retry %+v assurance %+v", d.Operation, d.Effects, d.Reversibility, d.Retry, d.Assurance)
			}
			if effect == "code.execute" {
				for name, ps := range d.Params {
					if ps.Type == domain.TypeCommand && (ps.MaxLength == 0 || ps.MaxLength > 8192 || !ps.Material) {
						t.Errorf("%s.%s: %+v", d.Operation, name, ps)
					}
				}
			}
		}
	}
	for op := range m34Writes {
		if !seen[op] {
			t.Errorf("no package defines %s", op)
		}
	}
	p, err := Decode(pcazurecompute.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("azure.vm.run_command")
	if c := d.Params["command_id"]; c.Type != domain.TypeEnum || !slices.Equal(c.Values, []string{"RunShellScript", "RunPowerShellScript"}) {
		t.Errorf("command_id %+v", c)
	}
	if s := d.Params["script"]; s.Type != domain.TypeCommand || s.MaxLength != 8192 {
		t.Errorf("script %+v", s)
	}

	packs, err := filepath.Glob("../../policy/packs/*/pack.json")
	if err != nil || len(packs) == 0 {
		t.Fatalf("policy packs: %v %v", packs, err)
	}
	for _, f := range packs {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for op := range m34Writes {
			if bytes.Contains(raw, []byte(`"`+op+`"`)) {
				t.Errorf("%s names %s", f, op)
			}
		}
		for _, pk := range m34Packages {
			if bytes.Contains(raw, []byte(pk.name)) {
				t.Errorf("%s names %s", f, pk.name)
			}
		}
	}
}

// TestT348_ASSMSessionIsTheInstanceAndTheDocument: each SSM operation's
// session is narrowed to exactly two ARNs, the one target instance and its
// literal document, which is also the body's document; the target is one
// EC2 instance id.
func TestT348_ASSMSessionIsTheInstanceAndTheDocument(t *testing.T) {
	p, err := Decode(pcawsssm.Package)
	if err != nil {
		t.Fatal(err)
	}
	const inst = "i-0123456789abcdef0"
	for op, doc := range map[string]string{
		"aws.ssm.send_command": "AWS-RunShellScript", "aws.ssm.send_powershell_command": "AWS-RunPowerShellScript",
	} {
		d, ok := p.Definition(op)
		if !ok {
			t.Fatalf("no %s", op)
		}
		got, err := d.AWSResourceARNs(actionir.Target{Type: "aws_ec2_instance", ID: inst}, "111122223333", "us-east-1", "aws")
		want := []string{"arn:aws:ec2:us-east-1:111122223333:instance/" + inst, "arn:aws:ssm:us-east-1::document/" + doc}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: %v %v, want %v", op, got, err, want)
		}
		h := d.Dispatch.HTTP
		if h.Body["DocumentName"] != "literal."+doc || h.Headers["X-Amz-Target"] != "AmazonSSM.SendCommand" || d.Target.IDPattern != `^i-[0-9a-f]{8,17}$` {
			t.Errorf("%s: body %v headers %v target %+v", op, h.Body, h.Headers, d.Target)
		}
	}
}

// TestHR525_ExtraARNsAreExactAndBounded: aws_extra_resources is refused
// beyond 3, without an aws_resource, with a wildcard, with a free agent
// parameter, repeating aws_resource, or repeated; three distinct exact ARNs
// are taken (founder decision FQ34-4).
func TestHR525_ExtraARNsAreExactAndBounded(t *testing.T) {
	const line = "          - 'arn:{aws.partition}:ssm:{aws.region}::document/AWS-RunShellScript'\n"
	if !bytes.Contains(pcawsssm.Package, []byte(line)) {
		t.Fatal("the package's extra resource line moved")
	}
	edit := func(extra string) []byte {
		return bytes.Replace(pcawsssm.Package, []byte(line), []byte(extra), 1)
	}
	doc := func(n int) string {
		return fmt.Sprintf("          - 'arn:{aws.partition}:ssm:{aws.region}::document/Doc-%d'\n", n)
	}
	if _, err := Decode(edit(line + doc(1) + doc(2))); err != nil {
		t.Fatalf("three exact ARNs: %v", err)
	}
	for name, raw := range map[string][]byte{
		"four":          edit(line + doc(1) + doc(2) + doc(3)),
		"wildcard":      edit("          - 'arn:{aws.partition}:ssm:{aws.region}::document/*'\n"),
		"star":          edit("          - '*'\n"),
		"agent param":   edit("          - 'arn:{aws.partition}:ssm:{aws.region}::document/{params.commands}'\n"),
		"repeated":      edit(line + line),
		"same as first": edit("          - 'arn:{aws.partition}:ec2:{aws.region}:{aws.account}:instance/{target.id}'\n"),
		"no aws_resource": bytes.Replace(pcawsssm.Package,
			[]byte("        aws_resource: 'arn:{aws.partition}:ec2:{aws.region}:{aws.account}:instance/{target.id}'\n"), nil, 1),
	} {
		if bytes.Equal(raw, pcawsssm.Package) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHR763_AgentCoreReadsAreTheClosedRouteTable: pc.aws-agentcore's three
// reads are the aws-rest route table's (D993a item 2), each with its one
// action and Resource "*"; a path outside the table (an exact match, the
// trailing "/" kept) or a write on a route is refused.
func TestHR763_AgentCoreReadsAreTheClosedRouteTable(t *testing.T) {
	p, err := Decode(pcawsagentcore.Package)
	if err != nil {
		t.Fatal(err)
	}
	for op, want := range map[string]string{
		"agentcore.runtimes.list": "ListAgentRuntimes", "agentcore.gateways.list": "ListGateways", "agentcore.gateway_targets.list": "ListGatewayTargets",
	} {
		d, ok := p.Definition(op)
		if !ok {
			t.Fatalf("no %s", op)
		}
		action, ok := d.AWSAction()
		res, err := d.AWSResourceARNs(actionir.Target{Type: d.Target.Type, ID: "gw-1"}, "111122223333", "us-east-1", "aws")
		if !ok || action != want || err != nil || !slices.Equal(res, []string{"*"}) || d.Access != domain.AccessRead {
			t.Errorf("%s: action %q %v, resources %v %v", op, action, ok, res, err)
		}
	}
	for name, edit := range map[string][2]string{
		"no trailing slash": {"        path: /runtimes/\n", "        path: /runtimes\n"},
		"other path":        {"        path: /gateways/\n", "        path: /gateways/x/\n"},
		"other method":      {"        method: POST\n        path: /runtimes/\n", "        method: PUT\n        path: /runtimes/\n"},
		"a write":           {"    access: read\n", "    access: write\n"},
	} {
		raw := bytes.Replace(pcawsagentcore.Package, []byte(edit[0]), []byte(edit[1]), 1)
		if bytes.Equal(raw, pcawsagentcore.Package) {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
