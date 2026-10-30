// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pcaws_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"testing"
	"time"

	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	pcaws "github.com/katocxl/pantherclaw/packages/pc-aws"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005",
}

func decode(t *testing.T) *domain.Package {
	t.Helper()
	p, err := manifest.Decode(pcaws.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pcaws.Name || p.Version != pcaws.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	return p
}

// TestHR526_IAMReadsAreMCPOnlyAndFixedByThePackage: every IAM read is an
// MCP tool (aws-query is outbound only, D262), each names exactly one IAM
// action in its literal Action, and the connection test is a GET of
// GetAccountSummary.
// Covers: HR-526
func TestHR526_IAMReadsAreMCPOnlyAndFixedByThePackage(t *testing.T) {
	p := decode(t)
	want := map[string]string{
		"aws.iam.role.read": "GetRole", "aws.iam.role.attached_policies.read": "ListAttachedRolePolicies",
		"aws.iam.role.inline_policy.read": "GetRolePolicy", "aws.iam.account.read": "GetAccountSummary",
	}
	for _, d := range p.Definitions {
		action, ok := d.AWSAction()
		if !ok || want[d.Operation] != action {
			t.Errorf("%s: action %q", d.Operation, action)
		}
		if d.Access != domain.AccessRead || d.Dispatch.HTTP.Encoding != domain.EncodingAWSQuery {
			t.Errorf("%s: not an aws-query read", d.Operation)
		}
		for _, m := range d.Mappings {
			if m.Channel != domain.ChannelMCP {
				t.Errorf("%s: a %s mapping", d.Operation, m.Channel)
			}
		}
	}
	if test, ok := p.TestRead(); !ok || test.Operation != "aws.iam.account.read" {
		t.Fatal("no connection test read")
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	tools := []string{}
	for _, tool := range m.Tools() {
		tools = append(tools, tool.Tool)
	}
	if !slices.Equal(tools, []string{"aws_iam_get_role", "aws_iam_get_role_policy", "aws_iam_list_attached_role_policies"}) {
		t.Fatalf("tools %v", tools)
	}
	for name, args := range map[string]string{
		"short account": `{"account_id":"1234","role_name":"r"}`,
		"role path":     `{"account_id":"111122223333","role_name":"a/b"}`,
		"extra field":   `{"account_id":"111122223333","role_name":"r","Action":"DeleteRole"}`,
	} {
		if _, err := m.MCP(context.Background(), tc, "aws_iam_get_role", []byte(args)); err == nil {
			t.Errorf("%s: mapped", name)
		}
	}
}

// TestT225_EachIAMReadRunsInASessionOfItsOwnAction: each read, built from
// its action alone, is answered by the simulated IAM when signed by a
// session narrowed to that read's action, and refused when signed by a
// session narrowed to another read: no session can do more than its one
// action, whatever the role allows.
// Covers: T-225, HR-525
func TestT225_EachIAMReadRunsInASessionOfItsOwnAction(t *testing.T) {
	p := decode(t)
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "simulated/base+secret0123456789"
	sim := awssim.New(secret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	client, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	cred := credentials.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte(secret), RoleARN: awssim.RoleARN,
		STSURL: srv.URL, STSRegion: awssim.Region, Region: awssim.Region, Service: "iam",
	}
	send := func(op, args, sessionAction string) int {
		t.Helper()
		tool := map[string]string{
			"aws.iam.role.read": "aws_iam_get_role", "aws.iam.role.inline_policy.read": "aws_iam_get_role_policy",
			"aws.iam.role.attached_policies.read": "aws_iam_list_attached_role_policies",
		}[op]
		parsed, err := m.MCP(context.Background(), tc, tool, []byte(args))
		if err != nil {
			t.Fatal(err)
		}
		d, _ := p.Definition(op)
		built, err := egress.Build(srv.URL, d, parsed.Action, "txn")
		if err != nil {
			t.Fatal(err)
		}
		req, err := client.HTTPRequest(context.Background(), built)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := broker.SessionPolicy(cred.Service, sessionAction)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := broker.AssumeRole(context.Background(), client, []string{u.Host}, cred, policy, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Clear()
		if err := sess.Sign(req, built.Body, time.Now()); err != nil {
			t.Fatal(err)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res.Status
	}
	role := `{"account_id":"` + awssim.Account + `","role_name":"` + awssim.RoleName + `"}`
	inline := `{"account_id":"` + awssim.Account + `","role_name":"` + awssim.RoleName + `","policy_name":"` + awssim.InlinePolicy + `"}`
	for _, c := range []struct {
		op, args string
	}{{"aws.iam.role.read", role}, {"aws.iam.role.attached_policies.read", role}, {"aws.iam.role.inline_policy.read", inline}} {
		d, _ := p.Definition(c.op)
		own, _ := d.AWSAction()
		if got := send(c.op, c.args, own); got != 200 {
			t.Errorf("%s in its own session: %d", c.op, got)
		}
		other := "GetAccountSummary"
		if got := send(c.op, c.args, other); got != 403 {
			t.Errorf("%s in a %s session: %d", c.op, other, got)
		}
	}
}
