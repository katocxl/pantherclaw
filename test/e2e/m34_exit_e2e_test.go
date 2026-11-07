// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/agentcore"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
)

// TestE2E_M34_CloudAgentRuntimes is M34's exit on the real stack (G0 M34):
//
//   - FQ34-2: the AgentCore gateway is proven by its interceptor Lambda's
//     AWS role: an aws_iam attestation enrolls its instance under an
//     auto-admitting issuer entry bound to a run grant, and
//     RuntimeService.StartRuntimeRun starts its run under that grant;
//   - FQ34-1: each tool call the customer's AgentCore gateway sends is
//     decided through the connection bound to its target: a read passes as
//     the original request and is recorded as delegated, a refund the grant
//     holds for a person is answered as a tool error with its transaction,
//     a refund over the grant's bound is denied, and a target nothing is
//     bound to is refused; a gateway in another account than the one its
//     interceptor proved is refused with RUNTIME_ACCOUNT_MISMATCH;
//   - FQ34-3, FQ34-5: a person's daily scan of AgentCore runs as the daily
//     job, finds the account's runtimes and raises pc.runtime.agent_deployed
//     once for an agent deployed outside PantherClaw, and not again;
//   - FQ34-4: pc.aws-ssm's aws.ssm.send_command runs on the strict AWS
//     simulator under a session policy of exactly the instance's and the
//     document's ARNs, one action and no wildcard.
//
// Covers: HR-760, HR-762, HR-764, HR-765, HR-766, HR-768, HR-769, HR-763
func TestE2E_M34_CloudAgentRuntimes(t *testing.T) {
	d, s := newRuntimeDriver(t, "M34-EXIT", false)
	f := s.m34

	// FQ34-2: the gateway's agent, proven by its AWS role.
	rt := s.setupRuntimeAgent(t)
	if rt.run == "" || rt.token == "" {
		t.Fatalf("runtime agent %+v", rt)
	}
	if g := s.row(t, "SELECT coalesce(grant_id::text, '') FROM pc.runs WHERE id = $1", rt.run); g != rt.grant.String() {
		t.Fatalf("the runtime run's grant %q, want the issuer entry's %s", g, rt.grant)
	}
	// A run name the server does not accept starts nothing.
	if _, err := rt.startRun(s.apiURL, "agentcore:bad name with spaces"); err == nil || !strings.Contains(err.Error(), "invalid_argument") {
		t.Fatalf("StartRuntimeRun with a bad name: %v", err)
	}

	// FQ34-1: decisions through the customer's gateway.
	refundableMore(t, s, "ch_m34exit")
	s.runtimeConnection(t, "agentcore-payments", agentcore.GatewayARN, agentcore.Target)
	read := toolEvent(t, agentcore.Target, "get_refund", map[string]any{"refund": "re_m34exit"})
	act := ids.NewV7()
	a := s.face(t, rt, agentcore.GatewayARN, act, read)
	if !a.Pass || !bytes.Equal(a.Body, rpcBody(t, read)) {
		t.Fatalf("a read through the AgentCore gateway: %d %s", a.Status, a.Raw)
	}
	txn, decision, _, channel := s.txnOf(t, rt.run, act)
	if decision != "ALLOW" || channel != "runtime" {
		t.Fatalf("the read's transaction %s: %s on %q", txn, decision, channel)
	}
	if n := s.delegatedOf(t, txn); n != "1" {
		t.Fatalf("the read is recorded delegated %s times, want once (HR-760)", n)
	}

	act = ids.NewV7()
	a = s.face(t, rt, agentcore.GatewayARN, act, toolEvent(t, agentcore.Target, "create_refund",
		map[string]any{"charge": "ch_m34exit", "amount": "40.00", "currency": "USD", "reason": "requested_by_customer"}))
	txn, decision, _, _ = s.txnOf(t, rt.run, act)
	if !a.IsError || !strings.HasPrefix(a.Text, "held for a person's approval in PantherClaw") || txn == "" || !strings.Contains(a.Text, txn) || decision != "REQUIRE_APPROVAL" {
		t.Fatalf("a refund the grant holds: %s (transaction %s %s)", a.Raw, txn, decision)
	}
	if n := s.delegatedOf(t, txn); n != "0" {
		t.Fatalf("a held refund is recorded delegated %s times", n)
	}

	act = ids.NewV7()
	a = s.face(t, rt, agentcore.GatewayARN, act, toolEvent(t, agentcore.Target, "create_refund",
		map[string]any{"charge": "ch_m34exit", "amount": "400.00", "currency": "USD", "reason": "requested_by_customer"}))
	txn, decision, _, _ = s.txnOf(t, rt.run, act)
	if !a.IsError || !strings.HasPrefix(a.Text, "PantherClaw denied this call") || decision != "DENY" {
		t.Fatalf("a refund over the grant's bound: %s (transaction %s %s)", a.Raw, txn, decision)
	}

	a = s.face(t, rt, agentcore.GatewayARN, ids.NewV7(), toolEvent(t, "billing", "get_refund", map[string]any{"refund": "re_m34exit"}))
	if !a.IsError || !strings.HasPrefix(a.Text, "RUNTIME_TARGET_UNKNOWN") {
		t.Fatalf("a target nothing is bound to: %s", a.Raw)
	}

	// D994a: a gateway in another account than the interceptor proved.
	other := gatewayARN(m34OtherAccount, "gw-other")
	s.runtimeConnection(t, "agentcore-other", other, agentcore.Target)
	act = ids.NewV7()
	a = s.face(t, rt, other, act, read)
	if txn, _, _, _ := s.txnOf(t, rt.run, act); !a.IsError || !strings.Contains(a.Text, "does not match the account its interceptor proved") || txn != "" {
		t.Fatalf("another account's gateway: %s (transaction %q)", a.Raw, txn)
	}

	// HR-766: the real interceptor, whose enrolment proof the server
	// refuses here, lets nothing through.
	ic := s.runInterceptor(t, f.awsSession(t, m34Function, "sts:GetCallerIdentity"))
	a = s.invoke(t, ic, "get_refund", map[string]any{"refund": "re_m34exit"})
	if a.Pass || !a.IsError || !strings.Contains(a.Text, "PantherClaw cannot decide this tool call") {
		t.Fatalf("the interceptor that cannot enroll: %s\n%s", a.Raw, ic.logs.String())
	}

	// FQ34-3, FQ34-5: the daily scan and the deployed-agent alert.
	s.scheduleAgentCore(t)
	if state, notScanned := s.dailyScan(t, 1); state != "DONE" || notScanned != "{}" {
		t.Fatalf("the first daily scan: %s, not scanned %s", state, notScanned)
	}
	eventually(t, time.Minute, "the baseline runtime alert", func() (bool, error) {
		return s.alertsOf(t, m34Rule) > 0, nil
	})
	first := s.alertsOf(t, m34Rule)
	if n := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore'", s.org); n == "0" || first == 0 {
		t.Fatalf("the first daily scan: %s discoveries, %d %s alerts", n, first, m34Rule)
	}
	f.deployRuntime(t, "shadow_agent")
	s.dueAgain(t)
	if state, notScanned := s.dailyScan(t, 2); state != "DONE" {
		t.Fatalf("the second daily scan: %s, not scanned %s", state, notScanned)
	}
	eventually(t, time.Minute, "one alert for the new runtime", func() (bool, error) {
		return s.alertsOf(t, m34Rule) == first+1, nil
	})
	s.dueAgain(t)
	if state, _ := s.dailyScan(t, 3); state != "DONE" {
		t.Fatalf("the third daily scan: %s", state)
	}
	time.Sleep(5 * time.Second) // the detection has had its chance to fire again
	if n := s.alertsOf(t, m34Rule); n != first+1 {
		t.Fatalf("%d %s alerts after a scan that found nothing new, want %d", n, m34Rule, first+1)
	}

	// FQ34-4: SSM on exact ARNs.
	d.ownGrant(ssmGrant, "")
	obs := d.ssmSend(t, m34Instance, "uptime")
	if obs.Outcome != domain.OutcomeAllow {
		t.Fatalf("send_command on the granted instance: %+v", obs)
	}
	cmds := f.acct.Commands()
	if len(cmds) != 1 || cmds[0].DocumentName != "AWS-RunShellScript" || !slices.Equal(cmds[0].InstanceIDs, []string{m34Instance}) ||
		!slices.Equal(cmds[0].Commands, []string{"uptime"}) {
		t.Fatalf("commands the account ran: %+v", cmds)
	}
	checkSSMSession(t, f.ssmPolicies(), m34Instance)
	if obs := d.ssmSend(t, aws.SecondInstance, "uptime"); obs.Outcome == domain.OutcomeAllow || len(f.acct.Commands()) != 1 {
		t.Fatalf("send_command on an instance the grant does not name: %+v, %d commands", obs, len(f.acct.Commands()))
	}
}

// checkSSMSession checks that every SendCommand session policy allowed
// exactly ssm:SendCommand on instance's and the shell document's ARNs.
func checkSSMSession(t *testing.T, docs []string, instance string) {
	t.Helper()
	if len(docs) == 0 {
		t.Fatal("no ssm:SendCommand session policy was asked for")
	}
	want := []string{
		"arn:aws:ec2:" + aws.Region + ":" + aws.Account + ":instance/" + instance,
		"arn:aws:ssm:" + aws.Region + "::document/AWS-RunShellScript",
	}
	slices.Sort(want)
	for _, doc := range docs {
		var p struct {
			Statement []struct {
				Effect   string `json:"Effect"`
				Action   any    `json:"Action"`
				Resource any    `json:"Resource"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal([]byte(doc), &p, json.RejectUnknownMembers(false)); err != nil || len(p.Statement) != 1 {
			t.Fatalf("session policy %s: %v", doc, err)
		}
		st := p.Statement[0]
		actions, resources := strs(st.Action), strs(st.Resource)
		slices.Sort(resources)
		if st.Effect != "Allow" || !slices.Equal(actions, []string{"ssm:SendCommand"}) || !slices.Equal(resources, want) || strings.Contains(doc, "*") {
			t.Fatalf("session policy %s, want ssm:SendCommand on exactly %v", doc, want)
		}
	}
}

// strs is a policy element: one string or a list of them.
func strs(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			s, _ := e.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}
