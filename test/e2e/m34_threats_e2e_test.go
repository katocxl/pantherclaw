// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	runtimeface "github.com/katocxl/pantherclaw/internal/gateway/runtime"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	saasapp "github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
	saas "github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/sim/agentcore"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT345_AGatewayThatCannotAskRunsNothing is T-345's stack part: a tool
// call PantherClaw did not decide never passes. A face call without the
// instance's proof is refused before any answer, a method the face does
// not decide is an error, and the interceptor that cannot enrol answers
// every call with a tool error.
//
// Covers: HR-760, HR-761, HR-764, HR-766
func TestT345_AGatewayThatCannotAskRunsNothing(t *testing.T) {
	_, s := newRuntimeDriver(t, "T-345", false)
	rt := s.setupRuntimeAgent(t)
	s.runtimeConnection(t, "agentcore-payments", agentcore.GatewayARN, agentcore.Target)
	event := toolEvent(t, agentcore.Target, "get_refund", map[string]any{"refund": "re_t345"})

	// No proof of the instance's key.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+runtimeface.AgentCorePath, bytes.NewReader(event))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(runtimeface.HeaderGateway, agentcore.GatewayARN)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a face call without a proof: %d", res.StatusCode)
	}

	// A token with a forged proof cannot pass an undecided method either.
	ping := bytes.ReplaceAll(event, []byte(`"method":"tools/call"`), []byte(`"method":"ping"`))
	if bytes.Equal(ping, event) {
		t.Fatal("test event did not contain a tools/call method")
	}
	req, err = http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+runtimeface.AgentCorePath, bytes.NewReader(ping))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "PAP "+rt.token)
	req.Header.Set("PAP-Proof", "forged")
	req.Header.Set("PAP-Run-Id", rt.run)
	req.Header.Set(runtimeface.HeaderGateway, agentcore.GatewayARN)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an undecided method with a forged proof: %d", res.StatusCode)
	}

	// A method the face does not decide.
	other := bytes.ReplaceAll(event, []byte(`"method":"tools/call"`), []byte(`"method":"sampling/createMessage"`))
	other = bytes.ReplaceAll(other, []byte(`\"method\":\"tools/call\"`), []byte(`\"method\":\"sampling/createMessage\"`))
	if a := s.face(t, rt, agentcore.GatewayARN, ids.NewV7(), other); a.Pass || !strings.HasPrefix(a.RPCMessage, runtimeface.CodeMethodNotDecided) {
		t.Fatalf("a method the face does not decide: %s", a.Raw)
	}

	// The interceptor that cannot enrol lets nothing through.
	ic := s.runInterceptor(t, s.m34.awsSession(t, m34Function, "sts:GetCallerIdentity"))
	for range 2 {
		if a := s.invoke(t, ic, "get_refund", map[string]any{"refund": "re_t345"}); a.Pass || !strings.Contains(a.Text, "PantherClaw cannot decide this tool call") {
			t.Fatalf("the interceptor that cannot enrol: %s\n%s", a.Raw, ic.logs.String())
		}
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.transactions WHERE run_id = $1", rt.run); n != "0" {
		t.Fatalf("%s transactions in the runtime run, want none", n)
	}
}

// TestT346_AForgedGatewayOrTargetDecidesNothing is T-346's stack part: a
// malformed gateway ARN is refused, a target nothing is bound to decides
// nothing, a target is bound to one connection per org, and a gateway in
// another account than the interceptor proved is refused with
// RUNTIME_ACCOUNT_MISMATCH before any transaction.
//
// Covers: HR-762, HR-764, HR-765
func TestT346_AForgedGatewayOrTargetDecidesNothing(t *testing.T) {
	_, s := newRuntimeDriver(t, "T-346", false)
	rt := s.setupRuntimeAgent(t)
	s.runtimeConnection(t, "agentcore-payments", agentcore.GatewayARN, agentcore.Target)
	event := toolEvent(t, agentcore.Target, "get_refund", map[string]any{"refund": "re_t346"})

	if a := s.face(t, rt, "arn:aws:lambda:us-east-1:"+aws.Account+":function:x", ids.NewV7(), event); a.Status != http.StatusBadRequest ||
		a.Code != runtimeface.CodeGatewayARNInvalid {
		t.Fatalf("a gateway ARN that is not one: %d %s", a.Status, a.Raw)
	}
	if a := s.face(t, rt, gatewayARN(aws.Account, "gw-unbound"), ids.NewV7(), event); a.Pass || !strings.HasPrefix(a.Text, runtimeface.CodeTargetUnknown) {
		t.Fatalf("a gateway nothing is bound to: %s", a.Raw)
	}

	// A second connection for the same target is refused.
	svc := capp.New(s.pool, nil, s.apiURL, "")
	c, err := svc.Seed(context.Background(), s.org, "e2e", capp.CreateInput{
		Name: "agentcore-borrowed", Kind: capp.KindMCP, Package: "pc.mock-payments", BaseURL: s.simURL + "/mcp", Gateway: s.gatewayID(t),
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessAgentHeld, DefaultMode: capp.ModeEnforce,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRuntimeTarget(s.m34person(td.RoleOrgAdmin, td.Scope{}), c.ID,
		runtimeface.TargetPrefix+agentcore.GatewayARN+"/"+agentcore.Target); err == nil {
		t.Fatal("a second connection was bound to a target already bound")
	}

	other := gatewayARN(m34OtherAccount, "gw-other")
	s.runtimeConnection(t, "agentcore-other", other, agentcore.Target)
	act := ids.NewV7()
	a := s.face(t, rt, other, act, event)
	if txn, _, _, _ := s.txnOf(t, rt.run, act); a.Pass || !strings.Contains(a.Text, "does not match the account its interceptor proved") || txn != "" {
		t.Fatalf("another account's gateway: %s (transaction %q)", a.Raw, txn)
	}
}

// TestT347_AnAgentDeployedOutsidePantherClawIsSeen is T-347's stack part:
// an AgentCore runtime deployed with the account's own role, outside
// PantherClaw, is found by the next daily scan and raises
// pc.runtime.agent_deployed (alert only).
//
// Covers: HR-763, HR-769
func TestT347_AnAgentDeployedOutsidePantherClawIsSeen(t *testing.T) {
	_, s := newRuntimeDriver(t, "T-347", false)
	s.scheduleAgentCore(t)
	if state, notScanned := s.dailyScan(t, 1); state != "DONE" {
		t.Fatalf("the first daily scan: %s, not scanned %s", state, notScanned)
	}
	eventually(t, time.Minute, "the baseline runtime alert", func() (bool, error) {
		return s.alertsOf(t, m34Rule) > 0, nil
	})
	first := s.alertsOf(t, m34Rule)
	s.m34.deployRuntime(t, "shadow_t347")
	s.dueAgain(t)
	if state, _ := s.dailyScan(t, 2); state != "DONE" {
		t.Fatalf("the second daily scan: %s", state)
	}
	eventually(t, time.Minute, "an alert for the runtime deployed outside PantherClaw", func() (bool, error) {
		return s.alertsOf(t, m34Rule) == first+1, nil
	})
	if n := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore' AND observed->>'name' = 'shadow_t347'", s.org); n != "1" {
		t.Fatalf("%s discoveries of the new runtime, want 1", n)
	}
}

// TestT348_AgentCommandsStayOnTheirInstance is T-348's stack part: SSM
// SendCommand needs a grant that names the instance; with one, the session
// the gateway assumes allows exactly that instance's and the document's
// ARNs, and an instance the grant does not name never reaches AWS.
//
// Covers: HR-525, HR-763
func TestT348_AgentCommandsStayOnTheirInstance(t *testing.T) {
	d, s := newRuntimeDriver(t, "T-348", false)
	f := s.m34
	if obs := d.ssmSend(t, m34Instance, "id"); obs.Outcome == domain.OutcomeAllow || len(f.acct.Commands()) != 0 {
		t.Fatalf("send_command with no grant naming it: %+v", obs)
	}
	d.ownGrant(ssmGrant, "")
	if obs := d.ssmSend(t, m34Instance, "id"); obs.Outcome != domain.OutcomeAllow || len(f.acct.Commands()) != 1 {
		t.Fatalf("send_command on the granted instance: %+v", obs)
	}
	checkSSMSession(t, f.ssmPolicies(), m34Instance)
	if obs := d.ssmSend(t, aws.SecondInstance, "id"); obs.Outcome == domain.OutcomeAllow || len(f.acct.Commands()) != 1 {
		t.Fatalf("send_command on another instance: %+v", obs)
	}
}

// TestT349_AScheduleScansOnlyAsItsPerson is T-349's stack part: only a
// person sets a schedule; a scan with a credential the account no longer
// accepts finds nothing; and once the person who set it is disabled, the
// daily job starts no scan for it.
//
// Covers: HR-768
func TestT349_AScheduleScansOnlyAsItsPerson(t *testing.T) {
	_, s := newRuntimeDriver(t, "T-349", true)
	f := s.m34
	machine := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	svc := &saasapp.Service{Pool: s.pool, Inventory: aapp.NewInventory(s.pool, nil), Editions: m34Business{}}
	if _, err := svc.SetSchedule(machine, saas.SourceAWSAgentCore, f.agentcoreConn, aws.Account, true); !errors.Is(err, saasapp.ErrScheduleHumanOnly) {
		t.Fatalf("a machine set a schedule: %v", err)
	}

	s.scheduleAgentCore(t)
	if state, _ := s.dailyScan(t, 1); state != "FAILED" {
		t.Fatalf("a daily scan with a stale credential: %s", state)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.discoveries WHERE org_id = $1 AND source = 'aws_agentcore'", s.org); n != "0" {
		t.Fatalf("%s discoveries from a stale credential", n)
	}

	s.db.AdminExec(t, "UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", s.org, f.owner)
	s.dueAgain(t)
	s.stopServer(t)
	s.serve(t)
	time.Sleep(10 * time.Second) // the daily job has run on start
	if n := s.row(t, "SELECT count(*)::text FROM pc.saas_scan_runs WHERE org_id = $1 AND origin = 'schedule'", s.org); n != "1" {
		t.Fatalf("%s scheduled scans after the person was disabled, want the first only", n)
	}
	var stale bool
	s.query(t, "SELECT last_started_at < now() - interval '24 hours' FROM pc.saas_scan_schedules WHERE org_id = $1", []any{s.org}, &stale)
	if !stale {
		t.Fatal("the skipped schedule's last start moved")
	}
}
