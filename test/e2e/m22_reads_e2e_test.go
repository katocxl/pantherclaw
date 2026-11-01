// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/proto"

	casesdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	casesstore "github.com/katocxl/pantherclaw/internal/cases/store"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/ticketsync/adapters/ticketsyncrpc"
	tsdomain "github.com/katocxl/pantherclaw/internal/ticketsync/domain"
)

// m22Rotation rotates the GitHub App's key through CredentialRotationService.
// The RPCs have no browser session, so activating and rolling back are refused
// with STEP_UP_REQUIRED and change nothing (T-240); a person's step-up activates
// through the same use case the server page calls. No response carries the
// sealed key.
func (s *stack) m22Rotation(t *testing.T, rc *connect.Client) {
	ctx := context.Background()
	rotations := pantherclawv1connect.NewCredentialRotationServiceClient(rc)
	conn := s.gh.conn.String()
	refused := func(err error) {
		t.Helper()
		if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "STEP_UP_REQUIRED") {
			t.Fatalf("refused with: %v", err)
		}
	}
	stateOf := func(id string) string {
		t.Helper()
		got, err := rotations.GetRotation(ctx, &pantherclawv1.GetRotationRequest{Id: id})
		if err != nil {
			t.Fatal(err)
		}
		return got.GetRotation().GetState()
	}

	var version int32
	s.query(t, "SELECT version FROM pc.credentials WHERE connection_id = $1 AND state = 'ACTIVE'", []any{s.gh.conn}, &version)
	preview, err := pantherclawv1connect.NewResponseServiceClient(rc).PreviewCredentialChange(ctx, &pantherclawv1.PreviewCredentialChangeRequest{
		ConnectionId: conn, Version: version,
	})
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s.gh.sim.AddAppKey(&key.PublicKey)
	asked, err := rotations.RequestRotation(ctx, &pantherclawv1.RequestRotationRequest{ConnectionId: conn, PreviewDigest: preview.GetPreviewDigest()})
	if err != nil {
		t.Fatal(err)
	}
	id := asked.GetRotation().GetId()
	s.eventually(t, string(creddomain.RotationRequested), "SELECT state FROM pc.credential_rotations WHERE id = $1", id)

	sealed := s.m22Seal(t, rc, id, key)
	if _, err := rotations.TestRotation(ctx, &pantherclawv1.TestRotationRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, "true", "SELECT (test_passed_at IS NOT NULL)::text FROM pc.credential_rotations WHERE id = $1", id)

	tested := stateOf(id)
	_, err = rotations.ActivateRotation(ctx, &pantherclawv1.ActivateRotationRequest{Id: id})
	refused(err)
	if got := stateOf(id); got != tested {
		t.Fatalf("a refused activation moved it from %s to %s", tested, got)
	}

	rotator := s.person(t, "m22-rotator", td.RoleGatewayAdmin)
	rotation := mustUUID(t, id)
	if _, err := credapp.New(s.pool, nil).ActivateRotation(rotator.ctx, rotation, stepup.StepUp{Credential: rotator.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationActivating), "SELECT state FROM pc.credential_rotations WHERE id = $1", id)

	_, err = rotations.RollBackRotation(ctx, &pantherclawv1.RollBackRotationRequest{Id: id, Reason: "changed my mind"})
	refused(err)
	if got := stateOf(id); got != string(creddomain.RotationActivating) {
		t.Fatalf("a refused rollback left it %s", got)
	}

	var gateway ids.UUID
	s.query(t, "SELECT gateway_id FROM pc.connections WHERE id = $1", []any{s.gh.conn}, &gateway)
	s.waitConfig(t, s.configVersion(t, gateway))
	s.gh.sim.RevokeAppKey(&s.gh.key.PublicKey)
	if _, err := rotations.ConfirmRotation(ctx, &pantherclawv1.ConfirmRotationRequest{Id: id}); err != nil {
		t.Fatal(err)
	}
	s.eventually(t, string(creddomain.RotationConfirmed), "SELECT state FROM pc.credential_rotations WHERE id = $1", id)

	got, err := rotations.GetRotation(ctx, &pantherclawv1.GetRotationRequest{Id: id})
	if err != nil {
		t.Fatal(err)
	}
	if r := got.GetRotation(); r.GetState() != string(creddomain.RotationConfirmed) || r.GetCandidateCredentialId() == "" ||
		r.GetPreviewDigest() != "sha256:"+preview.GetPreviewDigest() || r.GetActivatedBy() == "" || r.GetConfirmTime() == nil {
		t.Fatalf("the rotation read back: %+v", r)
	}
	list, err := rotations.ListRotations(ctx, &pantherclawv1.ListRotationsRequest{ConnectionId: conn})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(list.GetRotations(), func(r *pantherclawv1.CredentialRotation) bool { return r.GetId() == id }) {
		t.Fatalf("the list misses %s: %v", id, list.GetRotations())
	}
	for _, m := range []proto.Message{got, list} {
		wire, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, sealed) {
			t.Fatal("a response carried the sealed key")
		}
	}
}

// m22Seal seals key for the connection and uploads it as the rotation's
// candidate, as pclaw credential rotation seal does, and returns the sealed bytes.
func (s *stack) m22Seal(t *testing.T, rc *connect.Client, rotation string, key *rsa.PrivateKey) []byte {
	t.Helper()
	ctx := context.Background()
	k, err := pantherclawv1connect.NewConnectionServiceClient(rc).GetSealingKey(ctx, &pantherclawv1.GetSealingKeyRequest{ConnectionId: s.gh.conn.String()})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	plain, err := creddomain.GitHubApp{V: 1, Issuer: s.gh.app, Installation: s.gh.installation, Account: s.gh.account, PrivateKey: pemKey}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b := creddomain.Binding{
		Org: k.GetOrgId(), Connection: k.GetConnectionId(), Version: k.GetVersion(), AllowedHosts: k.GetAllowedHosts(),
		BrokerKey: k.GetBrokerKeyId(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: creddomain.KindGitHubApp,
	}
	sealed, err := pccrypto.Seal(pub, b.Info(), creddomain.AAD, plain)
	clear(plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pantherclawv1connect.NewCredentialRotationServiceClient(rc).SealRotationCandidate(ctx, &pantherclawv1.SealRotationCandidateRequest{
		RotationId: rotation,
		Credential: &pantherclawv1.PutCredentialRequest{
			ConnectionId: k.GetConnectionId(), Version: k.GetVersion(), BrokerKeyId: k.GetBrokerKeyId(), Sealed: sealed,
			AllowedHosts: k.GetAllowedHosts(), Header: k.GetHeader(), Scheme: k.GetScheme(), Kind: creddomain.KindGitHubApp,
			Github: &pantherclawv1.GitHubInstallation{AppClientId: s.gh.app, InstallationId: s.gh.installation, AccountLogin: s.gh.account},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return sealed
}

// m22ScanState reads D6's scan state through GetAgent and ListAgents: an agent
// is missed by the fewest scans of any finding and vanished only when every
// finding did; an agent no scan found has none.
func (s *stack) m22ScanState(t *testing.T, rc *connect.Client) {
	ctx := context.Background()
	agent := func(name string, vanished ...bool) string {
		t.Helper()
		id := ids.NewV7()
		s.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'test')", s.org, id, name)
		for i, v := range vanished {
			scanKey := bytes.Repeat([]byte{byte(i + 1)}, 32)
			copy(scanKey, id[:])
			s.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, missed_scans, vanish_notified_at)
				VALUES ($1, $2, $3, 'scan', $4, $5, CASE WHEN $6 THEN now() END)`, s.org, ids.NewV7(), id, scanKey, i+2, v)
		}
		return id.String()
	}
	seen := agent("seen-by-one", false, true)
	gone := agent("gone", true, true)
	plain := agent("no-scan")

	agents := pantherclawv1connect.NewAgentServiceClient(rc)
	all, err := agents.ListAgents(ctx, &pantherclawv1.ListAgentsRequest{PageSize: 200})
	if err != nil {
		t.Fatal(err)
	}
	listed := func(id string) *pantherclawv1.AgentScanState {
		t.Helper()
		i := slices.IndexFunc(all.GetAgents(), func(a *pantherclawv1.Agent) bool { return a.GetId() == id })
		if i < 0 {
			t.Fatalf("the list misses %s", id)
		}
		return all.GetAgents()[i].GetScanState()
	}
	got := func(id string) *pantherclawv1.AgentScanState {
		t.Helper()
		a, err := agents.GetAgent(ctx, &pantherclawv1.GetAgentRequest{Id: id})
		if err != nil {
			t.Fatal(err)
		}
		return a.GetSummary().GetAgent().GetScanState()
	}
	for name, st := range map[string]*pantherclawv1.AgentScanState{"get": got(seen), "list": listed(seen)} {
		if st.GetMissedScans() != 2 || st.GetVanished() || st.GetLastSeenTime() == nil {
			t.Errorf("%s: one finding left: %+v", name, st)
		}
	}
	for name, st := range map[string]*pantherclawv1.AgentScanState{"get": got(gone), "list": listed(gone)} {
		if st.GetMissedScans() != 2 || !st.GetVanished() {
			t.Errorf("%s: every finding gone: %+v", name, st)
		}
	}
	if a, b := got(plain), listed(plain); a != nil || b != nil {
		t.Errorf("no scan found it: %+v, %+v", a, b)
	}
}

// m22Tickets reads D7's links and sync log through TicketSyncService: a linked
// case's ticket, then the log of a real signed delivery and a ticket opened
// through the gateway, a page at a time, newest first.
func (s *stack) m22Tickets(t *testing.T, rc *connect.Client) {
	ctx := context.Background()
	tickets := pantherclawv1connect.NewTicketSyncServiceClient(rc)
	cfg, err := tickets.CreateTicketSyncConfig(ctx, &pantherclawv1.CreateTicketSyncConfigRequest{ConnectionId: s.jira.conn.String(), ProjectKey: "SEC"})
	if err != nil {
		t.Fatal(err)
	}
	config := cfg.GetConfig().GetId()
	admin := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'm22-admin'")
	open := func(title string) string {
		t.Helper()
		var c casesdomain.Case
		if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			c, err = casesstore.Open(ctx, tx, casesdomain.NewCase{Title: title, Source: "manual", OpenedBy: casesdomain.Author{Type: "user", ID: admin}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return c.ID.String()
	}
	linked := open("leaked token")
	if _, err := tickets.LinkCaseTicket(ctx, &pantherclawv1.LinkCaseTicketRequest{CaseId: linked, ConfigId: config, Key: "SEC-7"}); err != nil {
		t.Fatal(err)
	}
	refs, err := tickets.ListTicketRefs(ctx, &pantherclawv1.ListTicketRefsRequest{Subject: &pantherclawv1.ListTicketRefsRequest_CaseId{CaseId: linked}})
	if err != nil {
		t.Fatal(err)
	}
	if got := refs.GetRefs(); len(got) != 1 || got[0].GetKey() != "SEC-7" || got[0].GetCaseId() != linked || got[0].GetSystem() != "jira" {
		t.Fatalf("the links: %v", got)
	}
	none, err := tickets.ListTicketRefs(ctx, &pantherclawv1.ListTicketRefsRequest{Subject: &pantherclawv1.ListTicketRefsRequest_IncidentId{IncidentId: ids.NewV7().String()}})
	if err != nil || len(none.GetRefs()) != 0 {
		t.Fatalf("an incident with no ticket: %v, %v", none.GetRefs(), err)
	}

	other := open("another")
	outbound, err := tickets.OpenCaseTicket(ctx, &pantherclawv1.OpenCaseTicketRequest{CaseId: other, ConfigId: config})
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Appendf(nil, `{"timestamp":%d,"webhookEvent":"jira:issue_updated",
		"issue":{"key":"SEC-7","fields":{"status":{"statusCategory":{"key":"done"}}}},
		"changelog":{"items":[{"field":"status","fromString":"To Do","toString":"Done"}]}}`, time.Now().UnixMilli())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+ticketsyncrpc.WebhookPath+s.org.String()+"/"+config, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(tsdomain.JiraDeliveryHeader, "m22-exit-1")
	req.Header.Set(tsdomain.JiraSignatureHeader, tsdomain.SignJira([]byte(cfg.GetWebhookSecret()), body))
	res, err := http.DefaultClient.Do(req) //nolint:gosec // G704: the test server's own address
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("webhook: %d", res.StatusCode)
	}

	first, err := tickets.ListTicketSyncEvents(ctx, &pantherclawv1.ListTicketSyncEventsRequest{ConfigId: config, PageSize: 1})
	if err != nil || len(first.GetEvents()) != 1 || first.GetNextPageToken() == "" {
		t.Fatalf("the first page: %v, %v", first, err)
	}
	if e := first.GetEvents()[0]; e.GetDirection() != "INBOUND" || e.GetStatus() == "" || e.GetIssueKey() != "SEC-7" || e.GetOccurTime() == nil {
		t.Fatalf("the inbound event: %v", e)
	}
	second, err := tickets.ListTicketSyncEvents(ctx, &pantherclawv1.ListTicketSyncEventsRequest{ConfigId: config, PageSize: 1, PageToken: first.GetNextPageToken()})
	if err != nil || len(second.GetEvents()) != 1 || second.GetNextPageToken() != "" {
		t.Fatalf("the second page: %v, %v", second, err)
	}
	if e := second.GetEvents()[0]; e.GetDirection() != "OUTBOUND" || e.GetId() != outbound.GetOutboundId() || e.GetAction() != "CREATE" || e.GetCaseId() != other {
		t.Fatalf("the outbound event: %v", e)
	}
	_, err = tickets.ListTicketSyncEvents(ctx, &pantherclawv1.ListTicketSyncEventsRequest{ConfigId: ids.NewV7().String()})
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("an unknown configuration: %v", err)
	}
}

// m22ModelReads reads D8's drafts and usage through ModelService: what a call
// spent and which version it drafted, never its text (HR-554). The table holds
// no text to return, so the rows are seeded; drafting itself is M21's.
func (s *stack) m22ModelReads(t *testing.T, rc *connect.Client) {
	ctx := context.Background()
	call, version := ids.NewV7(), ids.NewV7()
	s.exec(t, `INSERT INTO pc.model_calls (org_id, id, actor, task, model, outcome, input_tokens, output_tokens, finished_at)
		VALUES ($1, $2, 'user:m22', 'POLICY_DRAFT', 'claude-opus-5-5', 'OK', 10, 5, now())`, s.org, call)
	s.exec(t, `INSERT INTO pc.model_calls (org_id, id, actor, task, model, reserved_tokens)
		VALUES ($1, $2, 'user:m22', 'SEARCH_QUERY', 'claude-opus-5-5', 100)`, s.org, ids.NewV7())
	s.exec(t, "INSERT INTO pc.model_drafts (org_id, version_id, call_id, kind) VALUES ($1, $2, $3, 'POLICY')", s.org, version, call)

	models := pantherclawv1connect.NewModelServiceClient(rc)
	drafts, err := models.ListModelDrafts(ctx, &pantherclawv1.ListModelDraftsRequest{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := drafts.GetDrafts(); len(got) != 1 || got[0].GetVersionId() != version.String() || got[0].GetKind() != "POLICY" || got[0].GetOrigin() != "model" || drafts.GetNextPageToken() != "" {
		t.Fatalf("the drafts: %v", drafts)
	}
	usage, err := models.GetModelUsage(ctx, &pantherclawv1.GetModelUsageRequest{Days: 7})
	if err != nil {
		t.Fatal(err)
	}
	if usage.GetSince() == nil || len(usage.GetRows()) != 2 {
		t.Fatalf("the usage: %v", usage)
	}
	row := func(task string) *pantherclawv1.ModelUsageRow {
		t.Helper()
		i := slices.IndexFunc(usage.GetRows(), func(r *pantherclawv1.ModelUsageRow) bool { return r.GetTask() == task })
		if i < 0 {
			t.Fatalf("no %s row: %v", task, usage)
		}
		return usage.GetRows()[i]
	}
	if r := row("POLICY_DRAFT"); r.GetOutcome() != "OK" || r.GetCalls() != 1 || r.GetInputTokens() != 10 || r.GetOutputTokens() != 5 {
		t.Errorf("the draft's call: %v", r)
	}
	if r := row("SEARCH_QUERY"); r.GetOutcome() != "PENDING" || r.GetCalls() != 1 || r.GetReservedTokens() != 100 {
		t.Errorf("the pending call: %v", r)
	}
}
