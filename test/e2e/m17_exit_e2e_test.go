// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/consequencerules"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	rapp "github.com/katocxl/pantherclaw/internal/ranges/app"
	rdomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M17_ACustomerRuleDownAPackageChainIsNeverWaived is M17's chain
// exit path (F405, F408, F411, HR-454, D145): a transfer to a payee whose
// bank changed predicts the package's consequence. The policy forbids that
// consequence and an active exception waives the rule, so the transfer is
// only held. Once an org's customer rule predicts the same operation below
// it, for the payee's reserve account, the transfer is a DENY that reaches
// nothing: no exception waives a customer consequence. Confirming a rule with
// a second person is HR-453's own test; here the approval is seeded.
//
// Covers: F405, F408, F411
func TestE2E_M17_ACustomerRuleDownAPackageChainIsNeverWaived(t *testing.T) {
	s := start(t, options{budget: "1000.00", stripe: true})
	const bundle = `{"id": "no-changed-payees", "rules": [{"id": "no-changed-payees", "kind": "FORBID", "summary": "no changed payees", ` +
		`"operations": ["stripe.payee.changed_recently"], "when": "true", "reason": "NO_CHANGED_PAYEES", "exceptable": true}]}`
	s.publishPolicy(t, bundle)
	var b pdomain.Bundle
	if err := json.Unmarshal([]byte(bundle), &b); err != nil {
		t.Fatal(err)
	}
	digest := pdomain.RuleDigest(b.Rules[0])

	owner, approver := ids.NewV7(), ids.NewV7()
	for i, u := range []ids.UUID{owner, approver} {
		s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, u, fmt.Sprintf("m17-%d", i))
	}
	agent := mustUUID(t, s.row(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", s.run))
	exception := ids.NewV7()
	s.exec(t, `INSERT INTO pc.policy_exceptions (org_id, id, bundle_id, rule_id, rule_digest, agent_id, operations, reason, owner_id,
		requested_by, requested_expiry) VALUES ($1, $2, 'no-changed-payees', 'no-changed-payees', $3, $4, '{stripe.payee.changed_recently}', 'month end', $5, $5,
		now() + interval '1 day')`, s.org, exception, digest[:], agent, owner)
	s.exec(t, `UPDATE pc.policy_exceptions SET state = 'ACTIVE', activated_at = now(), expires_at = now() + interval '1 hour'
		WHERE org_id = $1 AND id = $2`, s.org, exception)

	// The exception works: the package's consequence is waived, so the
	// transfer is held by the template, not denied.
	s.st.sim.ChangeBank(stripe.FixturePayee, time.Now().Add(-time.Hour))
	transfer := func(amount string) (int, reply) {
		form := url.Values{"destination": {stripe.FixturePayee}, "amount": {amount}, "currency": {"usd"}}
		code, r, _ := s.stripeCall(t, http.MethodPost, "/v1/transfers", form, ids.NewV7())
		return code, r
	}
	if code, r := transfer("1000"); code != http.StatusForbidden || r.Decision != "REQUIRE_APPROVAL" || slices.Contains(r.Reasons, "NO_CHANGED_PAYEES") {
		t.Fatalf("the transfer the exception waives: %d %+v", code, r)
	}

	body, sum, err := consequencerules.Encode(defs.ConsequenceRule{
		ID: "cx.changed-payee-reserves", Operation: "stripe.payee.changed_recently",
		When:          "facts.stripe_account_payout_details_changed.changed == true",
		RequiresFacts: []string{"stripe.account.payout_details_changed"},
		Consequence: defs.Consequence{
			Operation: "stripe.payee.changed_recently", Effect: "funds.payee_changed_recently", Target: "{target.id}r",
			Description: "The payee's reserve account can receive the funds too.",
		},
		ValidUntil: "2027-10-30", MaxDepth: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	rule := ids.NewV7()
	s.exec(t, `INSERT INTO pc.customer_consequence_rules (org_id, id, rule_id, version, body, digest, proposed_by)
		VALUES ($1, $2, 'cx.changed-payee-reserves', 1, $3, $4, $5)`, s.org, rule, body, sum[:], owner)
	s.exec(t, "UPDATE pc.customer_consequence_rules SET state = 'ACTIVE', approved_by = $3 WHERE org_id = $1 AND id = $2", s.org, rule, approver)

	code, r := transfer("1200")
	if code != http.StatusForbidden || r.Decision != "DENY" || !slices.Contains(r.Reasons, "NO_CHANGED_PAYEES") {
		t.Fatalf("a transfer with a customer consequence below the package's: %d %+v", code, r)
	}
	if n := len(s.st.sim.Transfers()); n != 0 {
		t.Fatalf("%d transfers", n)
	}
	got := s.row(t, `SELECT string_agg(rule_id || ':' || source, ' ' ORDER BY position) FROM pc.decision_consequences WHERE transaction_id = $1`, r.TransactionID)
	if got != "payee-changed-recently:package cx.changed-payee-reserves:customer" {
		t.Fatalf("recorded consequences: %q", got)
	}
}

// TestE2E_M17_ADownstreamConsequenceConfirmsItsParent is M17's downstream
// exit path (F414, HR-451): a merge whose push deploys is confirmed, and
// the parent's downstream state stays PENDING until its deployment, a
// consequence transaction of its own, is confirmed from the deployment's
// evidence; only then does the parent get its downstream receipt.
//
// Covers: F414
func TestE2E_M17_ADownstreamConsequenceConfirmsItsParent(t *testing.T) {
	s := start(t, options{budget: "1000.00", github: true})
	// Nothing holds the merge: its approvals are M8's path.
	s.db.AdminExec(t, "UPDATE pc.grant_revisions SET requirements = '[]'::bytea WHERE org_id = $1", s.org)
	gh := s.gh.sim
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/git/refs", `{"ref":"refs/heads/fix/m17","sha":"`+gh.Branch(ghRepo, "main")+`"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("branch: %d %+v", code, r)
	}
	content := base64.StdEncoding.EncodeToString([]byte("package parser // m17\n"))
	if code, r, _ := s.ghCall(t, http.MethodPut, "/repos/"+ghRepo+"/contents/src/parser.go",
		`{"message":"Fix","content":"`+content+`","branch":"fix/m17"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("write: %d %+v", code, r)
	}
	if code, r, _ := s.ghCall(t, http.MethodPost, "/repos/"+ghRepo+"/pulls", `{"title":"Fix","head":"fix/m17","base":"main"}`, ids.NewV7()); code != http.StatusCreated {
		t.Fatalf("open: %d %+v", code, r)
	}
	pr, _ := gh.PullRequest(ghRepo, 1)
	code, done := s.ghMerge(t, ids.NewV7(), 1, pr.HeadSHA)
	if code != http.StatusOK || done.Outcome != "ACCEPTED" {
		t.Fatalf("merge: %d %+v", code, done)
	}
	effect := "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1"
	downstream := "SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1"
	s.eventually(t, "CONFIRMED", effect, done.TransactionID)
	s.eventually(t, "PENDING", downstream, done.TransactionID)
	var consequence string
	s.query(t, `SELECT coalesce((SELECT to_transaction_id::text FROM pc.transaction_links
		WHERE from_transaction_id = $1 AND kind = 'consequence'), '')`, []any{done.TransactionID}, &consequence)
	if consequence == "" {
		t.Fatal("no consequence transaction for the deployment")
	}
	receipts := "SELECT count(*)::text FROM pc.effect_receipts WHERE transaction_id = $1 AND basis = 'consequence'"
	if got := s.row(t, receipts, done.TransactionID); got != "0" {
		t.Fatalf("%s downstream receipts before the deployment is confirmed", got)
	}
	deployments := gh.Deployments(ghRepo)
	if len(deployments) != 1 {
		t.Fatalf("deployments: %+v", deployments)
	}
	gh.SetDeploymentStatus(ghRepo, deployments[0].ID, "success")
	s.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", mustUUID(t, consequence))
	s.eventually(t, "CONFIRMED", effect, consequence)
	s.eventually(t, "CONFIRMED", downstream, done.TransactionID)
	if got := s.row(t, receipts, done.TransactionID); got != "1" {
		t.Fatalf("%s downstream receipts", got)
	}
}

// TestE2E_M17_AVanishedAgentIsOnlyNotified is M17's discovery exit path
// (PN-001.3, HR-458): through the server, complete CI scans of one scope
// that stop finding an MCP server count a miss each. After 3 the agent's
// disappearance is recorded once, and neither the discovery nor the agent
// changes.
//
// Covers: PN-001.3
func TestE2E_M17_AVanishedAgentIsOnlyNotified(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	sa := s.row(t, "SELECT service_account_id::text FROM pc.api_keys WHERE org_id = $1 AND service_account_id IS NOT NULL LIMIT 1", s.org)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by) VALUES ($1, $2, 'agent_owner', $3, 'ORG', 'e2e')`,
		s.org, ids.NewV7(), mustUUID(t, sa))
	s.db.AdminExec(t, "UPDATE pc.api_keys SET scopes = scopes || '{agent.manage}' WHERE org_id = $1", s.org)
	key, err := os.ReadFile(s.factsKey)
	if err != nil {
		t.Fatal(err)
	}
	agents := pantherclawv1connect.NewAgentServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 10 * time.Second, Transport: keyBearer{strings.TrimSpace(string(key))},
	}, s.apiURL)))
	scan := func(names ...string) *pantherclawv1.SubmitScanFindingsResponse {
		t.Helper()
		req := &pantherclawv1.SubmitScanFindingsRequest{Host: "runner", Scope: "acme/payments", Complete: true}
		for _, n := range names {
			sum := sha256.Sum256([]byte("mcp_server" + n))
			req.Findings = append(req.Findings, &pantherclawv1.ScanFinding{
				Kind: "mcp_server", Key: fmt.Sprintf("%x", sum[:]),
				Attributes: map[string]string{"name": n, "client": "cursor", "transport": "stdio"},
			})
		}
		res, err := agents.SubmitScanFindings(context.Background(), req)
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		return res
	}
	if r := scan("keep", "gone"); r.GetCreated() != 2 || r.GetMissed() != 0 {
		t.Fatalf("first scan: %+v", r)
	}
	vanished := "SELECT count(*)::text FROM pc.agent_changes WHERE org_id = $1 AND kind = 'agent.discovery_vanished'"
	for i := range 3 {
		if r := scan("keep"); r.GetMissed() != 1 {
			t.Fatalf("scan %d: %+v", i+2, r)
		}
		want := "0"
		if i == 2 {
			want = "1"
		}
		if got := s.row(t, vanished, s.org); got != want {
			t.Fatalf("after %d misses: %s vanish records, want %s", i+1, got, want)
		}
	}
	if got := s.row(t, `SELECT d.state || ' ' || a.state FROM pc.discoveries d JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
		WHERE d.org_id = $1 AND d.observed ->> 'name' = 'gone'`, s.org); got != "OPEN DISCOVERED" {
		t.Fatalf("the vanished discovery and agent: %q", got)
	}
}

// TestE2E_M17_ASPIFFEWorkloadEnrolls is M17's identity preset exit path
// (PN-002.3, HR-462): an Enterprise org's trust domain comes from the
// server's configuration, an Identity Publisher activates an entry that
// pins one SPIFFE ID, and pclaw enrolls with that workload's JWT-SVID;
// another workload of the trust domain is refused.
//
// Covers: PN-002.3
func TestE2E_M17_ASPIFFEWorkloadEnrolls(t *testing.T) {
	const (
		domain = "prod.acme.test"
		id     = "spiffe://" + domain + "/ns/agents/sa/runner"
	)
	s := start(t, options{budget: "1000.00", billing: true})
	if err := hostedPlans(t, s.pool).ApplyPlan(context.Background(), s.org, entitlements.Snapshot{
		PlanID: "enterprise", Edition: "enterprise", Status: entitlements.StatusActive, EventID: "evt_m17_exit", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	dir := t.TempDir()
	bundle := writeFile(t, dir, "bundle.json", []byte(`{"keys":[{"kty":"RSA","kid":"k1","use":"jwt-svid","n":"`+enc(key.N.Bytes())+
		`","e":"`+enc(big.NewInt(int64(key.E)).Bytes())+`"}]}`))
	s.restartWith(t, "identity", map[string]any{"spiffe_trust_domains": []any{map[string]any{
		"trust_domain": domain, "bundle_file": bundle, "orgs": []string{s.org.String()},
	}}})
	directory, err := issuerkeys.NewSPIFFEDirectory([]issuerkeys.TrustDomain{{
		TrustDomain: domain, BundleFile: bundle, Access: issuerkeys.Access{Orgs: []string{s.org.String()}},
	}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	ctx, details := s.agentDetails(t, "spiffe-bot")
	details.Context = adomain.ContextService
	bot, err := aapp.NewInventory(s.pool, unlimited{}).Create(ctx, details)
	if err != nil {
		t.Fatal(err)
	}
	svc := iapp.New(s.pool, keys.NewRegistry(), s.apiURL, clock.System{}).WithEntitlements(enterprise{}).WithAttestors(iapp.Attestors{SPIFFE: directory})
	entry, err := svc.ProposeIssuer(s.person(t, "m17-admin", td.RoleOrgAdmin).ctx, iapp.ProposeInput{
		AgentID: bot.ID, Binding: iapp.Binding{SPIFFE: &issuers.SPIFFEBinding{TrustDomain: domain, SPIFFEID: id}}, AutoAdmit: true, Reason: "e2e",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActivateIssuer(s.person(t, "m17-publisher", td.RoleIdentityPublisher).ctx, entry.EntryID, entry.Revision, false); err != nil {
		t.Fatal(err)
	}

	svid := func(sub string) string {
		now := time.Now()
		claims, err := json.Marshal(map[string]any{
			"sub": sub, "aud": []string{"pantherclaw:" + s.org.String()}, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		signing := enc([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`)) + "." + enc(claims)
		digest := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(t, dir, "svid", []byte(signing+"."+enc(sig)))
	}
	cli := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := pclaw.Run(context.Background(), args, &out, &errb, noEnv, pclaw.Options{})
		return code, out.String(), errb.String()
	}
	enroll := func(name, sub string) (int, string, string) {
		file := filepath.Join(dir, name+".json")
		if code, _, e := cli("workload", "init", "--key-file", file); code != 0 {
			t.Fatalf("init: %s", e)
		}
		return cli("workload", "enroll", "--key-file", file, "--server", s.apiURL, "--spiffe-token", svid(sub), "--org", s.org.String())
	}
	if code, o, e := enroll("rogue", "spiffe://"+domain+"/ns/agents/sa/other"); code == 0 {
		t.Fatalf("another workload enrolled: %s %s", o, e)
	}
	if code, o, e := enroll("runner", id); code != 0 {
		t.Fatalf("enroll: %d %s %s", code, o, e)
	}
}

// TestE2E_M17_ACustomerScenarioIsLabeled is M17's custom-range exit path
// (PN-009.6, HR-466): a CX- scenario's range and results are stored as
// customer-authored, whatever the runner sends, and the range has no
// assurance report. The runner claims library origin: the server derives
// the origin from the id, so the claim is dropped rather than refused, and
// the refusal comes at the export. The export is wired and the caller
// may export, so only HR-466 can stop it.
//
// Covers: PN-009.6
func TestE2E_M17_ACustomerScenarioIsLabeled(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	ctx, details := s.agentDetails(t, "range-coder")
	details.RangeAgent = true
	agent, err := aapp.NewInventory(s.pool, unlimited{}).Create(ctx, details)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	svc := &rapp.Service{Store: pgranges.Store{Pool: s.pool}, Editions: unlimited{}, Exporter: unreachedExporter{}}
	r, err := svc.StartRange(ctx, rapp.StartInput{Agent: agent.ID, RunnerVersion: "e2e", Scenarios: []rdomain.Scenario{{
		ID: "CX-00042", Digest: digest, Tier: rdomain.TierBusiness, Category: "boundary", Suite: "coding-agent", Title: "our tool", StepCount: 1,
		Origin: rdomain.OriginLibrary,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordResult(ctx, rapp.RecordInput{Range: r.ID, Scenario: "CX-00042", Digest: digest, Verdict: rdomain.Skipped}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.FinishRange(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Range.Origin != rdomain.OriginCustomer || len(got.Results) != 1 || got.Results[0].Scenario.Origin != rdomain.OriginCustomer {
		t.Fatalf("stored range %q, results %+v", got.Range.Origin, got.Results)
	}
	exporter := s.person(t, "range-exporter", td.RoleSecurityAdmin).ctx
	if _, err := svc.ExportAssuranceReport(exporter, r.ID); !errors.Is(err, rapp.ErrNotAttested) {
		t.Fatalf("a customer range's assurance report: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
}

// unreachedExporter fails if a customer range ever gets as far as a pack.
type unreachedExporter struct{}

func (unreachedExporter) ExportRange(context.Context, ids.UUID) (ids.UUID, error) {
	return ids.UUID{}, errors.New("a customer range reached the exporter")
}

// enterprise is the edition the identity presets need (HR-461..464).
type enterprise struct{}

func (enterprise) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition = billing.Enterprise
	return e, nil
}

// agentDetails returns an agent owner's context and the details of a new
// agent next to the seeded one.
func (s *stack) agentDetails(t *testing.T, name string) (context.Context, adomain.Details) {
	t.Helper()
	var team, env, owner string
	s.query(t, `SELECT a.team_id::text, a.environment_id::text, a.owner_user_id::text FROM pc.agents a
		JOIN pc.runs r ON r.agent_id = a.id WHERE r.id = $1`, []any{s.run}, &team, &env, &owner)
	return s.person(t, name+"-owner", td.RoleAgentOwner).ctx, adomain.Details{
		Name: name, TeamID: mustUUID(t, team), EnvironmentID: mustUUID(t, env), OwnerUserID: mustUUID(t, owner), Context: adomain.ContextCI,
	}
}

// restartWith restarts the server with section set in its configuration.
func (s *stack) restartWith(t *testing.T, section string, value any) {
	t.Helper()
	raw, err := os.ReadFile(s.serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg[section] = value
	if raw, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	s.stop()
	<-s.done
	if err := os.WriteFile(s.serverCfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s.serve(t)
}
