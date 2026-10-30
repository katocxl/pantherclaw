// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/exposure/recompute"
	"github.com/katocxl/pantherclaw/internal/gateway"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// TestE2E_M16_DataFlowHold is M16's data-flow exit path (F123, HR-431):
// through the real stack, a refund through the public payments connection
// is allowed while the run has read nothing sensitive; the agent then
// reads a refund that the facts provider classifies as pii
// (pc.classification, D80), the read records its class (D72), and the
// next refund, an external disclosure (D74), is held for approval with
// DATA_FLOW_HOLD and reaches nothing.
func TestE2E_M16_DataFlowHold(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	if code, r := s.refund(t, ids.NewV7(), "10.00"); code != http.StatusOK {
		t.Fatalf("a refund before any sensitive read: %d %+v", code, r)
	}

	// The seeded provider also declares the classification of refunds.
	s.db.AdminExec(t, `INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s, kind)
		SELECT org_id, provider_id, 'pc.classification', 'identifier', 'payments.refund', 3600, 'classification'
		FROM pc.fact_declarations WHERE org_id = $1 AND name = 'payments.charge.refundable'`, s.org)
	s.classify(t, "payments.refund", "re_customer", "pii")

	code := s.gatewayGet(t, "/payments/v1/refunds/re_customer")
	var class string
	s.query(t, `SELECT coalesce(read_class, '') FROM pc.transactions WHERE operation = 'payments.refund.get' AND decision = 'ALLOW'`, nil, &class)
	if class != "pii" {
		t.Fatalf("the classified read (%d) records read_class %q", code, class)
	}

	writes := s.simCalls.Load()
	code, held := s.refund(t, ids.NewV7(), "11.00")
	if code != http.StatusForbidden || held.Decision != "REQUIRE_APPROVAL" || !slices.Contains(held.Reasons, "DATA_FLOW_HOLD") {
		t.Fatalf("a disclosure after the pii read: %d %+v", code, held)
	}
	if s.simCalls.Load() != writes {
		t.Fatal("the held refund reached the payments API")
	}
}

// classify reports, as the seeded facts provider, that the subject's data
// class is class (pc.classification, with its provenance).
func (s *stack) classify(t *testing.T, subjectType, subject, class string) {
	t.Helper()
	key, err := os.ReadFile(s.factsKey)
	if err != nil {
		t.Fatal(err)
	}
	facts := pantherclawv1connect.NewFactServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 10 * time.Second, Transport: keyBearer{strings.TrimSpace(string(key))},
	}, s.apiURL)))
	res, err := facts.PutFacts(context.Background(), &pantherclawv1.PutFactsRequest{Observations: []*pantherclawv1.FactObservation{{
		Name: "pc.classification", SubjectType: subjectType, SubjectId: subject, Value: []byte(`{"id": "` + class + `"}`),
		ObserveTime: timestamppb.Now(), Source: "e2e-catalog", Method: "manual",
	}}})
	if err != nil {
		t.Fatalf("PutFacts: %v", err)
	}
	for _, r := range res.GetResults() {
		if !r.GetAccepted() {
			t.Fatalf("the classification was refused: %s %s", r.GetCode(), r.GetDetail())
		}
	}
}

// gatewayGet reads path through the gateway as the seeded workload, in its
// run, and returns the status.
func (s *stack) gatewayGet(t *testing.T, path string) int {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, s.gateway+path, nil)
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestE2E_M16_ExternalPolicyCheck is M16's external-check exit path (F366,
// HR-436..438): an org on the Business plan has an ACTIVE check, an OPA
// endpoint on this machine (dev.external_checks_loopback, D93b), for
// refunds. Its deny is a DENY that reaches nothing, and when it answers
// later than its timeout the refund is CANNOT_AUTHORIZE, never a guess.
// Activation with a security key is HR-438's own test; here the seeded
// administrator's key stands in.
func TestE2E_M16_ExternalPolicyCheck(t *testing.T) {
	var slow atomic.Bool
	opa := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if slow.Load() {
			time.Sleep(time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"result": {"decision": "deny", "reasons": ["refunds are frozen"]}}`)
	}))
	t.Cleanup(opa.Close)
	s := start(t, options{budget: "1000.00", billing: true, externalChecks: []string{opa.URL + "/v1/"}})

	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: opa.Certificate().Raw}))
	check := ids.NewV7()
	s.exec(t, `INSERT INTO pc.external_policy_checks (org_id, id, name, endpoint, ca_pem, timeout_ms, operations, created_by)
		VALUES ($1, $2, 'opa', $3, $4, 250, '{payments.refund.create}', 'user:e2e')`, s.org, check, opa.URL+"/v1/data/pantherclaw/allow", ca)
	s.db.AdminExec(t, `UPDATE pc.external_policy_checks c SET state = 'ACTIVE', activated_by = k.user_id, activated_credential = k.id
		FROM (SELECT user_id, id FROM pc.webauthn_credentials WHERE org_id = $1 LIMIT 1) k WHERE c.org_id = $1 AND c.id = $2`, s.org, check)

	writes := s.simCalls.Load()
	code, r := s.refund(t, ids.NewV7(), "10.00")
	if code != http.StatusForbidden || r.Decision != "DENY" || !slices.Contains(r.Reasons, "EXTERNAL_POLICY_DENY") {
		t.Fatalf("the check's deny: %d %+v", code, r)
	}
	slow.Store(true)
	code, r = s.refund(t, ids.NewV7(), "10.00")
	if code < 400 || r.Decision != "CANNOT_AUTHORIZE" {
		t.Fatalf("the check timing out: %d %+v", code, r)
	}
	if s.simCalls.Load() != writes {
		t.Fatal("a refund the check refused reached the payments API")
	}
}

// TestE2E_M16_SuggestionDraftedNeverPublished is M16's suggestion exit
// path (F185, HR-442): on the Business plan, the seeded grant's refund
// authority, unused for 40 days, becomes an unused-authority finding when
// the server's exposure job runs; the server's suggestion job turns it
// into an OPEN suggestion; a Security Admin who also authors policy drafts
// it into a DRAFT policy version, and nothing is published: the published
// version is the same before and after, and a second draft is refused.
func TestE2E_M16_SuggestionDraftedNeverPublished(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, billing: true})
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	alice := people.user(t, "alice", "alice@example.test")
	alice.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	aliceID := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'")
	for _, role := range []string{"security_admin", "policy_author"} {
		if code, o, e := alice.pclaw(t, "role", "bind", "--role", role, "--user", aliceID); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	alice.login(t, org, "")
	suggestions := pantherclawv1connect.NewSuggestionServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, alice)},
	}, s.apiURL)))

	// The seeded grant is 40 days old and its refunds were never used; the
	// exposure job runs now instead of at its next hourly refresh.
	s.db.AdminExec(t, "UPDATE pc.grants SET created_at = now() - interval '40 days' WHERE org_id = $1", s.org)
	s.db.AdminExec(t, "UPDATE pc.exposure_snapshots SET computed_at = computed_at - interval '2 hours' WHERE org_id = $1", s.org)
	jc, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return jobs.InsertTx(ctx, jc, tx, recompute.OrgArgs{Org: s.org}, nil)
	}); err != nil {
		t.Fatal(err)
	}

	var open *pantherclawv1.Suggestion
	eventually(t, 60*time.Second, "an OPEN unused-authority suggestion", func() (bool, error) {
		res, err := suggestions.ListSuggestions(context.Background(), &pantherclawv1.ListSuggestionsRequest{
			States: []pantherclawv1.SuggestionState{pantherclawv1.SuggestionState_SUGGESTION_STATE_OPEN},
		})
		if err != nil || len(res.GetSuggestions()) == 0 {
			return false, err
		}
		open = res.GetSuggestions()[0]
		return true, nil
	})
	finding := s.row(t, "SELECT id::text FROM pc.posture_findings WHERE kind = 'unused_authority' LIMIT 1")
	if open.GetPostureFindingId() != finding {
		t.Fatalf("the suggestion %+v is not about the unused-authority finding %s", open, finding)
	}

	published := s.row(t, "SELECT coalesce((SELECT id::text FROM pc.policy_versions WHERE state = 'PUBLISHED'), '')")
	res, err := suggestions.DraftFromSuggestion(context.Background(), &pantherclawv1.DraftFromSuggestionRequest{Id: open.GetId()})
	if err != nil || res.GetSuggestion().GetState() != pantherclawv1.SuggestionState_SUGGESTION_STATE_DRAFTED ||
		res.GetSuggestion().GetDraftPolicyVersionId() != res.GetPolicyVersionId() {
		t.Fatalf("DraftFromSuggestion: %+v %v", res, err)
	}
	if got := s.row(t, "SELECT state || ':' || (published_at IS NULL)::text FROM pc.policy_versions WHERE id = $1", res.GetPolicyVersionId()); got != "DRAFT:true" {
		t.Fatalf("the drafted version is %s, want an unpublished DRAFT", got)
	}
	if _, err := suggestions.DraftFromSuggestion(context.Background(), &pantherclawv1.DraftFromSuggestionRequest{Id: open.GetId()}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("a second draft: %v", err)
	}
	if now := s.row(t, "SELECT coalesce((SELECT id::text FROM pc.policy_versions WHERE state = 'PUBLISHED'), '')"); now != published {
		t.Fatalf("the published policy changed from %q to %q", published, now)
	}
}
