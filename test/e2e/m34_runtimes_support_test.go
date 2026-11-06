// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gateway"
	runtimeface "github.com/katocxl/pantherclaw/internal/gateway/runtime"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	saasapp "github.com/katocxl/pantherclaw/internal/saasdiscovery/app"
	saas "github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	"github.com/katocxl/pantherclaw/internal/sim/agentcore"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// The M34 stack (G0 M34): the refund stack with one simulated AWS account
// behind two simulators, AgentCore (control plane, its gateway and STS) and
// the account's own endpoint (STS and SSM), and dev seed's "aws-agentcore"
// and "aws-ssm" connections to them, each with the account's base key
// sealed for the gateway.
//
// The AgentCore gateway's agent (FQ34-2) is a service agent with an aws_iam
// issuer entry for the interceptor Lambda's role, bound to a run grant over
// the reference payments package. Its instance enrols with an aws_iam
// attestation the Lambda role signs: the same SigV4-signed GetCallerIdentity
// the interceptor sends (workloadclient.AWSAttestation), checked as the
// server checks it (issuers.CheckAWSRequest) and answered by the
// simulator's STS, which verifies the signature. The server itself sends a
// signed request only to a real STS host on the public internet (HR-464;
// identity.aws_sts_hosts names host names only and the egress client
// refuses loopback), so the enrolment runs the identity service in-process
// over the stack's database with that STS; every later step (the workload
// token, StartRuntimeRun, the gateway's face, the Authority's account
// check) goes through the running server and gateway. The stack's server
// allows only the STS host sts.e2e.invalid, so the real interceptor, which
// signs for sts.<region>.amazonaws.com, is refused at enrolment without a
// request leaving the machine: that is the fail-closed path (HR-766).

const (
	// m34STSHost is the only STS host the stack's server allows.
	m34STSHost = "sts.e2e.invalid"
	// m34LambdaSTS is the host the Lambda role's attestation names.
	m34LambdaSTS = "sts." + aws.Region + ".amazonaws.com"
	// m34OtherAccount is an account no instance was attested in.
	m34OtherAccount = "999988887777"
	// m34Instance is the SSM target the agent's grant names.
	m34Instance = aws.Instance
	// m34Function and m34Stream name the simulated Lambda.
	m34Function = "pc-agentcore-interceptor"
	m34Stream   = "2026/11/06/[$LATEST]0123456789abcdef"
)

var (
	seededAgentCore = regexp.MustCompile(`seeded aws-agentcore connection ([0-9a-f-]{36}) `)
	seededSSM       = regexp.MustCompile(`seeded aws-ssm connection ([0-9a-f-]{36}) `)
)

// m34Fixture is the M34 part of a stack.
type m34Fixture struct {
	acct     *aws.Server
	awsURL   string
	core     *agentcore.Server
	coreURL  string
	policies *policyLog

	agentcoreConn, ssmConn ids.UUID
	// owner is a person, an org admin in the database, who sets
	// schedules, binds runtime targets and owns the runtime agent.
	owner, team, env ids.UUID
	// rt is the AgentCore gateway's agent and its instance, once enrolled.
	rt *runtimeAgent
}

// runtimeAgent is the AgentCore gateway's agent: its run grant, issuer
// entry and the enrolled instance's key, token and run.
type runtimeAgent struct {
	agent, grant, entry ids.UUID
	key                 ed25519.PrivateKey
	identifier, token   string
	run                 string
}

// policyLog keeps every AssumeRole's session policy the simulators saw.
type policyLog struct {
	mu   sync.Mutex
	docs []string
}

func (p *policyLog) add(doc string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.docs = append(p.docs, doc)
}

func (p *policyLog) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.docs)
}

// recordPolicies wraps h, keeping the Policy of each sts:AssumeRole.
func (p *policyLog) recordPolicies(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.Header.Get("X-Amz-Target") == "" {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			_ = r.Body.Close()
			if form, err := url.ParseQuery(string(body)); err == nil && form.Get("Action") == "AssumeRole" {
				p.add(form.Get("Policy"))
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.ServeHTTP(w, r)
	})
}

// m34Options are the stack options of the M34 fixture: the two
// simulators' dev seed flags, a broker key for their credentials and the
// STS host the server allows.
func m34Options(t *testing.T, o options) (options, *m34Fixture) {
	t.Helper()
	f := &m34Fixture{policies: &policyLog{}}
	f.acct = aws.New(awsSecret, "", []string{"*"}, aws.Faults{}, pclog.Discard())
	awsSrv := httptest.NewServer(f.policies.recordPolicies(f.acct.Handler()))
	t.Cleanup(awsSrv.Close)
	f.core = agentcore.New(f.acct, pclog.Discard())
	coreSrv := httptest.NewServer(f.policies.recordPolicies(f.core.Handler()))
	t.Cleanup(coreSrv.Close)
	f.awsURL, f.coreURL = awsSrv.URL, coreSrv.URL
	o.brokerKey = true
	o.seedArgs = append(o.seedArgs, "--agentcore-url", f.coreURL, "--aws-ssm-url", f.awsURL)
	if o.serverSections == nil {
		o.serverSections = map[string]any{}
	}
	o.serverSections["identity"] = map[string]any{"aws_sts_hosts": []string{m34STSHost}}
	return o, f
}

// newRuntimeDriver starts the M34 stack, with people, for scenario id and
// seals both connections' credentials. staleAgentCore seals a base secret
// the account does not know for the AgentCore connection (T-349).
func newRuntimeDriver(t *testing.T, id string, staleAgentCore bool) (*rangeDriver, *stack) {
	t.Helper()
	p := inProcessIdP(t)
	o, f := m34Options(t, options{budget: "1000.00", people: &p})
	s := start(t, o)
	s.setupM34(t, f, staleAgentCore)
	d := newRangeDriver(t)
	d.s, d.people = s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	d.sc = domain.Scenario{ID: id}
	d.fix = app.Fixture{}
	return d, s
}

// ssmGrant is a grant to run commands on m34Instance only.
const ssmGrant = `{"operations": ["aws.ssm.send_command"], "targets": {"aws_ec2_instance": {"ids": ["` + m34Instance + `"]}}}`

// ssmSend has the agent run commands on instance through the MCP tool.
func (d *rangeDriver) ssmSend(t *testing.T, instance, commands string) domain.Observation {
	t.Helper()
	args, err := json.Marshal(map[string]string{"instance_id": instance, "commands": commands})
	if err != nil {
		t.Fatal(err)
	}
	obs, _, err := d.callOnce(callWith{Face: "mcp", Connection: "aws-ssm", Tool: "aws_ssm_send_command", Args: args}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// setupM34 binds fixture f to stack s: it reads the seeded connections,
// seals their credentials and makes the owner.
func (s *stack) setupM34(t *testing.T, f *m34Fixture, staleAgentCore bool) {
	t.Helper()
	s.m34 = f
	a, m := seededAgentCore.FindStringSubmatch(s.seedOut), seededSSM.FindStringSubmatch(s.seedOut)
	if a == nil || m == nil {
		t.Fatalf("dev seed output %q", s.seedOut)
	}
	f.agentcoreConn, f.ssmConn = mustUUID(t, a[1]), mustUUID(t, m[1])
	secret := awsSecret
	if staleAgentCore {
		secret = "simulated/rotated+secret98765432"
	}
	s.sealAWSFor(t, f.agentcoreConn, f.coreURL, agentcore.Service, secret)
	s.waitConfig(t, s.sealAWSFor(t, f.ssmConn, f.awsURL, "ssm", awsSecret))

	ctx := context.Background()
	f.owner, f.team, f.env = ids.NewV7(), ids.NewV7(), ids.NewV7()
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'runtimes', 'Runtimes')", []any{s.org, f.team}},
			{"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'runtimes', 'Runtimes', 'DEVELOPMENT')", []any{s.org, f.env, f.team}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject, email) VALUES ($1, $2, 'https://idp.test', 'runtime-owner', 'owner@runtime.test')", []any{s.org, f.owner}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The daily scan's person must still be an active member holding
	// agent.manage (D997a item 6): a binding in the database.
	s.db.AdminExec(t, "INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','e2e')",
		s.org, ids.NewV7(), f.owner)
}

// m34person is a context of the fixture's owner with role at scope (the org
// when scope is zero).
func (s *stack) m34person(role td.RoleName, scope td.Scope) context.Context {
	if scope.ID.IsZero() {
		scope = td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}
	}
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: s.m34.owner}, Bindings: []td.Binding{{Role: role, Scope: scope}},
	}, Credential: tapp.CredBrowserSession, Session: ids.NewV7()})
}

// sealAWSFor seals the simulated account's base key with secret for conn,
// signing for service with stsURL as its STS, as pclaw seal does, and
// returns the configuration version the gateway must reach.
func (s *stack) sealAWSFor(t *testing.T, conn ids.UUID, stsURL, service, secret string) int64 {
	t.Helper()
	plain, err := creddomain.AWSSigV4{
		V: 1, AccessKeyID: aws.BaseKeyID, SecretAccessKey: []byte(secret), RoleARN: aws.RoleARN,
		STSURL: stsURL, STSRegion: aws.Region, Region: aws.Region, Service: service,
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org.UUID(), id, "aws-admin-"+id.String()[24:])
	admin := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k.Binding.Kind = creddomain.KindAWSSigV4
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, plain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin, credapp.PutInput{
		Connection: conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme, Kind: creddomain.KindAWSSigV4,
	}); err != nil {
		t.Fatal(err)
	}
	return s.configVersion(t, k.Gateway)
}

// awsSession assumes the simulated role with the base key and a session
// policy allowing action on "*": what the Lambda's execution role hands
// the function, or a person's console session.
func (f *m34Fixture) awsSession(t *testing.T, name, action string) workloadclient.AWSCredentials {
	t.Helper()
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"*"}]}`
	form := url.Values{
		"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {aws.RoleARN}, "RoleSessionName": {name},
		"DurationSeconds": {"900"}, "Policy": {policy},
	}
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.awsURL+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := (sigv4.Signer{Region: aws.Region, Service: "sts"}).Sign(req, sigv4.Credentials{AccessKeyID: aws.BaseKeyID, SecretAccessKey: awsSecret},
		sigv4.HashPayload(body), time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	var out struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	if res.StatusCode != http.StatusOK || xml.Unmarshal(raw, &out) != nil {
		t.Fatalf("AssumeRole: %d %s", res.StatusCode, raw)
	}
	c := out.Result.Credentials
	return workloadclient.AWSCredentials{AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey, SessionToken: c.SessionToken, Region: aws.Region}
}

// simSTS sends a checked aws_iam attestation to the simulated account's
// STS instead of AWS's: the request is checked as awssts.Verifier checks
// it (host, body, headers, signature fields, audience, age), and the
// simulator verifies the SigV4 signature and answers who signed.
type simSTS struct{ url string }

func (v simSTS) Verify(ctx context.Context, org ids.OrgID, token string) (issuers.AWSCaller, issuers.AWSSigned, error) {
	r, err := issuers.ParseAWSRequest(token)
	if err != nil {
		return issuers.AWSCaller{}, issuers.AWSSigned{}, err
	}
	signed, err := issuers.CheckAWSRequest(r, org, func(h string) bool { return h == m34LambdaSTS }, time.Now())
	if err != nil {
		return issuers.AWSCaller{}, signed, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url+"/", strings.NewReader(issuers.AWSBody))
	if err != nil {
		return issuers.AWSCaller{}, signed, err
	}
	for k, val := range r.Headers {
		if !strings.EqualFold(k, "Host") {
			req.Header.Set(k, val)
		}
	}
	req.Host = signed.URL.Host // what was signed
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return issuers.AWSCaller{}, signed, err
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	var out struct {
		Result struct {
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
	}
	if res.StatusCode != http.StatusOK || xml.Unmarshal(body, &out) != nil || out.Result.Arn == "" {
		return issuers.AWSCaller{}, signed, fmt.Errorf("sts: %d %s", res.StatusCode, body)
	}
	return issuers.AWSCaller{Account: out.Result.Account, Arn: out.Result.Arn, UserID: out.Result.UserID}, signed, nil
}

// m34Bounds is the AgentCore gateway agent's run grant: reads of refunds,
// and refunds of at most 100.00 USD, each held for an approver.
const (
	m34Bounds = `{"operations": ["payments.refund.create", "payments.refund.get"],
	  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}}`
	m34Limits = `{"budgets": [{"id": "task", "grouping": "task", "operations": ["payments.refund.create"],
	  "currency": "USD", "limit": "500.00", "period": "none"}]}`
	m34Requirements = `[{"operations": ["payments.refund.create"], "reason": "REFUNDS_NEED_A_PERSON",
	  "approval": {"role": "approver", "count": 1}}]`
)

// setupRuntimeAgent makes the AgentCore gateway's agent (FQ34-2): a
// service agent, its run grant, an auto-admitting aws_iam issuer entry for
// the Lambda role bound to that grant, an instance enrolled with the
// role's attestation, its workload token from the server and a run from
// RuntimeService.StartRuntimeRun.
func (s *stack) setupRuntimeAgent(t *testing.T) *runtimeAgent {
	t.Helper()
	f := s.m34
	ctx := context.Background()
	rt := &runtimeAgent{}
	inv := aapp.NewInventory(s.pool, unlimited{})
	a, err := inv.Create(s.m34person(td.RoleAgentOwner, td.Scope{Type: td.ScopeTeam, ID: f.team}), adomain.Details{
		Name: "agentcore-gateway", TeamID: f.team, EnvironmentID: f.env, OwnerUserID: f.owner, Context: adomain.ContextService,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.agent = a.ID

	bounds, err := gdomain.DecodeBounds([]byte(m34Bounds))
	if err != nil {
		t.Fatal(err)
	}
	limits, err := gdomain.DecodeLimits([]byte(m34Limits))
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := gdomain.DecodeRequirements([]byte(m34Requirements))
	if err != nil {
		t.Fatal(err)
	}
	human := tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.owner},
		Bindings: []td.Binding{
			{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}},
			{Role: td.RoleRunLauncher, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}},
		},
	}, Credential: tapp.CredAccessToken})
	gs := &grantspg.Store{Pool: s.pool, Promotions: grantstest.OpenGate{}}
	grants := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: s.pool}, Authz: allowAll{}, Clock: clock.System{}}
	g, err := grants.Issue(human, grantsapp.IssueRequest{
		AgentID: rt.agent, Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: f.owner}, TaskRef: "agentcore",
		ExpiresAt: time.Now().Add(2 * time.Hour), Bounds: bounds, Limits: limits, Requirements: reqs,
	})
	if err != nil {
		t.Fatal(err)
	}
	rt.grant = g.ID.UUID()

	svc := iapp.New(s.pool, keys.NewRegistry(), s.apiURL, clock.System{}).WithAttestors(iapp.Attestors{AWS: simSTS{url: f.awsURL}})
	rev, err := svc.ProposeIssuer(s.m34person(td.RoleOrgAdmin, td.Scope{}), iapp.ProposeInput{
		AgentID: rt.agent, AutoAdmit: true, Reason: "the AgentCore gateway's interceptor Lambda", RunGrantID: &rt.grant,
		Binding: iapp.Binding{AWS: &issuers.AWSBinding{AccountID: aws.Account, RoleName: aws.RoleName}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActivateIssuer(s.m34person(td.RoleIdentityPublisher, td.Scope{}), rev.EntryID, rev.Revision, false); err != nil {
		t.Fatal(err)
	}
	rt.entry = rev.EntryID

	// The Lambda's execution environment: an in-memory key and the role's
	// attestation.
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt.key = key
	creds := f.awsSession(t, "pc-agentcore-interceptor", "sts:GetCallerIdentity")
	att, err := workloadclient.AWSAttestation(creds, issuers.Audience(s.org), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := svc.Nonce(ctx, s.org)
	if err != nil {
		t.Fatal(err)
	}
	enrollURL := s.apiURL + pantherclawv1connect.WorkloadServiceEnrollProcedure
	body := []byte(att)
	proof, err := pap.NewProof(key, pap.ProofParams{Method: http.MethodPost, URL: enrollURL, Body: body, Nonce: nonce, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := pap.VerifyRequest(nil, s.apiURL, pap.Request{Method: http.MethodPost, URL: enrollURL, BodySHA256: sha256.Sum256(body)}, proof, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	en, err := svc.Enroll(ctx, iapp.EnrollInput{Proof: checked, Attestation: &iapp.Attestation{Kind: issuers.KindAWS, Token: att}, PublicJWK: jwk})
	if err != nil {
		t.Fatalf("enrol with the Lambda role's attestation: %v", err)
	}
	if en.State != "ADMITTED" || en.Level < 2 {
		t.Fatalf("enrolled %+v", en)
	}
	rt.identifier = en.Instance.String()

	// From here on, through the server.
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: key}}, s.apiURL)))
	res, err := wc.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: rt.identifier})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	rt.token = res.GetWorkloadToken()
	if rt.run, err = rt.startRun(s.apiURL, runName()); err != nil {
		t.Fatalf("StartRuntimeRun: %v", err)
	}
	f.rt = rt
	return rt
}

// runName is the interceptor's run name for the simulated Lambda (D995a).
func runName() string {
	return "agentcore:" + m34Function + ":" + strings.NewReplacer("[", "-", "$", "-", "]", "-").Replace(m34Stream)
}

// startRun is the interceptor's StartRuntimeRun.
func (rt *runtimeAgent) startRun(server, name string) (string, error) {
	rc := pantherclawv1connect.NewRuntimeServiceClient(connect.NewClient(connecthttp.NewTransport(rt.client(), server)))
	res, err := rc.StartRuntimeRun(context.Background(), &pantherclawv1.StartRuntimeRunRequest{Name: name})
	if err != nil {
		return "", err
	}
	return res.GetRunId(), nil
}

// client signs with the instance's key and token, as the interceptor does.
func (rt *runtimeAgent) client() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: rt.key, Token: func() string { return rt.token }, Base: http.DefaultTransport,
	}}
}

// runtimeConnection creates the mcp connection name, held by the agent,
// serving the reference payments package, and binds it to the AgentCore
// target "agentcore:<arn>/<target>" (D991); it waits for the gateway to
// serve it.
func (s *stack) runtimeConnection(t *testing.T, name, arn, target string) ids.UUID {
	t.Helper()
	svc := capp.New(s.pool, nil, s.apiURL, "")
	c, err := svc.Seed(context.Background(), s.org, "e2e", capp.CreateInput{
		Name: name, Kind: capp.KindMCP, Package: mockpayments.Name, BaseURL: s.simURL + "/mcp", Gateway: s.gatewayID(t),
		DestinationClass: capp.ClassInternal, AccessMode: capp.AccessAgentHeld, DefaultMode: capp.ModeEnforce,
	})
	if err != nil {
		t.Fatalf("runtime connection %s: %v", name, err)
	}
	if _, err := svc.SetRuntimeTarget(s.m34person(td.RoleOrgAdmin, td.Scope{}), c.ID, runtimeface.TargetPrefix+arn+"/"+target); err != nil {
		t.Fatalf("runtime target of %s: %v", name, err)
	}
	s.waitConfig(t, s.configVersion(t, s.gatewayID(t)))
	return c.ID
}

// gatewayARN is an AgentCore gateway ARN in account.
func gatewayARN(account, id string) string {
	return "arn:aws:bedrock-agentcore:" + aws.Region + ":" + account + ":gateway/" + id
}

// faceAnswer is what the gateway's runtime face answered.
type faceAnswer struct {
	Status int
	Header http.Header
	Raw    []byte
	// Pass is set when the output lets the original request through, and
	// Body is that request.
	Pass bool
	Body jsontext.Value
	// Text and IsError are a tool error's; RPCCode and RPCMessage a
	// JSON-RPC error's; Code and Reason a refusal's before any answer.
	Text       string
	IsError    bool
	RPCCode    int
	RPCMessage string
	Code       string
	Reason     string
}

// face posts one interceptor event to the gateway's runtime face as rt,
// naming gateway arn and action act, as the interceptor does (D995).
func (s *stack) face(t *testing.T, rt *runtimeAgent, arn string, act ids.UUID, event []byte) faceAnswer {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+runtimeface.AgentCorePath, bytes.NewReader(event))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(runtimeface.HeaderGateway, arn)
	req.Header.Set(gateway.HeaderRunID, rt.run)
	if !act.IsZero() {
		req.Header.Set(gateway.HeaderActionID, act.String())
	}
	res, err := rt.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	return readFace(res.StatusCode, res.Header, raw)
}

func readFace(status int, h http.Header, raw []byte) faceAnswer {
	a := faceAnswer{Status: status, Header: h, Raw: raw}
	if status != http.StatusOK {
		var r struct {
			Code   string `json:"code"`
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &r)
		a.Code, a.Reason = r.Code, r.Reason
		return a
	}
	var out struct {
		MCP struct {
			Req *struct {
				Body jsontext.Value `json:"body"`
			} `json:"transformedGatewayRequest"`
			Res *struct {
				Body struct {
					Result struct {
						IsError bool `json:"isError"`
						Content []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
					Error struct {
						Code    int    `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				} `json:"body"`
			} `json:"transformedGatewayResponse"`
		} `json:"mcp"`
	}
	if json.Unmarshal(raw, &out, json.RejectUnknownMembers(false)) != nil {
		return a
	}
	if out.MCP.Req != nil {
		a.Pass, a.Body = true, out.MCP.Req.Body
		return a
	}
	if r := out.MCP.Res; r != nil {
		a.IsError, a.RPCCode, a.RPCMessage = r.Body.Result.IsError, r.Body.Error.Code, r.Body.Error.Message
		if len(r.Body.Result.Content) > 0 {
			a.Text = r.Body.Result.Content[0].Text
		}
	}
	return a
}

// toolEvent is the interceptor event of a tools/call of target___tool.
func toolEvent(t *testing.T, target, tool string, args map[string]any) []byte {
	t.Helper()
	ev, err := agentcore.Event(target+"___"+tool, args)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// rpcBody is the JSON-RPC request inside an event.
func rpcBody(t *testing.T, event []byte) jsontext.Value {
	t.Helper()
	var ev struct {
		MCP struct {
			GatewayRequest struct {
				Body jsontext.Value `json:"body"`
			} `json:"gatewayRequest"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal(event, &ev, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	return ev.MCP.GatewayRequest.Body
}

// txnOf is the transaction of action act in run, its decision, reason and
// channel; empty when none was recorded.
func (s *stack) txnOf(t *testing.T, run string, act ids.UUID) (id, decision, reason, channel string) {
	t.Helper()
	s.query(t, `SELECT coalesce(max(id::text), ''), coalesce(max(decision), ''), coalesce(max(reason_code), ''), coalesce(max(channel), '')
		FROM pc.transactions WHERE run_id = $1 AND action_id = $2`, []any{run, act}, &id, &decision, &reason, &channel)
	return id, decision, reason, channel
}

// delegatedOf counts txn's execution attempts recorded as delegated.
func (s *stack) delegatedOf(t *testing.T, txn string) string {
	t.Helper()
	return s.row(t, "SELECT count(*)::text FROM pc.execution_attempts WHERE transaction_id = $1 AND outcome = 'delegated'", txn)
}

// interceptor is a running cmd/pc-agentcore-interceptor --local.
type interceptor struct {
	url  string
	logs *syncBuffer
}

// runInterceptor builds and runs the interceptor with --local on a
// loopback address, as the Lambda's environment configures it, with creds
// as the Lambda role's.
func (s *stack) runInterceptor(t *testing.T, creds workloadclient.AWSCredentials) *interceptor {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "pc-agentcore-interceptor")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "-C", "../..", "build", "-o", bin, "./cmd/pc-agentcore-interceptor").CombinedOutput(); err != nil {
		t.Fatalf("build the interceptor: %v %s", err, out)
	}
	addr := freeAddr(t)
	cmd := exec.Command(bin, "--local", addr)
	cmd.Env = append(os.Environ(),
		"PC_SERVER_URL="+s.apiURL, "PC_GATEWAY_URL="+s.gateway, "PC_ORG="+s.org.String(),
		"AWS_ACCESS_KEY_ID="+creds.AccessKey, "AWS_SECRET_ACCESS_KEY="+creds.SecretKey, "AWS_SESSION_TOKEN="+creds.SessionToken,
		"AWS_REGION="+creds.Region, "AWS_LAMBDA_FUNCTION_NAME="+m34Function, "AWS_LAMBDA_LOG_STREAM_NAME="+m34Stream,
	)
	logs := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	ic := &interceptor{url: "http://" + addr + "/invoke", logs: logs}
	eventually(t, 30*time.Second, "the interceptor listens", func() (bool, error) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false, nil //nolint:nilerr // not listening yet
		}
		return true, c.Close()
	})
	return ic
}

// invoke has the AgentCore simulator build a tools/call event for its
// gateway's target and post it to the interceptor, and returns what the
// interceptor answered.
func (s *stack) invoke(t *testing.T, ic *interceptor, tool string, args map[string]any) faceAnswer {
	t.Helper()
	body, err := json.Marshal(map[string]any{"interceptor_url": ic.url, "tool": tool, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(s.m34.coreURL+"/sim/invoke-interceptor", "application/json", bytes.NewReader(body)) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var inv agentcore.Invocation
	if err := json.UnmarshalRead(res.Body, &inv, json.RejectUnknownMembers(false)); err != nil {
		t.Fatal(err)
	}
	if inv.Error != "" || inv.Status != http.StatusOK {
		t.Fatalf("invoke-interceptor: %+v\n%s", inv, ic.logs.String())
	}
	return readFace(http.StatusOK, nil, inv.Output)
}

// awsREST sends one SigV4-signed REST request for service with creds.
func awsREST(t *testing.T, method, rawURL, service string, body []byte, creds workloadclient.AWSCredentials) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := (sigv4.Signer{Region: aws.Region, Service: service}).Sign(req, sigv4.Credentials{
		AccessKeyID: creds.AccessKey, SecretAccessKey: creds.SecretKey, SessionToken: creds.SessionToken,
	}, sigv4.HashPayload(body), time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	return res.StatusCode, raw
}

// deployRuntime is a deploy straight to AgentCore, outside PantherClaw:
// what a person or a pipeline does with the console's role (T-347).
func (f *m34Fixture) deployRuntime(t *testing.T, name string) {
	t.Helper()
	creds := f.awsSession(t, "console-deploy", agentcore.Service+":CreateAgentRuntime")
	body, err := json.Marshal(map[string]any{
		"agentRuntimeName": name,
		"agentRuntimeArtifact": map[string]any{"containerConfiguration": map[string]any{
			"containerUri": aws.Account + ".dkr.ecr." + aws.Region + ".amazonaws.com/" + strings.ReplaceAll(name, "_", "-") + ":v1",
		}},
		"roleArn": aws.RoleARN, "networkConfiguration": map[string]any{"networkMode": "PUBLIC"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if code, raw := awsREST(t, http.MethodPut, f.coreURL+"/runtimes/", agentcore.Service, body, creds); code != http.StatusAccepted {
		t.Fatalf("CreateAgentRuntime: %d %s", code, raw)
	}
}

// m34Business is a Business edition for the in-process discovery service
// (the stack's server runs in development mode, which has every feature).
type m34Business = rangeBusiness

// scheduleAgentCore has the owner set a daily scan of the AgentCore
// connection for the simulated account (FQ34-3, HR-768).
func (s *stack) scheduleAgentCore(t *testing.T) {
	t.Helper()
	svc := &saasapp.Service{Pool: s.pool, Inventory: aapp.NewInventory(s.pool, nil), Editions: m34Business{}}
	if _, err := svc.SetSchedule(s.m34person(td.RoleOrgAdmin, td.Scope{}), saas.SourceAWSAgentCore, s.m34.agentcoreConn, aws.Account, true); err != nil {
		t.Fatalf("SetSchedule: %v", err)
	}
}

// dailyScan runs the daily scan job as the server does: a restart, whose
// dispatcher runs on start (saasapp.PeriodicJobs, RunOnStart), enqueues the
// org's job, which starts each due schedule's scan on the gateway. It
// waits for n scheduled scans to have finished and returns the newest's
// state and not_scanned.
func (s *stack) dailyScan(t *testing.T, n int) (string, string) {
	t.Helper()
	s.stopServer(t)
	s.serve(t)
	const done = `SELECT count(*)::text FROM pc.saas_scan_runs WHERE org_id = $1 AND origin = 'schedule' AND state IN ('DONE', 'FAILED')`
	eventually(t, 90*time.Second, "the scheduled scan finishes", func() (bool, error) {
		return s.row(t, done, s.org) == fmt.Sprint(n), nil
	})
	var state, notScanned string
	s.query(t, `SELECT state, not_scanned::text FROM pc.saas_scan_runs WHERE org_id = $1 AND origin = 'schedule' ORDER BY created_at DESC LIMIT 1`,
		[]any{s.org}, &state, &notScanned)
	return state, notScanned
}

// dueAgain makes every schedule due again (its last start a day ago).
func (s *stack) dueAgain(t *testing.T) {
	t.Helper()
	s.db.AdminExec(t, "UPDATE pc.saas_scan_schedules SET last_started_at = now() - interval '25 hours' WHERE org_id = $1", s.org)
}

// m34Rule is the deployed-agent detection (HR-769).
const m34Rule = "pc.runtime.agent_deployed"

// alertsOf counts the org's alerts of rule.
func (s *stack) alertsOf(t *testing.T, rule string) int {
	t.Helper()
	var n int
	s.query(t, "SELECT count(*)::int FROM pc.alerts WHERE org_id = $1 AND rule_id = $2", []any{s.org, rule}, &n)
	return n
}

// ssmPolicies are the session policies the simulators saw for
// ssm:SendCommand.
func (f *m34Fixture) ssmPolicies() []string {
	var out []string
	for _, p := range f.policies.all() {
		if strings.Contains(p, "ssm:SendCommand") {
			out = append(out, p)
		}
	}
	return out
}

// errNoAnswer is a face call that got no interceptor output.
var errNoAnswer = errors.New("no interceptor output")

// lineOf is the first line of logs containing s, for failure messages.
func lineOf(logs, s string) string {
	sc := bufio.NewScanner(strings.NewReader(logs))
	for sc.Scan() {
		if strings.Contains(sc.Text(), s) {
			return sc.Text()
		}
	}
	return ""
}
