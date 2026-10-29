// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeIssuers stands in for issuerkeys.Directory: the listed issuers are
// configured for the listed org, and verify like fakeGitHub.
type fakeIssuers map[string]ids.OrgID

func (f fakeIssuers) Allowed(issuer string, org ids.OrgID) bool {
	o, ok := f[issuer]
	return ok && o == org
}

func (f fakeIssuers) Verify(ctx context.Context, issuer string, org ids.OrgID, tok string) ([]byte, error) {
	if !f.Allowed(issuer, org) {
		return nil, errors.New("issuer not configured")
	}
	return fakeGitHub{}.Verify(ctx, tok)
}

const glRef = "gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/heads/main"

func gl(refs ...string) app.Binding {
	return app.Binding{GitLab: &issuers.GitLabBinding{
		Issuer: issuers.GitLabDefaultIssuer, ProjectID: "20", NamespaceID: "72", CIConfigRefURIs: refs,
	}}
}

// glClaims are the claims of a GitLab CI push pipeline of definition ref.
func (w *world) glClaims(ref string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": issuers.GitLabDefaultIssuer, "aud": "pantherclaw:" + w.org.String(), "jti": ids.NewV7().String(),
		"project_id": "20", "namespace_id": "72", "ref": "main", "ref_type": "branch", "ref_protected": "true",
		"pipeline_source": "push", "ci_config_ref_uri": ref, "ci_config_sha": sha40, "sha": sha40,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func glAtt(claims map[string]any) *app.Attestation {
	return &app.Attestation{Kind: issuers.KindGitLab, Token: jwt(claims)}
}

// TestHR461_GitLabEntriesAndAttestation: an entry names only an instance
// the operator configured for the org and only a ci agent; a token from a
// protected push pipeline of a pinned definition enrolls at L2 once, and
// merge-request pipelines and rogue instances enroll nothing.
// Covers: PN-002.3
func TestHR461_GitLabEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{GitLab: fakeIssuers{issuers.GitLabDefaultIssuer: w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextCI)

	rogue := gl(glRef)
	rogue.GitLab.Issuer = "https://gitlab.evil.test"
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: rogue, Reason: "x"}, nil); !errors.Is(err, app.ErrUnknownIssuer) {
		t.Errorf("unconfigured instance: %v", err)
	}
	kubeAgent := w.agent(t, adomain.ContextKubernetes)
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: kubeAgent, Binding: gl(glRef), Reason: "x"}, nil); !errors.Is(err, app.ErrContextMismatch) {
		t.Errorf("kubernetes agent: %v", err)
	}
	e := w.activeEntry(t, agent, gl(glRef), true)
	if e.Kind != issuers.KindGitLab || e.Issuer != issuers.GitLabDefaultIssuer || len(e.Algorithms) != 1 || e.Algorithms[0] != "RS256" {
		t.Fatalf("revision: %+v", e)
	}

	claims := w.glClaims(glRef)
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", glAtt(claims))
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("protected push pipeline: %+v, %v", in, err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", glAtt(claims))
	wantPAP(t, "reused GitLab token", err, pap.CodeInvalidToken)

	for name, mutate := range map[string]func(map[string]any){
		"merge request pipeline": func(c map[string]any) { c["pipeline_source"] = "merge_request_event" },
		"unprotected ref":        func(c map[string]any) { c["ref_protected"] = "false" },
		"rogue instance":         func(c map[string]any) { c["iss"] = "https://gitlab.evil.test" },
		"unpinned definition":    func(c map[string]any) { c["ci_config_ref_uri"] = glRef + "x" },
		"lives over an hour":     func(c map[string]any) { c["exp"] = time.Now().Add(61 * time.Minute).Unix() },
	} {
		c := w.glClaims(glRef)
		mutate(c)
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", glAtt(c))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
}

const spID = "spiffe://prod.acme.test/ns/agents/sa/runner"

func sp() app.Binding {
	return app.Binding{SPIFFE: &issuers.SPIFFEBinding{TrustDomain: "prod.acme.test", SPIFFEID: spID}}
}

// spAtt is a JWT-SVID with claims for w's org; it has no jti.
func (w *world) spAtt(mutate func(map[string]any)) *app.Attestation {
	now := time.Now()
	c := map[string]any{
		"sub": spID, "aud": []string{"pantherclaw:" + w.org.String()},
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(c)
	}
	return &app.Attestation{Kind: issuers.KindSPIFFE, Token: jwt(c)}
}

// TestHR462_SPIFFEEntriesAndAttestation: an entry names only a trust domain
// the operator configured for the org and only a service agent; a JWT-SVID
// of the pinned SPIFFE ID enrolls at L2 once, and other workloads or trust
// domains enroll nothing.
// Covers: PN-002.3
func TestHR462_SPIFFEEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{SPIFFE: fakeIssuers{"prod.acme.test": w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)

	rogue := app.Binding{SPIFFE: &issuers.SPIFFEBinding{TrustDomain: "evil.test", SPIFFEID: "spiffe://evil.test/w"}}
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: rogue, Reason: "x"}, nil); !errors.Is(err, app.ErrUnknownIssuer) {
		t.Errorf("unconfigured trust domain: %v", err)
	}
	ciAgent := w.agent(t, adomain.ContextCI)
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: ciAgent, Binding: sp(), Reason: "x"}, nil); !errors.Is(err, app.ErrContextMismatch) {
		t.Errorf("ci agent: %v", err)
	}
	e := w.activeEntry(t, agent, sp(), true)
	if e.Kind != issuers.KindSPIFFE || e.Issuer != "spiffe://prod.acme.test" {
		t.Fatalf("revision: %+v", e)
	}

	att := w.spAtt(nil)
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", att)
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("pinned workload: %+v, %v", in, err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", att)
	wantPAP(t, "reused JWT-SVID", err, pap.CodeInvalidToken)

	for name, mutate := range map[string]func(map[string]any){
		"other workload":     func(c map[string]any) { c["sub"] = "spiffe://prod.acme.test/ns/agents/sa/other" },
		"other trust domain": func(c map[string]any) { c["sub"] = "spiffe://evil.test/ns/agents/sa/runner" },
		"not a SPIFFE ID":    func(c map[string]any) { c["sub"] = "runner" },
		"lives over an hour": func(c map[string]any) { c["exp"] = time.Now().Add(61 * time.Minute).Unix() },
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", w.spAtt(mutate))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
}

// gcpAtt is a Google-signed ID token (format=full) for w's org.
func (w *world) gcpAtt(mutate func(map[string]any)) *app.Attestation {
	now := time.Now()
	c := map[string]any{
		"iss": issuers.GCPIssuer, "aud": "pantherclaw:" + w.org.String(), "sub": "113524806285125460987",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"google": map[string]any{"compute_engine": map[string]any{"project_id": "acme-prod", "instance_id": "5117906829363456"}},
	}
	if mutate != nil {
		mutate(c)
	}
	return &app.Attestation{Kind: issuers.KindGCP, Token: jwt(c)}
}

// TestHR463_GCPEntriesAndAttestation: a service agent's entry pins the
// numeric service account; its ID token enrolls at L2 once, and other
// accounts, projects and issuers enroll nothing.
// Covers: PN-002.3
func TestHR463_GCPEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{GCP: fakeGitHub{}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	b := app.Binding{GCP: &issuers.GCPBinding{ServiceAccountID: "113524806285125460987", ProjectID: "acme-prod"}}
	ciAgent := w.agent(t, adomain.ContextCI)
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: ciAgent, Binding: b, Reason: "x"}, nil); !errors.Is(err, app.ErrContextMismatch) {
		t.Errorf("ci agent: %v", err)
	}
	e := w.activeEntry(t, agent, b, true)
	if e.Kind != issuers.KindGCP || e.Issuer != issuers.GCPIssuer || len(e.Algorithms) != 1 || e.Algorithms[0] != "RS256" {
		t.Fatalf("revision: %+v", e)
	}
	att := w.gcpAtt(nil)
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", att)
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("pinned service account: %+v, %v", in, err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", att)
	wantPAP(t, "reused GCP token", err, pap.CodeInvalidToken)
	for name, mutate := range map[string]func(map[string]any){
		"other service account": func(c map[string]any) { c["sub"] = "113524806285125460988" },
		"other project": func(c map[string]any) {
			c["google"] = map[string]any{"compute_engine": map[string]any{"project_id": "acme-dev"}}
		},
		"other issuer":       func(c map[string]any) { c["iss"] = "https://evil.test" },
		"lives over an hour": func(c map[string]any) { c["exp"] = time.Now().Add(61 * time.Minute).Unix() },
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", w.gcpAtt(mutate))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
}

// fakeSTS stands in for awssts.Verifier: the request's X-Test-Arn header
// is the caller, signed at now.
type fakeSTS struct{ now time.Time }

func (f fakeSTS) Verify(_ context.Context, _ ids.OrgID, tok string) (issuers.AWSCaller, issuers.AWSSigned, error) {
	r, err := issuers.ParseAWSRequest(tok)
	if err != nil {
		return issuers.AWSCaller{}, issuers.AWSSigned{}, err
	}
	arn := r.Header("X-Test-Arn")
	acct, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arn, "arn:aws:sts::"), "arn:aws:iam::"), ":")
	return issuers.AWSCaller{Account: acct, Arn: arn},
		issuers.AWSSigned{URL: &url.URL{Host: "sts.amazonaws.com"}, SignedAt: f.now, Signature: r.Header("X-Test-Sig") + arn}, nil
}

// awsAtt is a signed request for w's org from a session with arn.
func (w *world) awsAtt(t *testing.T, arn, sig string) *app.Attestation {
	t.Helper()
	tok, err := issuers.AWSRequest{Headers: map[string]string{
		issuers.AWSAudienceHeader: "pantherclaw:" + w.org.String(), "X-Test-Arn": arn, "X-Test-Sig": sig,
	}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return &app.Attestation{Kind: issuers.KindAWS, Token: tok}
}

// TestHR464_AWSEntriesAndAttestation: a service agent's entry pins an
// account and role; a session of that role enrolls at L2 once, and other
// roles, accounts and IAM users enroll nothing.
// Covers: PN-002.3
func TestHR464_AWSEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{AWS: fakeSTS{now: time.Now()}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	b := app.Binding{AWS: &issuers.AWSBinding{AccountID: "123456789012", RoleName: "agent-runner"}}
	e := w.activeEntry(t, agent, b, true)
	if e.Kind != issuers.KindAWS || e.Issuer != issuers.AWSIssuer {
		t.Fatalf("revision: %+v", e)
	}
	session := "arn:aws:sts::123456789012:assumed-role/agent-runner/i-0abc"
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", w.awsAtt(t, session, "1"))
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("role session: %+v, %v", in, err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", w.awsAtt(t, session, "1"))
	wantPAP(t, "reused signed request", err, pap.CodeInvalidToken)
	for name, arn := range map[string]string{
		"other role":    "arn:aws:sts::123456789012:assumed-role/admin/i-0abc",
		"other account": "arn:aws:sts::210987654321:assumed-role/agent-runner/i-0abc",
		"IAM user":      "arn:aws:iam::123456789012:user/agent-runner",
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", w.awsAtt(t, arn, "2"))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
	// A signed request attests for 15 minutes from its signing time.
	w.svc.WithAttestors(app.Attestors{AWS: fakeSTS{now: time.Now().Add(-16 * time.Minute)}})
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", w.awsAtt(t, session, "3"))
	wantPAP(t, "signed over 15 minutes ago", err, pap.CodeAttestationLow)
}

const (
	azTenant = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
	azApp    = "00001111-aaaa-2222-bbbb-3333cccc4444"
	azObject = "11112222-bbbb-3333-cccc-4444dddd5555"
)

// entraApps stands in for issuerkeys.Entra: the app is pinned to org in
// azTenant, and verifies like fakeGitHub.
type entraApps struct{ org ids.OrgID }

func (e entraApps) OrgOf(app string) ids.OrgID {
	if app == azApp {
		return e.org
	}
	return ids.OrgID{}
}

func (e entraApps) Allowed(tenant, app string, org ids.OrgID) bool {
	return tenant == azTenant && app == azApp && org == e.org
}

func (e entraApps) Verify(ctx context.Context, app string, org ids.OrgID, tok string) ([]byte, error) {
	if e.OrgOf(app) != org {
		return nil, errors.New("app not pinned to this org")
	}
	return fakeGitHub{}.Verify(ctx, tok)
}

// azAtt is a managed identity token for azApp, issued at iat and living
// a day.
func azAtt(iat time.Time, mutate func(map[string]any)) *app.Attestation {
	c := map[string]any{
		"iss": "https://sts.windows.net/" + azTenant + "/", "aud": azApp, "tid": azTenant, "oid": azObject, "sub": azObject,
		"idtyp": "app", "uti": ids.NewV7().String(), "iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(24 * time.Hour).Unix(),
	}
	if mutate != nil {
		mutate(c)
	}
	return &app.Attestation{Kind: issuers.KindAzureMI, Token: jwt(c)}
}

// TestHR469_AzureMIEntriesAndAttestation: an entry pins only a tenant and
// app pair the operator pinned to the org, and its audience is that app;
// a day-long managed identity token enrolls at L2 once, for at most an
// hour, and another org's app or another identity enrolls nothing.
// Covers: PN-002.3
func TestHR469_AzureMIEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{Entra: entraApps{org: w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	b := app.Binding{AzureMI: &issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}}
	other := app.Binding{AzureMI: &issuers.AzureMIBinding{TenantID: azTenant, AppID: "00001111-aaaa-2222-bbbb-3333cccc4445", ObjectID: azObject}}
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: other, Reason: "x"}, nil); !errors.Is(err, app.ErrUnknownIssuer) {
		t.Errorf("app not pinned to the org: %v", err)
	}
	e := w.activeEntry(t, agent, b, true)
	if e.Kind != issuers.KindAzureMI || e.Audience != azApp || e.Issuer != "https://login.microsoftonline.com/"+azTenant+"/v2.0" {
		t.Fatalf("revision: %+v", e)
	}

	att := azAtt(time.Now().Add(-3*time.Hour), nil)
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", att)
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("managed identity: %+v, %v", in, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.agent_instances WHERE org_id = $1 AND att_level = 2
		AND attested_until <= now() + interval '61 minutes'`, w.org); n != 1 {
		t.Errorf("%d instances attested for at most an hour, want 1", n)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", att)
	wantPAP(t, "reused managed identity token", err, pap.CodeInvalidToken)

	for name, mutate := range map[string]func(map[string]any){
		"other identity":   func(c map[string]any) { c["oid"] = "11112222-bbbb-3333-cccc-4444dddd5556" },
		"user token":       func(c map[string]any) { c["idtyp"] = "user" },
		"other tenant":     func(c map[string]any) { c["tid"] = "bbbbcccc-0000-cccc-1111-dddd2222eeee" },
		"lives over a day": func(c map[string]any) { c["exp"] = time.Now().Add(23 * time.Hour).Unix() },
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", azAtt(time.Now().Add(-2*time.Hour), mutate))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
	// An app id the operator did not pin names no org at all.
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", azAtt(time.Now(), func(c map[string]any) { c["aud"] = "00001111-aaaa-2222-bbbb-3333cccc4445" }))
	wantPAP(t, "unpinned app", err, pap.CodeAttestationLow)
}

// TestHR469_EntraAgentEntriesAndAttestation: an autonomous agent
// identity's token for the pinned app enrolls at L2 once; a managed
// identity token never attests for an agent entry, and an agent acting
// for a user never attests.
// Covers: PN-002.3
func TestHR469_EntraAgentEntriesAndAttestation(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{Entra: entraApps{org: w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	b := app.Binding{EntraAgent: &issuers.EntraAgentBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}}
	e := w.activeEntry(t, agent, b, true)
	if e.Kind != issuers.KindEntraAgent || e.Audience != azApp {
		t.Fatalf("revision: %+v", e)
	}
	agentTok := func(mutate func(map[string]any)) *app.Attestation {
		a := azAtt(time.Now().Add(-time.Hour), func(c map[string]any) {
			c["xms_sub_fct"], c["xms_act_fct"] = "9 3 11", "3 9 11"
			if mutate != nil {
				mutate(c)
			}
		})
		a.Kind = issuers.KindEntraAgent
		return a
	}
	att := agentTok(nil)
	in, err := w.attestEnroll(t, w.svc, newWorkload(), "", att)
	if err != nil || in.State != "ADMITTED" || in.Level != 2 || in.Instance.Agent != agent {
		t.Fatalf("autonomous agent: %+v, %v", in, err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", att)
	wantPAP(t, "reused agent token", err, pap.CodeInvalidToken)
	for name, mutate := range map[string]func(map[string]any){
		"on behalf of a user": func(c map[string]any) { c["idtyp"] = "user" },
		"agent user account":  func(c map[string]any) { c["xms_sub_fct"] = "13" },
		"no agent facets":     func(c map[string]any) { delete(c, "xms_sub_fct"); delete(c, "xms_act_fct") },
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", agentTok(mutate))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
	// The same token offered as azure_mi finds no azure_mi entry.
	mi := agentTok(nil)
	mi.Kind = issuers.KindAzureMI
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", mi)
	wantPAP(t, "agent entry through azure_mi", err, pap.CodeAttestationLow)
}

// edition is a fixed edition (billing.Service).
type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestM17PresetsNeedEnterprise: below the Enterprise edition, or
// without an edition source, no M17 preset entry can be proposed; the M3
// presets are not gated.
// Covers: PN-002.3
func TestM17PresetsNeedEnterprise(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{
		GitLab: fakeIssuers{issuers.GitLabDefaultIssuer: w.org}, SPIFFE: fakeIssuers{"prod.acme.test": w.org},
		Entra: entraApps{org: w.org},
	})
	svc := w.agent(t, adomain.ContextService)
	ci := w.agent(t, adomain.ContextCI)
	for name, in := range map[string]app.ProposeInput{
		"gitlab_ci":    {AgentID: ci, Binding: gl(glRef)},
		"spiffe_jwt":   {AgentID: svc, Binding: sp()},
		"gcp_workload": {AgentID: svc, Binding: app.Binding{GCP: &issuers.GCPBinding{ServiceAccountID: "1"}}},
		"aws_iam":      {AgentID: svc, Binding: app.Binding{AWS: &issuers.AWSBinding{AccountID: "123456789012", RoleName: "r"}}},
		"azure_mi":     {AgentID: svc, Binding: app.Binding{AzureMI: &issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}}},
		"entra_agent_id": {AgentID: svc, Binding: app.Binding{EntraAgent: &issuers.EntraAgentBinding{
			TenantID: azTenant, AppID: azApp, ObjectID: azObject,
		}}},
	} {
		in.Reason = "x"
		for _, e := range []app.Entitlements{nil, edition(billing.Community), edition(billing.Team), edition(billing.Business)} {
			w.svc.WithEntitlements(e)
			if _, err := w.svc.ProposeIssuer(w.orgAdmin(), in, nil); !errors.Is(err, app.ErrEdition) {
				t.Errorf("%s with %v: %v", name, e, err)
			}
		}
		w.svc.WithEntitlements(edition(billing.Enterprise))
		if _, err := w.svc.ProposeIssuer(w.orgAdmin(), in, nil); err != nil {
			t.Errorf("%s on Enterprise: %v", name, err)
		}
	}
	w.svc.WithEntitlements(nil)
	gh := w.agent(t, adomain.ContextCI)
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: gh, Binding: app.Binding{GitHub: &issuers.GitHubBinding{
		RepositoryID: "1", RepositoryOwnerID: "2", WorkflowRefs: []string{"acme/agents/.github/workflows/ci.yml@refs/heads/main"},
	}}, Reason: "x"}, nil); errors.Is(err, app.ErrEdition) {
		t.Error("the GitHub preset is gated")
	}
}

// TestT202_MergeRequestTokensAndRogueGitLabIssuers: a merge-request
// pipeline's ID token never attests, and neither does a token from a
// self-managed instance the operator did not configure, nor an entry
// naming one (T-202).
// Covers: PN-002.3
func TestT202_MergeRequestTokensAndRogueGitLabIssuers(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{GitLab: fakeIssuers{issuers.GitLabDefaultIssuer: w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gl(glRef), true)
	rogue := gl("gitlab.evil.test/acme/agents/runner//.gitlab-ci.yml@refs/heads/main")
	rogue.GitLab.Issuer = "https://gitlab.evil.test"
	if _, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: rogue, Reason: "x"}, nil); !errors.Is(err, app.ErrUnknownIssuer) {
		t.Errorf("entry naming a rogue instance: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"merge request":          func(c map[string]any) { c["pipeline_source"] = "merge_request_event" },
		"external pull request":  func(c map[string]any) { c["pipeline_source"] = "external_pull_request_event" },
		"fork's unprotected ref": func(c map[string]any) { c["ref_protected"] = "false"; c["ref"] = "patch-1" },
		"rogue instance":         func(c map[string]any) { c["iss"] = "https://gitlab.evil.test" },
	} {
		c := w.glClaims(glRef)
		mutate(c)
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", glAtt(c))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE org_id = $1", w.org); n != 0 {
		t.Errorf("%d instances enrolled", n)
	}
}

// TestT203_SPIFFETrustDomainConfusion: a JWT-SVID verified by one trust
// domain's bundle never attests for a workload of another, even one an
// entry pins (T-203; the AWS half is in awssts).
// Covers: PN-002.3
func TestT203_SPIFFETrustDomainConfusion(t *testing.T) {
	w := newWorld(t)
	// Both trust domains are configured; the token names prod but the
	// entry pins a workload of edge.
	w.svc.WithAttestors(app.Attestors{SPIFFE: fakeIssuers{"prod.acme.test": w.org, "edge.acme.test": w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	w.activeEntry(t, agent, app.Binding{SPIFFE: &issuers.SPIFFEBinding{TrustDomain: "edge.acme.test", SPIFFEID: "spiffe://edge.acme.test/w"}}, true)
	for name, sub := range map[string]string{
		"other trust domain's workload": spID,
		"pinned path, other domain":     "spiffe://prod.acme.test/w",
		"look-alike domain":             "spiffe://edge.acme.test.evil/w",
	} {
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", w.spAtt(func(c map[string]any) { c["sub"] = sub }))
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
}

// TestT205_LongLivedEntraTokens: a stolen day-long Entra token attests
// once, for at most an hour, and only for the one org its app is pinned
// to; the same app can never be used to attest for another org (T-205).
// Covers: PN-002.3
func TestT205_LongLivedEntraTokens(t *testing.T) {
	w := newWorld(t)
	w.svc.WithAttestors(app.Attestors{Entra: entraApps{org: w.org}})
	w.svc.WithEntitlements(edition(billing.Enterprise))
	agent := w.agent(t, adomain.ContextService)
	w.activeEntry(t, agent, app.Binding{AzureMI: &issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}}, true)
	stolen := azAtt(time.Now().Add(-time.Hour), nil)
	if _, err := w.attestEnroll(t, w.svc, newWorkload(), "", stolen); err != nil {
		t.Fatal(err)
	}
	// Replayed by the thief from another key: refused for the rest of
	// the token's day.
	_, err := w.attestEnroll(t, w.svc, newWorkload(), "", stolen)
	wantPAP(t, "replayed token", err, pap.CodeInvalidToken)
	if n := w.count(t, `SELECT count(*) FROM pc.attestations WHERE org_id = $1
		AND expires_at <= accepted_at + interval '1 hour' AND expires_at <= issued_at + interval '1 hour'`, w.org); n != 1 {
		t.Errorf("%d attestations bounded by an hour, want 1", n)
	}

	// Another org, even with the same tenant and app pinned in its own
	// entry, cannot use the app: the operator pinned it to w's org.
	o := newWorld(t)
	o.svc.WithAttestors(app.Attestors{Entra: entraApps{org: w.org}})
	o.svc.WithEntitlements(edition(billing.Enterprise))
	other := o.agent(t, adomain.ContextService)
	b := app.Binding{AzureMI: &issuers.AzureMIBinding{TenantID: azTenant, AppID: azApp, ObjectID: azObject}}
	if _, err := o.svc.ProposeIssuer(o.orgAdmin(), app.ProposeInput{AgentID: other, Binding: b, Reason: "x"}, nil); !errors.Is(err, app.ErrUnknownIssuer) {
		t.Errorf("another org pinned the app: %v", err)
	}
	if got := o.svc.AttestationOrg(*azAtt(time.Now(), nil)); got != w.org {
		t.Errorf("the app's tokens name org %v, want only %v", got, w.org)
	}
	// A pantherclaw:<other org> audience never redirects an Entra token.
	tok := azAtt(time.Now(), func(c map[string]any) { c["aud"] = "pantherclaw:" + o.org.String() })
	if got := o.svc.AttestationOrg(*tok); !got.IsZero() {
		t.Errorf("an Entra token named org %v through a pantherclaw audience", got)
	}
}
