// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
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
