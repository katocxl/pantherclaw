// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/issuerkeys"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const m3tSAUID = "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f"

func m3tInstances(t *testing.T, w *world) int {
	t.Helper()
	return w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE org_id = $1", w.org)
}

func m3tAttestations(t *testing.T, w *world) int {
	t.Helper()
	return w.count(t, "SELECT count(*) FROM pc.attestations WHERE org_id = $1", w.org)
}

// m3tServiceAccountToken is a projected service-account token for w's
// audience; fakeCluster decides what TokenReview says about it.
func m3tServiceAccountToken(w *world) *app.Attestation {
	now := time.Now()
	return &app.Attestation{Kind: issuers.KindKubernetes, Token: jwt(map[string]any{
		"iss": "https://kubernetes.default.svc", "aud": []string{"pantherclaw:" + w.org.String()}, "jti": ids.NewV7().String(),
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})}
}

func m3tKubeBinding(cluster string) app.Binding {
	return app.Binding{Kubernetes: &issuers.KubernetesBinding{
		Cluster: cluster, Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: m3tSAUID,
	}}
}

func m3tRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// m3tSign signs claims with key under header (RS256).
func m3tSign(t *testing.T, key *rsa.PrivateKey, header string, claims map[string]any) string {
	t.Helper()
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	signing := enc([]byte(header)) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

func m3tKid(kid string) string { return `{"alg":"RS256","kid":"` + kid + `","typ":"JWT"}` }

// m3tIssuer is a GitHub-like OIDC issuer on a loopback TLS server that
// counts the requests reaching it.
type m3tIssuer struct {
	srv      *httptest.Server
	requests atomic.Int32
	jwks     atomic.Int32
	mu       sync.Mutex
	keys     map[string]*rsa.PrivateKey
	jwksURI  string
}

func m3tNewIssuer(t *testing.T, keys map[string]*rsa.PrivateKey) *m3tIssuer {
	t.Helper()
	is := &m3tIssuer{keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(rw http.ResponseWriter, _ *http.Request) {
		is.requests.Add(1)
		is.mu.Lock()
		uri := is.jwksURI
		is.mu.Unlock()
		if uri == "" {
			uri = is.srv.URL + "/jwks"
		}
		_, _ = rw.Write([]byte(`{"issuer":"` + is.srv.URL + `","jwks_uri":"` + uri + `"}`))
	})
	mux.HandleFunc("/jwks", func(rw http.ResponseWriter, _ *http.Request) {
		is.requests.Add(1)
		is.jwks.Add(1)
		is.mu.Lock()
		defer is.mu.Unlock()
		type jwk struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		var set struct {
			Keys []jwk `json:"keys"`
		}
		for kid, k := range is.keys {
			set.Keys = append(set.Keys, jwk{
				Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
				N: base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		b, _ := json.Marshal(set)
		_, _ = rw.Write(b)
	})
	is.srv = httptest.NewTLSServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *m3tIssuer) publish(keys map[string]*rsa.PrivateKey, jwksURI string) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.keys, is.jwksURI = keys, jwksURI
}

// fetcher is the production key fetcher for this issuer behind an egress
// client; allowLoopback is the operator allowing the issuer's address.
func (is *m3tIssuer) fetcher(t *testing.T, allowLoopback bool, clk *clock.Fake) *issuerkeys.Fetcher {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(is.srv.Certificate())
	cfg := httpx.EgressConfig{RootCAs: pool}
	if allowLoopback {
		cfg.AllowedPrefixes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	}
	f, err := issuerkeys.New(httpx.NewEgressClient(cfg), is.srv.URL, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestT033_AStolenDesktopKeyStaysL1AndIsAlerted: T-033 — malware copies a
// desktop instance's key from the OS key store and uses it from another
// network. Its tokens stay L1 and the network change is alerted; a valid
// attestation neither lifts the instance nor enrolls the key again under an
// agent that may reach L2; once the owner revokes the instance the key gets
// nothing. TestHR092_DesktopCapAndNetworkChange and
// TestHR092_DesktopAgentsCappedAtL1 cover the cap and what a new network is.
func TestT033_AStolenDesktopKeyStaysL1AndIsAlerted(t *testing.T) {
	w := newWorld(t).attestors(nil)
	stolen, desk, agent := w.admitted(t, adomain.ContextDesktop)
	if iss, err := w.token(stolen, t, desk, "203.0.113.7"); err != nil || iss.Level != 1 {
		t.Fatalf("the owner's laptop: %+v, %v", iss, err)
	}
	iss, err := w.token(stolen, t, desk, "198.51.100.23")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := w.svc.TokenVerifier()
	if tok, err := pap.VerifyToken(v, issuer, iss.Token, time.Now()); err != nil || iss.Level != 1 || tok.Level != 1 {
		t.Fatalf("token from the attacker's network: %+v, %v", tok, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.security.instance_network_changed'", w.org); n != 1 {
		t.Errorf("network change alerts %d, want 1", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agent_changes WHERE org_id = $1 AND agent_id = $2 AND kind = $3",
		w.org, agent, string(adomain.ChangeInstanceNetwork)); n != 1 {
		t.Errorf("network changes in the agent's history %d, want 1", n)
	}
	// A CI agent's entry auto-admits genuine pushes to main.
	ci := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, ci, gh(mainRef), true)
	_, err = w.attestToken(t, w.svc, stolen, desk, ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "attestation for the desktop instance", err, pap.CodeAttestationLow)
	_, err = w.attestEnroll(t, w.svc, stolen, "", ghAtt(w.ghClaims(mainRef)))
	wantCode(t, "the stolen key enrolled under the CI agent", err, pcerr.AlreadyExists, "KEY_ENROLLED")
	if n := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE org_id = $1 AND att_level = 2", w.org); n != 0 {
		t.Errorf("%d instances at L2", n)
	}
	if _, err := w.svc.Revoke(w.ownerCtx(), desk.Instance, "key used from an unknown network"); err != nil {
		t.Fatal(err)
	}
	_, err = w.token(stolen, t, desk, "198.51.100.23")
	wantPAP(t, "revoked instance", err, pap.CodeInstanceNotAdmitted)
	if n := m3tInstances(t, w); n != 1 {
		t.Errorf("instances %d, want only the desktop one", n)
	}
}

// TestT035_GitHubMisbindingEnrollsNothing: T-035 — tokens GitHub really
// issues, but not for a push to octo-org/agent-repo's protected main, try
// to enroll as the agent whose entry auto-admits exactly that: a recreated
// repository or a re-registered owner with the same names, a fork's own
// run, pull requests (whose ref is refs/pull/…), pull_request_target (which
// runs on main with every other claim matching), a review of a pull
// request, unprotected refs, a reusable workflow of another repository and
// another GitHub issuer. None enrolls, with or without an enrollment token,
// and none renews an enrolled instance's L2. TestHR093_* cover each rule.
func TestT035_GitHubMisbindingEnrollsNothing(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gh(mainRef), true)
	pullRequest := func(event string) func(map[string]any) {
		return func(c map[string]any) {
			c["event_name"], c["ref"], c["ref_protected"] = event, "refs/pull/7/merge", "false"
			c["workflow_ref"], c["head_ref"], c["base_ref"] = "octo-org/agent-repo/.github/workflows/agent.yml@refs/pull/7/merge", "feature", "main"
		}
	}
	for _, tc := range []struct {
		name string
		mod  func(map[string]any)
	}{
		{"repository deleted and recreated with the same name", func(c map[string]any) { c["repository_id"] = "654321" }},
		{"owner account re-registered with the same name", func(c map[string]any) { c["repository_owner_id"] = "4242" }},
		{"a fork's own push to main", func(c map[string]any) {
			c["repository_id"], c["repository_owner_id"] = "555555", "666"
			c["workflow_ref"] = "mallory/agent-repo/.github/workflows/agent.yml@refs/heads/main"
		}},
		{"pull_request from a fork or a branch", pullRequest("pull_request")},
		{"pull_request with every other claim pinned", func(c map[string]any) { c["event_name"] = "pull_request" }},
		{"pull_request_target", func(c map[string]any) { c["event_name"] = "pull_request_target" }},
		{"pull_request_review", pullRequest("pull_request_review")},
		{"main with its protection removed", func(c map[string]any) { c["ref_protected"] = "false" }},
		{"an unprotected branch", func(c map[string]any) {
			c["ref"], c["ref_protected"] = "refs/heads/feature", "false"
			c["workflow_ref"] = "octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/feature"
		}},
		{"a reusable workflow of another repository", func(c map[string]any) {
			c["job_workflow_ref"] = "mallory/tools/.github/workflows/agent.yml@refs/heads/main"
		}},
		{"a GitHub Enterprise Server issuer", func(c map[string]any) { c["iss"] = "https://ghes.example.test/_services/token" }},
	} {
		c := w.ghClaims(mainRef)
		tc.mod(c)
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(c))
		wantPAP(t, tc.name, err, pap.CodeAttestationLow)
		c["jti"] = ids.NewV7().String()
		_, err = w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(c))
		wantPAP(t, tc.name+" with an enrollment token", err, pap.CodeAttestationLow)
	}
	if n, a := m3tInstances(t, w), m3tAttestations(t, w); n != 0 || a != 0 {
		t.Fatalf("instances %d, attestations %d after mis-bound tokens", n, a)
	}
	wl := newWorkload()
	in, err := w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	if err != nil || in.State != "ADMITTED" || in.Level != 2 {
		t.Fatalf("the genuine push: %+v, %v", in, err)
	}
	target := w.ghClaims(mainRef)
	target["event_name"] = "pull_request_target"
	_, err = w.attestToken(t, w.svc, wl, in.Instance, ghAtt(target))
	wantPAP(t, "pull_request_target renewing L2", err, pap.CodeAttestationLow)
	if a := m3tAttestations(t, w); a != 1 {
		t.Errorf("attestations %d, want the genuine one", a)
	}
}

// TestT044_MisScopedIssuerEntriesAttestNoOne: T-044 — an org admin, or an
// insider writing to the database, tries to make an entry trust more than
// one agent's workloads. Entries bound by names or broad claims are refused;
// a broad entry written straight into the database matches nothing, since
// the preset rules run in code; and a widening revision stays PROPOSED —
// a workload matching only the widened claims cannot attest, while the old
// revision keeps working — until a person holding identity.issuer.activate
// activates it. TestHR140_* and TestHR141_* cover each rule.
func TestT044_MisScopedIssuerEntriesAttestNoOne(t *testing.T) {
	w := newWorld(t).attestors(nil)
	ci, pod := w.agent(t, adomain.ContextCI), w.agent(t, adomain.ContextKubernetes)
	github := func(mod func(*issuers.GitHubBinding)) app.Binding {
		b := gh(mainRef)
		mod(b.GitHub)
		return b
	}
	k8s := func(mod func(*issuers.KubernetesBinding)) app.Binding {
		b := m3tKubeBinding("prod")
		mod(b.Kubernetes)
		return b
	}
	for _, tc := range []struct {
		name  string
		agent ids.UUID
		b     app.Binding
	}{
		{"any repository of the owner", ci, github(func(g *issuers.GitHubBinding) { g.RepositoryID = "" })},
		{"the repository under any owner", ci, github(func(g *issuers.GitHubBinding) { g.RepositoryOwnerID = "" })},
		{"repository and owner by name", ci, github(func(g *issuers.GitHubBinding) {
			g.RepositoryID, g.RepositoryOwnerID = "agent-repo", "octo-org"
		})},
		{"any workflow", ci, github(func(g *issuers.GitHubBinding) { g.WorkflowRefs = nil })},
		{"a wildcard repository in the workflow", ci, github(func(g *issuers.GitHubBinding) {
			g.WorkflowRefs = []string{"octo-org/*/.github/workflows/agent.yml@refs/heads/main"}
		})},
		{"pull request refs", ci, github(func(g *issuers.GitHubBinding) {
			g.WorkflowRefs = []string{"octo-org/agent-repo/.github/workflows/agent.yml@refs/pull/1/merge"}
		})},
		{"any job type", ci, github(func(g *issuers.GitHubBinding) { g.JobType = "" })},
		{"any service account named coder", pod, k8s(func(k *issuers.KubernetesBinding) { k.ServiceAccountUID = "" })},
		{"any namespace", pod, k8s(func(k *issuers.KubernetesBinding) { k.Namespace = "*" })},
		{"any service account", pod, k8s(func(k *issuers.KubernetesBinding) { k.ServiceAccountName = "*" })},
		{"no preset", ci, app.Binding{}},
		{"two presets", ci, app.Binding{GitHub: gh(mainRef).GitHub, Kubernetes: m3tKubeBinding("prod").Kubernetes}},
	} {
		_, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: tc.agent, Binding: tc.b, AutoAdmit: true, Reason: "broad"},
			clusters{"prod": w.org})
		wantCode(t, tc.name, err, pcerr.InvalidArgument, "ISSUER_BINDING")
	}
	if n := w.count(t, "SELECT count(*) FROM pc.trusted_issuers WHERE org_id = $1", w.org); n != 0 {
		t.Fatalf("%d entries stored", n)
	}

	broad, _ := json.Marshal(app.Binding{GitHub: &issuers.GitHubBinding{
		RepositoryOwnerID: "7890", JobType: issuers.JobWorkflow,
		WorkflowRefs: []string{"octo-org/*/.github/workflows/agent.yml@refs/heads/main"},
	}})
	w.exec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
		binding, auto_admit, state, proposed_by, activated_by, activated_at) VALUES ($1, $2, $3, 1, $4, 'github_actions', $5, $6,
		'{RS256}', $7, true, 'ACTIVE', 'insider', 'insider', now())`,
		w.org, ids.NewV7(), ids.NewV7(), ci, issuers.GitHubIssuer, "pantherclaw:"+w.org.String(), broad)
	other := w.ghClaims("octo-org/other-repo/.github/workflows/agent.yml@refs/heads/main")
	other["repository_id"] = "222222"
	_, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(other))
	wantPAP(t, "another repository of the owner through a broad entry in the database", err, pap.CodeAttestationLow)

	agent := w.agent(t, adomain.ContextCI)
	pinned := gh(mainRef)
	pinned.GitHub.WorkflowSHAs = []string{sha40}
	e := w.activeEntry(t, agent, pinned, true)
	const otherSHA = "fedcba9876543210fedcba9876543210fedcba98"
	const forkRef = "mallory/agent-repo/.github/workflows/agent.yml@refs/heads/main"
	for _, tc := range []struct {
		name  string
		widen func(*issuers.GitHubBinding)
		token func(map[string]any)
	}{
		{
			"a release tag added", func(g *issuers.GitHubBinding) { g.WorkflowRefs = append(g.WorkflowRefs, tagRef) },
			func(c map[string]any) { c["workflow_ref"], c["ref"] = tagRef, "refs/tags/v1" },
		},
		{
			"the sha pin dropped", func(g *issuers.GitHubBinding) { g.WorkflowSHAs = nil },
			func(c map[string]any) { c["workflow_sha"] = otherSHA },
		},
		{
			"the repository swapped", func(g *issuers.GitHubBinding) {
				g.RepositoryID, g.RepositoryOwnerID, g.WorkflowRefs = "424242", "666", []string{forkRef}
			},
			func(c map[string]any) {
				c["repository_id"], c["repository_owner_id"], c["workflow_ref"] = "424242", "666", forkRef
			},
		},
	} {
		g := *pinned.GitHub
		g.WorkflowRefs, g.WorkflowSHAs = slices.Clone(g.WorkflowRefs), slices.Clone(g.WorkflowSHAs)
		tc.widen(&g)
		r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{
			EntryID: e.EntryID, AgentID: agent, Binding: app.Binding{GitHub: &g}, AutoAdmit: true, Reason: tc.name,
		}, nil)
		if err != nil || r.State != "PROPOSED" || len(r.Widening) == 0 {
			t.Fatalf("%s: %+v, %v", tc.name, r, err)
		}
		c := w.ghClaims(mainRef)
		tc.token(c)
		_, err = w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(c))
		wantPAP(t, tc.name+": the widened claims before activation", err, pap.CodeAttestationLow)
		_, err = w.svc.ActivateIssuer(w.orgAdmin(), e.EntryID, r.Revision, false)
		wantCode(t, tc.name+": an Org Admin activates", err, pcerr.PermissionDenied, "")
		if _, err := w.svc.WithdrawIssuer(w.orgAdmin(), e.EntryID, r.Revision); err != nil {
			t.Fatal(err)
		}
	}
	if n := m3tInstances(t, w); n != 0 {
		t.Fatalf("%d instances enrolled through mis-scoped entries", n)
	}
	if in, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(mainRef))); err != nil || in.State != "ADMITTED" {
		t.Fatalf("the active revision: %+v, %v", in, err)
	}
	g := *pinned.GitHub
	g.WorkflowRefs = []string{mainRef, tagRef}
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{
		EntryID: e.EntryID, AgentID: agent, Binding: app.Binding{GitHub: &g}, AutoAdmit: true, Reason: "release tags",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.svc.ActivateIssuer(w.publisher(td.KindServiceAccount), e.EntryID, r.Revision, false)
	wantCode(t, "a service account activates", err, pcerr.PermissionDenied, "")
	if _, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), e.EntryID, r.Revision, false); err != nil {
		t.Fatal(err)
	}
	tag := w.ghClaims(tagRef)
	tag["ref"] = "refs/tags/v1"
	if in, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(tag)); err != nil || in.State != "ADMITTED" {
		t.Fatalf("the widened claims after a person activated them: %+v, %v", in, err)
	}
}

// TestT045_IssuerKeySourcesCannotBeAbused: T-045 — a tenant cannot name a
// key source at all: issuer entries carry the preset's fixed issuer or a
// cluster the operator configured for the org. Through the production key
// fetcher and Kubernetes client, an issuer or API server on a private
// address the operator did not allow is never contacted (HR-071); a
// discovery document pointing the JWKS at the metadata address is not
// followed; a key planted under a known kid or offered in the token does
// not verify; a flood of unknown kids refetches at most once a minute; a
// key the issuer rotated out stops verifying when the cache expires; and an
// issuer that stops answering fails closed. TestHR142_* in issuerkeys and
// kube cover the limits one by one.
func TestT045_IssuerKeySourcesCannotBeAbused(t *testing.T) {
	w := newWorld(t)
	pod, ci := w.agent(t, adomain.ContextKubernetes), w.agent(t, adomain.ContextCI)
	configured, err := kube.NewDirectory([]kube.ClusterConfig{
		{Name: "prod", APIServer: "https://10.20.0.1:6443", CAFile: "ca.pem", TokenFile: "token", Orgs: []string{w.org.String()}},
		{Name: "shared", APIServer: "https://10.30.0.1:6443", CAFile: "ca.pem", TokenFile: "token", Orgs: []string{ids.New[ids.Org]().String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range []string{"metadata", "shared"} {
		_, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: pod, Binding: m3tKubeBinding(cl), Reason: "x"}, configured)
		wantCode(t, "cluster "+cl, err, pcerr.InvalidArgument, "ISSUER_CLUSTER")
	}
	kr, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: pod, Binding: m3tKubeBinding("prod"), AutoAdmit: true, Reason: "x"}, configured)
	if err != nil || kr.Issuer != "cluster:prod" {
		t.Fatalf("configured cluster: %+v, %v", kr, err)
	}
	if _, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), kr.EntryID, kr.Revision, false); err != nil {
		t.Fatal(err)
	}
	if e := w.activeEntry(t, ci, gh(mainRef), true); e.Issuer != issuers.GitHubIssuer {
		t.Fatalf("GitHub entry issuer %q", e.Issuer)
	}

	// A configured cluster whose API server is on loopback, with no allowed
	// range: the API server would authenticate anything, but is never asked.
	var reached atomic.Int32
	api := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		_, _ = rw.Write([]byte(`{"status":{"authenticated":true}}`))
	}))
	t.Cleanup(api.Close)
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "token")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("reviewer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	private, err := kube.NewDirectory([]kube.ClusterConfig{
		{Name: "prod", APIServer: api.URL, CAFile: caFile, TokenFile: tokenFile, Orgs: []string{w.org.String()}},
	})
	if err != nil {
		t.Fatal(err)
	}
	kc, err := kube.NewClient(private, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ksvc := app.New(w.pool, w.reg, issuer, clock.System{}).WithAttestors(app.Attestors{Kube: kc, Clusters: private})
	_, err = w.attestEnroll(t, ksvc, newWorkload(), "", m3tServiceAccountToken(w))
	wantPAP(t, "API server on a private address", err, pap.CodeAttestationLow)
	if n := reached.Load(); n != 0 {
		t.Fatalf("the private API server was reached %d times", n)
	}

	k1, rogue := m3tRSAKey(t), m3tRSAKey(t)
	is := m3tNewIssuer(t, map[string]*rsa.PrivateKey{"k1": k1})
	clk := clock.NewFake(time.Now())
	enroll := func(f *issuerkeys.Fetcher, header string, key *rsa.PrivateKey) (app.Enrolled, error) {
		t.Helper()
		svc := app.New(w.pool, w.reg, issuer, clock.System{}).WithAttestors(app.Attestors{GitHub: f})
		return w.attestEnroll(t, svc, newWorkload(), "", &app.Attestation{Kind: issuers.KindGitHub, Token: m3tSign(t, key, header, w.ghClaims(mainRef))})
	}
	_, err = enroll(is.fetcher(t, false, clk), m3tKid("k1"), k1)
	wantPAP(t, "issuer on a private address", err, pap.CodeAttestationLow)
	if n := is.requests.Load(); n != 0 {
		t.Fatalf("the private issuer was reached %d times", n)
	}

	f := is.fetcher(t, true, clk) // the operator allowed the issuer's range
	is.publish(map[string]*rsa.PrivateKey{"k1": k1}, "https://169.254.169.254/latest/meta-data/jwks")
	_, err = enroll(f, m3tKid("k1"), k1)
	wantPAP(t, "JWKS at the metadata address", err, pap.CodeAttestationLow)
	if n := is.jwks.Load(); n != 0 {
		t.Fatalf("JWKS served %d times", n)
	}
	is.publish(map[string]*rsa.PrivateKey{"k1": k1}, "")
	var attacker atomic.Int32
	evil := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { attacker.Add(1) }))
	t.Cleanup(evil.Close)
	for name, header := range map[string]string{
		"a planted key under a known kid": m3tKid("k1"),
		"a key URL in the token":          `{"alg":"RS256","kid":"k1","jku":"` + evil.URL + `/jwks"}`,
	} {
		_, err := enroll(f, header, rogue)
		wantPAP(t, name, err, pap.CodeAttestationLow)
	}
	if n := attacker.Load(); n != 0 {
		t.Fatalf("the attacker's key URL was fetched %d times", n)
	}
	if in, err := enroll(f, m3tKid("k1"), k1); err != nil || in.State != "ADMITTED" {
		t.Fatalf("genuine token: %+v, %v", in, err)
	}

	before := is.jwks.Load()
	for i := range 20 {
		_, err := enroll(f, m3tKid(fmt.Sprintf("flood-%d", i)), rogue)
		wantPAP(t, "unknown kid", err, pap.CodeAttestationLow)
	}
	if n := is.jwks.Load() - before; n > 1 {
		t.Fatalf("%d JWKS fetches for 20 unknown kids within a minute, want at most 1", n)
	}
	clk.Advance(issuerkeys.MissInterval)
	for i := range 5 {
		_, _ = enroll(f, m3tKid(fmt.Sprintf("later-%d", i)), rogue)
	}
	if n := is.jwks.Load() - before; n > 2 {
		t.Fatalf("%d JWKS fetches over two minutes of unknown kids, want at most 2", n)
	}

	k2 := m3tRSAKey(t)
	is.publish(map[string]*rsa.PrivateKey{"k2": k2}, "")
	clk.Advance(issuerkeys.CacheFor)
	_, err = enroll(f, m3tKid("k1"), k1)
	wantPAP(t, "a key rotated out once the cache expired", err, pap.CodeAttestationLow)
	if in, err := enroll(f, m3tKid("k2"), k2); err != nil || in.State != "ADMITTED" {
		t.Fatalf("the rotated-in key: %+v, %v", in, err)
	}
	is.srv.Close()
	clk.Advance(issuerkeys.CacheFor)
	_, err = enroll(f, m3tKid("k2"), k2)
	wantPAP(t, "an issuer that stopped answering", err, pap.CodeAttestationLow)
	if n := m3tInstances(t, w); n != 2 {
		t.Errorf("instances %d, want the two genuine ones", n)
	}
}

// TestT046_CopiedOrForeignAttestationTokensEnrollNothing: T-046 — an
// attacker copies a CI job's attestation token from its log. Replayed after
// the job used it, it is refused with or without an enrollment token;
// copied after it expired, it is refused. Another org that pins the same
// public repository ids on its own auto-admitting entry cannot enroll with
// this org's tokens, nor this org with its tokens, and a token naming both
// orgs routes nowhere. TestHR143_* cover single use, the audience and the
// lifetime one by one.
func TestT046_CopiedOrForeignAttestationTokensEnrollNothing(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gh(mainRef), true)
	logged := ghAtt(w.ghClaims(mainRef))
	if in, err := w.attestEnroll(t, w.svc, newWorkload(), "", logged); err != nil || in.State != "ADMITTED" {
		t.Fatalf("the CI job: %+v, %v", in, err)
	}
	_, err := w.attestEnroll(t, w.svc, newWorkload(), "", logged)
	wantPAP(t, "replayed from the log", err, pap.CodeInvalidToken)
	_, err = w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), logged)
	wantPAP(t, "replayed with an enrollment token", err, pap.CodeInvalidToken)

	clk := clock.NewFake(time.Now())
	later := app.New(w.pool, w.reg, issuer, clk).WithAttestors(app.Attestors{GitHub: fakeGitHub{}})
	unused := w.ghClaims(mainRef)
	unused["exp"] = time.Now().Add(5 * time.Minute).Unix()
	clk.Advance(7 * time.Minute)
	_, err = w.attestEnroll(t, later, newWorkload(), "", ghAtt(unused))
	wantPAP(t, "copied after it expired", err, pap.CodeAttestationLow)

	evil := newWorld(t).attestors(nil)
	evilAgent := evil.agent(t, adomain.ContextCI)
	evil.activeEntry(t, evilAgent, gh(mainRef), true)
	_, err = evil.attestEnroll(t, evil.svc, newWorkload(), evil.enrollmentToken(t, evilAgent), ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "this org's token in the other org", err, pap.CodeAttestationLow)
	both := evil.ghClaims(mainRef)
	both["aud"] = []string{"pantherclaw:" + evil.org.String(), "pantherclaw:" + w.org.String()}
	_, err = evil.attestEnroll(t, evil.svc, newWorkload(), "", ghAtt(both))
	wantPAP(t, "a token naming both orgs", err, pap.CodeAttestationLow)
	_, err = w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(evil.ghClaims(mainRef)))
	wantPAP(t, "the other org's token here", err, pap.CodeAttestationLow)
	if n, a := m3tInstances(t, w), m3tAttestations(t, w); n != 1 || a != 1 {
		t.Errorf("this org: %d instances, %d attestations; want the CI job's only", n, a)
	}
	if n, a := m3tInstances(t, evil), m3tAttestations(t, evil); n != 0 || a != 0 {
		t.Errorf("the other org: %d instances, %d attestations", n, a)
	}
}

// TestT047_KubernetesMisbindingAndDigestSpoofing: T-047 — workloads that
// are not the pinned pod try to attest as it: a service account deleted and
// recreated with the same name, the same name in another namespace, a
// deleted pod's token, a new pod reusing its name, a token bound to no pod
// or to another audience, a swapped image, the trusted digest from another
// repository, a sidecar next to the trusted image and a finished pod. None
// enrolls. A workload reporting a digest it does not run never makes it
// attested: at L2 the pod's digest stands, and without an attestation the
// trusted digest stays declared and is shown to the owner as untrusted.
// TestHR144_KubernetesAttestationReadsTheCluster covers the single checks.
func TestT047_KubernetesMisbindingAndDigestSpoofing(t *testing.T) {
	trusted, swapped := "sha256:"+hex64('a'), "sha256:"+hex64('b')
	kc := &fakeCluster{}
	w := newWorld(t).attestors(kc)
	base := fakeCluster{
		review: issuers.TokenReview{
			Authenticated: true, Audiences: []string{"pantherclaw:" + w.org.String()}, Username: "system:serviceaccount:agents:coder",
			UID: m3tSAUID, PodName: "coder-1", PodUID: "pod-1",
		},
		pod: issuers.Pod{
			Namespace: "agents", Name: "coder-1", UID: "pod-1", Phase: "Running", ImageIDs: []string{"ghcr.io/acme/agent@" + trusted},
		},
	}
	agent := w.agent(t, adomain.ContextKubernetes)
	b := m3tKubeBinding("prod")
	b.Kubernetes.ImageRepositories, b.Kubernetes.ImageDigests = []string{"ghcr.io/acme/agent"}, []string{trusted}
	w.activeEntry(t, agent, b, true)
	for _, tc := range []struct {
		name string
		mod  func(*fakeCluster)
	}{
		{"service account recreated with the same name", func(f *fakeCluster) { f.review.UID = "11111111-2222-4333-8444-555555555555" }},
		{"the same account name in another namespace", func(f *fakeCluster) {
			f.review.Username, f.pod.Namespace = "system:serviceaccount:sandbox:coder", "sandbox"
		}},
		{"a deleted pod's token", func(f *fakeCluster) { f.pod = issuers.Pod{} }},
		{"a new pod reusing the deleted pod's name", func(f *fakeCluster) { f.pod.UID = "pod-2" }},
		{"a token bound to no pod", func(f *fakeCluster) { f.review.PodName, f.review.PodUID = "", "" }},
		{"a token for another audience", func(f *fakeCluster) { f.review.Audiences = []string{"https://kubernetes.default.svc"} }},
		{"a swapped image in the pinned repository", func(f *fakeCluster) { f.pod.ImageIDs = []string{"ghcr.io/acme/agent@" + swapped} }},
		{"the trusted digest from another repository", func(f *fakeCluster) { f.pod.ImageIDs = []string{"docker.io/evil/agent@" + trusted} }},
		{"a sidecar next to the trusted image", func(f *fakeCluster) {
			f.pod.ImageIDs = []string{"ghcr.io/acme/agent@" + trusted, "docker.io/evil/sidecar@" + swapped}
		}},
		{"a finished pod", func(f *fakeCluster) { f.pod.Phase = "Succeeded" }},
	} {
		*kc = base
		tc.mod(kc)
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", m3tServiceAccountToken(w))
		wantPAP(t, tc.name, err, pap.CodeAttestationLow)
	}
	*kc = base
	if n := m3tInstances(t, w); n != 0 {
		t.Fatalf("%d instances enrolled", n)
	}

	v, _ := w.svc.TokenVerifier()
	release := func(wl workload, inst pap.Instance, declared string) pap.Token {
		t.Helper()
		iss, err := w.svc.IssueToken(context.Background(), app.TokenInput{
			Proof: w.checked(t, wl, tokenURL, []byte(declared)), Identifier: inst.String(), DeclaredRelease: declared,
		})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := pap.VerifyToken(v, issuer, iss.Token, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	wl, att := newWorkload(), m3tServiceAccountToken(w)
	in, err := w.svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, wl, enrollURL, []byte(att.Token)), Attestation: att, PublicJWK: wl.jwk(), DeclaredRelease: swapped,
	})
	if err != nil || in.State != "ADMITTED" {
		t.Fatalf("the pinned pod: %+v, %v", in, err)
	}
	if tok := release(wl, in.Instance, swapped); tok.Level != 2 || tok.ReleaseState != pap.ReleaseAttested || tok.ReleaseDigest != trusted {
		t.Fatalf("L2 workload reporting another digest: %+v", tok)
	}

	l1 := newWorkload()
	et := w.enrollmentToken(t, agent)
	pe, err := w.svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, l1, enrollURL, []byte(et)), EnrollmentToken: et, PublicJWK: l1.jwk(), DeclaredRelease: trusted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND subject_id = $2
		AND evidence->'untrusted'->>'declared_release_digest' = $3 AND evidence->'trusted'->>'attested_release_digest' IS NULL`,
		w.org, pe.Instance.Instance, trusted); n != 1 {
		t.Errorf("the owner is not shown the reported digest as untrusted")
	}
	if _, err := w.svc.Admit(w.ownerCtx(), pe.Instance.Instance, pe.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if tok := release(l1, pe.Instance, trusted); tok.Level != 1 || tok.ReleaseState != pap.ReleaseDeclared || tok.ReleaseDigest != trusted {
		t.Fatalf("L1 workload reporting the trusted digest: %+v", tok)
	}
	if got, err := w.svc.GetInstance(w.ownerCtx(), pe.Instance.Instance); err != nil || got.ReleaseState != pap.ReleaseDeclared {
		t.Fatalf("instance %+v, %v", got, err)
	}
}

// TestT049_NewIdentitiesInheritNoRuns: T-049 — a workload tries to carry a
// run from one identity to another. A run bound to an instance is refused
// for a sibling instance; the same workload enrolled again, a re-attestation
// with other claims (refused, so the workload must enroll anew), an instance
// enrolled by a new owner after an ownership transfer and an instance of
// another agent with the same name all start with no runs and cannot use
// the run, which keeps its instance and principal. The run is checked with
// Bind, the HR-022 check the Authority makes on every action
// (TestHR022_AuthorizeChecksTheRunBinding maps it to DENY RUN_MISMATCH);
// TestHR147_* cover the single rules.
func TestT049_NewIdentitiesInheritNoRuns(t *testing.T) {
	w := newWorld(t).attestors(nil)
	runs := runsapp.New(w.pool)
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gh(mainRef, tagRef), true)
	wl := newWorkload()
	first, err := w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	if err != nil {
		t.Fatal(err)
	}
	run, err := runs.StartRun(w.ownerCtx(), runsapp.StartInput{AgentID: agent, InstanceID: &first.Instance.Instance})
	if err != nil {
		t.Fatal(err)
	}
	refused := func(what string, of, instance ids.UUID) {
		t.Helper()
		_, err := runs.Bind(context.Background(), w.org, run.ID, of, instance)
		wantPAP(t, what, err, pap.CodeRunMismatch)
		if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1 AND instance_id = $2", w.org, instance); n != 0 {
			t.Errorf("%s: holds %d runs", what, n)
		}
	}
	enrolled := func(owner, of ids.UUID) ids.UUID {
		t.Helper()
		as := w.person(owner, td.KindUser, td.RoleAgentOwner, td.RoleAgentAdmitter)
		et, err := w.svc.CreateEnrollmentToken(as, of, 0)
		if err != nil {
			t.Fatal(err)
		}
		e, err := w.enroll(t, newWorkload(), et.Secret.Reveal())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.svc.Admit(as, e.Instance.Instance, e.Fingerprint); err != nil {
			t.Fatal(err)
		}
		return e.Instance.Instance
	}
	refused("a sibling instance", agent, enrolled(w.owner, agent))
	again, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(mainRef)))
	if err != nil || again.State != "ADMITTED" {
		t.Fatalf("enrolled again: %+v, %v", again, err)
	}
	refused("the same workload enrolled again", agent, again.Instance.Instance)
	tag := w.ghClaims(tagRef)
	tag["ref"] = "refs/tags/v1"
	_, err = w.attestToken(t, w.svc, wl, first.Instance, ghAtt(tag))
	wantPAP(t, "re-attestation with other claims", err, pap.CodeAttestationLow)
	tag["jti"] = ids.NewV7().String()
	moved, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(tag))
	if err != nil {
		t.Fatal(err)
	}
	refused("the instance enrolled with the other claims", agent, moved.Instance.Instance)

	bob := ids.NewV7()
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", w.org, bob)
	if _, err := w.inv.TransferOwnership(w.ownerCtx(), agent, bob, ids.UUID{}, "alice moved teams"); err != nil {
		t.Fatal(err)
	}
	refused("the new owner's instance", agent, enrolled(bob, agent))
	twin := w.agent(t, adomain.ContextCI) // every agent here is named "coder"
	refused("an instance of another agent with the same name", twin, enrolled(w.owner, twin))

	got, err := runs.GetRun(w.person(bob, td.KindUser, td.RoleAgentOwner), run.ID)
	if err != nil || got.State != "ACTIVE" || got.InstanceID == nil || *got.InstanceID != first.Instance.Instance ||
		got.Principal != (runsapp.Actor{Kind: "user", ID: w.owner.String()}) {
		t.Fatalf("the run after all of it: %+v, %v", got, err)
	}
	if _, err := runs.Bind(context.Background(), w.org, run.ID, agent, first.Instance.Instance); err != nil {
		t.Fatalf("the bound instance: %v", err)
	}
	if s, err := w.inv.Get(w.ownerCtx(), twin); err != nil || s.ActiveRuns != 0 {
		t.Errorf("the namesake: %+v, %v", s, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.runs WHERE org_id = $1", w.org); n != 1 {
		t.Errorf("runs %d, want 1", n)
	}
}
