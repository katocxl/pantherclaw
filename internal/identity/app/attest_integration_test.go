// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeGitHub stands in for issuerkeys.Fetcher, whose signature checks have
// their own tests: a token whose signature segment is "sig" verifies.
type fakeGitHub struct{}

func (fakeGitHub) Verify(_ context.Context, tok string) ([]byte, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("signature")
	}
	// Like go-jose, the fake decodes the signature without checking the
	// unused bits of its last character.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if want, _ := base64.RawURLEncoding.DecodeString("sig"); err != nil || string(sig) != string(want) {
		return nil, errors.New("signature")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// fakeCluster stands in for kube.Client.
type fakeCluster struct {
	review   issuers.TokenReview
	pod      issuers.Pod
	err      error
	audience string
}

func (f *fakeCluster) Review(_ context.Context, cluster, _, audience string) (issuers.TokenReview, error) {
	f.audience = audience
	if cluster != "prod" {
		return issuers.TokenReview{}, errors.New("unknown cluster")
	}
	return f.review, f.err
}

func (f *fakeCluster) Pod(_ context.Context, _, namespace, name string) (issuers.Pod, error) {
	if f.pod.Namespace != namespace || f.pod.Name != name {
		return issuers.Pod{}, nil
	}
	return f.pod, f.err
}

func jwt(claims map[string]any) string {
	p, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc(p) + ".sig"
}

const sha40 = "0123456789abcdef0123456789abcdef01234567"

// ghClaims are the claims of a GitHub Actions push run of workflow ref.
func (w *world) ghClaims(ref string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": issuers.GitHubIssuer, "aud": "pantherclaw:" + w.org.String(), "jti": ids.NewV7().String(),
		"repository_id": "123456", "repository_owner_id": "7890", "ref": "refs/heads/main", "ref_protected": "true",
		"event_name": "push", "workflow_ref": ref, "workflow_sha": sha40, "sha": sha40,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func ghAtt(claims map[string]any) *app.Attestation {
	return &app.Attestation{Kind: issuers.KindGitHub, Token: jwt(claims)}
}

func (w *world) attestors(kube *fakeCluster) *world {
	w.svc.WithAttestors(app.Attestors{GitHub: fakeGitHub{}, Kube: kube, Clusters: clusters{"prod": w.org}})
	return w
}

// activeEntry proposes and activates an entry for agent.
func (w *world) activeEntry(t *testing.T, agent ids.UUID, b app.Binding, auto bool) app.Revision {
	t.Helper()
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{AgentID: agent, Binding: b, AutoAdmit: auto, Reason: "test"},
		clusters{"prod": w.org})
	if err != nil {
		t.Fatal(err)
	}
	a, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), r.EntryID, r.Revision, false)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (w *world) attestEnroll(t *testing.T, svc *app.Service, wl workload, token string, att *app.Attestation) (app.Enrolled, error) {
	t.Helper()
	return svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, wl, enrollURL, []byte(token+att.Token)), EnrollmentToken: token, Attestation: att, PublicJWK: wl.jwk(),
	})
}

func (w *world) attestToken(t *testing.T, svc *app.Service, wl workload, id pap.Instance, att *app.Attestation) (app.Issued, error) {
	t.Helper()
	in := app.TokenInput{Proof: w.checked(t, wl, tokenURL, []byte(id.String())), Identifier: id.String(), Attestation: att}
	return svc.IssueToken(context.Background(), in)
}

// TestHR094_AutoAdmissionOnlyThroughAnActiveAutoAdmitEntry: without an
// enrollment token, an attestation enrolls only through an active entry
// that auto-admits; otherwise the owner still confirms the fingerprint.
func TestHR094_AutoAdmissionOnlyThroughAnActiveAutoAdmitEntry(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	e := w.activeEntry(t, agent, gh(mainRef), false)
	_, err := w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "entry without auto-admission", err, pap.CodeAttestationLow)
	pending, err := w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(w.ghClaims(mainRef)))
	if err != nil || pending.State != "PENDING_ADMISSION" || pending.Level != 2 {
		t.Fatalf("with an enrollment token: %+v, %v", pending, err)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.waitlist_entries WHERE org_id = $1 AND subject_id = $2
		AND evidence->'trusted'->>'issuer_entry_id' = $3`, w.org, pending.Instance.Instance, e.EntryID.String()); n != 1 {
		t.Fatalf("admission entry with attested evidence: %d", n)
	}
	// Turning on auto-admission waits for activation (HR-141).
	r, err := w.svc.ProposeIssuer(w.orgAdmin(), app.ProposeInput{EntryID: e.EntryID, AgentID: agent, Binding: gh(mainRef), AutoAdmit: true, Reason: "auto"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "proposed auto-admission", err, pap.CodeAttestationLow)
	if _, err := w.svc.ActivateIssuer(w.publisher(td.KindUser), e.EntryID, r.Revision, false); err != nil {
		t.Fatal(err)
	}
	wl := newWorkload()
	auto, err := w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	if err != nil || auto.State != "ADMITTED" || auto.Level != 2 || auto.Instance.Agent != agent {
		t.Fatalf("auto-admission: %+v, %v", auto, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.identity.instance_auto_admitted'", w.org); n != 1 {
		t.Errorf("auto-admission audit events %d, want 1", n)
	}
	if iss, err := w.attestToken(t, w.svc, wl, auto.Instance, nil); err != nil || iss.Level != 2 {
		t.Fatalf("token: %+v, %v", iss, err)
	}
	// With an enrollment token as well, the auto-admitting entry still
	// decides: the same attestation alone would have been admitted.
	both, err := w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(w.ghClaims(mainRef)))
	if err != nil || both.State != "ADMITTED" {
		t.Fatalf("enrollment token and auto-admitting attestation: %+v, %v", both, err)
	}
	// A token matching no entry, and one for a desktop agent (never L2,
	// HR-092), do not auto-admit.
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(tagRef)))
	wantPAP(t, "unpinned ref", err, pap.CodeAttestationLow)
	desk := newWorld(t).attestors(nil)
	deskAgent := desk.agent(t, adomain.ContextDesktop)
	b, _ := json.Marshal(gh(mainRef))
	desk.exec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
		binding, auto_admit, state, proposed_by, activated_by, activated_at) VALUES ($1, $2, $3, 1, $4, 'github_actions', $5, $6,
		'{RS256}', $7, true, 'ACTIVE', 'test', 'test', now())`,
		desk.org, ids.NewV7(), ids.NewV7(), deskAgent, issuers.GitHubIssuer, "pantherclaw:"+desk.org.String(), b)
	_, err = desk.attestEnroll(t, desk.svc, newWorkload(), "", ghAtt(desk.ghClaims(mainRef)))
	wantPAP(t, "desktop agent", err, pap.CodeAttestationLow)
}

// TestHR141_DisablingAnEntryEndsItsL2: a disabled entry admits no one and
// its instances drop to L1 at their next token.
func TestHR141_DisablingAnEntryEndsItsL2(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	e := w.activeEntry(t, agent, gh(mainRef), true)
	wl := newWorkload()
	in, err := w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.DisableIssuer(w.orgAdmin(), e.EntryID, "repository archived"); err != nil {
		t.Fatal(err)
	}
	if iss, err := w.attestToken(t, w.svc, wl, in.Instance, nil); err != nil || iss.Level != 1 {
		t.Fatalf("after disable: %+v, %v", iss, err)
	}
	_, err = w.attestToken(t, w.svc, wl, in.Instance, ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "re-attestation through a disabled entry", err, pap.CodeAttestationLow)
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "enrollment through a disabled entry", err, pap.CodeAttestationLow)
}

// TestHR143_AttestationTokensAreSingleUseAndShortLived.
func TestHR143_AttestationTokensAreSingleUseAndShortLived(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gh(mainRef), true)
	for name, mod := range map[string]func(map[string]any){
		"with a jti":    func(map[string]any) {},
		"without a jti": func(c map[string]any) { delete(c, "jti") },
	} {
		c := w.ghClaims(mainRef)
		mod(c)
		att := ghAtt(c)
		if _, err := w.attestEnroll(t, w.svc, newWorkload(), "", att); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", att)
		wantPAP(t, name+": reused", err, pap.CodeInvalidToken)
		// The same token with the unused bits of its last character changed
		// still verifies, and is still the same token.
		odd := &app.Attestation{Kind: att.Kind, Token: att.Token[:len(att.Token)-1] + "h"}
		_, err = w.attestEnroll(t, w.svc, newWorkload(), "", odd)
		wantPAP(t, name+": reused in another encoding", err, pap.CodeInvalidToken)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE org_id = $1", w.org); n != 2 {
		t.Fatalf("instances %d, want 2", n)
	}
	other := w.ghClaims(mainRef)
	other["aud"] = "pantherclaw:" + ids.New[ids.Org]().String()
	_, err := w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(other))
	wantPAP(t, "another org's audience", err, pap.CodeAttestationLow)
	two := w.ghClaims(mainRef)
	two["aud"] = []string{"pantherclaw:" + w.org.String(), "sigstore"}
	_, err = w.attestEnroll(t, w.svc, newWorkload(), w.enrollmentToken(t, agent), ghAtt(two))
	wantPAP(t, "a second audience", err, pap.CodeAttestationLow)
	long := w.ghClaims(mainRef)
	long["exp"] = time.Now().Add(61 * time.Minute).Unix()
	_, err = w.attestEnroll(t, w.svc, newWorkload(), "", ghAtt(long))
	wantPAP(t, "lifetime over an hour", err, pap.CodeAttestationLow)

	// L2 lasts until the attestation expires; tokens never outlive it.
	clk := clock.NewFake(time.Now())
	svc := app.New(w.pool, w.reg, issuer, clk).WithAttestors(app.Attestors{GitHub: fakeGitHub{}})
	short := w.ghClaims(mainRef)
	short["exp"] = time.Now().Add(4 * time.Minute).Unix()
	wl := newWorkload()
	in, err := w.attestEnroll(t, svc, wl, "", ghAtt(short))
	if err != nil {
		t.Fatal(err)
	}
	iss, err := w.attestToken(t, svc, wl, in.Instance, nil)
	if err != nil || iss.Level != 2 || iss.ExpiresAt.Unix() > short["exp"].(int64) {
		t.Fatalf("before exp: %+v, %v", iss, err)
	}
	clk.Advance(5 * time.Minute)
	if iss, err := w.attestToken(t, svc, wl, in.Instance, nil); err != nil || iss.Level != 1 {
		t.Fatalf("after exp: %+v, %v", iss, err)
	}
}

// TestHR147_ReattestationMustMatchTheEnrolledBinding: a fresh attestation
// renews L2 only with the claims the instance enrolled with; an instance
// enrolled without one never gains a binding.
func TestHR147_ReattestationMustMatchTheEnrolledBinding(t *testing.T) {
	w := newWorld(t).attestors(nil)
	agent := w.agent(t, adomain.ContextCI)
	w.activeEntry(t, agent, gh(mainRef, tagRef), true)
	wl := newWorkload()
	in, err := w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	if err != nil {
		t.Fatal(err)
	}
	tag := w.ghClaims(tagRef)
	tag["ref"] = "refs/tags/v1"
	_, err = w.attestToken(t, w.svc, wl, in.Instance, ghAtt(tag))
	wantPAP(t, "re-attestation from another workflow", err, pap.CodeAttestationLow)
	fresh := w.ghClaims(mainRef)
	fresh["exp"] = time.Now().Add(30 * time.Minute).Unix()
	if iss, err := w.attestToken(t, w.svc, wl, in.Instance, ghAtt(fresh)); err != nil || iss.Level != 2 {
		t.Fatalf("re-attestation: %+v, %v", iss, err)
	}
	got, err := w.svc.GetInstance(w.ownerCtx(), in.Instance.Instance)
	if err != nil || got.AttestedUntil == nil || got.AttestedUntil.Unix() != fresh["exp"].(int64) {
		t.Fatalf("attested until: %+v, %v", got.AttestedUntil, err)
	}
	l1wl, l1, _ := w.admitted(t, adomain.ContextCI)
	_, err = w.attestToken(t, w.svc, l1wl, l1, ghAtt(w.ghClaims(mainRef)))
	wantPAP(t, "attestation for an instance enrolled without one", err, pap.CodeAttestationLow)
	_, err = w.attestEnroll(t, w.svc, wl, "", ghAtt(w.ghClaims(mainRef)))
	wantCode(t, "the same key again", err, pcerr.AlreadyExists, "KEY_ENROLLED")
}

// TestHR144_KubernetesAttestationReadsTheCluster: TokenReview must
// authenticate the pinned account bound to a live pod, and the release
// digest comes from that pod, never from the workload.
func TestHR144_KubernetesAttestationReadsTheCluster(t *testing.T) {
	const saUID = "6f1d2c3b-4a59-4e2b-9c1d-0a1b2c3d4e5f"
	digest := "sha256:" + hex64('a')
	kube := &fakeCluster{
		review: issuers.TokenReview{
			Authenticated: true, Username: "system:serviceaccount:agents:coder", UID: saUID, PodName: "coder-1", PodUID: "pod-1",
		},
		pod: issuers.Pod{
			Namespace: "agents", Name: "coder-1", UID: "pod-1", Phase: "Running",
			ImageIDs: []string{"ghcr.io/acme/agent@" + digest},
		},
	}
	w := newWorld(t).attestors(kube)
	kube.review.Audiences = []string{"pantherclaw:" + w.org.String()}
	agent := w.agent(t, adomain.ContextKubernetes)
	w.activeEntry(t, agent, app.Binding{Kubernetes: &issuers.KubernetesBinding{
		Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: saUID,
		ImageRepositories: []string{"ghcr.io/acme/agent"},
	}}, true)
	sat := func() *app.Attestation {
		now := time.Now()
		return &app.Attestation{Kind: issuers.KindKubernetes, Token: jwt(map[string]any{
			"iss": "https://kubernetes.default.svc", "aud": []string{"pantherclaw:" + w.org.String()}, "jti": ids.NewV7().String(),
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		})}
	}
	wl := newWorkload()
	att := sat()
	in, err := w.svc.Enroll(context.Background(), app.EnrollInput{
		Proof: w.checked(t, wl, enrollURL, []byte(att.Token)), Attestation: att, PublicJWK: wl.jwk(),
		DeclaredRelease: "sha256:" + hex64('f'),
	})
	if err != nil || in.State != "ADMITTED" || kube.audience != "pantherclaw:"+w.org.String() {
		t.Fatalf("enroll: %+v, %v (audience %q)", in, err, kube.audience)
	}
	got, _ := w.svc.GetInstance(w.ownerCtx(), in.Instance.Instance)
	if got.ReleaseState != pap.ReleaseAttested || got.ReleaseDigest != digest {
		t.Fatalf("release %s %s, want the pod's digest, attested", got.ReleaseState, got.ReleaseDigest)
	}
	for name, mod := range map[string]func(*fakeCluster){
		"recreated service account": func(f *fakeCluster) { f.review.UID = "11111111-2222-4333-8444-555555555555" },
		"pod gone":                  func(f *fakeCluster) { f.pod.Name = "coder-2" },
		"pod replaced":              func(f *fakeCluster) { f.pod.UID = "pod-2" },
		"unpinned image":            func(f *fakeCluster) { f.pod.ImageIDs = []string{"docker.io/evil/agent@" + digest} },
		"cluster unavailable":       func(f *fakeCluster) { f.err = errors.New("connection refused") },
		"not authenticated":         func(f *fakeCluster) { f.review.Authenticated = false },
	} {
		saved := *kube
		mod(kube)
		_, err := w.attestEnroll(t, w.svc, newWorkload(), "", sat())
		wantPAP(t, name, err, pap.CodeAttestationLow)
		*kube = saved
	}
	// A new image under the same binding is attested drift (F033).
	kube.pod.ImageIDs = []string{"ghcr.io/acme/agent@sha256:" + hex64('b')}
	if iss, err := w.attestToken(t, w.svc, wl, in.Instance, sat()); err != nil || iss.Level != 2 {
		t.Fatalf("re-attestation: %+v, %v", iss, err)
	}
	got, _ = w.svc.GetInstance(w.ownerCtx(), in.Instance.Instance)
	if !got.NeedsReview || got.ReleaseDigest != "sha256:"+hex64('b') || got.ReleaseState != pap.ReleaseAttested {
		t.Fatalf("after a new image: %+v", got)
	}
}
