// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	gwSAUID   = "5b0e7c1a-2d3f-4e5a-8b6c-7d8e9f0a1b2c"
	gwDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	gwPodUID  = "8c1d2e3f-4a5b-4c6d-9e7f-8a9b0c1d2e3f"
	otherHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// fakeCluster answers TokenReview from what the test says the cluster
// would: tokens it knows authenticate as the gateway's service account.
type fakeCluster struct {
	review issuers.TokenReview
	pod    issuers.Pod
	fail   bool
	asked  int
}

func (f *fakeCluster) Review(_ context.Context, cluster, _, audience string) (issuers.TokenReview, error) {
	f.asked++
	if f.fail || cluster != "home" {
		return issuers.TokenReview{}, errors.New("cluster unavailable")
	}
	r := f.review
	if !strings.HasPrefix(audience, labels.GatewayAudiencePrefix) {
		r.Authenticated = false
	}
	return r, nil
}

func (f *fakeCluster) Pod(_ context.Context, _, _, name string) (issuers.Pod, error) {
	if name != f.pod.Name {
		return issuers.Pod{}, errors.New("not found")
	}
	return f.pod, nil
}

type clusters map[string]ids.OrgID

func (c clusters) Allowed(cluster string, org ids.OrgID) bool {
	o, ok := c[cluster]
	return ok && o == org
}

func newKubeCluster(org ids.OrgID) *fakeCluster {
	return &fakeCluster{
		review: issuers.TokenReview{
			Authenticated: true, Audiences: []string{labels.GatewayAudience(org)},
			Username: "system:serviceaccount:pantherclaw:pantherclaw-gateway", UID: gwSAUID,
			PodName: "gw-0", PodUID: gwPodUID,
		},
		pod: issuers.Pod{Namespace: "pantherclaw", Name: "gw-0", UID: gwPodUID, Phase: "Running", ImageIDs: []string{"ghcr.io/katocxl/pantherclaw-gateway@" + gwDigest}},
	}
}

// projected is a projected service-account token's compact form; only the
// payload matters, as TokenReview (the fake) decides.
func projected(t *testing.T, aud []string, ns, sa, jti string, iat time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"aud": aud, "iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(10 * time.Minute).Unix(), "jti": jti,
		"kubernetes.io": map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": sa, "uid": gwSAUID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

func binding() app.KubeBinding {
	return app.KubeBinding{Cluster: "home", Namespace: "pantherclaw", ServiceAccountName: "pantherclaw-gateway", ServiceAccountUID: gwSAUID, ImageDigests: []string{gwDigest}}
}

// TestHR739_AGatewayBindingNeedsGatewayManageAndIsAudited: binding and
// clearing need gateway.manage, are audited, and accept only a valid
// binding to a cluster configured for the org.
func TestHR739_AGatewayBindingNeedsGatewayManageAndIsAudited(t *testing.T) {
	e := newEnv(t)
	e.svc.WithKubernetes(newKubeCluster(e.org), clusters{"home": e.org, "away": ids.New[ids.Org]()}, []string{"home", "away"})
	g, err := e.svc.CreateGateway(e.admin, "in-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetKubernetesBinding(e.caller(td.KindUser, td.RoleViewer), g.ID, binding()); err == nil {
		t.Error("a viewer bound a gateway")
	}
	away := binding()
	away.Cluster = "away"
	bad := binding()
	bad.ServiceAccountUID = "not-a-uid"
	for name, b := range map[string]app.KubeBinding{"another org's cluster": away, "an invalid binding": bad} {
		if _, err := e.svc.SetKubernetesBinding(e.admin, g.ID, b); err == nil {
			t.Errorf("%s: bound", name)
		}
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE '%gateway.kubernetes_binding_%'"); n != 0 {
		t.Fatalf("refused bindings audited %d times", n)
	}
	got, err := e.svc.SetKubernetesBinding(e.admin, g.ID, binding())
	if err != nil {
		t.Fatal(err)
	}
	if b := app.ParseKubeBinding(got.KubeBinding); b == nil || b.ServiceAccountUID != gwSAUID {
		t.Errorf("stored binding %s", got.KubeBinding)
	}
	if _, err := e.svc.ClearKubernetesBinding(e.caller(td.KindUser, td.RoleViewer), g.ID); err == nil {
		t.Error("a viewer cleared a binding")
	}
	if _, err := e.svc.ClearKubernetesBinding(e.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"gateway.kubernetes_binding_set", "gateway.kubernetes_binding_cleared"} {
		if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE '%' || $1", k); n != 1 {
			t.Errorf("%s audited %d times", k, n)
		}
	}
}

// TestT337_AProjectedTokenEnrollsOnlyItsBoundGatewayOnce (HR-739): a bound
// gateway's pod token enrolls one replica once; the same jti again, a token
// TokenReview does not authenticate, a pod of another image, a token for
// another org or service account, an unbound or cleared gateway, an
// unreachable cluster, or two gateways bound alike enroll nothing.
func TestT337_AProjectedTokenEnrollsOnlyItsBoundGatewayOnce(t *testing.T) {
	e := newEnv(t)
	cl := newKubeCluster(e.org)
	e.svc.WithKubernetes(cl, clusters{"home": e.org}, []string{"home"})
	g, err := e.svc.CreateGateway(e.admin, "in-cluster")
	if err != nil {
		t.Fatal(err)
	}
	aud := []string{labels.GatewayAudience(e.org)}
	now := time.Now()
	tok := projected(t, aud, "pantherclaw", "pantherclaw-gateway", "jti-1", now)
	// Unbound: nothing to enroll.
	if _, err := e.svc.EnrollKubernetes(context.Background(), tok, csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("an unbound gateway: %v", err)
	}
	if _, err := e.svc.SetKubernetesBinding(e.admin, g.ID, binding()); err != nil {
		t.Fatal(err)
	}
	en, err := e.svc.EnrollKubernetes(context.Background(), tok, csr(t))
	if err != nil {
		t.Fatal(err)
	}
	if id := identityOf(t, en.Certificate); id.Gateway != g.ID || id.Org != e.org {
		t.Errorf("certificate for %v", id)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind LIKE '%gateway.enrolled' AND convert_from(body, 'UTF8') LIKE '%kubernetes_token%'"); n != 1 {
		t.Errorf("kubernetes enrolment audited %d times", n)
	}
	// D968a: the same jti enrolls nothing, even in another token.
	if _, err := e.svc.EnrollKubernetes(context.Background(), tok, csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Errorf("a reused token: %v", err)
	}
	if _, err := e.svc.EnrollKubernetes(context.Background(), projected(t, aud, "pantherclaw", "pantherclaw-gateway", "jti-1", now.Add(time.Second)), csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Errorf("a reused jti: %v", err)
	}

	n := 1
	fresh := func() string {
		n++
		return projected(t, aud, "pantherclaw", "pantherclaw-gateway", "jti-"+string(rune('a'+n)), now)
	}
	refuse := func(name, tok string, edit, undo func()) {
		t.Helper()
		edit()
		defer undo()
		if _, err := e.svc.EnrollKubernetes(context.Background(), tok, csr(t)); !errors.Is(err, app.ErrEnrollment) {
			t.Errorf("%s: %v", name, err)
		}
	}
	keep := *cl
	reset := func() { r, p := keep.review, keep.pod; cl.review, cl.pod, cl.fail = r, p, false }
	nop := func() {}
	refuse("not authenticated", fresh(), func() { cl.review.Authenticated = false }, reset)
	refuse("another service account UID", fresh(), func() { cl.review.UID = ids.NewV7().String() }, reset)
	refuse("a pod of another image", fresh(), func() { cl.pod.ImageIDs = []string{"ghcr.io/x@" + otherHash} }, reset)
	refuse("a pending pod", fresh(), func() { cl.pod.Phase = "Pending" }, reset)
	refuse("two containers", fresh(), func() { cl.pod.ImageIDs = append(cl.pod.ImageIDs, cl.pod.ImageIDs[0]) }, reset)
	refuse("an unreachable cluster", fresh(), func() { cl.fail = true }, reset)
	refuse("another org's audience", projected(t, []string{labels.GatewayAudience(ids.New[ids.Org]())}, "pantherclaw", "pantherclaw-gateway", "jti-x", now), nop, nop)
	refuse("two gateway audiences", projected(t, append(aud, labels.GatewayAudience(ids.New[ids.Org]())), "pantherclaw", "pantherclaw-gateway", "jti-y", now), nop, nop)
	refuse("another service account", projected(t, aud, "pantherclaw", "other", "jti-z", now), nop, nop)
	refuse("an expired token", projected(t, aud, "pantherclaw", "pantherclaw-gateway", "jti-old", now.Add(-time.Hour)), nop, nop)
	refuse("not a JWS", "pcg_not-a-token", nop, nop)

	// Two gateways bound to the same service account: ambiguous, so none.
	g2, err := e.svc.CreateGateway(e.admin, "twin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SetKubernetesBinding(e.admin, g2.ID, binding()); err != nil {
		t.Fatal(err)
	}
	refuse("two gateways bound alike", fresh(), nop, nop)
	if _, err := e.svc.ClearKubernetesBinding(e.admin, g2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.EnrollKubernetes(context.Background(), fresh(), csr(t)); err != nil {
		t.Errorf("the one bound gateway again with a fresh token: %v", err)
	}
	// Cleared: only enrollment tokens enroll it afterwards.
	if _, err := e.svc.ClearKubernetesBinding(e.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	refuse("a cleared binding", fresh(), nop, nop)
	if n := e.count(t, "SELECT count(*) FROM pc.gateway_certs WHERE gateway_id = $1", g.ID); n != 2 {
		t.Errorf("%d certificates, want the two kubernetes enrolments", n)
	}
}
