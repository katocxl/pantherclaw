// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kube_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeAPIServer answers TokenReview and one pod.
func fakeAPIServer(t *testing.T) (*httptest.Server, *string) {
	t.Helper()
	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = r.Header.Get("Authorization") + " " + string(body)
		_, _ = w.Write([]byte(`{"status":{"authenticated":true,"audiences":["pantherclaw:org"],"user":{
			"username":"system:serviceaccount:agents:coder","uid":"sa-uid",
			"extra":{"authentication.kubernetes.io/pod-name":["coder-1"],"authentication.kubernetes.io/pod-uid":["pod-uid"]}}}}`))
	})
	mux.HandleFunc("GET /api/v1/namespaces/agents/pods/coder-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"namespace":"agents","name":"coder-1","uid":"pod-uid"},
			"status":{"phase":"Running","containerStatuses":[{"imageID":"ghcr.io/acme/agent@sha256:` + strings.Repeat("a", 64) + `"}]}}`))
	})
	mux.HandleFunc("GET /api/v1/namespaces/agents/pods/edged-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"metadata":{"namespace":"agents","name":"edged-1","uid":"pod-uid"},
			"spec":{"initContainers":[{"name":"setup"},{"name":"pantherclaw-edge","restartPolicy":"Always"}]},
			"status":{"phase":"Running","hostIP":"10.0.0.5","containerStatuses":[{"name":"agent","imageID":"ghcr.io/acme/agent@sha256:` + strings.Repeat("a", 64) + `"}],
			"initContainerStatuses":[{"name":"setup","imageID":"busybox@sha256:` + strings.Repeat("b", 64) + `"},
			{"name":"pantherclaw-edge","imageID":"ghcr.io/katocxl/pantherclaw-edge@sha256:` + strings.Repeat("e", 64) + `"}]}}`))
	})
	mux.HandleFunc("GET /api/v1/namespaces/agents/pods/huge", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"x":"` + strings.Repeat("a", kube.MaxResponse) + `"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv, &seen
}

func clusterFor(t *testing.T, srv *httptest.Server, prefixes []string) kube.ClusterConfig {
	t.Helper()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("pantherclaw-reviewer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	return kube.ClusterConfig{
		Name: "prod", APIServer: srv.URL, CAFile: ca, TokenFile: tok, AllowedPrefixes: prefixes,
		Orgs: []string{ids.New[ids.Org]().String()},
	}
}

// TestHR144_TokenReviewAndPodComeFromTheCluster: the client asks the API
// server, with its own credential and the org audience, and reads the pod's
// image digest from the pod status.
func TestHR144_TokenReviewAndPodComeFromTheCluster(t *testing.T) {
	srv, seen := fakeAPIServer(t)
	dir, err := kube.NewDirectory([]kube.ClusterConfig{clusterFor(t, srv, []string{"127.0.0.0/8"})})
	if err != nil {
		t.Fatal(err)
	}
	c, err := kube.NewClient(dir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r, err := c.Review(ctx, "prod", "projected-token", "pantherclaw:org")
	if err != nil || !r.Authenticated || r.UID != "sa-uid" || r.PodName != "coder-1" || r.PodUID != "pod-uid" {
		t.Fatalf("review: %+v, %v", r, err)
	}
	if !strings.HasPrefix(*seen, "Bearer pantherclaw-reviewer-token ") || !strings.Contains(*seen, `"audiences":["pantherclaw:org"]`) {
		t.Fatalf("request: %s", *seen)
	}
	p, err := c.Pod(ctx, "prod", "agents", "coder-1")
	if err != nil || p.UID != "pod-uid" || len(p.ImageIDs) != 1 || p.Edge != nil {
		t.Fatalf("pod: %+v, %v", p, err)
	}
	// The edge sidecar's running image, from initContainerStatuses (D1218
	// H1), and the node IP (D1218 M2).
	p, err = c.Pod(ctx, "prod", "agents", "edged-1")
	if err != nil || p.Edge == nil || p.Edge.ImageID != "ghcr.io/katocxl/pantherclaw-edge@sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("a pod with the edge: %+v, %v", p, err)
	}
	if pi, err := c.PodImages(ctx, "prod", "agents", "edged-1"); err != nil || pi.HostIP != "10.0.0.5" {
		t.Fatalf("pod images: %+v, %v", pi, err)
	}
	if p, err := c.Pod(ctx, "prod", "agents", "gone"); err != nil || p.UID != "" {
		t.Fatalf("a deleted pod must read as empty: %+v, %v", p, err)
	}
	if _, err := c.Pod(ctx, "prod", "agents", "huge"); err == nil {
		t.Error("accepted an oversized response")
	}
	if _, err := c.Review(ctx, "staging", "t", "a"); err == nil {
		t.Error("asked an unconfigured cluster")
	}
}

// TestHR144_ReviewerTokenRotationNeedsNoRestart: a reviewer token replaced
// in token_file is used within a minute, without a restart (THREAT_MODEL
// R-15). A file that cannot be read keeps the last token in use until a read
// succeeds, and a wall clock that steps back reads the file again.
func TestHR144_ReviewerTokenRotationNeedsNoRestart(t *testing.T) {
	srv, seen := fakeAPIServer(t)
	cfg := clusterFor(t, srv, []string{"127.0.0.0/8"})
	dir, err := kube.NewDirectory([]kube.ClusterConfig{cfg})
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC))
	c, err := kube.NewClientWithClock(dir, 5*time.Second, clk)
	if err != nil {
		t.Fatal(err)
	}
	bearer := func() string {
		t.Helper()
		if _, err := c.Review(context.Background(), "prod", "projected-token", "pantherclaw:org"); err != nil {
			t.Fatal(err)
		}
		tok, _, _ := strings.Cut(strings.TrimPrefix(*seen, "Bearer "), " ")
		return tok
	}
	rotate := func(tok string) {
		t.Helper()
		if err := os.WriteFile(cfg.TokenFile, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	rotate("rotated-1")
	clk.Advance(kube.TokenRefresh - time.Second)
	if got := bearer(); got != "pantherclaw-reviewer-token" {
		t.Fatalf("read the file again before %v: %q", kube.TokenRefresh, got)
	}
	clk.Advance(time.Second)
	if got := bearer(); got != "rotated-1" {
		t.Fatalf("a rotated token was not picked up: %q", got)
	}

	rotate("") // half-written, as while an operator replaces the file
	clk.Advance(kube.TokenRefresh)
	if got := bearer(); got != "rotated-1" {
		t.Fatalf("an unreadable file must keep the last token: %q", got)
	}
	rotate("rotated-2")
	if got := bearer(); got != "rotated-2" {
		t.Fatalf("a failed read must be retried on the next call: %q", got)
	}

	rotate("rotated-3")
	clk.Set(clk.Now().Add(-time.Hour))
	if got := bearer(); got != "rotated-3" {
		t.Fatalf("a clock that stepped back pinned the old token: %q", got)
	}
}

// TestHR142_ClusterCallsStayInsideTheirGuards: a cluster's API server on a
// private address needs that range configured, and its CA is pinned.
func TestHR142_ClusterCallsStayInsideTheirGuards(t *testing.T) {
	srv, _ := fakeAPIServer(t)
	ctx := context.Background()
	dir, _ := kube.NewDirectory([]kube.ClusterConfig{clusterFor(t, srv, nil)})
	c, err := kube.NewClient(dir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Review(ctx, "prod", "t", "a"); err == nil {
		t.Error("reached a loopback API server without an allowed range")
	}
	cfg := clusterFor(t, srv, []string{"127.0.0.0/8"})
	if err := os.WriteFile(cfg.CAFile, otherCA(t), 0o600); err != nil {
		t.Fatal(err)
	}
	dir, _ = kube.NewDirectory([]kube.ClusterConfig{cfg})
	c, err = kube.NewClient(dir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Review(ctx, "prod", "t", "a"); err == nil {
		t.Error("trusted an API server certificate from another CA")
	}
}

// otherCA returns a self-signed CA certificate the test server does not
// chain to.
func otherCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other-ca"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
