// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package kubeadmission_test

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/kubeadmission"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/decision"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// secret is a webhook path secret of 48 characters, like the chart's.
var secret = strings.Repeat("s3cr3t", 8)

// webhook is a handler for cluster "prod", allowed for org, whose secret
// file holds secret. It has no database: the requests these tests send are
// decided, or refused, before anything is looked up or recorded.
type webhook struct {
	h      http.Handler
	clk    *clock.Fake
	file   string
	org    ids.OrgID
	limits *httpx.Limiter
}

func newWebhook(t *testing.T, perMinute int) *webhook {
	t.Helper()
	dir := t.TempDir()
	w := &webhook{clk: clock.NewFake(time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)), file: filepath.Join(dir, "webhook"), org: ids.New[ids.Org]()}
	w.writeSecret(t, secret)
	clusters, err := kube.NewDirectory([]kube.ClusterConfig{{
		Name: "prod", APIServer: "https://kube.example.test", CAFile: filepath.Join(dir, "ca"), TokenFile: filepath.Join(dir, "token"),
		Orgs: []string{w.org.String()}, WebhookSecretFile: w.file,
	}, {
		Name: "nosecret", APIServer: "https://kube2.example.test", CAFile: filepath.Join(dir, "ca"), TokenFile: filepath.Join(dir, "token"),
		Orgs: []string{w.org.String()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.limits = httpx.NewLimiter(perMinute, time.Minute, w.clk)
	mux := http.NewServeMux()
	kubeadmission.New(kubeadmission.Config{Clusters: clusters, EdgeDigests: []string{"sha256:" + strings.Repeat("e", 64)}, Limiter: w.limits, Clock: w.clk}).Mount(mux)
	w.h = mux
	return w
}

func (w *webhook) writeSecret(t *testing.T, s string) {
	t.Helper()
	if err := os.WriteFile(w.file, []byte(s+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (w *webhook) path(cluster, org, sec string) string {
	return kubeadmission.Path + cluster + "/" + org + "/" + sec
}

// post sends body to path from addr and returns the response.
func (w *webhook) post(path string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r.RemoteAddr = "10.0.0.5:51000"
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	return rec
}

// reviewBody is an AdmissionReview of op on resource/sub with object, a
// dry run unless wet is set.
func reviewBody(t *testing.T, op, sub string, object any) []byte {
	t.Helper()
	req := map[string]any{
		"uid": "705ab4f5-6393-11e8-b7cc-42010a800002", "kind": map[string]any{"group": "", "version": "v1", "kind": "Pod"},
		"resource":  map[string]any{"group": "", "version": "v1", "resource": "pods"},
		"namespace": "agents", "operation": op, "name": "coder-1", "dryRun": true,
		"userInfo": map[string]any{"username": "system:serviceaccount:kube-system:replicaset-controller"},
	}
	if sub != "" {
		req["subResource"] = sub
	}
	if object != nil {
		req["object"] = object
	}
	b, err := json.Marshal(map[string]any{"apiVersion": review.APIVersion, "kind": review.Kind, "request": req})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// answer decodes a 200 response's review.
func answer(t *testing.T, what string, rec *httptest.ResponseRecorder) review.Response {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d %q", what, rec.Code, rec.Body.String())
	}
	var rv review.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &rv); err != nil || rv.Response == nil || rv.APIVersion != review.APIVersion || rv.Kind != review.Kind {
		t.Fatalf("%s: answer %q: %v", what, rec.Body.String(), err)
	}
	return *rv.Response
}

func wantDenied(t *testing.T, what string, res review.Response, code string) {
	t.Helper()
	if res.Allowed || res.Result == nil || res.Result.Reason != code || res.Result.Code != http.StatusForbidden || res.UID == "" {
		t.Errorf("%s: %+v (%+v), want denied with %s", what, res, res.Result, code)
	}
}

// TestHR731_OnlyTheConfiguredPathIsServed: a request to the configured
// cluster, an org listed on it and the cluster's secret is decided; an
// unknown cluster, an org not listed, a malformed org, a wrong or longer
// secret, a cluster without a secret file or a secret file below 32 bytes
// answers 404 with an empty body; another method is not served.
func TestHR731_OnlyTheConfiguredPathIsServed(t *testing.T) {
	w := newWebhook(t, 1000)
	body := reviewBody(t, review.OperationUpdate, "ephemeralcontainers", map[string]any{"metadata": map[string]any{"name": "coder-1"}})
	wantDenied(t, "the configured path", answer(t, "the configured path", w.post(w.path("prod", w.org.String(), secret), body)), decision.CodeEphemeral)

	for name, path := range map[string]string{
		"an unknown cluster":     w.path("staging", w.org.String(), secret),
		"another org":            w.path("prod", ids.New[ids.Org]().String(), secret),
		"a malformed org":        w.path("prod", "acme", secret),
		"a wrong secret":         w.path("prod", w.org.String(), strings.Repeat("x", len(secret))),
		"a longer secret":        w.path("prod", w.org.String(), secret+"x"),
		"a cluster with no file": w.path("nosecret", w.org.String(), secret),
	} {
		rec := w.post(path, body)
		if rec.Code != http.StatusNotFound || rec.Body.Len() != 0 {
			t.Errorf("%s: %d %q, want 404 with an empty body", name, rec.Code, rec.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodGet, w.path("prod", w.org.String(), secret), nil)
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, r)
	if rec.Code == http.StatusOK {
		t.Errorf("GET is served: %d", rec.Code)
	}

	// A file of 31 bytes matches nothing, even its own content, once it is
	// read again.
	w.writeSecret(t, strings.Repeat("y", kubeadmission.MinSecretBytes-1))
	w.clk.Advance(kubeadmission.SecretReread)
	if rec := w.post(w.path("prod", w.org.String(), strings.Repeat("y", kubeadmission.MinSecretBytes-1)), body); rec.Code != http.StatusNotFound {
		t.Errorf("a short secret: %d, want 404", rec.Code)
	}
}

// TestHR731_TheSecretIsReadAgainEveryMinute: a rotated secret replaces the
// old one once a minute has passed, and not before.
func TestHR731_TheSecretIsReadAgainEveryMinute(t *testing.T) {
	w := newWebhook(t, 1000)
	body := reviewBody(t, review.OperationUpdate, "ephemeralcontainers", map[string]any{})
	old, rotated := w.path("prod", w.org.String(), secret), w.path("prod", w.org.String(), strings.Repeat("r", 48))
	if rec := w.post(old, body); rec.Code != http.StatusOK {
		t.Fatalf("before the rotation: %d", rec.Code)
	}
	w.writeSecret(t, strings.Repeat("r", 48))
	w.clk.Advance(kubeadmission.SecretReread - time.Second)
	if rec := w.post(old, body); rec.Code != http.StatusOK {
		t.Errorf("the old secret within the minute: %d, want 200", rec.Code)
	}
	w.clk.Advance(time.Second)
	if rec := w.post(old, body); rec.Code != http.StatusNotFound {
		t.Errorf("the old secret after the minute: %d, want 404", rec.Code)
	}
	if rec := w.post(rotated, body); rec.Code != http.StatusOK {
		t.Errorf("the rotated secret: %d, want 200", rec.Code)
	}
}

// TestHR731_RequestsAreLimitedPerAddressAndBodiesBounded: the limiter
// refuses an address past its budget before the path is even looked at,
// and a body over 1 MiB is refused.
func TestHR731_RequestsAreLimitedPerAddressAndBodiesBounded(t *testing.T) {
	w := newWebhook(t, 2)
	body := reviewBody(t, review.OperationUpdate, "ephemeralcontainers", map[string]any{})
	path := w.path("prod", w.org.String(), secret)
	for i := range 2 {
		if rec := w.post(path, body); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	if rec := w.post(path, body); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("past the limit: %d %v, want 429 with Retry-After", rec.Code, rec.Header())
	}
	if rec := w.post(w.path("staging", w.org.String(), secret), body); rec.Code != http.StatusTooManyRequests {
		t.Errorf("past the limit on another path: %d, want 429", rec.Code)
	}

	w = newWebhook(t, 1000)
	huge := reviewBody(t, review.OperationUpdate, "ephemeralcontainers", map[string]any{"pad": strings.Repeat("p", kubeadmission.MaxBody)})
	if rec := w.post(w.path("prod", w.org.String(), secret), huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a body over 1 MiB: %d, want 413", rec.Code)
	}
}

// TestHR730_WhatTheWebhookCannotDecideIsDenied: ephemeral containers are
// always denied; a pod object it cannot read, another resource or
// operation, or a namespace that is not a DNS label is denied with
// K8S_UNAVAILABLE; a body that is not a v1 AdmissionReview is not
// answered with an allow (the API server then fails closed).
func TestHR730_WhatTheWebhookCannotDecideIsDenied(t *testing.T) {
	w := newWebhook(t, 1000)
	path := w.path("prod", w.org.String(), secret)
	wantDenied(t, "an ephemeral container", answer(t, "ephemeral", w.post(path, reviewBody(t, review.OperationUpdate, "ephemeralcontainers", map[string]any{}))), decision.CodeEphemeral)

	unreadable := reviewBody(t, review.OperationCreate, "", "not a pod")
	wantDenied(t, "an unreadable pod", answer(t, "unreadable", w.post(path, unreadable)), decision.CodeUnavailable)
	wantDenied(t, "a pod CREATE without an object", answer(t, "no object", w.post(path, reviewBody(t, review.OperationCreate, "", nil))), decision.CodeUnavailable)
	wantDenied(t, "a pod DELETE", answer(t, "delete", w.post(path, reviewBody(t, "DELETE", "", map[string]any{}))), decision.CodeUnavailable)
	wantDenied(t, "a pods/exec CREATE", answer(t, "exec", w.post(path, reviewBody(t, review.OperationCreate, "exec", map[string]any{}))), decision.CodeUnavailable)

	var other map[string]any
	if err := json.Unmarshal(reviewBody(t, review.OperationCreate, "", map[string]any{}), &other); err != nil {
		t.Fatal(err)
	}
	other["request"].(map[string]any)["resource"] = map[string]any{"group": "apps", "version": "v1", "resource": "deployments"}
	b, _ := json.Marshal(other)
	wantDenied(t, "a deployment", answer(t, "deployment", w.post(path, b)), decision.CodeUnavailable)
	other["request"].(map[string]any)["resource"] = map[string]any{"group": "", "version": "v1", "resource": "pods"}
	other["request"].(map[string]any)["namespace"] = "Not_A_Label"
	b, _ = json.Marshal(other)
	wantDenied(t, "a namespace that is not a DNS label", answer(t, "namespace", w.post(path, b)), decision.CodeUnavailable)

	for name, body := range map[string]string{
		"not JSON":         "{",
		"another version":  `{"apiVersion":"admission.k8s.io/v1beta1","kind":"AdmissionReview","request":{"uid":"x"}}`,
		"no request":       `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`,
		"a request no uid": `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"operation":"CREATE"}}`,
	} {
		rec := w.post(path, []byte(body))
		if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), `"allowed":true`) {
			t.Errorf("%s: %d %q, want no allow", name, rec.Code, rec.Body.String())
		}
	}
}
