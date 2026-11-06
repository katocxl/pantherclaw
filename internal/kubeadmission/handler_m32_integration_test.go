// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package kubeadmission_test

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/kubeadmission"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/decision"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var edgeImage = "ghcr.io/katocxl/pantherclaw-edge@sha256:" + strings.Repeat("e", 64)

// dbWebhook is newWebhook's handler with a database: cluster prod, org
// with one active kubernetes entry for agents/coder when entry is set.
type dbWebhook struct {
	*webhook
	d    *dbtest.DB
	pool *db.Pool
}

func newDBWebhook(t *testing.T, pool func(*dbtest.DB) *db.Pool) *dbWebhook {
	t.Helper()
	d := dbtest.New(t)
	w := &dbWebhook{webhook: &webhook{clk: clock.NewFake(time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)), org: ids.New[ids.Org]()}, d: d, pool: d.AppPool(t)}
	dir := t.TempDir()
	w.file = filepath.Join(dir, "webhook")
	w.writeSecret(t, secret)
	clusters, err := kube.NewDirectory([]kube.ClusterConfig{{
		Name: "prod", APIServer: "https://kube.example.test", CAFile: filepath.Join(dir, "ca"), TokenFile: filepath.Join(dir, "token"),
		Orgs: []string{w.org.String()}, WebhookSecretFile: w.file,
	}})
	if err != nil {
		t.Fatal(err)
	}
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'kube')", w.org)
	p := w.pool
	if pool != nil {
		p = pool(d)
	}
	w.limits = httpx.NewLimiter(1000, time.Minute, w.clk)
	mux := http.NewServeMux()
	kubeadmission.New(kubeadmission.Config{Clusters: clusters, Pool: p, EdgeDigests: []string{"sha256:" + strings.Repeat("e", 64)}, Limiter: w.limits, Clock: w.clk}).Mount(mux)
	w.h = mux
	return w
}

// entry adds an active kubernetes entry for prod/agents/coder.
func (w *dbWebhook) entry(t *testing.T) {
	t.Helper()
	agent := ids.NewV7()
	b, err := json.Marshal(map[string]any{"kubernetes": issuers.KubernetesBinding{
		Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: "6b1a2b55-6e43-4c2a-9b9c-0b6e1c1d2e3f",
	}})
	if err != nil {
		t.Fatal(err)
	}
	w.d.AdminExec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'coder', 'DISCOVERED', 'test')`, w.org, agent)
	w.d.AdminExec(t, `INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms,
		binding, state, proposed_by, activated_by, activated_at) VALUES ($1, $2, $3, 1, $4, 'kubernetes', 'https://kubernetes.default.svc', $5,
		'{RS256}', $6, 'ACTIVE', 'test', 'test', now())`, w.org, ids.NewV7(), ids.NewV7(), agent, "pantherclaw:"+w.org.String(), b)
}

func (w *dbWebhook) count(t *testing.T, sql string) int {
	t.Helper()
	var n int
	w.d.AdminQueryRow(t, sql, []any{w.org}, &n)
	return n
}

// agentPod is the example agent pod: the edge as the native sidecar with
// the only projected token, one app container, automount off.
func agentPod(org ids.OrgID) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": "coder-1", "namespace": "agents"},
		"spec": map[string]any{
			"serviceAccountName": "coder", "automountServiceAccountToken": false,
			"initContainers": []any{map[string]any{
				"name": labels.EdgeContainer, "image": edgeImage, "restartPolicy": "Always",
				"volumeMounts": []any{map[string]any{"name": "edge-token", "mountPath": "/var/run/pantherclaw/edge"}},
			}},
			"containers": []any{map[string]any{"name": "agent", "image": "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64)}},
			"volumes": []any{map[string]any{"name": "edge-token", "projected": map[string]any{"sources": []any{map[string]any{
				"serviceAccountToken": map[string]any{"path": "token", "audience": labels.AgentAudience(org), "expirationSeconds": 3600},
			}}}}},
		},
	}
}

// wet turns a dry-run review into one the API server would act on.
func wet(b []byte) []byte {
	return bytes.Replace(b, []byte(`"dryRun":true`), []byte(`"dryRun":false`), 1)
}

const (
	deniedAudits = "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE '%kubernetes.admission_denied'"
	seenRows     = "SELECT count(*)::int FROM pc.kube_admission_seen WHERE org_id = $1"
	seenAllowed  = "SELECT count(*)::int FROM pc.kube_admission_seen WHERE org_id = $1 AND last_allowed_at IS NOT NULL"
	seenDenied   = "SELECT count(*)::int FROM pc.kube_admission_seen WHERE org_id = $1 AND last_denied_at IS NOT NULL"
	allAudits    = "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1"
)

// TestHR735_DeniesAreAuditedOnceAMinuteAndAllowsOnlySeen: a deny writes
// one audit record and the seen row per minute and code; a dry run writes
// nothing; an allow of a pod with an entry writes only the seen row.
func TestHR735_DeniesAreAuditedOnceAMinuteAndAllowsOnlySeen(t *testing.T) {
	w := newDBWebhook(t, nil)
	path := w.path("prod", w.org.String(), secret)
	pod := reviewBody(t, review.OperationCreate, "", agentPod(w.org))

	wantDenied(t, "a dry run without an entry", answer(t, "dry", w.post(path, pod)), decision.CodeNoIssuer)
	if n, s := w.count(t, allAudits), w.count(t, seenRows); n != 0 || s != 0 {
		t.Fatalf("a dry run wrote %d ledger entries and %d seen rows", n, s)
	}
	for range 3 {
		wantDenied(t, "no entry", answer(t, "deny", w.post(path, wet(pod))), decision.CodeNoIssuer)
	}
	if n, s := w.count(t, deniedAudits), w.count(t, seenDenied); n != 1 || s != 1 {
		t.Fatalf("three denies in a minute: %d audits, %d seen rows", n, s)
	}
	w.clk.Advance(kubeadmission.Throttle)
	wantDenied(t, "no entry a minute later", answer(t, "deny", w.post(path, wet(pod))), decision.CodeNoIssuer)
	if n := w.count(t, deniedAudits); n != 2 {
		t.Errorf("a deny a minute later: %d audits, want 2", n)
	}

	w.entry(t)
	before := w.count(t, allAudits)
	for range 2 {
		if res := answer(t, "allow", w.post(path, wet(pod))); !res.Allowed {
			t.Fatalf("a pod with an entry: %+v", res.Result)
		}
	}
	if n, s := w.count(t, allAudits), w.count(t, seenAllowed); n != before || s != 1 {
		t.Errorf("allows wrote %d ledger entries and %d allowed rows, want none and 1", n-before, s)
	}
}

// TestHR730_AnAllowThatCannotBeRecordedIsDenied: with the database gone,
// the entry lookup fails and the pod is denied K8S_UNAVAILABLE; a dry run
// is denied the same way.
func TestHR730_AnAllowThatCannotBeRecordedIsDenied(t *testing.T) {
	var closed *db.Pool
	w := newDBWebhook(t, func(d *dbtest.DB) *db.Pool {
		closed = d.AppPool(t)
		return closed
	})
	w.entry(t)
	path := w.path("prod", w.org.String(), secret)
	pod := reviewBody(t, review.OperationCreate, "", agentPod(w.org))
	if res := answer(t, "allow", w.post(path, wet(pod))); !res.Allowed {
		t.Fatalf("with the database up: %+v", res.Result)
	}
	closed.Close()
	wantDenied(t, "the database closed", answer(t, "closed", w.post(path, wet(pod))), decision.CodeUnavailable)
	wantDenied(t, "a dry run, the database closed", answer(t, "closed", w.post(path, pod)), decision.CodeUnavailable)
}

// TestT335_AnAgentPodWithARouteAroundTheEdgeIsNotAdmitted: with an issuer
// entry for its service account, the example pod is admitted; the same
// pod without the edge, with host network, a privileged container, a
// hostPath, the token automounted, or an ephemeral container added is
// denied with its code and audited.
func TestT335_AnAgentPodWithARouteAroundTheEdgeIsNotAdmitted(t *testing.T) {
	w := newDBWebhook(t, nil)
	w.entry(t)
	path := w.path("prod", w.org.String(), secret)
	if res := answer(t, "allow", w.post(path, wet(reviewBody(t, review.OperationCreate, "", agentPod(w.org))))); !res.Allowed {
		t.Fatalf("the example pod: %+v", res.Result)
	}
	spec := func(p map[string]any) map[string]any { return p["spec"].(map[string]any) }
	for name, c := range map[string]struct {
		edit func(p map[string]any)
		code string
	}{
		"no edge":      {func(p map[string]any) { spec(p)["initContainers"] = []any{} }, decision.CodeEdgeMissing},
		"host network": {func(p map[string]any) { spec(p)["hostNetwork"] = true }, decision.CodePodEscape},
		"host PID":     {func(p map[string]any) { spec(p)["hostPID"] = true }, decision.CodePodEscape},
		"a hostPath": {func(p map[string]any) {
			spec(p)["volumes"] = append(spec(p)["volumes"].([]any), map[string]any{"name": "h", "hostPath": map[string]any{"path": "/"}})
		}, decision.CodePodEscape},
		"token mounted": {func(p map[string]any) { spec(p)["automountServiceAccountToken"] = true }, decision.CodeTokenExposed},
		"privileged": {func(p map[string]any) {
			spec(p)["containers"].([]any)[0].(map[string]any)["securityContext"] = map[string]any{"privileged": true}
		}, decision.CodePodEscape},
	} {
		p := agentPod(w.org)
		c.edit(p)
		wantDenied(t, name, answer(t, name, w.post(path, wet(reviewBody(t, review.OperationCreate, "", p)))), c.code)
	}
	wantDenied(t, "an ephemeral container", answer(t, "ephemeral", w.post(path, wet(reviewBody(t, review.OperationUpdate, "ephemeralcontainers", agentPod(w.org))))), decision.CodeEphemeral)
	// One audit record per code within the minute.
	if n := w.count(t, deniedAudits); n != 4 {
		t.Errorf("%d denials audited, want one per code (4)", n)
	}
}
