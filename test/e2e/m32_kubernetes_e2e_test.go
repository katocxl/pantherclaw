// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The images of the M32 fixture's pods.
var (
	m32EdgeDigest  = "sha256:" + strings.Repeat("e", 64)
	m32ProbeDigest = "sha256:" + strings.Repeat("d", 64)
	m32GWDigest    = "sha256:" + strings.Repeat("c", 64)
)

// kubePod is one pod of the fake cluster: the service account its
// projected token authenticates as, and its containers.
type kubePod struct {
	namespace, name, uid string
	sa, saUID            string
	app, appImage        string
	edgeImage            string // "": no edge sidecar
}

// kubeCluster is a fake Kubernetes API server for M32: TokenReview of the
// pods' projected tokens, the pods (with init container statuses) and a
// namespace's NetworkPolicies, which a test can open up.
type kubeCluster struct {
	srv  *httptest.Server
	mu   sync.Mutex
	pods map[string]kubePod // by token
	open bool               // NetworkPolicies: one allowing everything
}

// chartNetworkPolicies is the agents namespace's policy as the chart
// renders it (HR-740, D965).
const chartNetworkPolicies = `{"items":[{"metadata":{"name":"pantherclaw-agents"},"spec":{"podSelector":{},"policyTypes":["Ingress","Egress"],
"egress":[{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"pantherclaw"}},"podSelector":{"matchLabels":{"app.kubernetes.io/component":"gateway"}}}],"ports":[{"protocol":"TCP","port":8090}]},
{"to":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"pantherclaw"}},"podSelector":{"matchLabels":{"app.kubernetes.io/component":"api"}}}],"ports":[{"protocol":"TCP","port":8080}]}]}}]}`

const openNetworkPolicies = `{"items":[{"metadata":{"name":"allow-all"},"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}}]}`

func newKubeCluster(t *testing.T) *kubeCluster {
	t.Helper()
	k := &kubeCluster{pods: map[string]kubePod{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.UnmarshalRead(r.Body, &req)
		k.mu.Lock()
		p, ok := k.pods[req.Spec.Token]
		k.mu.Unlock()
		if !ok {
			_, _ = w.Write([]byte(`{"status":{"authenticated":false}}`))
			return
		}
		out, _ := json.Marshal(map[string]any{"status": map[string]any{
			"authenticated": true, "audiences": req.Spec.Audiences,
			"user": map[string]any{
				"username": "system:serviceaccount:" + p.namespace + ":" + p.sa, "uid": p.saUID,
				"extra": map[string]any{"authentication.kubernetes.io/pod-name": []string{p.name}, "authentication.kubernetes.io/pod-uid": []string{p.uid}},
			},
		}})
		_, _ = w.Write(out)
	})
	mux.HandleFunc("GET /api/v1/namespaces/{ns}/pods/{name}", func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		var found *kubePod
		for _, p := range k.pods {
			if p.namespace == r.PathValue("ns") && p.name == r.PathValue("name") {
				found = &p
			}
		}
		k.mu.Unlock()
		if found == nil {
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		p := *found
		spec := map[string]any{"containers": []any{map[string]any{"name": p.app}}}
		status := map[string]any{"phase": "Running", "containerStatuses": []any{map[string]any{"name": p.app, "imageID": p.appImage}}}
		if p.edgeImage != "" {
			spec["initContainers"] = []any{map[string]any{"name": labels.EdgeContainer, "restartPolicy": "Always"}}
			status["initContainerStatuses"] = []any{map[string]any{"name": labels.EdgeContainer, "imageID": p.edgeImage}}
		}
		out, _ := json.Marshal(map[string]any{"metadata": map[string]any{"namespace": p.namespace, "name": p.name, "uid": p.uid}, "spec": spec, "status": status})
		_, _ = w.Write(out)
	})
	mux.HandleFunc("GET /apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies", func(w http.ResponseWriter, _ *http.Request) {
		k.mu.Lock()
		open := k.open
		k.mu.Unlock()
		if open {
			_, _ = w.Write([]byte(openNetworkPolicies))
			return
		}
		_, _ = w.Write([]byte(chartNetworkPolicies))
	})
	k.srv = httptest.NewTLSServer(mux)
	t.Cleanup(k.srv.Close)
	return k
}

// token mints a projected token for p with audience aud and registers it.
func (k *kubeCluster) token(p kubePod, aud string) string {
	now := time.Now()
	enc := base64.RawURLEncoding.EncodeToString
	claims, _ := json.Marshal(map[string]any{
		"aud": []string{aud}, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(50 * time.Minute).Unix(), "jti": ids.NewV7().String(),
		"kubernetes.io": map[string]any{"namespace": p.namespace, "serviceaccount": map[string]any{"name": p.sa, "uid": p.saUID}},
	})
	tok := enc([]byte(`{"alg":"RS256"}`)) + "." + enc(claims) + "." + enc([]byte("sig"))
	k.mu.Lock()
	k.pods[tok] = p
	k.mu.Unlock()
	return tok
}

func (k *kubeCluster) setOpen(open bool) {
	k.mu.Lock()
	k.open = open
	k.mu.Unlock()
}

// kubeFixture is a stack serving cluster "home" for its org: the
// admission listener, two kubernetes issuer entries (the probe pod in
// namespace agents, with a run grant, and the control pod in pantherclaw)
// and the seeded gateway bound to the gateway pod's service account.
type kubeFixture struct {
	s         *stack
	cluster   *kubeCluster
	clusters  *kube.Directory
	dir       string
	secret    string
	admission string // https://host:port
	adminCA   *x509.CertPool
	agentPod  kubePod
	ctlPod    kubePod
	gwPod     kubePod
	podAgent  ids.UUID
	grant     ids.UUID
	gatewayID ids.UUID
}

// selfSigned writes a certificate pair for 127.0.0.1 to dir.
func selfSigned(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pantherclaw-admission"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	cp := x509.NewCertPool()
	cp.AddCert(cert)
	return writeFile(t, dir, "admission.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		writeFile(t, dir, "admission.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})), cp
}

// restartWithSections is restartWith for several sections at once.
func (s *stack) restartWithSections(t *testing.T, sections map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(s.serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for k, v := range sections {
		// A section the stack already has (identity, with people) keeps
		// its other settings.
		old, isMap := cfg[k].(map[string]any)
		add, addMap := v.(map[string]any)
		if isMap && addMap {
			for kk, vv := range add {
				old[kk] = vv
			}
			continue
		}
		cfg[k] = v
	}
	if raw, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	s.stop()
	<-s.done
	if err := os.WriteFile(s.serverCfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s.serve(t)
}

func startKube(t *testing.T) *kubeFixture {
	t.Helper()
	return setupKube(t, start(t, options{budget: "1000"}))
}

// setupKube turns stack s into the M32 fixture.
func setupKube(t *testing.T, s *stack) *kubeFixture {
	t.Helper()
	f := &kubeFixture{s: s, cluster: newKubeCluster(t), dir: t.TempDir(), secret: strings.Repeat("w3bh00k", 7)}
	f.agentPod = kubePod{
		namespace: "agents", name: "probe-1", uid: ids.NewV7().String(), sa: "pantherclaw-probe", saUID: ids.NewV7().String(),
		app: "probe", appImage: "ghcr.io/katocxl/pantherclaw-probe@" + m32ProbeDigest, edgeImage: "ghcr.io/katocxl/pantherclaw-edge@" + m32EdgeDigest,
	}
	f.ctlPod = f.agentPod
	f.ctlPod.namespace, f.ctlPod.name, f.ctlPod.uid, f.ctlPod.saUID = "pantherclaw", "probe-control-1", ids.NewV7().String(), ids.NewV7().String()
	f.gwPod = kubePod{
		namespace: "pantherclaw", name: "gw-0", uid: ids.NewV7().String(), sa: "pantherclaw-gateway", saUID: ids.NewV7().String(),
		app: "gateway", appImage: "ghcr.io/katocxl/pantherclaw-gateway@" + m32GWDigest,
	}

	cluster := map[string]any{
		"name": "home", "api_server": f.cluster.srv.URL, "ca_file": pemFile(t, f.dir, "cluster-ca.pem", f.cluster.srv.Certificate()),
		"token_file": writeFile(t, f.dir, "reviewer", []byte("reviewer-token")), "allowed_prefixes": []string{"127.0.0.0/8"},
		"orgs": []string{s.org.String()}, "webhook_secret_file": writeFile(t, f.dir, "webhook", []byte(f.secret)),
	}
	var err error
	f.clusters, err = kube.NewDirectory([]kube.ClusterConfig{{
		Name: "home", APIServer: f.cluster.srv.URL, CAFile: cluster["ca_file"].(string), TokenFile: cluster["token_file"].(string),
		AllowedPrefixes: []string{"127.0.0.0/8"}, Orgs: []string{s.org.String()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	cert, key, cp := selfSigned(t, f.dir)
	f.adminCA = cp
	addr := freeAddr(t)
	f.admission = "https://" + addr
	s.restartWithSections(t, map[string]any{
		"identity": map[string]any{"kubernetes_clusters": []any{cluster}},
		"admission": map[string]any{
			"listen": addr, "tls_cert_file": cert, "tls_key_file": key,
			"edge_image_digests": []string{m32EdgeDigest}, "probe_image_digests": []string{m32ProbeDigest},
		},
	})
	f.entries(t)
	return f
}

// entries creates the two kubernetes agents and issuer entries, the probe
// pod's with a run grant, and binds the seeded gateway.
func (f *kubeFixture) entries(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	org := f.s.org
	team, env, owner := ids.NewV7(), ids.NewV7(), ids.NewV7()
	if err := f.s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'kube', 'Kube')", []any{org, team}},
			{"INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'kube', 'Kube', 'DEVELOPMENT')", []any{org, env, team}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'kube-owner')", []any{org, owner}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	person := func(role td.RoleName, scope td.Scope) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: owner}, Bindings: []td.Binding{{Role: role, Scope: scope}},
		}})
	}
	inv := aapp.NewInventory(f.s.pool, unlimited{})
	newAgent := func(name string) ids.UUID {
		a, err := inv.Create(person(td.RoleAgentOwner, td.Scope{Type: td.ScopeTeam, ID: team}), adomain.Details{
			Name: name, TeamID: team, EnvironmentID: env, OwnerUserID: owner, Context: adomain.ContextKubernetes,
		})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	f.podAgent = newAgent("kube-probe")
	ctlAgent := newAgent("kube-control")

	// The run grant: a root grant for the probe agent, as the owner.
	f.grant = ids.NewV7()
	f.s.db.AdminExec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth,
		current_revision, grantor_kind, grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'e2e')`, org, f.grant, f.podAgent, owner, env)
	f.s.db.AdminExec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by)
		VALUES ($1, $2, $3, 1, now() - interval '1 hour', now() + interval '2 hours', convert_to('{"operations":["payments.refund.create"]}', 'UTF8'),
		convert_to('[]', 'UTF8'), convert_to('{}', 'UTF8'), 0, 0, 0, false, 'e2e')`, org, ids.NewV7(), f.grant)
	f.s.db.AdminExec(t, "INSERT INTO pc.grant_lineage (org_id, grant_id, ancestor_id, distance) VALUES ($1, $2, $2, 0)", org, f.grant)

	svc := iapp.New(f.s.pool, keys.NewRegistry(), f.s.apiURL, clock.System{})
	orgScope := td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	activate := func(agent ids.UUID, p kubePod, grant *ids.UUID) {
		r, err := svc.ProposeIssuer(person(td.RoleOrgAdmin, orgScope), iapp.ProposeInput{
			AgentID: agent, AutoAdmit: true, Reason: "e2e", RunGrantID: grant,
			Binding: iapp.Binding{Kubernetes: &issuers.KubernetesBinding{Cluster: "home", Namespace: p.namespace, ServiceAccountName: p.sa, ServiceAccountUID: p.saUID}},
		}, f.clusters)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ActivateIssuer(person(td.RoleIdentityPublisher, orgScope), r.EntryID, r.Revision, false); err != nil {
			t.Fatal(err)
		}
	}
	activate(f.podAgent, f.agentPod, &f.grant)
	activate(ctlAgent, f.ctlPod, nil)

	// The seeded gateway, bound to the gateway pod's service account.
	f.s.db.AdminQueryRow(t, "SELECT id FROM pc.gateways WHERE org_id = $1 ORDER BY created_at LIMIT 1", []any{org}, &f.gatewayID)
	kc, err := kube.NewClient(f.clusters, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	gws := gwapp.New(f.s.pool, nil, "", nil).WithKubernetes(kc, f.clusters, []string{"home"})
	if _, err := gws.SetKubernetesBinding(person(td.RoleGatewayAdmin, orgScope), f.gatewayID, gwapp.KubeBinding{
		Cluster: "home", Namespace: f.gwPod.namespace, ServiceAccountName: f.gwPod.sa, ServiceAccountUID: f.gwPod.saUID,
		ImageDigests: []string{m32GWDigest},
	}); err != nil {
		t.Fatal(err)
	}
}

// admit posts an AdmissionReview for pod to the webhook and returns the
// answer's allowed flag and reason.
func (f *kubeFixture) admit(t *testing.T, secret string, pod map[string]any) (int, bool, string) {
	t.Helper()
	return f.review(t, secret, "CREATE", "", pod)
}

// review posts an AdmissionReview of op on pods/sub.
func (f *kubeFixture) review(t *testing.T, secret, op, sub string, pod map[string]any) (int, bool, string) {
	t.Helper()
	req := map[string]any{
		"uid": ids.NewV7().String(), "kind": map[string]any{"group": "", "version": "v1", "kind": "Pod"},
		"resource": map[string]any{"group": "", "version": "v1", "resource": "pods"}, "namespace": "agents", "operation": op,
		"name": "probe-1", "object": pod, "userInfo": map[string]any{"username": "system:serviceaccount:kube-system:replicaset-controller"},
	}
	if sub != "" {
		req["subResource"] = sub
	}
	body, err := json.Marshal(map[string]any{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": req})
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: f.adminCA, MinVersion: tls.VersionTLS12}}}
	res, err := hc.Post(f.admission+"/admission/v1/home/"+f.s.org.String()+"/"+secret, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Response struct {
			Allowed bool `json:"allowed"`
			Status  struct {
				Reason string `json:"reason"`
			} `json:"status"`
		} `json:"response"`
	}
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("admission answer %q: %v", b, err)
		}
	}
	return res.StatusCode, out.Response.Allowed, out.Response.Status.Reason
}

// probePod is the agent pod spec the admission webhook sees for the probe
// pod: the edge native sidecar with the only projected token.
func (f *kubeFixture) probePod(edgeImage string) map[string]any {
	inits := []any{}
	if edgeImage != "" {
		inits = append(inits, map[string]any{
			"name": labels.EdgeContainer, "image": edgeImage, "restartPolicy": "Always",
			"volumeMounts": []any{map[string]any{"name": "edge-token", "mountPath": "/var/run/pantherclaw/edge"}},
		})
	}
	return map[string]any{
		"metadata": map[string]any{"name": "probe-1", "namespace": "agents"},
		"spec": map[string]any{
			"serviceAccountName": f.agentPod.sa, "automountServiceAccountToken": false, "initContainers": inits,
			"containers": []any{map[string]any{"name": "probe", "image": f.agentPod.appImage}},
			"volumes": []any{map[string]any{"name": "edge-token", "projected": map[string]any{"sources": []any{map[string]any{
				"serviceAccountToken": map[string]any{"path": "token", "audience": labels.AgentAudience(f.s.org), "expirationSeconds": 3600},
			}}}}},
		},
	}
}

// runEdge runs the edge in kubernetes mode as pod p until the returned
// stop is called; it returns the edge's loopback address.
func (f *kubeFixture) runEdge(t *testing.T, p kubePod) (string, string, func()) {
	t.Helper()
	t.Setenv(edge.PodNameEnv, p.name)
	t.Setenv(edge.NamespaceEnv, p.namespace)
	dir := t.TempDir()
	c := edge.Config{
		Format: edge.ConfigFormat, Mode: edge.ModeKubernetes, Listen: freeAddr(t), GatewayURL: f.s.gateway,
		Hosts: map[string]string{"payments.example": "payments"}, APIURL: f.s.apiURL, CADir: dir,
		KubeTokenFile: writeFile(t, dir, "token", []byte(f.cluster.token(p, labels.AgentAudience(f.s.org)))),
	}
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var logs bytes.Buffer
	var logMu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(b []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logs.Write(b)
	}), nil))
	t.Cleanup(func() {
		if t.Failed() {
			logMu.Lock()
			defer logMu.Unlock()
			t.Logf("edge %s/%s log:\n%s", p.namespace, p.name, logs.String())
		}
	})
	go func() { done <- edge.Run(ctx, c, pw, log); _ = pw.Close() }()
	line, err := bufio.NewReader(pr).ReadString('\n')
	if err != nil {
		cancel()
		logMu.Lock()
		defer logMu.Unlock()
		t.Fatalf("edge %s did not start: %v %v\n%s", p.name, err, <-done, logs.String())
	}
	go func() { _, _ = io.Copy(io.Discard, pr) }()
	var ready edge.Ready
	if err := json.Unmarshal([]byte(line), &ready); err != nil || ready.Event != edge.ReadyEvent {
		t.Fatalf("edge ready line %q: %v", line, err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return ready.Listen, dir, stop
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

// kubeReport is a probe report as the probe posts it to its edge.
func kubeReport(kind string, results []report.Result) []byte {
	now := time.Now().UTC()
	b, _ := json.Marshal(report.Report{
		Format: report.Format, Session: "set-by-the-edge", Nonce: "set-by-the-edge-0000", Kind: kind, StartedAt: now.Add(-time.Second), FinishedAt: now,
		Engine: report.Engine{Version: "kubernetes", APIVersion: "1.0", Runtime: report.RuntimeKubernetes}, Results: results,
	})
	return b
}

// m32Blocked are the kubernetes profile's probes; m32Twins those with a
// positive twin in the control run.
var (
	m32Blocked = []string{
		covdomain.ProbeKubeAPI, covdomain.ProbeKubelet, covdomain.ProbeNodeIP, covdomain.ProbeMetadata, covdomain.ProbeDNSCluster,
		covdomain.ProbeDNSExternal, covdomain.ProbeDirectHTTPS, covdomain.ProbeServiceOther, covdomain.ProbeIPv6,
	}
	m32Twins = []string{
		covdomain.ProbeKubeAPI, covdomain.ProbeKubelet, covdomain.ProbeNodeIP, covdomain.ProbeDNSCluster, covdomain.ProbeDNSExternal,
		covdomain.ProbeDirectHTTPS, covdomain.ProbeServiceOther,
	}
)

func sandboxResults(observed string) []report.Result {
	var rs []report.Result
	for _, n := range m32Blocked {
		rs = append(rs, report.Result{Name: n, Role: report.RoleProbe, Expect: report.Blocked, Observed: observed})
	}
	return append(rs,
		report.Result{Name: covdomain.ProbeEdgeMediated, Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable, Detail: "https://payments.example through the edge"},
		report.Result{Name: covdomain.ProbeEdgeUnmappedRefused, Role: report.RoleNegative, Expect: report.Blocked, Observed: report.Blocked},
	)
}

func controlResults() []report.Result {
	var rs []report.Result
	for _, n := range m32Twins {
		rs = append(rs, report.Result{Name: n, Role: report.RolePositive, Expect: report.Reachable, Observed: report.Reachable})
	}
	return rs
}

type reportAnswer struct {
	KubeClosureID string   `json:"kube_closure_id"`
	Kind          string   `json:"kind"`
	Passed        bool     `json:"passed"`
	Failed        []string `json:"failed"`
	Error         string   `json:"error"`
}

// postReport posts a probe report to the edge at addr.
func postReport(t *testing.T, addr string, body []byte) (int, reportAnswer) {
	t.Helper()
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
	res, err := hc.Post("http://"+addr+edge.ReportPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var a reportAnswer
	b, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("report answer %q: %v", b, err)
	}
	return res.StatusCode, a
}

func (f *kubeFixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	f.s.db.AdminQueryRow(t, sql, append([]any{f.s.org}, args...), &n)
	return n
}

// waitCount waits until sql counts want.
func (f *kubeFixture) waitCount(t *testing.T, want int, sql string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		n := f.count(t, sql, args...)
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d, want %d", sql, n, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// enrollGateway enrolls a gateway replica with the gateway pod's projected
// token at the server's API.
func (f *kubeFixture) enrollGateway(t *testing.T, tok string) error {
	t.Helper()
	ef, err := gateway.ReadEnrollFile(f.s.gatewayEnroll)
	if err != nil {
		t.Fatal(err)
	}
	_, err = control.EnrollKubernetes(context.Background(), &http.Client{Timeout: 10 * time.Second}, f.s.apiURL, pclog.NewSecret(tok), ef.CASHA256)
	return err
}

// TestE2E_M32_KubernetesEnforcement (T-335..T-339): the admission webhook
// admits the probe pod and denies one without the edge; the gateway enrolls
// a replica from its pod's projected token once; the edge in kubernetes
// mode enrolls with the probe pod's token, starts the pod's run under the
// issuer entry's run grant, and its signed reports record a passing
// control and a passing kube closure, a closure for the connection its
// hosts map; with the NetworkPolicy opened the next closure fails.
func TestE2E_M32_KubernetesEnforcement(t *testing.T) {
	f := startKube(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("server log:\n%s", f.s.logs.String())
		}
	})

	// Admission (T-335, HR-730..735).
	if code, _, _ := f.admit(t, strings.Repeat("x", len(f.secret)), f.probePod(f.agentPod.edgeImage)); code != http.StatusNotFound {
		t.Errorf("a wrong webhook secret: %d, want 404", code)
	}
	if code, ok, reason := f.admit(t, f.secret, f.probePod(f.agentPod.edgeImage)); code != http.StatusOK || !ok {
		t.Fatalf("the probe pod: %d allowed=%v %s", code, ok, reason)
	}
	if code, ok, reason := f.admit(t, f.secret, f.probePod("")); code != http.StatusOK || ok || reason != "K8S_EDGE_MISSING" {
		t.Errorf("a pod without the edge: %d allowed=%v %s", code, ok, reason)
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE '%kubernetes.admission_denied'"); n != 1 {
		t.Errorf("%d admission denials audited, want 1", n)
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.kube_admission_seen WHERE org_id = $1 AND namespace = 'agents' AND last_allowed_at IS NOT NULL AND last_denied_at IS NOT NULL"); n != 1 {
		t.Errorf("the seen row: %d", n)
	}

	// Gateway enrolment from a projected token (T-337, HR-739, D968a).
	gwTok := f.cluster.token(f.gwPod, labels.GatewayAudience(f.s.org))
	if err := f.enrollGateway(t, gwTok); err != nil {
		t.Fatalf("gateway enrolment from the projected token: %v", err)
	}
	if err := f.enrollGateway(t, gwTok); err == nil {
		t.Error("the same projected token enrolled a second replica")
	}
	if err := f.enrollGateway(t, f.cluster.token(f.gwPod, labels.AgentAudience(f.s.org))); err == nil {
		t.Error("a token for the agent audience enrolled a gateway")
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.gateway_certs WHERE org_id = $1 AND gateway_id = $2", f.gatewayID); n != 2 {
		t.Errorf("%d gateway certificates, want the seeded one and the kubernetes one", n)
	}

	// The control twin in the release namespace (T-339, D970c): its pod's
	// entry has no run grant, so the edge starts no run there (HR-744).
	ctl, _, stopCtl := f.runEdge(t, f.ctlPod)
	if code, a := postReport(t, ctl, kubeReport(report.KindControl, controlResults())); code != http.StatusOK || !a.Passed || a.Kind != report.KindControl {
		t.Fatalf("the control report: %d %+v", code, a)
	}
	stopCtl()

	// The probe pod: its run, launched by its instance under the grant.
	f.s.db.AdminExec(t, "UPDATE pc.connections SET agent_hosts = '{payments.example}' WHERE org_id = $1 AND id = $2", f.s.org, f.s.conn)
	probe, _, _ := f.runEdge(t, f.agentPod)
	f.waitCount(t, 1, `SELECT count(*)::int FROM pc.runs r JOIN pc.agent_instances i ON i.org_id = r.org_id AND i.id = r.instance_id
		WHERE r.org_id = $1 AND r.agent_id = $2 AND r.grant_id = $3 AND r.task_ref = 'probe-1' AND r.launcher_instance_id = r.instance_id
		AND r.launcher_issuer_id = i.issuer_revision_id`, f.podAgent, f.grant)
	if n := f.count(t, "SELECT count(*)::int FROM pc.runs WHERE org_id = $1 AND launcher_issuer_id IS NOT NULL"); n != 1 {
		t.Errorf("%d pod runs, want only the probe pod's (the control entry has no run grant)", n)
	}

	// T-338: the probe pod's signed report closes every kind.
	code, a := postReport(t, probe, kubeReport(report.KindSandbox, sandboxResults(report.Blocked)))
	if code != http.StatusOK || !a.Passed || a.Kind != report.KindSandbox || len(a.Failed) != 0 {
		t.Fatalf("the kube closure: %d %+v", code, a)
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.coverage_closures WHERE org_id = $1 AND kube_closure_id = $2", mustUUID(t, a.KubeClosureID)); n != 1 {
		t.Errorf("%d coverage closures for the mapped connection, want 1", n)
	}
	if n := f.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind LIKE '%kubernetes.closure_recorded'"); n != 2 {
		t.Errorf("%d kube closures audited, want the control's and the probe's", n)
	}

	// T-339: the namespace opened to everything: the server's own check
	// fails, whatever the probes saw.
	f.cluster.setOpen(true)
	code, a = postReport(t, probe, kubeReport(report.KindSandbox, sandboxResults(report.Blocked)))
	if code != http.StatusOK || a.Passed {
		t.Errorf("a closure with an open NetworkPolicy: %d %+v", code, a)
	}
	f.cluster.setOpen(false)
	// A probe that got through fails the closure too.
	code, a = postReport(t, probe, kubeReport(report.KindSandbox, sandboxResults(report.Reachable)))
	if code != http.StatusOK || a.Passed {
		t.Errorf("a closure with reachable probes: %d %+v", code, a)
	}

	// HR-741: an instance not enrolled by kubernetes attestation (the seeded
	// workload) gets no closure nonce.
	kc := pantherclawv1connect.NewKubernetesServiceClient(connect.NewClient(connecthttp.NewTransport(
		&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: f.s.key, Token: func() string { return f.s.token }}}, f.s.apiURL)))
	_, err := kc.IssueClosureNonce(context.Background(), &pantherclawv1.IssueClosureNonceRequest{Namespace: "agents"})
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "K8S_NOT_KUBERNETES_INSTANCE") {
		t.Errorf("a non-kubernetes instance's nonce: %v", err)
	}
	if _, err := kc.StartPodRun(context.Background(), &pantherclawv1.StartPodRunRequest{PodName: "probe-1"}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("a non-kubernetes instance's pod run: %v", err)
	}
}
