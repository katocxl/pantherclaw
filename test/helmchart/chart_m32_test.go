// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package helmchart

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/decision"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const (
	m32Org      = "0196f1d2-c3b4-7a5e-8f60-8a7b9c0d1e2f"
	edgeDigest  = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	probeDigest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// m32Values turns on Kubernetes enforcement for one agent namespace (G0
// M32 D969): the cluster, the in-cluster gateway, the admission listener,
// the fixed Service addresses and the canary.
const m32Values = `
api:
  tls: {existingSecret: pantherclaw-api-tls}
  service: {clusterIP: 10.96.200.11}
identity:
  kubernetesClusters:
    - name: home
      orgs: [` + m32Org + `]
      allowedPrefixes: [10.96.0.0/12]
gateway:
  enabled: true
  org: ` + m32Org + `
  image: {digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
  service: {clusterIP: 10.96.200.10}
  tls: {existingSecret: pantherclaw-gateway-tls}
  caSHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
admission:
  enabled: true
  cluster: home
  tls: {existingSecret: pantherclaw-admission-tls, caBundle: Y2E=}
  edgeImageDigests: ["` + edgeDigest + `"]
  probeImageDigests: ["` + probeDigest + `"]
probe:
  canary:
    clusterIP: 10.96.200.12
    image: {repository: ghcr.io/acme/canary, digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
agentNamespaces:
  - name: agents
    org: ` + m32Org + `
    hosts: {api.github.com: github}
`

// renderWith runs helm template with a values file and --set values; it
// returns helm's error output when the chart refuses to render.
func renderWith(t *testing.T, values string, set ...string) ([]map[string]any, error) {
	t.Helper()
	chart, err := filepath.Abs(filepath.Join(root, "deploy", "helm", "pantherclaw"))
	if err != nil {
		t.Fatal(err)
	}
	vf := filepath.Join(t.TempDir(), "values.yaml")
	if err := os.WriteFile(vf, []byte(values), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"template", "pc", chart, "--namespace", "pantherclaw", "-f", vf}
	for _, s := range set {
		args = append(args, "--set", s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, helm(t), args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, errors.New(errb.String())
	}
	var docs []map[string]any
	dec := yaml.NewDecoder(&out)
	for {
		var d map[string]any
		err := dec.Decode(&d)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if d != nil {
			docs = append(docs, d)
		}
	}
	return docs, nil
}

func mustRender(t *testing.T, values string, set ...string) []map[string]any {
	t.Helper()
	docs, err := renderWith(t, values, set...)
	if err != nil {
		t.Fatalf("helm template: %v", err)
	}
	return docs
}

func ofKind(docs []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, d := range docs {
		if d["kind"] == kind {
			out = append(out, d)
		}
	}
	return out
}

// TestHR730_EveryWebhookTheChartRendersFailsClosed: each org's
// ValidatingWebhookConfiguration fails closed, has no side effects, waits
// 5 seconds, decides pod CREATE and ephemeral containers in the org's
// enforced namespaces, and calls the API's admission port at a path naming
// the cluster, the org and a generated secret. Without agent namespaces
// there is none.
func TestHR730_EveryWebhookTheChartRendersFailsClosed(t *testing.T) {
	if vwcs := ofKind(render(t), "ValidatingWebhookConfiguration"); len(vwcs) != 0 {
		t.Fatalf("the default chart renders %d webhooks", len(vwcs))
	}
	vwcs := ofKind(mustRender(t, m32Values), "ValidatingWebhookConfiguration")
	if len(vwcs) != 1 {
		t.Fatalf("%d webhook configurations, want 1", len(vwcs))
	}
	hooks := l(vwcs[0]["webhooks"])
	if len(hooks) != 1 {
		t.Fatalf("%d webhooks", len(hooks))
	}
	h := m(hooks[0])
	if h["failurePolicy"] != "Fail" || h["sideEffects"] != "None" || h["timeoutSeconds"] != 5 {
		t.Errorf("failurePolicy %v, sideEffects %v, timeoutSeconds %v", h["failurePolicy"], h["sideEffects"], h["timeoutSeconds"])
	}
	sel := m(get(h, "namespaceSelector", "matchLabels"))
	if sel["pantherclaw.dev/protect"] != "enforce" || sel["pantherclaw.dev/org"] != m32Org || len(sel) != 2 {
		t.Errorf("namespaceSelector %v", sel)
	}
	var rules []string
	for _, r := range l(h["rules"]) {
		rules = append(rules, strings.Join([]string{l(m(r)["operations"])[0].(string), l(m(r)["resources"])[0].(string)}, " "))
	}
	if !slices.Equal(rules, []string{"CREATE pods", "UPDATE pods/ephemeralcontainers"}) {
		t.Errorf("rules %v", rules)
	}
	svc := m(get(h, "clientConfig", "service"))
	path, _ := svc["path"].(string)
	parts := strings.Split(strings.TrimPrefix(path, "/admission/v1/"), "/")
	if svc["name"] != "pc-pantherclaw-api" || svc["port"] != 8444 || len(parts) != 3 || parts[0] != "home" || parts[1] != m32Org || len(parts[2]) < 32 {
		t.Errorf("clientConfig %v", svc)
	}
	if get(h, "clientConfig", "caBundle") != "Y2E=" {
		t.Errorf("caBundle %v", get(h, "clientConfig", "caBundle"))
	}
	// cert-manager instead of a caBundle.
	cm := ofKind(mustRender(t, m32Values, "admission.tls.caBundle=", "admission.tls.certManagerCertificate=pantherclaw/admission"), "ValidatingWebhookConfiguration")
	if get(cm[0], "metadata", "annotations", "cert-manager.io/inject-ca-from") != "pantherclaw/admission" {
		t.Errorf("cert-manager annotation %v", get(cm[0], "metadata", "annotations"))
	}
}

// TestHR731_TheAdmissionListenerIsOffByDefault: the default chart serves
// no admission port; with admission enabled the API listens on 8444 with
// the staged certificate pair.
func TestHR731_TheAdmissionListenerIsOffByDefault(t *testing.T) {
	for _, d := range render(t) {
		if name(d) == "ConfigMap/pc-pantherclaw-api" && strings.Contains(get(d, "data", "server.json").(string), `"admission"`) {
			t.Errorf("the default API configuration has an admission section: %s", get(d, "data", "server.json"))
		}
	}
	var cfg struct {
		Admission struct {
			Listen           string   `json:"listen"`
			TLSCertFile      string   `json:"tls_cert_file"`
			EdgeImageDigests []string `json:"edge_image_digests"`
		} `json:"admission"`
	}
	for _, d := range mustRender(t, m32Values) {
		if name(d) == "ConfigMap/pc-pantherclaw-api" {
			if err := json.Unmarshal([]byte(get(d, "data", "server.json").(string)), &cfg); err != nil {
				t.Fatal(err)
			}
		}
	}
	if cfg.Admission.Listen != "0.0.0.0:8444" || cfg.Admission.TLSCertFile == "" || !slices.Equal(cfg.Admission.EdgeImageDigests, []string{edgeDigest}) {
		t.Errorf("admission %+v", cfg.Admission)
	}
}

// TestHR740_TheAgentNetworkPolicyAllowsOnlyTheGatewayAndTheAPI: the agent
// namespace's policy selects every pod, allows no ingress, and egress only
// to the release namespace's gateway pods on the gateway port and api pods
// on 8080 over TCP, never port 53; ingressFrom adds ingress and
// apiEgressCIDRs replaces the api peer with ipBlocks.
func TestHR740_TheAgentNetworkPolicyAllowsOnlyTheGatewayAndTheAPI(t *testing.T) {
	var np map[string]any
	for _, d := range mustRender(t, m32Values) {
		if name(d) == "NetworkPolicy/pantherclaw-agents" && get(d, "metadata", "namespace") == "agents" {
			np = d
		}
	}
	if np == nil {
		t.Fatal("no agent NetworkPolicy")
	}
	s := m(np["spec"])
	if len(m(s["podSelector"])) != 0 || !slices.Equal(l(s["policyTypes"]), []any{"Ingress", "Egress"}) || len(l(s["ingress"])) != 0 {
		t.Errorf("podSelector %v policyTypes %v ingress %v", s["podSelector"], s["policyTypes"], s["ingress"])
	}
	egress := l(s["egress"])
	if len(egress) != 2 {
		t.Fatalf("egress %v", egress)
	}
	for i, want := range []struct {
		component string
		port      int
	}{{"gateway", 8090}, {"api", 8080}} {
		r := m(egress[i])
		to, ports := l(r["to"]), l(r["ports"])
		if len(to) != 1 || len(ports) != 1 {
			t.Fatalf("egress[%d] %v", i, r)
		}
		if get(to[0], "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name") != "pantherclaw" ||
			get(to[0], "podSelector", "matchLabels", "app.kubernetes.io/component") != want.component ||
			m(ports[0])["port"] != want.port || m(ports[0])["protocol"] != "TCP" {
			t.Errorf("egress[%d] = %v, want %s on %d", i, r, want.component, want.port)
		}
	}

	extra := m32Values + `    ingressFrom: [{podSelector: {matchLabels: {app: ingress}}}]
    apiEgressCIDRs: [203.0.113.10/32]
`
	for _, d := range mustRender(t, extra) {
		if name(d) != "NetworkPolicy/pantherclaw-agents" || get(d, "metadata", "namespace") != "agents" {
			continue
		}
		s := m(d["spec"])
		if len(l(s["ingress"])) != 1 {
			t.Errorf("ingressFrom: ingress %v", s["ingress"])
		}
		api := m(l(s["egress"])[1])
		if get(l(api["to"])[0], "ipBlock", "cidr") != "203.0.113.10/32" {
			t.Errorf("apiEgressCIDRs: %v", api)
		}
	}
}

// TestHR740_AgentNamespacesNeedFixedAddressesAndTheEnforcementParts: the
// chart refuses to render agent namespaces without the gateway's fixed
// address, the API's, the canary's, the admission listener or the gateway.
func TestHR740_AgentNamespacesNeedFixedAddressesAndTheEnforcementParts(t *testing.T) {
	for set, want := range map[string]string{
		"gateway.service.clusterIP=": "gateway.service.clusterIP is required",
		"api.service.clusterIP=":     "api.service.clusterIP is required",
		"probe.canary.clusterIP=":    "probe.canary.clusterIP is required",
		"admission.enabled=false":    "agentNamespaces needs admission.enabled",
		"gateway.enabled=false":      "agentNamespaces needs gateway.enabled",
		"api.tls.existingSecret=":    "agentNamespaces needs api.tls.existingSecret",
	} {
		_, err := renderWith(t, m32Values, set)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", set, err, want)
		}
	}
}

// webhookSecret is the rendered webhook Secret's value for cluster home
// and the API pods' checksum annotation.
func webhookSecret(t *testing.T, docs []map[string]any) (string, string, string) {
	t.Helper()
	var secret, path, sum string
	for _, d := range docs {
		switch name(d) {
		case "Secret/pc-pantherclaw-webhook":
			if get(d, "metadata", "annotations", "helm.sh/resource-policy") != "keep" {
				t.Errorf("the webhook Secret is not kept: %v", get(d, "metadata", "annotations"))
			}
			secret, _ = get(d, "data", "home").(string)
		case "ValidatingWebhookConfiguration/pc-pantherclaw-pantherclaw-" + m32Org:
			path, _ = get(l(d["webhooks"])[0], "clientConfig", "service", "path").(string)
		case "Deployment/pc-pantherclaw-api":
			sum, _ = get(d, "spec", "template", "metadata", "annotations", "checksum/admission-webhook").(string)
		}
	}
	return secret, path, sum
}

// TestHR740_TheWebhookSecretIsGeneratedAndARerenderRotatesIt: the chart
// generates the webhook secret into a Secret it keeps, puts the same value
// in the webhook path, and a fresh render generates another one, which
// changes the API pods' checksum so they roll (D969a, D969b).
func TestHR740_TheWebhookSecretIsGeneratedAndARerenderRotatesIt(t *testing.T) {
	s1, p1, c1 := webhookSecret(t, mustRender(t, m32Values))
	s2, p2, c2 := webhookSecret(t, mustRender(t, m32Values))
	if s1 == "" || p1 == "" || c1 == "" {
		t.Fatalf("secret %q, path %q, checksum %q", s1, p1, c1)
	}
	for _, c := range []struct{ secret, path string }{{s1, p1}, {s2, p2}} {
		rawb, err := base64.StdEncoding.DecodeString(c.secret)
		raw := string(rawb)
		if err != nil || len(raw) < 48 || !strings.HasSuffix(c.path, "/"+raw) {
			t.Errorf("secret %q (%v) is not the path's %q", raw, err, c.path)
		}
	}
	if s1 == s2 || c1 == c2 {
		t.Errorf("a re-render kept the secret %v or the checksum %v", s1 == s2, c1 == c2)
	}
}

// TestHR733_TheChartsProbePodsAreAdmitted: the probe CronJobs' pods, the
// chart's own agent pods, pass the admission decision with an issuer
// entry for their service account and the configured edge digest.
func TestHR733_TheChartsProbePodsAreAdmitted(t *testing.T) {
	org := ids.MustParse[ids.Org](m32Org)
	found := 0
	for _, d := range ofKind(mustRender(t, m32Values), "CronJob") {
		spec := get(d, "spec", "jobTemplate", "spec", "template", "spec")
		raw, err := json.Marshal(map[string]any{"metadata": map[string]any{"name": "probe-1"}, "spec": spec})
		if err != nil {
			t.Fatal(err)
		}
		pod, err := review.ParsePod(raw)
		if err != nil {
			t.Fatal(err)
		}
		e := issuers.KubernetesBinding{Cluster: "home", Namespace: get(d, "metadata", "namespace").(string), ServiceAccountName: decision.ServiceAccount(pod)}
		if code := decision.Pod(decision.Input{Org: org, Pod: pod, Entries: []issuers.KubernetesBinding{e}, EdgeDigests: []string{edgeDigest}}); code != "" {
			t.Errorf("%s: the chart's probe pod is refused with %s", name(d), code)
		}
		found++
	}
	if found != 2 {
		t.Errorf("%d probe CronJobs, want the agent namespace's and the control twin", found)
	}
}

// TestHR733_TheExamplePodIsAdmitted: examples/agent-pod.yaml, with its
// REPLACE values filled, passes the admission decision.
func TestHR733_TheExamplePodIsAdmitted(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(root, "deploy", "helm", "pantherclaw", "examples", "agent-pod.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "sha256:REPLACE", edgeDigest)
	s = strings.ReplaceAll(s, "00000000-0000-0000-0000-000000000000", m32Org)
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := review.ParsePod(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := issuers.KubernetesBinding{Cluster: "home", Namespace: "agents", ServiceAccountName: "my-agent"}
	if code := decision.Pod(decision.Input{Org: ids.MustParse[ids.Org](m32Org), Pod: pod, Entries: []issuers.KubernetesBinding{e}, EdgeDigests: []string{edgeDigest}}); code != "" {
		t.Errorf("the example pod is refused with %s", code)
	}
}

// TestHR398_TheM32PodsAreHardened: the gateway, canary and probe pods the
// M32 values add run as non-root without a service account token, every
// container read-only, without privilege escalation and with every
// capability dropped.
func TestHR398_TheM32PodsAreHardened(t *testing.T) {
	pods := map[string]map[string]any{}
	for _, d := range mustRender(t, m32Values) {
		switch d["kind"] {
		case "Deployment":
			pods[name(d)] = m(get(d, "spec", "template", "spec"))
		case "CronJob":
			pods[name(d)] = m(get(d, "spec", "jobTemplate", "spec", "template", "spec"))
		}
	}
	for _, want := range []string{"Deployment/pc-pantherclaw-gateway", "Deployment/pantherclaw-canary", "CronJob/pantherclaw-probe", "CronJob/pantherclaw-probe-control"} {
		if pods[want] == nil {
			t.Errorf("no %s", want)
		}
	}
	for pod, spec := range pods {
		if spec["automountServiceAccountToken"] != false {
			t.Errorf("%s: mounts a service account token", pod)
		}
		for _, c := range containers(spec) {
			sc := m(c["securityContext"])
			at := pod + " " + c["name"].(string)
			if sc["runAsNonRoot"] != true || sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false || sc["privileged"] == true {
				t.Errorf("%s: securityContext %v", at, sc)
			}
			if drop := l(get(sc, "capabilities", "drop")); len(drop) != 1 || drop[0] != "ALL" {
				t.Errorf("%s: capabilities.drop %v", at, drop)
			}
		}
	}
}
