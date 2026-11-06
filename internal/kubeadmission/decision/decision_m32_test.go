// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package decision_test

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/decision"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	edgeDigest  = "sha256:" + strings.Repeat("e", 64)
	agentDigest = "sha256:" + strings.Repeat("a", 64)
	otherDigest = "sha256:" + strings.Repeat("b", 64)
)

// agentPod is the examples/agent-pod.yaml shape as the API server sends it:
// one app container, the edge as the native sidecar holding the only
// projected token, automount off.
func agentPod(org ids.OrgID) map[string]any {
	return map[string]any{
		"metadata": map[string]any{"name": "coder-1", "namespace": "agents"},
		"spec": map[string]any{
			"serviceAccountName":           "coder",
			"automountServiceAccountToken": false,
			"initContainers": []any{map[string]any{
				"name": labels.EdgeContainer, "image": "ghcr.io/katocxl/pantherclaw-edge@" + edgeDigest, "restartPolicy": "Always",
				"volumeMounts": []any{
					map[string]any{"name": "edge-token", "mountPath": "/var/run/pantherclaw/edge"},
					map[string]any{"name": "pc-edge", "mountPath": "/pc-edge"},
				},
			}},
			"containers": []any{map[string]any{
				"name": "agent", "image": "ghcr.io/acme/agent@" + agentDigest,
				"volumeMounts": []any{map[string]any{"name": "pc-edge", "mountPath": "/pc-edge"}},
			}},
			"volumes": []any{
				map[string]any{"name": "edge-token", "projected": map[string]any{"sources": []any{map[string]any{
					"serviceAccountToken": map[string]any{"path": "token", "audience": labels.AgentAudience(org), "expirationSeconds": 3600},
				}}}},
				map[string]any{"name": "pc-edge", "emptyDir": map[string]any{"medium": "Memory"}},
			},
		},
	}
}

func spec(p map[string]any) map[string]any { return p["spec"].(map[string]any) }

func container(p map[string]any, list string, i int) map[string]any {
	return spec(p)[list].([]any)[i].(map[string]any)
}

// decide parses p as the webhook does and decides it.
func decide(t *testing.T, org ids.OrgID, p map[string]any, entries []issuers.KubernetesBinding) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	pod, err := review.ParsePod(raw)
	if err != nil {
		t.Fatal(err)
	}
	return decision.Pod(decision.Input{Org: org, Pod: pod, Entries: entries, EdgeDigests: []string{edgeDigest}})
}

func entry() issuers.KubernetesBinding {
	return issuers.KubernetesBinding{Cluster: "prod", Namespace: "agents", ServiceAccountName: "coder", ServiceAccountUID: "6b1a2b55-6e43-4c2a-9b9c-0b6e1c1d2e3f"}
}

func want(t *testing.T, what, got, code string) {
	t.Helper()
	if got != code {
		t.Errorf("%s: decided %q, want %q", what, got, code)
	}
}

// TestHR732_APodNeedsAnIssuerEntryOneAppContainerAndPinnedImages: the
// example pod with an active entry is admitted; without an entry, with a
// second app container, or with an image the entry's pins do not accept,
// it is refused with the rule's code.
func TestHR732_APodNeedsAnIssuerEntryOneAppContainerAndPinnedImages(t *testing.T) {
	org := ids.New[ids.Org]()
	e := entry()
	want(t, "the example pod", decide(t, org, agentPod(org), []issuers.KubernetesBinding{e}), "")

	pinned := e
	pinned.ImageRepositories, pinned.ImageDigests = []string{"ghcr.io/acme/agent"}, []string{agentDigest}
	want(t, "an image matching the pins", decide(t, org, agentPod(org), []issuers.KubernetesBinding{pinned}), "")
	tagged := agentPod(org)
	container(tagged, "containers", 0)["image"] = "ghcr.io/acme/agent:v1@" + agentDigest
	want(t, "a tag beside the pinned digest", decide(t, org, tagged, []issuers.KubernetesBinding{pinned}), "")

	want(t, "no issuer entry", decide(t, org, agentPod(org), nil), decision.CodeNoIssuer)

	two := agentPod(org)
	spec(two)["containers"] = append(spec(two)["containers"].([]any), map[string]any{"name": "helper", "image": "ghcr.io/acme/agent@" + agentDigest})
	want(t, "two app containers", decide(t, org, two, []issuers.KubernetesBinding{e}), decision.CodeAppContainers)
	none := agentPod(org)
	spec(none)["containers"] = []any{}
	want(t, "no app container", decide(t, org, none, []issuers.KubernetesBinding{e}), decision.CodeAppContainers)

	byTag := agentPod(org)
	container(byTag, "containers", 0)["image"] = "ghcr.io/acme/agent:latest"
	want(t, "an image by tag only", decide(t, org, byTag, []issuers.KubernetesBinding{pinned}), decision.CodeImageNotPinned)
	otherRepo := agentPod(org)
	container(otherRepo, "containers", 0)["image"] = "ghcr.io/evil/agent@" + agentDigest
	want(t, "another repository", decide(t, org, otherRepo, []issuers.KubernetesBinding{pinned}), decision.CodeImageNotPinned)
	otherDig := agentPod(org)
	container(otherDig, "containers", 0)["image"] = "ghcr.io/acme/agent@" + otherDigest
	want(t, "another digest", decide(t, org, otherDig, []issuers.KubernetesBinding{pinned}), decision.CodeImageNotPinned)
	// With two entries, one unpinned entry admits any image.
	want(t, "an unpinned entry beside a pinned one", decide(t, org, otherDig, []issuers.KubernetesBinding{pinned, e}), "")
}

// TestHR733_APodNeedsExactlyOneEdgeSidecarWithAnAllowedDigest: the edge as
// the one native sidecar with a configured digest is admitted; a missing
// edge, an edge that is a plain init container, another sidecar name, a
// second sidecar or a digest off the list is refused (K8S_EDGE_MISSING).
func TestHR733_APodNeedsExactlyOneEdgeSidecarWithAnAllowedDigest(t *testing.T) {
	org := ids.New[ids.Org]()
	es := []issuers.KubernetesBinding{entry()}
	want(t, "the example pod", decide(t, org, agentPod(org), es), "")
	// A plain init container besides the edge is not a sidecar.
	withInit := agentPod(org)
	spec(withInit)["initContainers"] = append(spec(withInit)["initContainers"].([]any), map[string]any{"name": "setup", "image": "busybox@" + otherDigest})
	want(t, "a plain init container beside the edge", decide(t, org, withInit, es), "")

	cases := map[string]func(p map[string]any){
		"no edge": func(p map[string]any) { spec(p)["initContainers"] = []any{} },
		"the edge as a plain init container": func(p map[string]any) {
			delete(container(p, "initContainers", 0), "restartPolicy")
		},
		"a sidecar named otherwise": func(p map[string]any) { container(p, "initContainers", 0)["name"] = "proxy" },
		"a second sidecar": func(p map[string]any) {
			spec(p)["initContainers"] = append(spec(p)["initContainers"].([]any), map[string]any{
				"name": "shadow", "image": "ghcr.io/katocxl/pantherclaw-edge@" + edgeDigest, "restartPolicy": "Always",
			})
		},
		"an edge digest off the list": func(p map[string]any) {
			container(p, "initContainers", 0)["image"] = "ghcr.io/katocxl/pantherclaw-edge@" + otherDigest
		},
		"an edge by tag": func(p map[string]any) {
			container(p, "initContainers", 0)["image"] = "ghcr.io/katocxl/pantherclaw-edge:latest"
		},
	}
	for name, edit := range cases {
		p := agentPod(org)
		edit(p)
		want(t, name, decide(t, org, p, es), decision.CodeEdgeMissing)
	}
}

// TestHR734_HostAccessAndExposedTokensAreRefused: the example pod is
// admitted; host namespaces, a privileged container or a hostPath give
// K8S_POD_ESCAPE, and an automounted token or a projected token outside the
// edge, for another audience or for longer than an hour give
// K8S_TOKEN_EXPOSED.
func TestHR734_HostAccessAndExposedTokensAreRefused(t *testing.T) {
	org := ids.New[ids.Org]()
	es := []issuers.KubernetesBinding{entry()}
	want(t, "the example pod", decide(t, org, agentPod(org), es), "")
	short := agentPod(org)
	spec(short)["volumes"].([]any)[0].(map[string]any)["projected"].(map[string]any)["sources"].([]any)[0].(map[string]any)["serviceAccountToken"].(map[string]any)["expirationSeconds"] = 600
	want(t, "a token of ten minutes", decide(t, org, short, es), "")

	escape := map[string]func(p map[string]any){
		"hostNetwork": func(p map[string]any) { spec(p)["hostNetwork"] = true },
		"hostPID":     func(p map[string]any) { spec(p)["hostPID"] = true },
		"hostIPC":     func(p map[string]any) { spec(p)["hostIPC"] = true },
		"a privileged agent": func(p map[string]any) {
			container(p, "containers", 0)["securityContext"] = map[string]any{"privileged": true}
		},
		"a privileged edge": func(p map[string]any) {
			container(p, "initContainers", 0)["securityContext"] = map[string]any{"privileged": true}
		},
		"a hostPath volume": func(p map[string]any) {
			spec(p)["volumes"] = append(spec(p)["volumes"].([]any), map[string]any{"name": "node", "hostPath": map[string]any{"path": "/"}})
		},
	}
	for name, edit := range escape {
		p := agentPod(org)
		edit(p)
		want(t, name, decide(t, org, p, es), decision.CodePodEscape)
	}

	sat := func(p map[string]any) map[string]any {
		return spec(p)["volumes"].([]any)[0].(map[string]any)["projected"].(map[string]any)["sources"].([]any)[0].(map[string]any)["serviceAccountToken"].(map[string]any)
	}
	exposed := map[string]func(p map[string]any){
		"automount unset": func(p map[string]any) { delete(spec(p), "automountServiceAccountToken") },
		"automount on":    func(p map[string]any) { spec(p)["automountServiceAccountToken"] = true },
		"the token in the agent": func(p map[string]any) {
			c := container(p, "containers", 0)
			c["volumeMounts"] = append(c["volumeMounts"].([]any), map[string]any{"name": "edge-token", "mountPath": "/token"})
		},
		"the token in a plain init container": func(p map[string]any) {
			spec(p)["initContainers"] = append(spec(p)["initContainers"].([]any), map[string]any{
				"name": "copy", "image": "busybox@" + otherDigest,
				"volumeMounts": []any{map[string]any{"name": "edge-token", "mountPath": "/token"}},
			})
		},
		"another org's audience": func(p map[string]any) { sat(p)["audience"] = labels.AgentAudience(ids.New[ids.Org]()) },
		"the gateway audience":   func(p map[string]any) { sat(p)["audience"] = labels.GatewayAudience(org) },
		"no expiry":              func(p map[string]any) { delete(sat(p), "expirationSeconds") },
		"two hours":              func(p map[string]any) { sat(p)["expirationSeconds"] = 7200 },
	}
	for name, edit := range exposed {
		p := agentPod(org)
		edit(p)
		want(t, name, decide(t, org, p, es), decision.CodeTokenExposed)
	}
	// Every code has fixed text that never echoes the pod.
	for _, code := range []string{
		decision.CodeNoIssuer, decision.CodeAppContainers, decision.CodeImageNotPinned, decision.CodeEdgeMissing,
		decision.CodePodEscape, decision.CodeTokenExposed, decision.CodeEphemeral, decision.CodeUnavailable,
	} {
		if decision.Message(code) == "" {
			t.Errorf("%s has no message", code)
		}
	}
}

// TestHR730_ANilPodIsUndecidable: the decision fails closed on a pod it
// was not given.
func TestHR730_ANilPodIsUndecidable(t *testing.T) {
	want(t, "no pod", decision.Pod(decision.Input{Org: ids.New[ids.Org](), Entries: []issuers.KubernetesBinding{entry()}}), decision.CodeUnavailable)
	if got := decision.ServiceAccount(&review.Pod{}); got != "default" {
		t.Errorf("a pod naming no service account runs as %q, want default", got)
	}
}
