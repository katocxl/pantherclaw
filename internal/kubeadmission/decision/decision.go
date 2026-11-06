// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package decision is what the Kubernetes admission webhook decides about
// a pod of an enforced namespace (G0 M32 D967, HR-735). It is pure: the
// caller looks up the active trusted-issuer entries for the pod's service
// account and passes them in. Every check must pass; the first that fails
// names the refusal code.
package decision

import (
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Refusal codes, carried in the response's status.reason.
const (
	// CodeNoIssuer: no active kubernetes trusted-issuer entry pins the
	// pod's org, cluster, namespace and service account.
	CodeNoIssuer = "K8S_NO_ISSUER"
	// CodeAppContainers: the pod has not exactly one app container.
	CodeAppContainers = "K8S_APP_CONTAINERS"
	// CodeImageNotPinned: an entry pins images and the app image is not
	// repo@sha256:… matching it, or the entry pins digests and a regular
	// init container's image is not one of them.
	CodeImageNotPinned = "K8S_IMAGE_NOT_PINNED"
	// CodeEdgeMissing: not exactly one native sidecar, named
	// pantherclaw-edge, running a configured edge image digest.
	CodeEdgeMissing = "K8S_EDGE_MISSING"
	// CodePodEscape: host namespaces, a shared process namespace, a
	// privileged container or a hostPath volume; an edge without a fixed
	// non-root user; or a container other than the edge and the pinned
	// probe that may escalate privileges, adds a capability other than
	// NET_BIND_SERVICE, unmasks /proc or may run as the edge's user.
	CodePodEscape = "K8S_POD_ESCAPE"
	// CodeImageChanged: a pod UPDATE changes a container's image.
	CodeImageChanged = "K8S_IMAGE_CHANGED"
	// CodeTokenExposed: the pod automounts its service-account token, or a
	// projected token reaches a container other than the edge, names
	// another audience or lives longer than an hour.
	CodeTokenExposed = "K8S_TOKEN_EXPOSED" //nolint:gosec // G101: a reason code, not a credential
	// CodeEphemeral: an ephemeral container (always refused).
	CodeEphemeral = "K8S_EPHEMERAL"
	// CodeUnavailable: the webhook could not decide (fail closed).
	CodeUnavailable = "K8S_UNAVAILABLE"
	// CodeAllowed is the metric code of an allowed pod.
	CodeAllowed = "ALLOWED"
)

// MaxTokenSeconds bounds a projected token's expirationSeconds.
const MaxTokenSeconds = 3600

// Messages are fixed text for each code; they never echo pod content.
var messages = map[string]string{
	CodeNoIssuer:       "no active Kubernetes trusted-issuer entry pins this namespace and service account",
	CodeAppContainers:  "an agent pod must have exactly one app container",
	CodeImageNotPinned: "the app image must be pinned by digest and match the entry's pins, and init containers must use a pinned digest",
	CodeEdgeMissing:    "an agent pod must run exactly one native sidecar named pantherclaw-edge with a configured edge image digest",
	CodePodEscape: "host namespaces, a shared process namespace, privileged containers and hostPath volumes are refused in agent pods; " +
		"the edge must run as a fixed non-root user that no other container may run as, and other containers may not escalate " +
		"privileges, add capabilities other than NET_BIND_SERVICE or unmask /proc",
	CodeImageChanged: "the images of an agent pod's containers cannot change after admission; create a new pod",
	CodeTokenExposed: "automountServiceAccountToken must be false and projected tokens may reach only the edge, for this org's audience, for at most 3600 seconds",
	CodeEphemeral:    "ephemeral containers are refused in agent pods",
	CodeUnavailable:  "PantherClaw could not decide on this pod; it is refused until it can",
}

// Message is the fixed text for a refusal code.
func Message(code string) string { return messages[code] }

// ServiceAccount is the pod's service account; Kubernetes uses "default"
// when the spec names none.
func ServiceAccount(p *review.Pod) string {
	if p.Spec.ServiceAccountName == "" {
		return "default"
	}
	return p.Spec.ServiceAccountName
}

// Input is one pod decision.
type Input struct {
	Org ids.OrgID
	Pod *review.Pod
	// Entries are the bindings of the active kubernetes entries for the
	// pod's org, cluster, namespace and service account.
	Entries []issuers.KubernetesBinding
	// EdgeDigests are admission.edge_image_digests.
	EdgeDigests []string
	// ProbeDigests are admission.probe_image_digests: an app container on
	// them is the chart's probe, which runs as the edge's user.
	ProbeDigests []string
}

// Pod decides on a pod CREATE: "" allows, otherwise the refusal code.
func Pod(in Input) string {
	p := in.Pod
	if p == nil {
		return CodeUnavailable
	}
	switch {
	case len(in.Entries) == 0:
		return CodeNoIssuer
	case len(p.Spec.Containers) != 1:
		return CodeAppContainers
	case !imagesAccepted(p, in.Entries):
		return CodeImageNotPinned
	case !edgePresent(p, in.EdgeDigests):
		return CodeEdgeMissing
	case escapes(p, in.ProbeDigests):
		return CodePodEscape
	case tokenExposed(p, in.Org):
		return CodeTokenExposed
	}
	return ""
}

// imageRef splits "repo[:tag]@sha256:…" into repository and digest.
var imageRef = regexp.MustCompile(`^([^@\s]+)@(sha256:[0-9a-f]{64})$`)

// splitImage returns an image's repository (tag removed) and digest; ok is
// false when it is not pinned by digest.
func splitImage(image string) (repo, digest string, ok bool) {
	m := imageRef.FindStringSubmatch(image)
	if m == nil {
		return "", "", false
	}
	repo = m[1]
	if i := strings.LastIndexByte(repo, ':'); i > strings.LastIndexByte(repo, '/') {
		repo = repo[:i]
	}
	return repo, m[2], true
}

// imagesAccepted reports whether some entry accepts the app image and,
// when it pins digests, every regular init container's image too (a
// native sidecar is the edge, checked against the edge list).
func imagesAccepted(p *review.Pod, entries []issuers.KubernetesBinding) bool {
	return slices.ContainsFunc(entries, func(e issuers.KubernetesBinding) bool {
		if !imageAccepted(p.Spec.Containers[0].Image, e) {
			return false
		}
		if len(e.ImageDigests) == 0 {
			return true
		}
		return !slices.ContainsFunc(p.Spec.InitContainers, func(c review.Container) bool {
			if c.IsSidecar() {
				return false
			}
			_, digest, ok := splitImage(c.Image)
			return !ok || !slices.Contains(e.ImageDigests, digest)
		})
	})
}

// imageAccepted reports whether the entry accepts the app image: an entry
// without pins accepts any image; one with pins needs repo@sha256:… that
// matches every list it sets.
func imageAccepted(image string, e issuers.KubernetesBinding) bool {
	if len(e.ImageRepositories) == 0 && len(e.ImageDigests) == 0 {
		return true
	}
	repo, digest, pinned := splitImage(image)
	if !pinned {
		return false
	}
	if len(e.ImageRepositories) > 0 && !slices.Contains(e.ImageRepositories, repo) {
		return false
	}
	return len(e.ImageDigests) == 0 || slices.Contains(e.ImageDigests, digest)
}

// edgePresent reports exactly one native sidecar, named pantherclaw-edge,
// whose image digest is configured.
func edgePresent(p *review.Pod, digests []string) bool {
	var sidecars []review.Container
	for _, c := range p.Spec.InitContainers {
		if c.IsSidecar() {
			sidecars = append(sidecars, c)
		}
	}
	if len(sidecars) != 1 || sidecars[0].Name != labels.EdgeContainer {
		return false
	}
	_, digest, ok := splitImage(sidecars[0].Image)
	return ok && slices.Contains(digests, digest)
}

// allContainers is every container of the pod.
func allContainers(p *review.Pod) []review.Container {
	return slices.Concat(p.Spec.Containers, p.Spec.InitContainers, p.Spec.EphemeralContainers)
}

// capNetBindService is the one capability a container may add.
const capNetBindService = "NET_BIND_SERVICE"

// procMountDefault is the only procMount accepted.
const procMountDefault = "Default"

// escapes reports a pod that could reach the host or the edge's token and
// key: host namespaces, a shared process namespace, a privileged container
// or a hostPath volume; an edge without a fixed non-root user; or a
// container other than the edge and the pinned probe that may escalate
// privileges, adds a capability other than NET_BIND_SERVICE, unmasks /proc
// or may run as the edge's user (the image's user counts as possibly the
// edge's when neither the container nor the pod sets one). Call it after
// edgePresent.
func escapes(p *review.Pod, probeDigests []string) bool {
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC ||
		(p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace) {
		return true
	}
	for _, c := range allContainers(p) {
		if sc := c.SecurityContext; sc != nil && sc.Privileged != nil && *sc.Privileged {
			return true
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.HostPath != nil {
			return true
		}
	}
	edge := slices.IndexFunc(p.Spec.InitContainers, func(c review.Container) bool { return c.IsSidecar() })
	if edge < 0 {
		return true
	}
	edgeUser := p.RunAsUser(p.Spec.InitContainers[edge])
	if edgeUser == nil || *edgeUser == 0 {
		return true
	}
	check := func(c review.Container) bool {
		if sc := c.SecurityContext; sc != nil {
			if sc.AllowPrivilegeEscalation != nil && *sc.AllowPrivilegeEscalation {
				return true
			}
			if sc.ProcMount != nil && *sc.ProcMount != procMountDefault {
				return true
			}
			if sc.Capabilities != nil && slices.ContainsFunc(sc.Capabilities.Add, func(cp string) bool {
				return strings.TrimPrefix(strings.ToUpper(cp), "CAP_") != capNetBindService
			}) {
				return true
			}
		}
		u := p.RunAsUser(c)
		return u == nil || *u == *edgeUser
	}
	app := p.Spec.Containers[0]
	if _, digest, ok := splitImage(app.Image); !ok || !slices.Contains(probeDigests, digest) {
		if check(app) {
			return true
		}
	}
	for i, c := range p.Spec.InitContainers {
		if i != edge && check(c) {
			return true
		}
	}
	return slices.ContainsFunc(p.Spec.EphemeralContainers, check)
}

// ImageChanged reports an UPDATE that changes the image of a container,
// init container or ephemeral container, or the set of them, between old
// and updated (H1: a running pod's images are fixed at admission).
func ImageChanged(old, updated *review.Pod) bool {
	images := func(p *review.Pod) map[string]string {
		m := map[string]string{}
		for kind, cs := range map[string][]review.Container{
			"containers": p.Spec.Containers, "initContainers": p.Spec.InitContainers, "ephemeralContainers": p.Spec.EphemeralContainers,
		} {
			for _, c := range cs {
				m[kind+"/"+c.Name] = c.Image
			}
		}
		return m
	}
	a, b := images(old), images(updated)
	if len(a) != len(b) {
		return true
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return true
		}
	}
	return false
}

// tokenExposed applies check 6: pod-level automount explicitly off, and
// every volume with a projected service-account token mounted only into
// the edge, for the org's agent audience, for at most an hour.
func tokenExposed(p *review.Pod, org ids.OrgID) bool {
	if a := p.Spec.AutomountServiceAccountToken; a == nil || *a {
		return true
	}
	tokenVolumes := map[string]bool{}
	for _, v := range p.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, s := range v.Projected.Sources {
			t := s.ServiceAccountToken
			if t == nil {
				continue
			}
			tokenVolumes[v.Name] = true
			if t.Audience != labels.AgentAudience(org) || t.ExpirationSeconds == nil || *t.ExpirationSeconds > MaxTokenSeconds {
				return true
			}
		}
	}
	mounts := func(cs []review.Container, edgeAllowed bool) bool {
		for _, c := range cs {
			edge := edgeAllowed && c.Name == labels.EdgeContainer && c.IsSidecar()
			for _, m := range c.VolumeMounts {
				if tokenVolumes[m.Name] && !edge {
					return true
				}
			}
		}
		return false
	}
	return mounts(p.Spec.Containers, false) || mounts(p.Spec.InitContainers, true) || mounts(p.Spec.EphemeralContainers, false)
}
