// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	dnsLabel     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsSubdomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	uidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	imageRepo    = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+$`)
	imageDigest  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// imageIDRef extracts repository and digest from a container status
	// imageID such as "docker-pullable://ghcr.io/acme/agent@sha256:…".
	imageIDRef = regexp.MustCompile(`^(?:[a-z-]+://)?([^@\s]+)@(sha256:[0-9a-f]{64})$`)
)

// KubernetesBinding pins Kubernetes service-account tokens to one agent
// (HR-140, HR-144). The service-account UID makes a deleted and recreated
// account with the same name a different identity.
type KubernetesBinding struct {
	// Cluster names a cluster from the server configuration (founder
	// decision 3); it is never a tenant-supplied address.
	Cluster            string `json:"cluster"`
	Namespace          string `json:"namespace"`
	ServiceAccountName string `json:"service_account_name"`
	ServiceAccountUID  string `json:"service_account_uid"`
	// ImageRepositories and ImageDigests optionally restrict the pod's
	// image; empty accepts any image (whose digest is still recorded).
	ImageRepositories []string `json:"image_repositories,omitzero"`
	ImageDigests      []string `json:"image_digests,omitzero"`
}

// Issuer is the issuer name recorded for this binding's tokens.
func (b KubernetesBinding) Issuer() string { return "cluster:" + b.Cluster }

// Validate checks the binding (HR-140).
func (b KubernetesBinding) Validate() error {
	var errs []string
	if !dnsLabel.MatchString(b.Cluster) || !dnsLabel.MatchString(b.Namespace) {
		errs = append(errs, "cluster and namespace must be DNS labels")
	}
	if !dnsSubdomain.MatchString(b.ServiceAccountName) || !uidPattern.MatchString(b.ServiceAccountUID) {
		errs = append(errs, "service account name and UID are required")
	}
	if len(b.ImageRepositories) > 20 || len(b.ImageDigests) > 50 {
		errs = append(errs, "too many image pins")
	}
	for _, r := range b.ImageRepositories {
		if !imageRepo.MatchString(r) {
			errs = append(errs, fmt.Sprintf("image repository %q", r))
		}
	}
	for _, d := range b.ImageDigests {
		if !imageDigest.MatchString(d) {
			errs = append(errs, fmt.Sprintf("image digest %q", d))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEntry, strings.Join(errs, "; "))
	}
	return nil
}

// Widening lists what b accepts that prev did not (HR-141).
func (b KubernetesBinding) Widening(prev *KubernetesBinding) []string {
	if prev == nil {
		return []string{"new trusted issuer entry"}
	}
	var out []string
	if prev.Cluster != b.Cluster || prev.Namespace != b.Namespace || prev.ServiceAccountName != b.ServiceAccountName ||
		prev.ServiceAccountUID != b.ServiceAccountUID {
		out = append(out, "cluster, namespace or service account changed")
	}
	out = append(out, widenedList("image_repositories", prev.ImageRepositories, b.ImageRepositories)...)
	out = append(out, widenedList("image_digests", prev.ImageDigests, b.ImageDigests)...)
	return out
}

// TokenReview is the part of a TokenReview response the preset uses. The
// adapter calls TokenReview with audiences [pantherclaw:<org>].
type TokenReview struct {
	Authenticated bool
	Audiences     []string
	// Username is "system:serviceaccount:<namespace>:<name>".
	Username string
	// UID is the service account's UID.
	UID string
	// PodName and PodUID come from user.extra
	// (authentication.kubernetes.io/pod-name and pod-uid).
	PodName string
	PodUID  string
}

// Pod is the part of the bound pod PantherClaw reads from the API server.
type Pod struct {
	Namespace string
	Name      string
	UID       string
	Phase     string
	// ImageIDs are status.containerStatuses[].imageID of the app
	// containers (init containers excluded).
	ImageIDs []string
	// Edge is set when the pod runs a native sidecar (an init container
	// with restartPolicy Always) named pantherclaw-edge: the image id its
	// status.initContainerStatuses entry reports, empty until it runs.
	Edge *PodEdge
}

// PodEdge is a pod's pantherclaw-edge native sidecar.
type PodEdge struct {
	ImageID string
}

// edgeDigest is the sha256 digest an image id names ("sha256:…",
// "repo@sha256:…" or "docker-pullable://repo@sha256:…"), or "".
func edgeDigest(imageID string) string {
	i := strings.LastIndex(imageID, "sha256:")
	if i < 0 || !digestOnly.MatchString(imageID[i:]) {
		return ""
	}
	return imageID[i:]
}

var digestOnly = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// MatchKubernetes applies the Kubernetes preset (HR-144): TokenReview must
// authenticate the token for the org's audience as the pinned namespace,
// service-account name and UID, bound to a running pod that the API server
// still reports with the same UID. The release digest comes from that
// pod's status, never from the workload; an M3 pod has exactly one app
// container, so the digest is unambiguous (a multi-container pod is
// refused rather than guessed). A pod that runs the pantherclaw-edge native
// sidecar matches only while the sidecar's running image digest is on
// edgeDigests (admission.edge_image_digests, G0 M32 D1218 H1): an image
// swapped in after admission does not attest.
func MatchKubernetes(b KubernetesBinding, org ids.OrgID, r TokenReview, p Pod, edgeDigests []string) (Match, error) {
	if err := b.Validate(); err != nil {
		return Match{}, err
	}
	switch {
	case !r.Authenticated:
		return Match{}, rejected("token not authenticated")
	case !slices.Contains(r.Audiences, Audience(org)):
		return Match{}, rejected("audience")
	case r.Username != "system:serviceaccount:"+b.Namespace+":"+b.ServiceAccountName:
		return Match{}, rejected("service account %q", r.Username)
	case r.UID != b.ServiceAccountUID:
		return Match{}, rejected("service account UID (recreated account?)")
	case r.PodName == "" || r.PodUID == "":
		return Match{}, rejected("token is not bound to a pod")
	case p.Namespace != b.Namespace || p.Name != r.PodName || p.UID != r.PodUID:
		return Match{}, rejected("bound pod no longer exists")
	case p.Phase != "Running":
		return Match{}, rejected("pod phase %q", p.Phase)
	case len(p.ImageIDs) != 1:
		return Match{}, rejected("pod has %d app containers; exactly one is required", len(p.ImageIDs))
	case p.Edge != nil && !slices.Contains(edgeDigests, edgeDigest(p.Edge.ImageID)):
		return Match{}, rejected("the pod's edge image is not an admitted edge image")
	}
	m := imageIDRef.FindStringSubmatch(p.ImageIDs[0])
	if m == nil {
		return Match{}, rejected("pod image is not pinned by digest")
	}
	repo, digest := m[1], m[2]
	if len(b.ImageRepositories) > 0 && !slices.Contains(b.ImageRepositories, repo) {
		return Match{}, rejected("image repository %q not pinned", repo)
	}
	if len(b.ImageDigests) > 0 && !slices.Contains(b.ImageDigests, digest) {
		return Match{}, rejected("image digest not pinned")
	}
	return Match{
		Binding: Binding{
			"cluster":              b.Cluster,
			"namespace":            b.Namespace,
			"service_account_uid":  b.ServiceAccountUID,
			"service_account_name": b.ServiceAccountName,
		},
		ReleaseDigest: digest,
	}, nil
}
