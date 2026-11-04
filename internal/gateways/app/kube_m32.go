// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Gateway enrollment from a projected service-account token (G0 M32 D968):
// a gateway bound to one service account of a configured cluster enrolls a
// replica with the pod's token (audience pantherclaw-gateway:<org>) instead
// of a `pcg_` token. TokenReview against the bound cluster decides; the
// token's own claims only pick the candidate binding.

// KubeReviewer is the cluster API the server calls (identity/adapters/kube).
type KubeReviewer interface {
	Review(ctx context.Context, cluster, token, audience string) (issuers.TokenReview, error)
	Pod(ctx context.Context, cluster, namespace, name string) (issuers.Pod, error)
}

// KubeClusters is the operator's cluster configuration.
type KubeClusters interface {
	// Allowed reports whether org may use cluster.
	Allowed(cluster string, org ids.OrgID) bool
}

// gatewayKube is the Kubernetes side of gateway enrollment; nil when no
// cluster is configured.
type gatewayKube struct {
	review   KubeReviewer
	clusters KubeClusters
	names    []string
}

// WithKubernetes lets bound gateways enroll from projected tokens (G0 M32
// D968): names are the configured clusters.
func (s *Service) WithKubernetes(review KubeReviewer, clusters KubeClusters, names []string) *Service {
	if review != nil && clusters != nil && len(names) > 0 {
		s.kube = &gatewayKube{review: review, clusters: clusters, names: slices.Sorted(slices.Values(names))}
	}
	return s
}

// Errors of the binding calls.
var (
	ErrKubeClusterNotAllowed = pcerr.New(pcerr.FailedPrecondition, "KUBERNETES_CLUSTER_NOT_ALLOWED",
		"the cluster is not configured for this organization (identity.kubernetes_clusters)")
	ErrKubeBindingHosted = pcerr.New(pcerr.FailedPrecondition, "GATEWAY_HOSTED", "a PantherClaw-hosted gateway has no Kubernetes binding")
)

// KubeBinding is a gateway's Kubernetes binding, as stored in
// gateways.kube_binding (migration 00361).
type KubeBinding struct {
	Cluster            string   `json:"cluster"`
	Namespace          string   `json:"namespace"`
	ServiceAccountName string   `json:"service_account_name"`
	ServiceAccountUID  string   `json:"service_account_uid"`
	ImageDigests       []string `json:"image_digests,omitempty"`
}

var (
	kubeName   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	kubeSA     = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	kubeDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// imageDigest is the digest at the end of a container status imageID
	// ("docker-pullable://repo@sha256:…", "repo@sha256:…").
	imageDigest = regexp.MustCompile(`@(sha256:[0-9a-f]{64})$`)
)

func (b KubeBinding) valid() bool {
	if !kubeName.MatchString(b.Cluster) || !kubeName.MatchString(b.Namespace) || !kubeSA.MatchString(b.ServiceAccountName) {
		return false
	}
	if _, err := ids.ParseUUID(b.ServiceAccountUID); err != nil || len(b.ImageDigests) > 50 {
		return false
	}
	for _, d := range b.ImageDigests {
		if !kubeDigest.MatchString(d) {
			return false
		}
	}
	return true
}

// ParseKubeBinding reads a stored binding; nil when there is none or it is
// malformed (which then binds nothing).
func ParseKubeBinding(raw []byte) *KubeBinding {
	if len(raw) == 0 {
		return nil
	}
	var b KubeBinding
	if json.Unmarshal(raw, &b) != nil || !b.valid() {
		return nil
	}
	return &b
}

// SetKubernetesBinding binds an active gateway to one service account of a
// cluster configured for the org (gateway.manage), replacing any earlier
// binding (audit gateway.kubernetes_binding_set).
func (s *Service) SetKubernetesBinding(ctx context.Context, gateway ids.UUID, b KubeBinding) (dbq.PcGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcGateway{}, err
	}
	if !b.valid() {
		return dbq.PcGateway{}, pcerr.New(pcerr.InvalidArgument, "KUBERNETES_BINDING_INVALID", "invalid Kubernetes binding")
	}
	if s.kube == nil || !s.kube.clusters.Allowed(b.Cluster, c.Org) {
		return dbq.PcGateway{}, ErrKubeClusterNotAllowed
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return dbq.PcGateway{}, err
	}
	return s.setKubeBinding(ctx, c.Org, c.Actor(), gateway, raw, auditkind.GatewayKubernetesBindingSet, map[string]string{
		"cluster": b.Cluster, "namespace": b.Namespace, "service_account_name": b.ServiceAccountName,
		"service_account_uid": b.ServiceAccountUID, "image_digests": strings.Join(b.ImageDigests, ","),
	})
}

// ClearKubernetesBinding removes a gateway's binding (gateway.manage, audit
// gateway.kubernetes_binding_cleared); only enrollment tokens enroll it
// afterwards.
func (s *Service) ClearKubernetesBinding(ctx context.Context, gateway ids.UUID) (dbq.PcGateway, error) {
	c, err := s.manager(ctx, td.PermGatewayManage)
	if err != nil {
		return dbq.PcGateway{}, err
	}
	return s.setKubeBinding(ctx, c.Org, c.Actor(), gateway, nil, auditkind.GatewayKubernetesBindingCleared, nil)
}

func (s *Service) setKubeBinding(ctx context.Context, org ids.OrgID, actor evdomain.Actor, gateway ids.UUID, raw []byte, kind string,
	details map[string]string,
) (dbq.PcGateway, error) {
	var out dbq.PcGateway
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		g, err := q.LockGateway(ctx, org, gateway)
		if db.IsNoRows(err) {
			return ErrGatewayNotFound
		} else if err != nil {
			return err
		}
		if g.State != "ACTIVE" {
			return ErrGatewayRevoked
		}
		if hosted, err := q.IsHostedGateway(ctx, org, g.ID); err != nil {
			return err
		} else if hosted && raw != nil {
			return ErrKubeBindingHosted
		}
		if out, err = q.SetGatewayKubeBinding(ctx, raw, org, gateway); err != nil {
			return err
		}
		return record(ctx, tx, actor, kind, gateway, details)
	})
	return out, err
}

// tokenClaims are the claims of a projected token that pick the candidate
// binding. They are not trusted: TokenReview decides.
type tokenClaims struct {
	Aud  audience `json:"aud"`
	Kube struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// audience is a JWT aud: a string or a list of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// maxKubeToken bounds a projected token (the proto allows 16 KiB).
const maxKubeToken = 16 << 10

// peekKubeToken returns the org of the token's one gateway audience and the
// namespace and service account it names.
func peekKubeToken(token string) (ids.OrgID, string, string, error) {
	parts := strings.Split(token, ".")
	if len(token) > maxKubeToken || len(parts) != 3 {
		return ids.OrgID{}, "", "", errors.New("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return ids.OrgID{}, "", "", err
	}
	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return ids.OrgID{}, "", "", err
	}
	var orgs []string
	for _, a := range c.Aud {
		if o, ok := strings.CutPrefix(a, labels.GatewayAudiencePrefix); ok {
			orgs = append(orgs, o)
		}
	}
	if len(orgs) != 1 {
		return ids.OrgID{}, "", "", errors.New("not exactly one gateway audience")
	}
	org, err := ids.Parse[ids.Org](orgs[0])
	if err != nil {
		return ids.OrgID{}, "", "", err
	}
	return org, c.Kube.Namespace, c.Kube.ServiceAccount.Name, nil
}

// kubeCandidate is the one gateway a token may enroll.
type kubeCandidate struct {
	cluster string
	gateway ids.UUID
	binding KubeBinding
}

// EnrollKubernetes exchanges a bound gateway pod's projected token and a
// certificate request for the same 24-hour certificate as Enroll (G0 M32
// D968). Exactly one active gateway of the org must be bound to the
// token's cluster, namespace and service account. TokenReview with audience
// pantherclaw-gateway:<org> against that cluster must authenticate the
// token as that service account (name and UID), bound to a Running pod
// with exactly one app container whose image matches the pinned digests.
// Every failure gives the same ErrEnrollment.
func (s *Service) EnrollKubernetes(ctx context.Context, token string, csr []byte) (Enrolled, error) {
	if s.kube == nil {
		return Enrolled{}, ErrEnrollment
	}
	pub, err := ca.ParseRequest(csr)
	if err != nil {
		return Enrolled{}, ErrEnrollment
	}
	org, ns, sa, err := peekKubeToken(token)
	if err != nil || !kubeName.MatchString(ns) || !kubeSA.MatchString(sa) {
		return Enrolled{}, ErrEnrollment
	}
	cand, err := s.kubeCandidate(ctx, org, ns, sa)
	if err != nil {
		return Enrolled{}, err
	}
	pod, err := s.kube.verify(ctx, org, cand, token)
	if err != nil {
		return Enrolled{}, err
	}
	var out Enrolled
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if state, err := q.OrgState(ctx, org); db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrEnrollment // HR-392
		} else if err != nil {
			return err
		}
		g, err := q.LockGateway(ctx, org, cand.gateway)
		if err != nil || g.State != "ACTIVE" {
			return ErrEnrollment
		}
		// The binding may have changed while the cluster was asked.
		if b := ParseKubeBinding(g.KubeBinding); b == nil || !sameBinding(*b, cand.binding) {
			return ErrEnrollment
		}
		if hosted, err := q.IsHostedGateway(ctx, org, g.ID); err != nil {
			return err
		} else if hosted {
			return ErrEnrollment
		}
		id := Identity{Org: org, Gateway: g.ID, Cert: ids.NewV7()}
		iss, err := s.issue(ctx, q, pub, id, "ENROLL", nil)
		if err != nil {
			return err
		}
		out = Enrolled{Certificate: iss.DER, CACertificate: s.ca.Certificate(), Gateway: g.ID, Org: org, GatewayAPIURL: s.gatewayAPIURL}
		return record(ctx, tx, gatewayActor(id), auditkind.GatewayEnrolled, g.ID, map[string]string{
			"certificate_id": id.Cert.String(), "key_thumbprint": iss.Thumbprint, "enrolled_with": "kubernetes_token",
			"cluster": cand.cluster, "namespace": ns, "service_account_name": sa, "pod_name": pod.Name, "pod_uid": pod.UID,
		})
	})
	return out, err
}

// kubeCandidate finds the one active gateway bound to (cluster, ns, sa) in a
// cluster the org may use.
func (s *Service) kubeCandidate(ctx context.Context, org ids.OrgID, ns, sa string) (kubeCandidate, error) {
	var found []kubeCandidate
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, cl := range s.kube.names {
			if !s.kube.clusters.Allowed(cl, org) {
				continue
			}
			rows, err := q.ListGatewaysForKubeBinding(ctx, dbq.ListGatewaysForKubeBindingParams{
				OrgID: org, Cluster: cl, Namespace: ns, ServiceAccountName: sa,
			})
			if err != nil {
				return err
			}
			for _, g := range rows {
				if b := ParseKubeBinding(g.KubeBinding); b != nil {
					found = append(found, kubeCandidate{cluster: cl, gateway: g.ID, binding: *b})
				}
			}
		}
		return nil
	})
	if err != nil {
		return kubeCandidate{}, err
	}
	if len(found) != 1 {
		return kubeCandidate{}, ErrEnrollment // none, or ambiguous: fail closed
	}
	return found[0], nil
}

// verify runs TokenReview and reads the bound pod.
func (k *gatewayKube) verify(ctx context.Context, org ids.OrgID, c kubeCandidate, token string) (issuers.Pod, error) {
	aud := labels.GatewayAudience(org)
	rv, err := k.review.Review(ctx, c.cluster, token, aud)
	if err != nil {
		return issuers.Pod{}, ErrEnrollment
	}
	b := c.binding
	switch {
	case !rv.Authenticated, !slices.Contains(rv.Audiences, aud),
		rv.Username != "system:serviceaccount:"+b.Namespace+":"+b.ServiceAccountName,
		rv.UID != b.ServiceAccountUID, rv.PodName == "", rv.PodUID == "":
		return issuers.Pod{}, ErrEnrollment
	}
	pod, err := k.review.Pod(ctx, c.cluster, b.Namespace, rv.PodName)
	if err != nil {
		return issuers.Pod{}, ErrEnrollment
	}
	if pod.Namespace != b.Namespace || pod.Name != rv.PodName || pod.UID != rv.PodUID || pod.Phase != "Running" || len(pod.ImageIDs) != 1 {
		return issuers.Pod{}, ErrEnrollment
	}
	m := imageDigest.FindStringSubmatch(pod.ImageIDs[0])
	if m == nil || (len(b.ImageDigests) > 0 && !slices.Contains(b.ImageDigests, m[1])) {
		return issuers.Pod{}, ErrEnrollment
	}
	return pod, nil
}

func sameBinding(a, b KubeBinding) bool {
	return a.Cluster == b.Cluster && a.Namespace == b.Namespace && a.ServiceAccountName == b.ServiceAccountName &&
		a.ServiceAccountUID == b.ServiceAccountUID && slices.Equal(a.ImageDigests, b.ImageDigests)
}
