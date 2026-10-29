// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Attestation is a platform token offered as L2 evidence (PAP-1 §3.3). It
// is verified, consumed once and never stored or logged (HR-143).
type Attestation struct {
	Kind  issuers.Kind
	Token string
}

// Verifier checks one preset's attestation token with its issuer's keys
// and returns the payload the issuer signed (issuerkeys.Fetcher). The
// preset's claims are checked afterwards, by the issuers package.
type Verifier interface {
	Verify(ctx context.Context, token string) ([]byte, error)
}

// ClusterReviewer asks a configured cluster's API server (kube.Client).
type ClusterReviewer interface {
	Review(ctx context.Context, cluster, token, audience string) (issuers.TokenReview, error)
	Pod(ctx context.Context, cluster, namespace, name string) (issuers.Pod, error)
}

// Attestors verify attestation tokens. A preset without its verifier
// refuses every attestation (fail closed).
type Attestors struct {
	GitHub Verifier
	// Kube calls the clusters that Clusters allows for an org.
	Kube     ClusterReviewer
	Clusters Clusters
	// GitLab is the operator-configured GitLab instances (D119).
	GitLab IssuerDirectory
}

// IssuerDirectory is a preset's operator-configured issuers, each with its
// own keys (issuerkeys.Directory). A tenant names one only through an
// entry, and only one configured for its org (HR-142).
type IssuerDirectory interface {
	Allowed(issuer string, org ids.OrgID) bool
	Verify(ctx context.Context, issuer string, org ids.OrgID, token string) ([]byte, error)
}

// WithAttestors sets the attestation verifiers and returns s.
func (s *Service) WithAttestors(a Attestors) *Service {
	s.att = a
	return s
}

// maxAttestation bounds an attestation token before anything decodes it.
const maxAttestation = 16 << 10

func attErr(detail error) error {
	if detail == nil {
		detail = errors.New("no match")
	}
	return fmt.Errorf("%w: %w", pap.Err(pap.CodeAttestationLow), detail)
}

// errAttestationReused is returned for a token whose replay key is already
// recorded (HR-143).
var errAttestationReused = fmt.Errorf("%w: attestation token reused", pap.Err(pap.CodeInvalidToken))

// AttestationOrg reads the org an attestation token's audience names,
// without verifying anything. It only picks the org whose nonces and proof
// store the request uses; the verified audience must then name the same
// org (HR-143). It returns the zero id unless exactly one audience is
// pantherclaw:<org>.
func AttestationOrg(token string) ids.OrgID {
	payload, err := unverifiedPayload(token)
	if err != nil {
		return ids.OrgID{}
	}
	var c struct {
		Aud jsontext.Value `json:"aud"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ids.OrgID{}
	}
	var found ids.OrgID
	for _, a := range audiences(c.Aud) {
		s, ok := strings.CutPrefix(a, "pantherclaw:")
		if !ok {
			continue
		}
		org, err := ids.Parse[ids.Org](s)
		if err != nil || !found.IsZero() {
			return ids.OrgID{}
		}
		found = org
	}
	return found
}

func audiences(v jsontext.Value) []string {
	var one string
	if json.Unmarshal(v, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(v, &many) == nil {
		return many
	}
	return nil
}

// unverifiedPayload decodes a compact JWS payload without checking it.
func unverifiedPayload(token string) ([]byte, error) {
	if len(token) > maxAttestation {
		return nil, errors.New("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWS")
	}
	return base64.RawURLEncoding.Strict().DecodeString(parts[1])
}

// attested is an attestation token verified and matched to one active
// issuer revision.
type attested struct {
	rev    dbq.PcTrustedIssuer
	match  issuers.Match
	issuer string
	key    [32]byte
	window issuers.Window
	claims map[string]string
}

// attest verifies a and matches it against org's active entries of its
// kind. It calls the issuer or the cluster, so it runs outside any
// transaction; the replay key is recorded by the transaction that uses the
// attestation, after this verification (HR-143). An issuer or cluster
// that cannot answer refuses the attestation (fail closed).
func (s *Service) attest(ctx context.Context, org ids.OrgID, a Attestation) ([]attested, error) {
	if !issuers.Known(a.Kind) {
		// An unknown kind is refused, never mapped to a preset (HR-465).
		return nil, attErr(fmt.Errorf("unknown preset %q", a.Kind))
	}
	if len(a.Token) > maxAttestation {
		return nil, attErr(errors.New("token too large"))
	}
	var revs []dbq.PcTrustedIssuer
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		revs, err = dbq.New(tx).ListActiveIssuers(ctx, org, string(a.Kind))
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	if len(revs) == 0 {
		return nil, attErr(errors.New("no active issuer entry of this kind"))
	}
	switch a.Kind {
	case issuers.KindGitHub:
		return s.attestGitHub(ctx, org, a.Token, revs)
	case issuers.KindKubernetes:
		return s.attestKubernetes(ctx, org, a.Token, revs)
	case issuers.KindGitLab:
		return s.attestGitLab(ctx, org, a.Token, revs)
	default:
		return nil, attErr(fmt.Errorf("unknown preset %q", a.Kind))
	}
}

func bindingOf(r dbq.PcTrustedIssuer) (Binding, error) {
	var b Binding
	err := json.Unmarshal(r.Binding, &b)
	return b, err
}

// attestGitLab verifies a GitLab CI ID token with the keys of the instance
// its iss names, which must be configured for org; that iss only picks the
// keys and is checked again, verified, against each entry (HR-461).
func (s *Service) attestGitLab(ctx context.Context, org ids.OrgID, token string, revs []dbq.PcTrustedIssuer) ([]attested, error) {
	if s.att.GitLab == nil {
		return nil, attErr(errors.New("no GitLab instance is configured"))
	}
	unverified, err := unverifiedPayload(token)
	if err != nil {
		return nil, attErr(err)
	}
	var head struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(unverified, &head); err != nil {
		return nil, attErr(err)
	}
	payload, err := s.att.GitLab.Verify(ctx, head.Issuer, org, token)
	if err != nil {
		return nil, attErr(err)
	}
	c, err := issuers.ParseGitLabClaims(payload)
	if err != nil {
		return nil, attErr(err)
	}
	w, err := issuers.ParseWindow(payload)
	if err == nil {
		err = w.Check(s.clk.Now())
	}
	if err != nil {
		return nil, attErr(err)
	}
	var out []attested
	var last error
	for _, r := range revs {
		b, err := bindingOf(r)
		if err != nil || b.GitLab == nil {
			continue
		}
		m, err := issuers.MatchGitLab(*b.GitLab, org, c)
		if err != nil {
			last = err
			continue
		}
		out = append(out, attested{
			rev: r, match: m, issuer: c.Issuer, key: issuers.ReplayKey(w.JTI, token), window: w,
			claims: withClaims(m.Binding, map[string]string{"ref": c.Ref, "sha": c.SHA, "pipeline_source": c.PipelineSource}),
		})
	}
	if len(out) == 0 {
		return nil, attErr(last)
	}
	return out, nil
}

func (s *Service) attestGitHub(ctx context.Context, org ids.OrgID, token string, revs []dbq.PcTrustedIssuer) ([]attested, error) {
	if s.att.GitHub == nil {
		return nil, attErr(errors.New("the GitHub preset is not configured"))
	}
	payload, err := s.att.GitHub.Verify(ctx, token)
	if err != nil {
		return nil, attErr(err)
	}
	c, err := issuers.ParseGitHubClaims(payload)
	if err != nil {
		return nil, attErr(err)
	}
	w, err := issuers.ParseWindow(payload)
	if err == nil {
		err = w.Check(s.clk.Now())
	}
	if err != nil {
		return nil, attErr(err)
	}
	var out []attested
	var last error
	for _, r := range revs {
		b, err := bindingOf(r)
		if err != nil || b.GitHub == nil {
			continue
		}
		m, err := issuers.MatchGitHub(*b.GitHub, org, c)
		if err != nil {
			last = err
			continue
		}
		out = append(out, attested{
			rev: r, match: m, issuer: issuers.GitHubIssuer, key: issuers.ReplayKey(w.JTI, token), window: w,
			claims: withClaims(m.Binding, map[string]string{"ref": c.Ref, "sha": c.SHA, "event_name": c.EventName}),
		})
	}
	if len(out) == 0 {
		return nil, attErr(last)
	}
	return out, nil
}

type kubeEntry struct {
	rev dbq.PcTrustedIssuer
	b   issuers.KubernetesBinding
}

func (s *Service) attestKubernetes(ctx context.Context, org ids.OrgID, token string, revs []dbq.PcTrustedIssuer) ([]attested, error) {
	if s.att.Kube == nil || s.att.Clusters == nil {
		return nil, attErr(errors.New("no Kubernetes cluster is configured"))
	}
	byCluster := map[string][]kubeEntry{}
	for _, r := range revs {
		b, err := bindingOf(r)
		if err != nil || b.Kubernetes == nil || !s.att.Clusters.Allowed(b.Kubernetes.Cluster, org) {
			continue // a cluster the operator no longer allows for the org attests nothing
		}
		byCluster[b.Kubernetes.Cluster] = append(byCluster[b.Kubernetes.Cluster], kubeEntry{r, *b.Kubernetes})
	}
	aud := issuers.Audience(org)
	var out []attested
	last := errors.New("no configured cluster authenticated the token")
	for _, cl := range slices.Sorted(maps.Keys(byCluster)) {
		rv, err := s.att.Kube.Review(ctx, cl, token, aud)
		if err != nil {
			return nil, attErr(err)
		}
		if !rv.Authenticated {
			continue
		}
		ns, ok := serviceAccountNamespace(rv.Username)
		entries := slices.DeleteFunc(slices.Clone(byCluster[cl]), func(e kubeEntry) bool { return e.b.Namespace != ns })
		if !ok || rv.PodName == "" || len(entries) == 0 {
			last = fmt.Errorf("cluster %s: no entry pins %q bound to a pod", cl, rv.Username)
			continue
		}
		pod, err := s.att.Kube.Pod(ctx, cl, ns, rv.PodName)
		if err != nil {
			return nil, attErr(err)
		}
		for _, e := range entries {
			m, err := issuers.MatchKubernetes(e.b, org, rv, pod)
			if err != nil {
				last = err
				continue
			}
			out = append(out, attested{
				rev: e.rev, match: m, issuer: e.b.Issuer(),
				claims: withClaims(m.Binding, map[string]string{"pod_name": pod.Name, "pod_uid": pod.UID, "image_digest": m.ReleaseDigest}),
			})
		}
	}
	if len(out) == 0 {
		return nil, attErr(last)
	}
	// TokenReview authenticated this exact token, so its payload is the
	// cluster's.
	payload, err := unverifiedPayload(token)
	if err != nil {
		return nil, attErr(err)
	}
	w, err := issuers.ParseWindow(payload)
	if err == nil {
		err = w.Check(s.clk.Now())
	}
	if err != nil {
		return nil, attErr(err)
	}
	for i := range out {
		out[i].window, out[i].key = w, issuers.ReplayKey(w.JTI, token)
	}
	return out, nil
}

// serviceAccountNamespace parses "system:serviceaccount:<namespace>:<name>".
func serviceAccountNamespace(username string) (string, bool) {
	rest, ok := strings.CutPrefix(username, "system:serviceaccount:")
	ns, name, ok2 := strings.Cut(rest, ":")
	return ns, ok && ok2 && ns != "" && name != ""
}

func withClaims(binding issuers.Binding, extra map[string]string) map[string]string {
	out := maps.Clone(map[string]string(binding))
	for k, v := range extra {
		if v != "" {
			out[k] = v
		}
	}
	return out
}

// choose picks the entry an attestation enrolls through, among those of
// agent when the enrollment token named one. Matches for several agents
// are ambiguous and refused; among one agent's entries an auto-admitting
// one wins, then the oldest entry.
func choose(cands []attested, agent *ids.UUID) (attested, error) {
	var pick *attested
	for i := range cands {
		c := &cands[i]
		switch {
		case agent != nil && c.rev.AgentID != *agent:
			continue
		case pick != nil && pick.rev.AgentID != c.rev.AgentID:
			return attested{}, attErr(errors.New("the attestation matches entries of more than one agent"))
		case pick == nil, c.rev.AutoAdmit && !pick.rev.AutoAdmit,
			c.rev.AutoAdmit == pick.rev.AutoAdmit && c.rev.EntryID.String() < pick.rev.EntryID.String():
			pick = c
		}
	}
	if pick == nil {
		return attested{}, attErr(errors.New("no entry of this agent matches"))
	}
	return *pick, nil
}

// reattest picks the attestation that renews r's L2: r enrolled through an
// entry that is still active, and the fresh token matches that entry's
// active revision with exactly the binding r enrolled with (HR-147).
func reattest(cands []attested, r dbq.PcAgentInstance, active *dbq.PcTrustedIssuer) (attested, error) {
	if r.Binding == nil || active == nil {
		return attested{}, attErr(errors.New("the instance did not enroll through an active issuer entry"))
	}
	var bound issuers.Binding
	if err := json.Unmarshal(r.Binding, &bound); err != nil {
		return attested{}, err
	}
	for _, c := range cands {
		if c.rev.ID == active.ID && c.match.Binding.Equal(bound) {
			return c, nil
		}
	}
	return attested{}, attErr(errors.New("binding claims differ from the instance's"))
}

// record consumes the attestation for instance (HR-143).
func (t attested) record(ctx context.Context, q *dbq.Queries, org ids.OrgID, instance ids.UUID) error {
	claims, err := json.Marshal(t.claims)
	if err != nil {
		return err
	}
	n, err := q.InsertAttestation(ctx, dbq.InsertAttestationParams{
		OrgID: org, ID: ids.NewV7(), InstanceID: instance, IssuerRevisionID: t.rev.ID, Issuer: t.issuer,
		TokenKey: t.key[:], Claims: claims, ReleaseDigest: optString(t.match.ReleaseDigest),
		IssuedAt: t.window.IssuedAt, ExpiresAt: t.window.ExpiresAt,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errAttestationReused
	}
	return nil
}
