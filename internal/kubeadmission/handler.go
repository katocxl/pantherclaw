// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package kubeadmission is the Kubernetes validating admission webhook (G0
// M32 D967, D967a, HR-735): POST /admission/v1/{cluster}/{org}/{secret}. A
// configured cluster's API server calls it for every pod CREATE and
// pods/ephemeralcontainers UPDATE in a namespace labeled
// pantherclaw.dev/protect=enforce for the org. It fails closed: anything it
// cannot decide is refused (K8S_UNAVAILABLE), and the webhook
// configuration's failurePolicy is Fail.
package kubeadmission

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	json "encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/decision"
	"github.com/katocxl/pantherclaw/internal/kubeadmission/review"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/config"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

const (
	// Path is the route prefix; the cluster, org and secret follow.
	Path = "/admission/v1/"
	// PerMinute bounds the requests of one client address (the ticket
	// webhook's limit; a cluster's API servers send from a few addresses).
	PerMinute = 1200
	// MaxBody bounds a review's body.
	MaxBody = 1 << 20
	// MinSecretBytes is the shortest webhook secret accepted.
	MinSecretBytes = 32
	// SecretReread is how often a cluster's secret file is read again.
	SecretReread = time.Minute
	// Throttle is the most often one (org, cluster, namespace, code) deny
	// is audited and one (org, cluster, namespace, outcome) seen row is
	// written.
	Throttle = time.Minute
)

// actor is the audit actor of the webhook's decisions.
var actor = evdomain.Actor{Type: "system", ID: "kubernetes-admission"}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Config configures a Handler.
type Config struct {
	Clusters    *kube.Directory
	Pool        *db.Pool
	EdgeDigests []string
	// Limiter bounds each client address; nil: PerMinute per address.
	Limiter *httpx.Limiter
	Clock   clock.Clock
	Log     *slog.Logger
}

// Handler serves the webhook.
type Handler struct {
	clusters    *kube.Directory
	pool        *db.Pool
	edgeDigests []string
	limiter     *httpx.Limiter
	clk         clock.Clock
	log         *slog.Logger
	secrets     *secretCache
	audits      *throttle
	seen        *throttle
}

// New returns the webhook handler.
func New(cfg Config) *Handler {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	lim := cfg.Limiter
	if lim == nil {
		lim = httpx.NewLimiter(PerMinute, time.Minute, clk)
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{
		clusters: cfg.Clusters, pool: cfg.Pool, edgeDigests: cfg.EdgeDigests, limiter: lim, clk: clk, log: log,
		secrets: &secretCache{entries: map[string]secretEntry{}},
		audits:  newThrottle(Throttle), seen: newThrottle(Throttle),
	}
}

// Mount adds the route to mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+Path+"{cluster}/{org}/{secret}", h.serve)
}

// notFound is every refusal of the path: 404 with an empty body.
func notFound(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }

func (h *Handler) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !h.limiter.AllowRequest(r) {
		telemetry.RateLimited(ctx, telemetry.ScopeKubernetesAdmission)
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	cluster := r.PathValue("cluster")
	cc, ok := h.clusters.Get(cluster)
	if !ok {
		notFound(w)
		return
	}
	org, err := ids.Parse[ids.Org](r.PathValue("org"))
	if err != nil || !h.clusters.Allowed(cluster, org) {
		notFound(w)
		return
	}
	if !h.secrets.matches(ctx, h.log, cc, r.PathValue("secret"), h.clk.Now()) {
		notFound(w)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	rv, err := review.Parse(body)
	if err != nil {
		http.Error(w, "not an admission.k8s.io/v1 AdmissionReview request", http.StatusBadRequest)
		return
	}
	code := h.decide(ctx, cluster, org, rv.Request)
	allowed := code == ""
	var status *review.Status
	if !allowed {
		status = &review.Status{Code: http.StatusForbidden, Reason: code, Message: decision.Message(code)}
	}
	out, err := json.Marshal(review.Answer(rv.Request, allowed, status))
	if err != nil {
		http.Error(w, "try again", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out) //nolint:gosec // G705: a JSON AdmissionReview served as application/json, not HTML
}

// decide returns "" to allow or the refusal code, and records the decision.
func (h *Handler) decide(ctx context.Context, cluster string, org ids.OrgID, req *review.Request) string {
	var pod *review.Pod
	code, namespace := h.evaluate(ctx, cluster, org, req, &pod)
	outcome, metricCode := "allowed", decision.CodeAllowed
	if code != "" {
		outcome, metricCode = "denied", code
	}
	telemetry.KubernetesAdmission(ctx, outcome, metricCode)
	if req.IsDryRun() || !dnsLabel.MatchString(namespace) {
		return code
	}
	if err := h.record(ctx, cluster, org, namespace, req, pod, code); err != nil {
		h.log.WarnContext(ctx, "kubeadmission.record_failed", slog.String("cluster", cluster),
			slog.String("org", org.String()), slog.Any("error", err))
		if code == "" {
			// Fail closed: an allow that could not be recorded is not
			// given (D967: any internal error denies).
			code = decision.CodeUnavailable
		}
	}
	return code
}

// evaluate applies D967 to one request and returns the code and the
// namespace it is about.
func (h *Handler) evaluate(ctx context.Context, cluster string, org ids.OrgID, req *review.Request, podOut **review.Pod) (string, string) {
	namespace := req.Namespace
	if req.Resource.Group != "" || req.Resource.Resource != "pods" {
		return decision.CodeUnavailable, namespace
	}
	switch {
	case req.SubResource == "ephemeralcontainers" && req.Operation == review.OperationUpdate:
		return decision.CodeEphemeral, namespace
	case req.SubResource != "" || req.Operation != review.OperationCreate:
		return decision.CodeUnavailable, namespace
	}
	pod, err := review.ParsePod(req.Object)
	if err != nil {
		return decision.CodeUnavailable, namespace
	}
	*podOut = pod
	if namespace == "" {
		namespace = pod.Metadata.Namespace
	}
	if !dnsLabel.MatchString(namespace) {
		return decision.CodeUnavailable, namespace
	}
	entries, err := h.entries(ctx, cluster, org, namespace, decision.ServiceAccount(pod))
	if err != nil {
		h.log.WarnContext(ctx, "kubeadmission.lookup_failed", slog.String("cluster", cluster),
			slog.String("org", org.String()), slog.Any("error", err))
		return decision.CodeUnavailable, namespace
	}
	return decision.Pod(decision.Input{Org: org, Pod: pod, Entries: entries, EdgeDigests: h.edgeDigests}), namespace
}

// entries are the bindings of the active kubernetes entries for the
// service account (ListKubernetesIssuersFor).
func (h *Handler) entries(ctx context.Context, cluster string, org ids.OrgID, namespace, sa string) ([]issuers.KubernetesBinding, error) {
	var out []issuers.KubernetesBinding
	err := h.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListKubernetesIssuersFor(ctx, dbq.ListKubernetesIssuersForParams{
			OrgID: org, Cluster: cluster, Namespace: namespace, ServiceAccountName: sa,
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			var b struct {
				Kubernetes *issuers.KubernetesBinding `json:"kubernetes"`
			}
			if err := json.Unmarshal(r.Binding, &b); err != nil || b.Kubernetes == nil || b.Kubernetes.Validate() != nil {
				continue // a malformed entry admits nothing
			}
			k := *b.Kubernetes
			if k.Cluster == cluster && k.Namespace == namespace && k.ServiceAccountName == sa {
				out = append(out, k)
			}
		}
		return nil
	})
	return out, err
}

// record writes the seen row (D967a) and, for a deny, the audit record,
// each at most once a minute per key. A failed write frees its key again.
func (h *Handler) record(ctx context.Context, cluster string, org ids.OrgID, namespace string, req *review.Request, pod *review.Pod, code string) error {
	now := h.clk.Now()
	allowed := code == ""
	outcome := "allowed"
	if !allowed {
		outcome = "denied"
	}
	seenKey := org.String() + "|" + cluster + "|" + namespace + "|" + outcome
	auditKey := org.String() + "|" + cluster + "|" + namespace + "|" + code
	writeSeen := h.seen.take(seenKey, now)
	writeAudit := !allowed && h.audits.take(auditKey, now)
	if !writeSeen && !writeAudit {
		return nil
	}
	err := h.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if writeSeen {
			if err := dbq.New(tx).UpsertKubeAdmissionSeen(ctx, dbq.UpsertKubeAdmissionSeenParams{
				OrgID: org, Cluster: cluster, Namespace: namespace, Allowed: allowed, SeenAt: now,
			}); err != nil {
				return err
			}
		}
		if writeAudit {
			podName, sa := req.Name, ""
			if pod != nil {
				if pod.Metadata.Name != "" {
					podName = pod.Metadata.Name
				} else if podName == "" {
					podName = pod.Metadata.GenerateName
				}
				sa = decision.ServiceAccount(pod)
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: auditkind.KubernetesAdmissionDenied, Actor: actor, Outcome: audit.Denied, ReasonCode: code,
				Object: &audit.Object{Type: "kubernetes_namespace", ID: cluster + "/" + namespace},
				Details: map[string]string{
					"cluster": cluster, "namespace": namespace, "pod_name": clip(podName), "service_account": clip(sa), "code": code,
				},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if writeSeen {
			h.seen.release(seenKey, now)
		}
		if writeAudit {
			h.audits.release(auditKey, now)
		}
	}
	return err
}

// clip keeps an untrusted name within an audit detail's bound.
func clip(s string) string {
	if len(s) > 253 {
		return s[:253]
	}
	return s
}

// secretCache holds each cluster's webhook secret digest, re-read every
// SecretReread.
type secretCache struct {
	mu      sync.Mutex
	entries map[string]secretEntry
}

type secretEntry struct {
	path   string
	digest [32]byte
	ok     bool
	read   time.Time
}

// errShortSecret is a secret file below MinSecretBytes.
var errShortSecret = errors.New("kubeadmission: webhook secret is shorter than 32 bytes")

// matches compares the path secret with the cluster's in constant time. A
// cluster without a readable secret of at least 32 bytes matches nothing.
func (s *secretCache) matches(ctx context.Context, log *slog.Logger, cc kube.ClusterConfig, given string, now time.Time) bool {
	if cc.WebhookSecretFile == "" {
		return false
	}
	s.mu.Lock()
	e, ok := s.entries[cc.Name]
	if !ok || e.path != cc.WebhookSecretFile || now.Sub(e.read) >= SecretReread || now.Before(e.read) {
		e = secretEntry{path: cc.WebhookSecretFile, read: now}
		sec, err := config.ReadSecretFile(cc.WebhookSecretFile)
		if err == nil && len(sec.Reveal()) < MinSecretBytes {
			err = errShortSecret
		}
		if err != nil {
			log.WarnContext(ctx, "kubeadmission.secret_unreadable", slog.String("cluster", cc.Name), slog.Any("error", err))
		} else {
			e.digest, e.ok = sha256.Sum256(sec.Reveal()), true
		}
		s.entries[cc.Name] = e
	}
	s.mu.Unlock()
	got := sha256.Sum256([]byte(given))
	return subtle.ConstantTimeCompare(got[:], e.digest[:]) == 1 && e.ok
}

// throttle lets one key through at most once per every.
type throttle struct {
	mu    sync.Mutex
	every time.Duration
	last  map[string]time.Time
}

// maxThrottleKeys bounds the map; older keys are pruned past it.
const maxThrottleKeys = 10000

func newThrottle(every time.Duration) *throttle {
	return &throttle{every: every, last: map[string]time.Time{}}
}

// take reports whether key may pass at now, and if so records it.
func (t *throttle) take(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at, ok := t.last[key]; ok && now.Sub(at) < t.every && !now.Before(at) {
		return false
	}
	if len(t.last) >= maxThrottleKeys {
		for k, at := range t.last {
			if now.Sub(at) >= t.every || now.Before(at) {
				delete(t.last, k)
			}
		}
	}
	t.last[key] = now
	return true
}

// release forgets a take at now that did not complete.
func (t *throttle) release(key string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last[key].Equal(at) {
		delete(t.last, key)
	}
}
