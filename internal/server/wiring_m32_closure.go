// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/kube"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The M32 closure stream's wiring (G0 M32 D970, D970a–c, D973, D973a):
// KubernetesService, called by the edge of an agent pod and authenticated
// by PAP/1 like WorkloadService.

// kubernetesProcedures are KubernetesService's procedures: workload
// procedures, authenticated in their handler, never plan-gated (HR-357),
// so they have no plan-gate class. Edition: platform attestation's
// (PN-002.2, Community).
var kubernetesProcedures = map[string]td.Permission{
	pantherclawv1connect.KubernetesServiceIssueClosureNonceProcedure: td.PermWorkloadRun,
	pantherclawv1connect.KubernetesServiceSubmitClosureProcedure:     td.PermWorkloadRun,
	pantherclawv1connect.KubernetesServiceStartPodRunProcedure:       td.PermWorkloadRun,
}

func init() { maps.Copy(procedurePermissions, kubernetesProcedures) }

// registerKubernetesClosure serves KubernetesService.
func registerKubernetesClosure(rs *connect.Server, d apiDeps, workload *workloadrpc.Workload, runs *runsapp.Service) error {
	kc, err := kube.NewClient(d.clusters, attestTimeout)
	if err != nil {
		return err
	}
	pantherclawv1connect.RegisterKubernetesServiceHandler(rs, &kubeClosures{
		pool: d.pool, workload: workload, kube: kc, admission: d.admission, runs: runs, clk: clock.System{},
		coverage: &coverage.Service{Pool: d.pool, Freshness: d.freshness},
	})
	return nil
}

// kubeReader is what the closure reads from a cluster with its reviewer
// credential (kube.Client).
type kubeReader interface {
	PodImages(ctx context.Context, cluster, namespace, name string) (kube.PodImages, error)
	NetworkPolicies(ctx context.Context, cluster, namespace string) ([]kube.NetworkPolicy, error)
}

type kubeClosures struct {
	pantherclawv1connect.UnimplementedKubernetesServiceHandler
	pool      *db.Pool
	workload  *workloadrpc.Workload
	kube      kubeReader
	admission AdmissionConfig
	coverage  *coverage.Service
	runs      *runsapp.Service
	clk       clock.Clock
}

// Refusals.
var (
	errKubeSigner = pcerr.New(pcerr.PermissionDenied, "K8S_NOT_KUBERNETES_INSTANCE",
		"the caller is not an L2 instance enrolled by Kubernetes attestation through an active issuer entry")
	errKubeNamespace = pcerr.New(pcerr.PermissionDenied, "K8S_NAMESPACE",
		"the namespace is not the one the caller was attested in")
	errKubePod = pcerr.New(pcerr.PermissionDenied, "K8S_POD_NAME",
		"the pod name is not the one the caller was attested for")
	errKubeNoRunGrant = pcerr.New(pcerr.FailedPrecondition, "K8S_NO_RUN_GRANT",
		"the caller's issuer entry has no run grant")
	errKubeReport = pcerr.New(pcerr.InvalidArgument, "K8S_CLOSURE_REJECTED", "the closure report was refused")
)

func rejectReport(why string) error {
	return pcerr.Wrap(errors.New(why), pcerr.InvalidArgument, errKubeReport.Reason(), errKubeReport.Message()+": "+why)
}

// kubeSigner is an authenticated caller: its instance, the active revision
// of the issuer entry it was attested by, that entry's binding and the pod
// it was last attested for.
type kubeSigner struct {
	inst    pap.Instance
	row     dbq.PcAgentInstance
	rev     dbq.PcTrustedIssuer
	binding issuers.KubernetesBinding
	pod     string
}

// signer loads the caller and refuses anything but an admitted L2 instance
// enrolled by Kubernetes attestation whose entry is still active.
func (s *kubeClosures) signer(ctx context.Context, q *dbq.Queries, in pap.Instance) (kubeSigner, error) {
	row, err := q.GetInstance(ctx, in.Org, in.Instance)
	if db.IsNoRows(err) {
		return kubeSigner{}, errKubeSigner
	} else if err != nil {
		return kubeSigner{}, err
	}
	if row.AgentID != in.Agent || row.State != "ADMITTED" || row.EnrolledVia != "attestation" || row.AttLevel < 2 ||
		row.IssuerRevisionID == nil || row.AttestedUntil == nil || !row.AttestedUntil.After(s.clk.Now()) {
		return kubeSigner{}, errKubeSigner
	}
	rev, err := q.ActiveRevisionFor(ctx, in.Org, *row.IssuerRevisionID)
	if db.IsNoRows(err) {
		return kubeSigner{}, errKubeSigner
	} else if err != nil {
		return kubeSigner{}, err
	}
	var b struct {
		Kubernetes *issuers.KubernetesBinding `json:"kubernetes"`
	}
	if rev.Kind != "kubernetes" || json.Unmarshal(rev.Binding, &b) != nil || b.Kubernetes == nil ||
		b.Kubernetes.Cluster == "" || b.Kubernetes.Namespace == "" {
		return kubeSigner{}, errKubeSigner
	}
	pod, err := q.LatestAttestedPodName(ctx, in.Org, in.Instance)
	if db.IsNoRows(err) || (err == nil && pod == "") {
		return kubeSigner{}, errKubeSigner
	} else if err != nil {
		return kubeSigner{}, err
	}
	return kubeSigner{inst: in, row: row, rev: rev, binding: *b.Kubernetes, pod: pod}, nil
}

// IssueClosureNonce implements KubernetesServiceHandler.
func (s *kubeClosures) IssueClosureNonce(ctx context.Context, req *pantherclawv1.IssueClosureNonceRequest) (*pantherclawv1.IssueClosureNonceResponse, error) {
	in, err := s.workload.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	var out *pantherclawv1.IssueClosureNonceResponse
	err = s.pool.InTenantTx(ctx, in.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sg, err := s.signer(ctx, q, in)
		if err != nil {
			return err
		}
		if req.GetNamespace() != sg.binding.Namespace {
			return errKubeNamespace
		}
		// Only a probe pod gets a nonce (D1218 L2): its edge and probe
		// images are checked first, and it holds at most
		// maxOutstandingNonces unused ones.
		if _, err := s.podDigests(ctx, sg); err != nil {
			return err
		}
		if err := q.LockKubeClosureNonces(ctx, in.Org.UUID(), in.Instance); err != nil {
			return err
		}
		n, err := q.CountOutstandingKubeClosureNonces(ctx, in.Org, in.Instance)
		if err != nil {
			return err
		}
		if n >= maxOutstandingNonces {
			return rejectReport(fmt.Sprintf("the pod already holds %d unused nonces", n))
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		row, err := q.IssueKubeClosureNonce(ctx, dbq.IssueKubeClosureNonceParams{
			OrgID: in.Org, Nonce: nonce, Cluster: sg.binding.Cluster, Namespace: sg.binding.Namespace, InstanceID: in.Instance,
		})
		if err != nil {
			return err
		}
		out = &pantherclawv1.IssueClosureNonceResponse{
			Nonce: base64.RawURLEncoding.EncodeToString(nonce), ExpireTime: timestamppb.New(row.ExpiresAt),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.workload.SetNonce(ctx, in)
	return out, nil
}

// StartPodRun implements KubernetesServiceHandler (D973, D973a): the pod's
// run, launched by its instance under the issuer entry's run grant.
func (s *kubeClosures) StartPodRun(ctx context.Context, req *pantherclawv1.StartPodRunRequest) (*pantherclawv1.StartPodRunResponse, error) {
	in, err := s.workload.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	var run runsapp.Run
	err = s.pool.InTenantTx(ctx, in.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sg, err := s.signer(ctx, q, in)
		if err != nil {
			return err
		}
		if sg.rev.RunGrantID == nil {
			return errKubeNoRunGrant
		}
		if req.GetPodName() != sg.pod {
			return errKubePod
		}
		run, err = s.runs.StartForWorkloadTx(ctx, tx, runsapp.WorkloadStart{
			Org: in.Org, AgentID: in.Agent, Instance: in.Instance, IssuerRevision: sg.rev.ID, IssuerEntry: sg.rev.EntryID,
			RunGrant: *sg.rev.RunGrantID, PodName: sg.pod,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.workload.SetNonce(ctx, in)
	return &pantherclawv1.StartPodRunResponse{RunId: run.ID.String()}, nil
}

// SubmitClosure implements KubernetesServiceHandler (D970, D970b, D970c).
func (s *kubeClosures) SubmitClosure(ctx context.Context, req *pantherclawv1.SubmitClosureRequest) (*pantherclawv1.SubmitClosureResponse, error) {
	in, err := s.workload.Authenticate(ctx)
	if err != nil {
		return nil, err
	}
	var out *pantherclawv1.SubmitClosureResponse
	err = s.pool.InTenantTx(ctx, in.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.submit(ctx, tx, in, req.GetReportJws())
		return err
	})
	if err != nil {
		return nil, err
	}
	s.workload.SetNonce(ctx, in)
	return out, nil
}

func (s *kubeClosures) submit(ctx context.Context, tx db.TenantTx, in pap.Instance, compact string) (*pantherclawv1.SubmitClosureResponse, error) {
	q := dbq.New(tx)
	sg, err := s.signer(ctx, q, in)
	if err != nil {
		return nil, err
	}
	r, issued, err := s.verifyReport(ctx, q, sg, compact)
	if err != nil {
		return nil, err
	}
	if err := s.kindAllowed(ctx, q, sg, r.Kind); err != nil {
		return nil, err
	}
	if slices.ContainsFunc(r.Results, func(x report.Result) bool { return x.Target == "" }) {
		// Every kubernetes catalog result names its target (D1218a N1).
		return nil, rejectReport("a result without its target")
	}
	pod, err := s.podDigests(ctx, sg)
	if err != nil {
		return nil, err
	}
	digests := pod.Digests
	results := probeResults(r.Results)
	own, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	probes := slices.Clone(results)
	var checks []covdomain.ConfigCheck
	var verdict covdomain.Verdict
	var passed bool
	if r.Kind == report.KindControl {
		// The control twin, in the release namespace: every twin reachable.
		passed = len(results) > 0 && !slices.ContainsFunc(results, func(p covdomain.ProbeResult) bool {
			return !p.Passed() || p.Role != covdomain.RolePositiveControl
		})
		for _, p := range results {
			if !p.Passed() {
				verdict.Failed = append(verdict.Failed, p.Name)
			}
		}
	} else {
		if checks, err = s.checks(ctx, q, sg); err != nil {
			return nil, err
		}
		twins, err := s.twins(ctx, q, in.Org, sg.binding.Cluster)
		if err != nil {
			return nil, err
		}
		if err := targetsMatch(results, pod.HostIP, twins); err != nil {
			return nil, err
		}
		probes = append(probes, twins...)
		verdict = covdomain.EvaluateIn(covdomain.ContainmentKubernetes, probes, checks)
		passed = verdict.Passed
	}
	result := "FAILED"
	if passed {
		result = "PASSED"
	}
	sum := sha256.Sum256([]byte(compact))
	now := s.clk.Now()
	kc, err := q.InsertKubeClosureWithResults(ctx, dbq.InsertKubeClosureWithResultsParams{
		OrgID: in.Org, ID: ids.NewV7(), Cluster: sg.binding.Cluster, Namespace: sg.binding.Namespace, InstanceID: in.Instance,
		Kind: r.Kind, ReportDigest: "sha256:" + hex.EncodeToString(sum[:]), Result: result, EvaluatedAt: now, Results: own,
	})
	if db.IsNoRows(err) {
		return nil, rejectReport("the report was already recorded")
	} else if err != nil {
		return nil, err
	}
	out := &pantherclawv1.SubmitClosureResponse{
		KubeClosureId: kc.ID.String(), Kind: r.Kind, Passed: passed, Failed: verdict.Failed,
		ExpireTime: timestamppb.New(kc.ExpiresAt),
	}
	if r.Kind == report.KindSandbox {
		if out.Closures, err = s.record(ctx, tx, q, sg, r, kc, issued, probes, checks, digests, sum); err != nil {
			return nil, err
		}
	}
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: auditkind.KubernetesClosureRecorded, Actor: evdomain.Actor{Type: "instance", ID: in.Instance.String()},
		Outcome: audit.Success, Object: &audit.Object{Type: "kube_closure", ID: kc.ID.String()},
		Details: map[string]string{
			"cluster": sg.binding.Cluster, "namespace": sg.binding.Namespace, "kind": r.Kind, "result": result,
			"connections": strconv.Itoa(len(out.Closures)),
		},
	})
	return out, err
}

// verifyReport checks the report's signature with the caller's key, its
// shape, kind, runtime, namespace, pod and nonce (consumed once). It
// returns the report and when its nonce was issued.
func (s *kubeClosures) verifyReport(ctx context.Context, q *dbq.Queries, sg kubeSigner, compact string) (report.Report, time.Time, error) {
	var jwk jws.JWK
	if err := json.Unmarshal(sg.row.PublicJwk, &jwk); err != nil {
		return report.Report{}, time.Time{}, err
	}
	pub, err := jwk.Key()
	if err != nil {
		return report.Report{}, time.Time{}, err
	}
	r, err := report.Verify(compact, pub)
	switch {
	case err != nil:
		return report.Report{}, time.Time{}, rejectReport("signature or format")
	case r.Kind != report.KindSandbox && r.Kind != report.KindControl:
		return report.Report{}, time.Time{}, rejectReport("kind " + r.Kind)
	case r.Engine.Runtime != report.RuntimeKubernetes:
		return report.Report{}, time.Time{}, rejectReport("runtime")
	case r.Network.Name != sg.binding.Namespace:
		return report.Report{}, time.Time{}, rejectReport("the report's namespace is not the signer's")
	case r.Session != sg.pod:
		return report.Report{}, time.Time{}, rejectReport("the report's pod is not the signer's")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(r.Nonce)
	if err != nil || len(nonce) != 32 {
		return report.Report{}, time.Time{}, rejectReport("nonce")
	}
	n, err := q.ConsumeKubeClosureNonce(ctx, dbq.ConsumeKubeClosureNonceParams{
		OrgID: sg.inst.Org, Nonce: nonce, InstanceID: sg.inst.Instance, Namespace: sg.binding.Namespace,
	})
	if db.IsNoRows(err) {
		return report.Report{}, time.Time{}, rejectReport("the nonce is unknown, used, expired or another instance's")
	} else if err != nil {
		return report.Report{}, time.Time{}, err
	}
	return r, n.IssuedAt, nil
}

var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// digestOf is the sha256 digest an image id names: "sha256:…",
// "repo@sha256:…" or "docker-pullable://repo@sha256:…".
func digestOf(imageID string) string {
	i := strings.LastIndex(imageID, "sha256:")
	if i < 0 || !imageDigest.MatchString(imageID[i:]) {
		return ""
	}
	return imageID[i:]
}

// maxOutstandingNonces is how many unused, unexpired nonces one pod may
// hold (D1218 L2).
const maxOutstandingNonces = 8

// signerPod is what podDigests read from the signer's pod.
type signerPod struct {
	// Digests are the edge's and the probe's image digests.
	Digests []string
	// HostIP is the pod's status.hostIP.
	HostIP string
}

// podDigests reads the signer's pod, never the report's Images (D970b):
// exactly one edge native sidecar whose digest is on the edge list, and
// exactly one app container, the probe, whose digest is on the probe list.
// It returns the edge and probe digests and the pod's node IP.
func (s *kubeClosures) podDigests(ctx context.Context, sg kubeSigner) (signerPod, error) {
	p, err := s.kube.PodImages(ctx, sg.binding.Cluster, sg.binding.Namespace, sg.pod)
	if err != nil {
		return signerPod{}, err
	}
	if !p.Found {
		return signerPod{}, rejectReport("the signer's pod is not found")
	}
	var edges []string
	for name, ic := range p.Inits {
		if ic.Sidecar && name == labels.EdgeContainer {
			edges = append(edges, digestOf(ic.ImageID))
		}
	}
	if len(edges) != 1 || !slices.Contains(s.admission.EdgeImageDigests, edges[0]) {
		return signerPod{}, rejectReport("the pod's edge image is not on admission.edge_image_digests")
	}
	if len(p.Apps) != 1 {
		return signerPod{}, rejectReport("the pod has more than one app container")
	}
	var probe string
	for _, id := range p.Apps {
		probe = digestOf(id)
	}
	if probe == "" || !slices.Contains(s.admission.ProbeImageDigests, probe) {
		return signerPod{}, rejectReport("the pod's probe image is not on admission.probe_image_digests")
	}
	return signerPod{Digests: []string{edges[0], probe}, HostIP: p.HostIP}, nil
}

// kindAllowed binds a report's kind to where the signer runs (D1218 M2,
// item 5): a control report only from the chart's control probe, under
// its own service account's entry, in the configured release namespace,
// which the admission webhook does not enforce; a sandbox report never
// from the release namespace.
func (s *kubeClosures) kindAllowed(ctx context.Context, q *dbq.Queries, sg kubeSigner, kind string) error {
	rel := s.admission.ReleaseNamespace
	if kind == report.KindSandbox {
		if rel != "" && sg.binding.Namespace == rel {
			return rejectReport("a sandbox report from the release namespace")
		}
		return nil
	}
	if rel == "" || sg.binding.Namespace != rel || sg.binding.ServiceAccountName != labels.ProbeControlServiceAccount {
		return rejectReport("a control report from a pod other than the release namespace's control probe")
	}
	_, err := q.GetKubeAdmissionSeen(ctx, sg.inst.Org, sg.binding.Cluster, rel)
	switch {
	case err == nil:
		return rejectReport("a control report from an enforced namespace")
	case !db.IsNoRows(err):
		return err
	}
	return nil
}

// Fixed targets of the kubernetes catalog (internal/sandbox/probe).
var kubeFixedTargets = map[string][]string{
	covdomain.ProbeDirectHTTPS: {"1.1.1.1:443"},
	covdomain.ProbeDNSExternal: {"udp 8.8.8.8:53", "tcp 8.8.8.8:53"},
	covdomain.ProbeMetadata:    {"169.254.169.254:80", "[fd00:ec2::254]:80"},
	covdomain.ProbeIPv6:        {"an IPv6 address or default route"},
}

// Probes whose targets are the control twin's (same cluster, same chart
// values), and those on the pod's own node.
var (
	kubeTwinTargets = []string{covdomain.ProbeKubeAPI, covdomain.ProbeServiceOther, covdomain.ProbeDNSCluster}
	kubeNodePorts   = map[string][]string{covdomain.ProbeKubelet: {"10250", "10255"}, covdomain.ProbeNodeIP: {"22", "443"}}
)

// targetsMatch checks the target of every passing probe result of a
// sandbox report against what the server knows (D1218 M2): kubelet and
// node_ip against the signer pod's status.hostIP, kube_api, service_other
// and dns_cluster against the targets of the same probe in the cluster's
// newest PASSED control closure, and the catalog's fixed targets. A result
// that did not pass overstates nothing and is not checked. Without a
// control closure the twin-checked probes close nothing, so their targets
// are not checked.
func targetsMatch(results []covdomain.ProbeResult, hostIP string, twins []covdomain.ProbeResult) error {
	control := map[string][]string{}
	for _, t := range twins {
		control[t.Name] = append(control[t.Name], t.Target)
	}
	for _, r := range results {
		if r.Role != covdomain.RoleProbe || !r.Passed() {
			continue
		}
		var allowed []string
		switch {
		case kubeNodePorts[r.Name] != nil:
			if net.ParseIP(hostIP) == nil {
				return rejectReport("the signer pod's node IP is not known")
			}
			for _, p := range kubeNodePorts[r.Name] {
				allowed = append(allowed, net.JoinHostPort(hostIP, p))
			}
		case slices.Contains(kubeTwinTargets, r.Name):
			if len(twins) == 0 {
				continue
			}
			allowed = control[r.Name]
		case kubeFixedTargets[r.Name] != nil:
			allowed = kubeFixedTargets[r.Name]
		default:
			continue
		}
		if !slices.Contains(allowed, r.Target) {
			return rejectReport("the " + r.Name + " probe's target is not the pod's node, the control's or the catalog's")
		}
	}
	return nil
}

func probeResults(rs []report.Result) []covdomain.ProbeResult {
	out := make([]covdomain.ProbeResult, 0, len(rs))
	for _, r := range rs {
		out = append(out, covdomain.ProbeResult{Name: r.Name, Role: r.Role, Expect: r.Expect, Observed: r.Observed, Target: r.Target, Detail: r.Detail})
	}
	return out
}

// twins are the positive controls of the cluster's newest unexpired
// PASSED control closure (D970c); none when there is none, which closes
// nothing but ipv6 and metadata.
func (s *kubeClosures) twins(ctx context.Context, q *dbq.Queries, org ids.OrgID, cluster string) ([]covdomain.ProbeResult, error) {
	c, err := q.LatestKubeControlClosure(ctx, org, cluster)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var rs []covdomain.ProbeResult
	if err := json.Unmarshal(c.Results, &rs); err != nil {
		return nil, err
	}
	return slices.DeleteFunc(rs, func(p covdomain.ProbeResult) bool { return p.Role != covdomain.RolePositiveControl }), nil
}

// kubeAdmissionWindow is how recent the webhook's last decision must be.
const kubeAdmissionWindow = 24 * time.Hour

// checks are the server's own checks of the namespace (D967a, D970).
func (s *kubeClosures) checks(ctx context.Context, q *dbq.Queries, sg kubeSigner) ([]covdomain.ConfigCheck, error) {
	adm := covdomain.ConfigCheck{ID: covdomain.CheckAdmissionEnforced}
	seen, err := q.GetKubeAdmissionSeen(ctx, sg.inst.Org, sg.binding.Cluster, sg.binding.Namespace)
	switch {
	case db.IsNoRows(err):
		adm.Detail = "the admission webhook decided no pod of the namespace"
	case err != nil:
		return nil, err
	default:
		since := s.clk.Now().Add(-kubeAdmissionWindow)
		adm.OK = (seen.LastAllowedAt != nil && seen.LastAllowedAt.After(since)) ||
			(seen.LastDeniedAt != nil && seen.LastDeniedAt.After(since))
		if !adm.OK {
			adm.Detail = "the admission webhook decided no pod of the namespace within 24 hours"
		}
	}
	np := covdomain.ConfigCheck{ID: covdomain.CheckNetpolEgressGatewayOnly}
	nps, err := s.kube.NetworkPolicies(ctx, sg.binding.Cluster, sg.binding.Namespace)
	if err != nil {
		np.Detail = "the NetworkPolicies could not be read"
	} else if why := netpolGatewayOnly(nps, s.admission); why != "" {
		np.Detail = why
	} else {
		np.OK = true
	}
	return []covdomain.ConfigCheck{adm, np}, nil
}

// Labels of the D965 shape.
const (
	nsNameLabel    = "kubernetes.io/metadata.name"
	componentLabel = "app.kubernetes.io/component"
)

// netpolGatewayOnly checks the D965 shape of a namespace's NetworkPolicies
// against the chart's configuration and returns why it does not hold, or
// "" (D1218 M1). At least one policy selects every pod for Egress; every
// Egress rule names peers and numbered TCP ports only; and every
// combination of a rule's peers and ports is one the chart renders: the
// gateway pods of the release namespace on the gateway port, its api pods
// on the api port, or one of the configured apiEgressCIDRs, exactly, with
// no except, on the API Service port. Anything else fails closed,
// including a configuration that names no release namespace or ports.
func netpolGatewayOnly(nps []kube.NetworkPolicy, a AdmissionConfig) string {
	if a.ReleaseNamespace == "" || a.GatewayPort == 0 || a.APIPort == 0 {
		return "admission.release_namespace, gateway_port and api_port are not configured"
	}
	egress := func(np kube.NetworkPolicy) bool {
		if len(np.PolicyTypes) == 0 {
			return len(np.Egress) > 0
		}
		return slices.Contains(np.PolicyTypes, "Egress")
	}
	if !slices.ContainsFunc(nps, func(np kube.NetworkPolicy) bool { return np.PodSelector.Empty() && egress(np) }) {
		return "no NetworkPolicy selects every pod for Egress"
	}
	for _, np := range nps {
		if !egress(np) {
			continue
		}
		for i, r := range np.Egress {
			where := fmt.Sprintf("%s egress[%d]", np.Name, i)
			if len(r.To) == 0 || len(r.Ports) == 0 {
				return where + " allows every peer or every port"
			}
			ports := make([]int, 0, len(r.Ports))
			for _, p := range r.Ports {
				n, err := strconv.Atoi(p.Port)
				if (p.Protocol != "" && p.Protocol != "TCP") || err != nil || n < 1 || n > 65535 || p.EndPort != 0 {
					return where + " allows a port other than one numbered TCP port"
				}
				ports = append(ports, n)
			}
			for _, peer := range r.To {
				want, ok := peerPort(peer, a)
				if !ok {
					return where + " allows a peer other than the release namespace's gateway or api pods or a configured apiEgressCIDR"
				}
				if slices.ContainsFunc(ports, func(n int) bool { return n != want }) {
					return where + " allows a port other than the gateway port, the api port or the API Service port for its peer"
				}
			}
		}
	}
	return ""
}

// peerPort returns the one port the chart renders for peer, and false for
// a peer the chart never renders.
func peerPort(p kube.Peer, a AdmissionConfig) (int, bool) {
	if p.CIDR != "" {
		pr, err := netip.ParsePrefix(p.CIDR)
		if err != nil || len(p.Except) > 0 || p.PodSelector != nil || p.NamespaceSelector != nil || a.APIEgressPort == 0 {
			return 0, false
		}
		if !slices.ContainsFunc(a.APIEgressCIDRs, func(c string) bool {
			cp, err := netip.ParsePrefix(c)
			return err == nil && cp == pr
		}) {
			return 0, false
		}
		return a.APIEgressPort, true
	}
	ns, pod := p.NamespaceSelector, p.PodSelector
	if ns == nil || pod == nil || ns.Expressions > 0 || pod.Expressions > 0 || len(ns.MatchLabels) != 1 ||
		ns.MatchLabels[nsNameLabel] != a.ReleaseNamespace || len(pod.MatchLabels) != 1 {
		return 0, false
	}
	switch pod.MatchLabels[componentLabel] {
	case "gateway":
		return a.GatewayPort, true
	case "api":
		return a.APIPort, true
	}
	return 0, false
}

// kubeEngine stands in for the container engine on a kube closure: the
// coverage closure's engine columns are required, and a pod has no engine
// PantherClaw inspected.
var kubeEngine = covdomain.Engine{Version: "kubernetes", APIVersion: "1.0", Runtime: covdomain.RuntimeKubernetes}

// mappedHosts are the hosts the edge mediated in the report: the targets
// of its passed edge_mediated controls ("https://<host> through the
// edge").
func mappedHosts(rs []report.Result) []string {
	var out []string
	for _, r := range rs {
		if r.Name != covdomain.ProbeEdgeMediated || r.Role != report.RolePositive || !r.Passed() {
			continue
		}
		rest, ok := strings.CutPrefix(r.Target, "https://")
		host, _, _ := strings.Cut(rest, " ")
		host = strings.ToLower(host)
		if ok && host != "" && !strings.ContainsAny(host, "/:@") && !slices.Contains(out, host) {
			out = append(out, host)
		}
	}
	return out
}

// record records the coverage closure of every connection mapped to a host
// the edge mediated (D970). A connection whose binding changed since the
// nonce was issued, or that has none, gets none.
func (s *kubeClosures) record(ctx context.Context, tx db.TenantTx, q *dbq.Queries, sg kubeSigner, r report.Report,
	kc dbq.PcKubeClosure, issued time.Time, probes []covdomain.ProbeResult, checks []covdomain.ConfigCheck, digests []string, sum [32]byte,
) ([]*pantherclawv1.KubernetesConnectionClosure, error) {
	hosts := mappedHosts(r.Results)
	if len(hosts) == 0 {
		return nil, nil
	}
	conns, err := q.KubeMappedConnections(ctx, sg.inst.Org, hosts)
	if err != nil {
		return nil, err
	}
	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, err
	}
	config := sha256.Sum256(checksJSON)
	verdict := covdomain.EvaluateIn(covdomain.ContainmentKubernetes, probes, checks)
	var out []*pantherclawv1.KubernetesConnectionClosure
	for _, conn := range conns {
		b, err := q.CoverageBinding(ctx, sg.inst.Org, conn)
		if db.IsNoRows(err) || (err == nil && b.PackageVersionID == nil) {
			continue
		} else if err != nil {
			return nil, err
		}
		id, err := s.coverage.RecordClosure(ctx, tx, covdomain.Closure{
			Agent: sg.inst.Agent, Connection: conn, KubeClosure: kc.ID, SessionStartedAt: issued, ObservedAt: kc.EvaluatedAt,
			Probes: probes, ConfigChecks: checks, SigningKeyJKT: sg.row.Jkt, ServerNonce: r.Nonce, ResultsSHA256: sum,
			Engine: kubeEngine, ImageDigests: digests, ConfigSHA256: config,
			Bound: covdomain.Bound{
				ConnectionRevision: b.Revision, Gateway: b.GatewayID, PackageVersion: *b.PackageVersionID,
				CredentialVersion: b.CredentialVersion,
			},
		})
		switch {
		case errors.Is(err, coverage.ErrClosureStale), errors.Is(err, coverage.ErrNoBinding):
			continue
		case err != nil:
			return nil, err
		}
		out = append(out, &pantherclawv1.KubernetesConnectionClosure{
			ConnectionId: conn.String(), ClosureId: id.String(), Passed: verdict.Passed, Failed: verdict.Failed,
		})
	}
	return out, nil
}
