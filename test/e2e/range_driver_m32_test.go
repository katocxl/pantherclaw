// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/kube/labels"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// kubeFixtures are the stacks turned into the M32 fixture, set up on a
// scenario's first kube.probe.
var kubeFixtures sync.Map // *stack → *kubeFixture

func (d *rangeDriver) kubeFixture() *kubeFixture {
	if f, ok := kubeFixtures.Load(d.s); ok {
		return f.(*kubeFixture)
	}
	f := setupKube(d.t, d.s)
	kubeFixtures.Store(d.s, f)
	d.t.Cleanup(func() { kubeFixtures.Delete(d.s) })
	return f
}

// kubeWorkload is a pod's workload identity held by the attacker: the key
// the pod's edge would hold, enrolled with the pod's projected token.
type kubeWorkload struct {
	key   ed25519.PrivateKey
	token string
	kc    pantherclawv1connect.KubernetesServiceClient
}

// enrolPod enrolls a fresh key with p's projected token and issues it a
// workload token, as the edge does at boot.
func (f *kubeFixture) enrolPod(p kubePod) (*kubeWorkload, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	w := &kubeWorkload{key: key}
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return nil, err
	}
	keyOnly := &http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: key}}
	wc := pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(keyOnly, f.s.apiURL)))
	en, err := wc.Enroll(context.Background(), &pb.EnrollRequest{PublicJwk: string(jwk), Attestation: &pb.Attestation{
		Kind: pb.AttestationKind_ATTESTATION_KIND_KUBERNETES, Token: f.cluster.token(p, labels.AgentAudience(f.s.org)),
	}})
	if err != nil {
		return nil, fmt.Errorf("enroll %s: %w", p.name, err)
	}
	if en.GetState() != pb.InstanceState_INSTANCE_STATE_ADMITTED {
		return nil, fmt.Errorf("enroll %s: %s", p.name, en.GetState())
	}
	iss, err := wc.IssueToken(context.Background(), &pb.IssueTokenRequest{Identifier: en.GetIdentifier()})
	if err != nil {
		return nil, fmt.Errorf("token %s: %w", p.name, err)
	}
	w.token = iss.GetWorkloadToken()
	withToken := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: func() string { return w.token }}}
	w.kc = pantherclawv1connect.NewKubernetesServiceClient(connect.NewClient(connecthttp.NewTransport(withToken, f.s.apiURL)))
	return w, nil
}

// submit signs rep for pod p in its namespace with key and nonce, and
// submits it with w's credentials.
func (w *kubeWorkload) submit(key ed25519.PrivateKey, p kubePod, nonce, kind string, results []report.Result) (*pb.SubmitClosureResponse, error) {
	now := time.Now().UTC()
	signed, err := report.Sign(key, report.Report{
		Format: report.Format, Session: p.name, Nonce: nonce, Kind: kind, StartedAt: now.Add(-time.Second), FinishedAt: now,
		Engine:  report.Engine{Version: "kubernetes", APIVersion: "1.0", Runtime: report.RuntimeKubernetes},
		Network: report.Network{Name: p.namespace}, Results: results,
	})
	if err != nil {
		return nil, err
	}
	return w.kc.SubmitClosure(context.Background(), &pb.SubmitClosureRequest{ReportJws: signed})
}

func (w *kubeWorkload) nonce(namespace string) (string, error) {
	n, err := w.kc.IssueClosureNonce(context.Background(), &pb.IssueClosureNonceRequest{Namespace: namespace})
	return n.GetNonce(), err
}

// closure takes a fresh nonce and submits a report of kind with results.
func (w *kubeWorkload) closure(p kubePod, kind string, results []report.Result) (*pb.SubmitClosureResponse, error) {
	n, err := w.nonce(p.namespace)
	if err != nil {
		return nil, err
	}
	return w.submit(w.key, p, n, kind, results)
}

// refused is the observation of a server refusal: its reason, the part
// of the message before the first colon.
func refused(err error) domain.Observation {
	var ce *connect.Error
	if errors.As(err, &ce) {
		reason, _, _ := strings.Cut(ce.Message(), ":")
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason, Detail: ce.Message()}
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Detail: err.Error()}
}

// kubeProbe runs kube.probe (G0 M32; RT-215..RT-219).
func (d *rangeDriver) kubeProbe(st domain.Step) (domain.Observation, error) {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	f := d.kubeFixture()
	switch w.Attack {
	case "pod_without_edge", "host_network", "exposed_token", "ephemeral_container", "guessed_webhook_path":
		return f.admissionAttack(d.t, w.Attack)
	case "pod_run_other_name", "pod_run_without_grant", "pod_run_not_kubernetes":
		return f.runAttack(d.t, w.Attack)
	case "gateway_token_reused", "gateway_other_service_account":
		return f.gatewayAttack(d.t, w.Attack)
	case "report_other_key", "report_nonce_replayed", "nonce_other_namespace", "probe_image_off_list",
		"edge_image_off_list", "report_other_pod", "nonce_expired", "nonce_flood", "closure_not_kubernetes", "control_from_agent_pod", "sandbox_from_release_namespace",
		"result_without_target":
		return f.forgeAttack(d.t, w.Attack)
	case "probe_target_forged":
		return f.forgedTarget(d.t)
	case "network_policy_open", "admission_not_seen", "probe_reached":
		return f.overstateAttack(d.t, w.Attack)
	}
	return domain.Observation{}, fmt.Errorf("unknown attack %q", w.Attack)
}

func (f *kubeFixture) admissionAttack(t *testing.T, attack string) (domain.Observation, error) {
	secret := f.secret
	pod := f.probePod(f.agentPod.edgeImage)
	spec := pod["spec"].(map[string]any)
	switch attack {
	case "pod_without_edge":
		pod = f.probePod("")
	case "host_network":
		spec["hostNetwork"] = true
	case "exposed_token":
		spec["automountServiceAccountToken"] = true
	case "guessed_webhook_path":
		secret = strings.Repeat("g", len(f.secret))
	case "ephemeral_container":
		return f.ephemeral(t)
	}
	code, allowed, reason := f.admit(t, secret, pod)
	switch {
	case code == http.StatusNotFound:
		return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "NOT_FOUND", Detail: "404"}, nil
	case code != http.StatusOK:
		return domain.Observation{}, fmt.Errorf("admission answered %d", code)
	case allowed:
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the pod was admitted"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason}, nil
}

// ephemeral asks the webhook to add an ephemeral container to the probe
// pod.
func (f *kubeFixture) ephemeral(t *testing.T) (domain.Observation, error) {
	code, allowed, reason := f.review(t, f.secret, "UPDATE", "ephemeralcontainers", f.probePod(f.agentPod.edgeImage))
	switch {
	case code != http.StatusOK:
		return domain.Observation{}, fmt.Errorf("admission answered %d", code)
	case allowed:
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the ephemeral container was admitted"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: reason}, nil
}

func (f *kubeFixture) runAttack(t *testing.T, attack string) (domain.Observation, error) {
	var (
		res *pb.StartPodRunResponse
		err error
	)
	switch attack {
	case "pod_run_other_name":
		w, werr := f.enrolPod(f.agentPod)
		if werr != nil {
			return domain.Observation{}, werr
		}
		res, err = w.kc.StartPodRun(context.Background(), &pb.StartPodRunRequest{PodName: "probe-chosen-by-the-agent"})
	case "pod_run_without_grant":
		w, werr := f.enrolPod(f.ctlPod)
		if werr != nil {
			return domain.Observation{}, werr
		}
		res, err = w.kc.StartPodRun(context.Background(), &pb.StartPodRunRequest{PodName: f.ctlPod.name})
	case "pod_run_not_kubernetes":
		kc := pantherclawv1connect.NewKubernetesServiceClient(connect.NewClient(connecthttp.NewTransport(
			&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: f.s.key, Token: func() string { return f.s.token }}}, f.s.apiURL)))
		res, err = kc.StartPodRun(context.Background(), &pb.StartPodRunRequest{PodName: f.agentPod.name})
	}
	if err != nil {
		return refused(err), nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "run " + res.GetRunId()}, nil
}

func (f *kubeFixture) gatewayAttack(t *testing.T, attack string) (domain.Observation, error) {
	var err error
	switch attack {
	case "gateway_token_reused":
		tok := f.cluster.token(f.gwPod, labels.GatewayAudience(f.s.org))
		if err := f.enrollGateway(t, tok); err != nil {
			return domain.Observation{}, fmt.Errorf("the first enrolment: %w", err)
		}
		err = f.enrollGateway(t, tok)
	case "gateway_other_service_account":
		// The probe pod's own token, minted for the gateway audience.
		err = f.enrollGateway(t, f.cluster.token(f.agentPod, labels.GatewayAudience(f.s.org)))
	}
	if err != nil {
		return refused(err), nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a gateway replica enrolled"}, nil
}

func (f *kubeFixture) forgeAttack(t *testing.T, attack string) (domain.Observation, error) {
	w, err := f.enrolPod(f.agentPod)
	if err != nil {
		return domain.Observation{}, err
	}
	results := sandboxResults(report.Blocked)
	var res *pb.SubmitClosureResponse
	switch attack {
	case "report_other_key":
		_, other, kerr := ed25519.GenerateKey(rand.Reader)
		if kerr != nil {
			return domain.Observation{}, kerr
		}
		n, nerr := w.nonce(f.agentPod.namespace)
		if nerr != nil {
			return domain.Observation{}, nerr
		}
		res, err = w.submit(other, f.agentPod, n, report.KindSandbox, results)
	case "report_nonce_replayed":
		n, nerr := w.nonce(f.agentPod.namespace)
		if nerr != nil {
			return domain.Observation{}, nerr
		}
		if _, err := w.submit(w.key, f.agentPod, n, report.KindSandbox, results); err != nil {
			return domain.Observation{}, fmt.Errorf("the first report: %w", err)
		}
		res, err = w.submit(w.key, f.agentPod, n, report.KindSandbox, results)
	case "nonce_other_namespace":
		_, err = w.nonce("pantherclaw")
	case "probe_image_off_list":
		p := f.agentPod
		p.name, p.uid, p.appImage = "probe-other-image", ids.NewV7().String(), "ghcr.io/acme/not-the-probe@sha256:"+strings.Repeat("f", 64)
		ow, oerr := f.enrolPod(p)
		if oerr != nil {
			return domain.Observation{}, oerr
		}
		res, err = ow.closure(p, report.KindSandbox, results)
	case "edge_image_off_list":
		// An edge sidecar running an image the webhook would not admit
		// (D1218 H1): the pod does not attest.
		p := f.agentPod
		p.name, p.uid, p.edgeImage = "probe-other-edge", ids.NewV7().String(), "ghcr.io/acme/not-the-edge@sha256:"+strings.Repeat("0", 64)
		if _, err := f.enrolPod(p); err != nil {
			// A PAP/1 refusal: "PAP/1: <code>".
			obs := refused(err)
			if code, ok := strings.CutPrefix(obs.Detail, "PAP/1: "); ok {
				obs.Reason, _, _ = strings.Cut(code, ":")
			}
			return obs, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "a pod with another edge image attested"}, nil
	case "report_other_pod":
		p := f.agentPod
		p.name = "probe-2"
		n, nerr := w.nonce(f.agentPod.namespace)
		if nerr != nil {
			return domain.Observation{}, nerr
		}
		res, err = w.submit(w.key, p, n, report.KindSandbox, results)
	case "nonce_expired":
		n, nerr := w.nonce(f.agentPod.namespace)
		if nerr != nil {
			return domain.Observation{}, nerr
		}
		f.expireNonces(t)
		res, err = w.submit(w.key, f.agentPod, n, report.KindSandbox, results)
	case "nonce_flood":
		// More outstanding nonces than a pod may hold (D1218 L2).
		for range 9 {
			if _, err = w.nonce(f.agentPod.namespace); err != nil {
				return refused(err), nil
			}
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "nine outstanding nonces"}, nil
	case "closure_not_kubernetes":
		kc := pantherclawv1connect.NewKubernetesServiceClient(connect.NewClient(connecthttp.NewTransport(
			&http.Client{Timeout: 10 * time.Second, Transport: &workloadclient.Transport{Key: f.s.key, Token: func() string { return f.s.token }}}, f.s.apiURL)))
		_, err = kc.IssueClosureNonce(context.Background(), &pb.IssueClosureNonceRequest{Namespace: f.agentPod.namespace})
	case "result_without_target":
		// A result that names no target (D1218a N1).
		results[0].Target = ""
		res, err = w.closure(f.agentPod, report.KindSandbox, results)
	case "control_from_agent_pod":
		// The agent pod claims to be the unenforced control (D1218 item 5).
		res, err = w.closure(f.agentPod, report.KindControl, controlResults())
	case "sandbox_from_release_namespace":
		// The unenforced control pod reports itself contained.
		ctl, cerr := f.enrolPod(f.ctlPod)
		if cerr != nil {
			return domain.Observation{}, cerr
		}
		res, err = ctl.closure(f.ctlPod, report.KindSandbox, results)
	}
	if err != nil {
		return refused(err), nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("closure %s passed=%v", res.GetKubeClosureId(), res.GetPassed())}, nil
}

// expireNonces moves every outstanding closure nonce of the org past its
// expiry.
func (f *kubeFixture) expireNonces(t *testing.T) {
	f.s.db.AdminExec(t, `UPDATE pc.kube_closure_nonces SET issued_at = issued_at - interval '1 hour',
		expires_at = expires_at - interval '1 hour' WHERE org_id = $1 AND used_at IS NULL`, f.s.org)
}

// passControl has the webhook decide a pod of the agent namespace and the
// control twin pass: a closure with every probe unreachable would pass.
func (f *kubeFixture) passControl(t *testing.T) error {
	if code, ok, reason := f.admit(t, f.secret, f.probePod(f.agentPod.edgeImage)); code != http.StatusOK || !ok {
		return fmt.Errorf("the probe pod was not admitted: %d %s", code, reason)
	}
	ctl, err := f.enrolPod(f.ctlPod)
	if err != nil {
		return err
	}
	res, err := ctl.closure(f.ctlPod, report.KindControl, controlResults())
	if err != nil {
		return fmt.Errorf("the control twin: %w", err)
	}
	if !res.GetPassed() {
		return fmt.Errorf("the control twin did not pass: %v", res)
	}
	return nil
}

// forgedTarget submits a closure whose passing probes name targets other
// than the cluster's (D1218 M2; RT-219): a kube_api the control did not
// reach, then a kubelet on another node.
func (f *kubeFixture) forgedTarget(t *testing.T) (domain.Observation, error) {
	if err := f.passControl(t); err != nil {
		return domain.Observation{}, err
	}
	w, err := f.enrolPod(f.agentPod)
	if err != nil {
		return domain.Observation{}, err
	}
	var obs domain.Observation
	for name, target := range map[string]string{covdomain.ProbeKubeAPI: "10.96.0.99:443", covdomain.ProbeKubelet: "10.0.0.6:10250"} {
		results := sandboxResults(report.Blocked)
		for i := range results {
			if results[i].Name == name {
				results[i] = probe.Result(name, report.RoleProbe, report.Blocked, target, context.DeadlineExceeded)
			}
		}
		res, err := w.closure(f.agentPod, report.KindSandbox, results)
		if err == nil {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("a forged %s target: closure %s passed=%v", name, res.GetKubeClosureId(), res.GetPassed())}, nil
		}
		if obs = refused(err); obs.Reason != "K8S_CLOSURE_REJECTED" {
			return obs, nil
		}
	}
	return obs, nil
}

func (f *kubeFixture) overstateAttack(t *testing.T, attack string) (domain.Observation, error) {
	if err := f.passControl(t); err != nil {
		return domain.Observation{}, err
	}
	w, err := f.enrolPod(f.agentPod)
	if err != nil {
		return domain.Observation{}, err
	}
	results := sandboxResults(report.Blocked)
	switch attack {
	case "network_policy_open":
		f.cluster.setOpen(true)
		defer f.cluster.setOpen(false)
	case "admission_not_seen":
		f.s.db.AdminExec(t, `UPDATE pc.kube_admission_seen SET last_allowed_at = now() - interval '25 hours',
			last_denied_at = CASE WHEN last_denied_at IS NULL THEN NULL ELSE now() - interval '25 hours' END WHERE org_id = $1`, f.s.org)
	case "probe_reached":
		results = sandboxResults(report.Reachable)
	}
	res, err := w.closure(f.agentPod, report.KindSandbox, results)
	if err != nil {
		return domain.Observation{}, err
	}
	if res.GetPassed() {
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: "the closure passed"}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "NOT_ENFORCED", Detail: strings.Join(res.GetFailed(), ",")}, nil
}
