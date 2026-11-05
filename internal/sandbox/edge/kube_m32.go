// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// The edge's kubernetes mode (G0 M32 D966, D973): the native sidecar of an
// agent pod. It listens on loopback only, enrolls an in-memory key from the
// pod's projected token, keeps a workload token fresh (re-attesting with each
// new projected token), and runs one run per pod, named after the pod.

// PodNameEnv is the downward-API variable that names the pod.
const PodNameEnv = "PC_POD_NAME"

// NamespaceEnv is the downward-API variable that names the pod's namespace
// (D970b).
const NamespaceEnv = "PC_NAMESPACE"

// caFile is the session CA certificate's name in the shared CA directory.
const caFile = "ca.crt"

// The pod CA lives as long as the pod may (its key only in memory): 30 days
// by default, at most 90 (G0 M32 D966).
const (
	kubeCAValidityDefault = 30 * 24 * time.Hour
	kubeCAValidityMax     = 90 * 24 * time.Hour
)

// kubeCAValidity is the configured CA validity, or the default.
func kubeCAValidity(c Config) time.Duration {
	if c.CAValiditySeconds == 0 {
		return kubeCAValidityDefault
	}
	return time.Duration(c.CAValiditySeconds) * time.Second
}

// Run-start backoff after a refusal or failure (D973: serve nothing
// meanwhile).
const (
	runRetryMin = 2 * time.Second
	runRetryMax = 5 * time.Minute
)

// checkKubernetesConfig checks a kubernetes mode configuration: a loopback
// listener, the gateway, the hosts, the projected token, the server API and
// the CA directory; no subnet, key, token file, binding or fixed run.
func checkKubernetesConfig(c Config) error {
	switch {
	case c.Subnet != "" || c.KeyFile != "" || c.TokenFile != "" || c.BindingFile != "" || c.Run != "" || c.Placeholder != "":
		return errors.New("edge: a kubernetes edge has no subnet, key_file, token_file, binding_file, run or placeholder")
	case c.GatewayURL == "" || len(c.Hosts) == 0 || c.KubeTokenFile == "" || c.APIURL == "" || c.CADir == "":
		return errors.New("edge: a kubernetes edge needs gateway_url, hosts, kube_token_file, api_url and ca_dir")
	case !filepath.IsAbs(c.CADir) && !strings.HasPrefix(c.CADir, "/"):
		return errors.New("edge: ca_dir must be an absolute path")
	case c.CAValiditySeconds < 0 || time.Duration(c.CAValiditySeconds)*time.Second > kubeCAValidityMax:
		return errors.New("edge: a kubernetes edge's ca_validity_seconds is at most 90 days")
	}
	if _, err := loopbackAddr(c.Listen); err != nil {
		return err
	}
	if _, err := apiBase(c.APIURL); err != nil {
		return err
	}
	return nil
}

// loopbackAddr parses listen, which must be a loopback IP literal and port.
func loopbackAddr(listen string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(listen)
	if err != nil || !ap.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("edge: a kubernetes edge listens on a loopback address only, not %q", listen)
	}
	return ap, nil
}

// apiBase checks the server's API URL: https, or plain http to loopback.
func apiBase(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", fmt.Errorf("edge: api_url %q must be a base URL", raw)
	}
	if u.Scheme != "https" {
		a, perr := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || perr != nil || !a.IsLoopback() {
			return "", fmt.Errorf("edge: api_url %q must use https", raw)
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

// kubeWorkload is the pod's workload identity: its in-memory key, its
// instance and its current workload token.
type kubeWorkload struct {
	key        ed25519.PrivateKey
	tokenFile  string
	api        string
	identifier string
	log        *slog.Logger

	// keyOnly signs key-only proofs (Enroll, IssueToken); withToken also
	// sends the workload token (StartPodRun, SubmitClosure).
	keyOnly, withToken *http.Client

	mu    sync.Mutex
	token string
	// seen is the projected token the server last answered for: each is
	// single use (HR-143), so it is sent once.
	seen [sha256.Size]byte
}

func newKubeWorkload(c Config, log *slog.Logger) (*kubeWorkload, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader) // in memory only (D966)
	if err != nil {
		return nil, err
	}
	api, err := apiBase(c.APIURL)
	if err != nil {
		return nil, err
	}
	w := &kubeWorkload{key: key, tokenFile: c.KubeTokenFile, api: api, log: log}
	w.keyOnly = &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key}, CheckRedirect: noRedirect}
	w.withToken = &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{Key: key, Token: w.Token}, CheckRedirect: noRedirect}
	return w, nil
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse } // HR-070

// Token returns the current workload token, "" when there is none.
func (w *kubeWorkload) Token() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.token
}

func (w *kubeWorkload) workloadClient() pantherclawv1connect.WorkloadServiceClient {
	return pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(w.keyOnly, w.api)))
}

// attestation reads the projected token (the kubelet rotates it).
func (w *kubeWorkload) attestation() (*pantherclawv1.Attestation, [sha256.Size]byte, error) {
	b, err := os.ReadFile(w.tokenFile) //nolint:gosec // G304: the pod's own projected token
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("edge: projected token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	return &pantherclawv1.Attestation{Kind: pantherclawv1.AttestationKind_ATTESTATION_KIND_KUBERNETES, Token: tok}, sha256.Sum256([]byte(tok)), nil
}

// enroll enrolls the key with the projected token. The issuer entry must
// admit automatically: an instance waiting for admission is an error.
func (w *kubeWorkload) enroll(ctx context.Context) error {
	att, sum, err := w.attestation()
	if err != nil {
		return err
	}
	pub, _ := w.key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return err
	}
	res, err := w.workloadClient().Enroll(ctx, &pantherclawv1.EnrollRequest{PublicJwk: string(jwk), Attestation: att})
	if err != nil {
		return fmt.Errorf("edge: enroll: %w", err)
	}
	w.seen = sum
	if res.GetState() != pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED {
		return fmt.Errorf("edge: instance %s is not admitted (the kubernetes issuer entry must admit automatically)", res.GetInstanceId())
	}
	w.identifier = res.GetIdentifier()
	w.log.Info("edge.enrolled", "instance", res.GetInstanceId(), "attestation_level", res.GetAttestationLevel())
	return nil
}

// issue asks for one workload token, attesting with the projected token
// when it is one not yet sent; a refused attestation is retried without
// one, as pclaw does (HR-143).
func (w *kubeWorkload) issue(ctx context.Context) (workloadclient.Issued, error) {
	req := &pantherclawv1.IssueTokenRequest{Identifier: w.identifier}
	att, sum, err := w.attestation()
	if err != nil {
		w.log.Warn("edge.renewal", "message", "renewing without an attestation: "+err.Error())
	} else if sum != w.seen {
		req.Attestation = att
	}
	wc := w.workloadClient()
	res, err := wc.IssueToken(ctx, req)
	if req.Attestation != nil {
		code, _ := workloadclient.CodeOf(err)
		if refused := code == pap.CodeAttestationLow || code == pap.CodeInvalidToken; err == nil || refused {
			w.seen = sum
			if refused {
				w.log.Warn("edge.renewal", "message", "the server refused the attestation ("+string(code)+"); renewing without it")
				req.Attestation = nil
				res, err = wc.IssueToken(ctx, req)
			}
		}
	}
	if err != nil {
		return workloadclient.Issued{}, err
	}
	return workloadclient.Issued{Token: res.GetWorkloadToken(), ExpiresAt: res.GetExpireTime().AsTime(), Level: int(res.GetAttestationLevel())}, nil
}

func (w *kubeWorkload) deliver(iss workloadclient.Issued) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.token = iss.Token
	return nil
}

// podRuns is the pod's one run at a time (D966, D973): started at boot,
// started again when the gateway says it ended. While none can be started,
// the edge forwards nothing.
type podRuns struct {
	pod   string
	start func(ctx context.Context, pod string) (string, error)
	log   *slog.Logger

	mu     sync.Mutex
	run    string
	wakeup chan struct{}
}

func newPodRuns(pod string, start func(context.Context, string) (string, error), log *slog.Logger) *podRuns {
	return &podRuns{pod: pod, start: start, log: log, wakeup: make(chan struct{}, 1)}
}

// Current is the run requests name, "" while there is none.
func (p *podRuns) Current() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.run
}

// Ended drops run when it is still the current one, and wakes the loop.
func (p *podRuns) Ended(run string) {
	p.mu.Lock()
	if p.run != run {
		p.mu.Unlock()
		return
	}
	p.run = ""
	p.mu.Unlock()
	p.log.Info("edge.run_ended", "run", run)
	select {
	case p.wakeup <- struct{}{}:
	default:
	}
}

// Run keeps a run going until ctx ends.
func (p *podRuns) Run(ctx context.Context) {
	wait := time.Duration(0)
	for {
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		if p.Current() == "" {
			run, err := p.start(ctx, p.pod)
			if err != nil {
				wait = min(max(2*wait, runRetryMin), runRetryMax)
				// D973: refused (no run grant, for example): serve nothing.
				p.log.Error("edge.run_refused", "pod", p.pod, "error", err.Error(), "retry_in", wait.String())
				continue
			}
			p.mu.Lock()
			p.run = run
			p.mu.Unlock()
			p.log.Info("edge.run_started", "pod", p.pod, "run", run)
		}
		wait = 0
		select {
		case <-ctx.Done():
			return
		case <-p.wakeup:
		}
	}
}

// kubernetesClient is KubernetesService, signed with the pod's key and
// carrying its workload token.
func (w *kubeWorkload) kubernetesClient() pantherclawv1connect.KubernetesServiceClient {
	return pantherclawv1connect.NewKubernetesServiceClient(connect.NewClient(connecthttp.NewTransport(w.withToken, w.api)))
}

// startPodRun starts the pod's run (KubernetesService.StartPodRun, G0 M32
// D973) under the issuer entry's run grant; a refusal leaves the edge with
// no run, so it forwards nothing.
func (w *kubeWorkload) startPodRun(ctx context.Context, pod string) (string, error) {
	res, err := w.kubernetesClient().StartPodRun(ctx, &pantherclawv1.StartPodRunRequest{PodName: pod})
	if err != nil {
		return "", fmt.Errorf("edge: start pod run: %w", err)
	}
	if _, err := ids.ParseUUID(res.GetRunId()); err != nil {
		return "", errors.New("edge: start pod run: the server sent no run id")
	}
	return res.GetRunId(), nil
}

// ReportPath is the loopback-only path the probe posts its report to
// (kubernetes mode, G0 M32 D966, D970b).
const ReportPath = "/__pc/report"

// maxReportBody bounds a probe report.
const maxReportBody = 256 << 10

// reporter signs probe reports with the pod's workload key and submits them
// (D970b).
type reporter struct {
	w              *kubeWorkload
	pod, namespace string
	log            *slog.Logger
}

// reportAnswer is what the probe gets back.
type reportAnswer struct {
	KubeClosureID string   `json:"kube_closure_id,omitempty"`
	Kind          string   `json:"kind,omitempty"`
	Passed        bool     `json:"passed"`
	Failed        []string `json:"failed,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func writeReportAnswer(w http.ResponseWriter, status int, a reportAnswer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, a)
}

// ServeHTTP takes one report: a fresh nonce for the pod's namespace, the
// session (the pod), the network (the namespace) and no image digests (the
// server reads the pod's own), signed and submitted with SubmitClosure.
func (rp *reporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeReportAnswer(w, http.StatusMethodNotAllowed, reportAnswer{Error: "method_not_allowed"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBody+1))
	if err != nil || len(body) > maxReportBody {
		writeReportAnswer(w, http.StatusRequestEntityTooLarge, reportAnswer{Error: "report_too_large"})
		return
	}
	var rep report.Report
	if err := json.Unmarshal(body, &rep, json.RejectUnknownMembers(true)); err != nil {
		writeReportAnswer(w, http.StatusBadRequest, reportAnswer{Error: "report_invalid"})
		return
	}
	ctx := r.Context()
	kc := rp.w.kubernetesClient()
	nonce, err := kc.IssueClosureNonce(ctx, &pantherclawv1.IssueClosureNonceRequest{Namespace: rp.namespace})
	if err != nil {
		rp.log.WarnContext(ctx, "edge.report_refused", "step", "nonce", "error", err.Error())
		writeReportAnswer(w, http.StatusBadGateway, reportAnswer{Error: "nonce_refused"})
		return
	}
	rep.Nonce, rep.Session, rep.Network.Name, rep.Images = nonce.GetNonce(), rp.pod, rp.namespace, report.Images{}
	signed, err := report.Sign(rp.w.key, rep)
	if err != nil {
		writeReportAnswer(w, http.StatusUnprocessableEntity, reportAnswer{Error: "report_invalid"})
		return
	}
	res, err := kc.SubmitClosure(ctx, &pantherclawv1.SubmitClosureRequest{ReportJws: signed})
	if err != nil {
		rp.log.WarnContext(ctx, "edge.report_refused", "step", "submit", "error", err.Error())
		writeReportAnswer(w, http.StatusBadGateway, reportAnswer{Error: "submit_refused"})
		return
	}
	rp.log.InfoContext(ctx, "edge.report_submitted", "kube_closure", res.GetKubeClosureId(), "kind", res.GetKind(), "passed", res.GetPassed())
	writeReportAnswer(w, http.StatusOK, reportAnswer{
		KubeClosureID: res.GetKubeClosureId(), Kind: res.GetKind(), Passed: res.GetPassed(), Failed: res.GetFailed(),
	})
}

// runKubernetes serves kubernetes mode until ctx ends.
func runKubernetes(ctx context.Context, c Config, out io.Writer, log *slog.Logger) error {
	pod := os.Getenv(PodNameEnv)
	if pod == "" {
		return fmt.Errorf("edge: %s (the downward-API pod name) is not set", PodNameEnv)
	}
	namespace := os.Getenv(NamespaceEnv)
	if namespace == "" {
		return fmt.Errorf("edge: %s (the downward-API namespace) is not set", NamespaceEnv)
	}
	addr, err := loopbackAddr(c.Listen)
	if err != nil {
		return err
	}
	w, err := newKubeWorkload(c, log)
	if err != nil {
		return err
	}
	if err := w.enroll(ctx); err != nil {
		return err
	}
	renewer := &workloadclient.Renewer{Issue: w.issue, Deliver: w.deliver, Report: func(s string) { log.Warn("edge.renewal", "message", s) }}
	if err := renewer.Renew(ctx); err != nil {
		return fmt.Errorf("edge: workload token: %w", err)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		if err := renewer.Run(ctx); err != nil {
			// A refusal for good: the instance is no longer admitted.
			cancel(fmt.Errorf("edge: renewal: %w", err))
		}
	}()
	runs := newPodRuns(pod, w.startPodRun, log)
	go runs.Run(ctx)
	e, err := New(Options{
		GatewayURL: c.GatewayURL, GatewayAddr: c.GatewayAddr, GatewayCAPin: c.GatewayCAPin, Hosts: c.Hosts,
		RunSource: runs.Current, RunEnded: runs.Ended, Key: w.key, Token: w.Token,
		CAValidity: kubeCAValidity(c), Log: log,
	})
	if err != nil {
		return err
	}
	if err := writeCA(c.CADir, e.CACertificate()); err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr.String())
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	ln = &loopbackListener{Listener: ln}
	srv := &http.Server{
		Handler:           kubeHandler(e, &reporter{w: w, pod: pod, namespace: namespace, log: log}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer scancel()
		_ = srv.Shutdown(sctx)
	}()
	ready := Ready{Event: ReadyEvent, Listen: ln.Addr().String(), CASHA256: e.CAFingerprint(), CAPEM: string(e.CACertificate()), HostAddrs: []string{}}
	if err := json.MarshalWrite(out, ready); err != nil {
		_ = ln.Close()
		return err
	}
	_, _ = io.WriteString(out, "\n")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.InfoContext(ctx, "edge.stopped", "refused", e.Refused(), "credentials_stripped", e.Stripped())
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return cause
	}
	return nil
}

// kubeHandler serves the agent's proxy requests through e, and a direct
// (non-proxy) request for ReportPath through rp. Proxy requests carry an
// absolute URL or are CONNECTs, so they never reach rp.
func kubeHandler(e *Edge, rp http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect && r.URL.Host == "" && r.URL.Path == ReportPath {
			rp.ServeHTTP(w, r)
			return
		}
		e.ServeHTTP(w, r)
	})
}

// writeCA writes the session CA's certificate (never its key) to dir/ca.crt
// for the agent container, replacing it atomically.
func writeCA(dir string, pem []byte) error {
	tmp, err := os.CreateTemp(dir, ".ca-*.crt")
	if err != nil {
		return fmt.Errorf("edge: ca_dir: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(pem); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("edge: ca_dir: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil { //nolint:gosec // G302: a public certificate the agent container reads
		_ = tmp.Close()
		return fmt.Errorf("edge: ca_dir: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("edge: ca_dir: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, caFile)); err != nil {
		return fmt.Errorf("edge: ca_dir: %w", err)
	}
	return nil
}

// loopbackListener accepts only connections to a loopback address: the pod
// shares one network namespace, so nothing outside it can reach the edge.
type loopbackListener struct {
	net.Listener
}

func (l *loopbackListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if a, ok := c.LocalAddr().(*net.TCPAddr); ok && a.AddrPort().Addr().Unmap().IsLoopback() {
			return c, nil
		}
		_ = c.Close()
	}
}
