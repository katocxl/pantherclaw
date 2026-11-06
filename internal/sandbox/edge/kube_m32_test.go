// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// kubeConfig is a valid kubernetes mode configuration.
func kubeConfig() Config {
	return Config{
		Format: ConfigFormat, Mode: ModeKubernetes, Listen: "127.0.0.1:3128", GatewayURL: "https://gateway.pantherclaw.internal:8443",
		Hosts: map[string]string{"api.github.com": "github"}, KubeTokenFile: "/var/run/pantherclaw/edge/token",
		APIURL: "https://pantherclaw-api.pantherclaw.internal:8080", CADir: "/pc-edge",
	}
}

// TestHR736_AKubernetesEdgeListensOnLoopbackOnlyWithNoFixedRun: the
// kubernetes configuration is accepted only with a loopback listener, no
// fixed run, key, token file, binding or subnet, and a CA of at most 90
// days.
func TestHR736_AKubernetesEdgeListensOnLoopbackOnlyWithNoFixedRun(t *testing.T) {
	if err := checkKubernetesConfig(kubeConfig()); err != nil {
		t.Fatalf("the chart's configuration: %v", err)
	}
	v6 := kubeConfig()
	v6.Listen = "[::1]:3128"
	if err := checkKubernetesConfig(v6); err != nil {
		t.Errorf("IPv6 loopback: %v", err)
	}
	ninety := kubeConfig()
	ninety.CAValiditySeconds = int64((90 * 24 * time.Hour).Seconds())
	if err := checkKubernetesConfig(ninety); err != nil {
		t.Errorf("a 90-day CA: %v", err)
	}
	if got := kubeCAValidity(kubeConfig()); got != 30*24*time.Hour {
		t.Errorf("default CA validity %v, want 30 days", got)
	}
	for name, edit := range map[string]func(*Config){
		"every address":           func(c *Config) { c.Listen = ":3128" },
		"0.0.0.0":                 func(c *Config) { c.Listen = "0.0.0.0:3128" },
		"the pod IP":              func(c *Config) { c.Listen = "10.244.1.7:3128" },
		"a host name":             func(c *Config) { c.Listen = "localhost:3128" },
		"a fixed run":             func(c *Config) { c.Run = ids.NewV7().String() },
		"a key file":              func(c *Config) { c.KeyFile = "/key.json" },
		"a token file":            func(c *Config) { c.TokenFile = "/token" },
		"a binding file":          func(c *Config) { c.BindingFile = "/binding" },
		"a subnet":                func(c *Config) { c.Subnet = "172.30.0.0/24" },
		"no projected token":      func(c *Config) { c.KubeTokenFile = "" },
		"no API":                  func(c *Config) { c.APIURL = "" },
		"no CA directory":         func(c *Config) { c.CADir = "" },
		"a relative CA directory": func(c *Config) { c.CADir = "pc-edge" },
		"a CA of 91 days":         func(c *Config) { c.CAValiditySeconds = int64((91 * 24 * time.Hour).Seconds()) },
		"an API over plain http":  func(c *Config) { c.APIURL = "http://pantherclaw-api.pantherclaw.internal:8080" },
		"an API URL with a path":  func(c *Config) { c.APIURL = "https://api.example.test/v1" },
	} {
		c := kubeConfig()
		edit(&c)
		if err := checkKubernetesConfig(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHR736_OnlyTheCACertificateIsWritten: the session CA's certificate is
// written to ca.crt in the CA directory, replaced atomically, and holds no
// key; nothing else is left in the directory.
func TestHR736_OnlyTheCACertificateIsWritten(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		GatewayURL: "https://gateway.example.test", Hosts: map[string]string{"api.github.com": "github"},
		RunSource: func() string { return "" }, Key: key, Token: func() string { return "t" }, CAValidity: kubeCAValidityDefault,
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, caFile), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCA(dir, e.CACertificate()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != caFile {
		t.Fatalf("CA directory holds %v (%v), want only %s", entries, err, caFile)
	}
	b, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		t.Fatal(err)
	}
	blk, rest := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || bytes.Contains(b, []byte("PRIVATE KEY")) {
		t.Fatalf("ca.crt is not one certificate: %q", b)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || !c.IsCA {
		t.Fatalf("ca.crt: %v %+v", err, c)
	}
	if d := c.NotAfter.Sub(c.NotBefore); d > kubeCAValidityDefault+2*time.Hour {
		t.Errorf("the pod CA lives %v, want at most 30 days", d)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dir, caFile)); err != nil || info.Mode().Perm() != 0o644 {
			t.Errorf("ca.crt mode %v, %v", info.Mode(), err)
		}
	}
	if err := writeCA(filepath.Join(dir, "missing"), e.CACertificate()); err == nil {
		t.Error("a missing CA directory was accepted")
	}
}

// TestHR736_TheListenerAcceptsOnlyLoopbackConnections: a connection to a
// loopback address is served; one to another local address is closed.
func TestHR736_TheListenerAcceptsOnlyLoopbackConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip(err)
	}
	ln := &loopbackListener{Listener: inner}
	defer func() { _ = ln.Close() }()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "edge") }), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	port := inner.Addr().(*net.TCPAddr).Port
	get := func(host string) error {
		c := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}
		res, err := c.Get("http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/")
		if err != nil {
			return err
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		if string(b) != "edge" {
			return errors.New(string(b))
		}
		return nil
	}
	if err := get("127.0.0.1"); err != nil {
		t.Fatalf("loopback: %v", err)
	}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.IsLoopback() || ip.IP.To4() == nil || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		if err := get(ip.IP.String()); err == nil {
			t.Errorf("a connection to %s was served", ip.IP)
		}
		return
	}
	t.Log("no non-loopback IPv4 address to try")
}

// podIdentifier is the PAP/1 identifier the fake server enrolls the pod as.
var podIdentifier = "pc:org/" + ids.New[ids.Org]().String() + "/agent/" + ids.NewV7().String() + "/inst/" + ids.NewV7().String()

// fakeServer is the server's WorkloadService and KubernetesService as the
// edge calls them.
type fakeServer struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	pantherclawv1connect.UnimplementedKubernetesServiceHandler

	mu       sync.Mutex
	enrolls  []*pantherclawv1.EnrollRequest
	issues   []*pantherclawv1.IssueTokenRequest
	nonces   []string
	submits  []string
	auths    []string
	state    pantherclawv1.InstanceState
	refuseAt error
	runs     int
}

func (f *fakeServer) Enroll(ctx context.Context, req *pantherclawv1.EnrollRequest) (*pantherclawv1.EnrollResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolls = append(f.enrolls, req)
	return &pantherclawv1.EnrollResponse{InstanceId: ids.NewV7().String(), Identifier: podIdentifier, State: f.state, AttestationLevel: 2}, nil
}

func (f *fakeServer) IssueToken(_ context.Context, req *pantherclawv1.IssueTokenRequest) (*pantherclawv1.IssueTokenResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = append(f.issues, req)
	return &pantherclawv1.IssueTokenResponse{WorkloadToken: "workload-token", ExpireTime: timestamppb.New(time.Now().Add(15 * time.Minute)), AttestationLevel: 2}, nil
}

func (f *fakeServer) authz(ctx context.Context) {
	if info, ok := connect.CallInfoForServerContext(ctx); ok {
		f.auths = append(f.auths, info.RequestHeader().Get("Authorization"))
	}
}

func (f *fakeServer) IssueClosureNonce(ctx context.Context, req *pantherclawv1.IssueClosureNonceRequest) (*pantherclawv1.IssueClosureNonceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz(ctx)
	f.nonces = append(f.nonces, req.GetNamespace())
	n := make([]byte, 32)
	_, _ = rand.Read(n)
	return &pantherclawv1.IssueClosureNonceResponse{Nonce: base64.RawURLEncoding.EncodeToString(n), ExpireTime: timestamppb.New(time.Now().Add(15 * time.Minute))}, nil
}

func (f *fakeServer) SubmitClosure(ctx context.Context, req *pantherclawv1.SubmitClosureRequest) (*pantherclawv1.SubmitClosureResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz(ctx)
	f.submits = append(f.submits, req.GetReportJws())
	return &pantherclawv1.SubmitClosureResponse{KubeClosureId: ids.NewV7().String(), Kind: report.KindSandbox, Passed: true}, nil
}

func (f *fakeServer) StartPodRun(ctx context.Context, req *pantherclawv1.StartPodRunRequest) (*pantherclawv1.StartPodRunResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authz(ctx)
	if f.refuseAt != nil {
		return nil, f.refuseAt
	}
	f.runs++
	return &pantherclawv1.StartPodRunResponse{RunId: ids.NewV7().String()}, nil
}

// startFake serves f on loopback over plain http (the edge allows that to
// loopback only) and returns its base URL.
func startFake(t *testing.T, f *fakeServer) string {
	t.Helper()
	s, err := rpc.NewServer(rpc.Options{Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterWorkloadServiceHandler(s, f)
	pantherclawv1connect.RegisterKubernetesServiceHandler(s, f)
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// podWorkload is a kubernetes workload against f with its projected token
// in a file.
func podWorkload(t *testing.T, f *fakeServer) (*kubeWorkload, string) {
	t.Helper()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("projected-token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := kubeConfig()
	c.APIURL, c.KubeTokenFile = startFake(t, f), tok
	w, err := newKubeWorkload(c, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	return w, tok
}

// TestHR737_TheEdgeEnrollsFromItsProjectedTokenAndRenewsByAttestingAgain:
// the edge enrolls a fresh in-memory key with a kubernetes attestation of
// the projected token, sends each projected token once, re-attests when
// the kubelet rotated it, and refuses an instance that waits for
// admission. Nothing is written but the CA certificate.
func TestHR737_TheEdgeEnrollsFromItsProjectedTokenAndRenewsByAttestingAgain(t *testing.T) {
	f := &fakeServer{state: pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED}
	w, tok := podWorkload(t, f)
	ctx := t.Context()
	if err := w.enroll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.enrolls) != 1 {
		t.Fatalf("%d enrolls", len(f.enrolls))
	}
	att := f.enrolls[0].GetAttestation()
	if att.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_KUBERNETES || att.GetToken() != "projected-token-1" ||
		f.enrolls[0].GetEnrollmentToken() != "" {
		t.Fatalf("enroll %+v", f.enrolls[0])
	}
	pub, _ := w.key.Public().(ed25519.PublicKey)
	if !strings.Contains(f.enrolls[0].GetPublicJwk(), base64.RawURLEncoding.EncodeToString(pub)) || strings.Contains(f.enrolls[0].GetPublicJwk(), `"d"`) {
		t.Fatalf("the enrolled JWK %s is not the edge's public key alone", f.enrolls[0].GetPublicJwk())
	}

	// The token enrolled with is not sent again.
	if _, err := w.issue(ctx); err != nil {
		t.Fatal(err)
	}
	if f.issues[0].GetAttestation() != nil || f.issues[0].GetIdentifier() != podIdentifier {
		t.Errorf("first issue %+v, want no attestation", f.issues[0])
	}
	// The kubelet rotates the token: the next issue attests with it, once.
	if err := os.WriteFile(tok, []byte("projected-token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	iss, err := w.issue(ctx)
	if err != nil || iss.Token != "workload-token" {
		t.Fatal(iss, err)
	}
	if a := f.issues[1].GetAttestation(); a.GetKind() != pantherclawv1.AttestationKind_ATTESTATION_KIND_KUBERNETES || a.GetToken() != "projected-token-2" {
		t.Errorf("renewal after rotation %+v, want the new token", f.issues[1])
	}
	if _, err := w.issue(ctx); err != nil || f.issues[2].GetAttestation() != nil {
		t.Errorf("the rotated token was sent twice: %+v %v", f.issues[2], err)
	}
	if err := w.deliver(iss); err != nil || w.Token() != "workload-token" {
		t.Errorf("deliver: %v %q", err, w.Token())
	}

	// An entry that does not admit automatically leaves the edge with
	// nothing to serve.
	pending := &fakeServer{state: pantherclawv1.InstanceState_INSTANCE_STATE_PENDING_ADMISSION}
	pw, _ := podWorkload(t, pending)
	if err := pw.enroll(ctx); err == nil || !strings.Contains(err.Error(), "not admitted") {
		t.Errorf("a pending instance: %v", err)
	}
	// Without the projected token there is no enrollment.
	gone, _ := podWorkload(t, &fakeServer{state: pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED})
	gone.tokenFile = filepath.Join(t.TempDir(), "absent")
	if err := gone.enroll(ctx); err == nil {
		t.Error("enrolled without a projected token")
	}
}

// TestHR737_OneRunPerPodNamedAfterThePod: the pod's run starts at boot under
// the pod's name, a new one starts when the gateway says it ended, an end
// of another run changes nothing, and while no run can be started the edge
// forwards nothing.
func TestHR737_OneRunPerPodNamedAfterThePod(t *testing.T) {
	var mu sync.Mutex
	var pods []string
	started := make(chan string, 4)
	start := func(_ context.Context, pod string) (string, error) {
		mu.Lock()
		pods = append(pods, pod)
		mu.Unlock()
		run := ids.NewV7().String()
		started <- run
		return run, nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := newPodRuns("coder-7f9c", start, pclog.Discard())
	go p.Run(ctx)
	first := waitRun(t, started)
	waitCurrent(t, p, first)
	p.Ended(ids.NewV7().String()) // another run: ignored
	if p.Current() != first {
		t.Fatalf("an unrelated end replaced the run")
	}
	p.Ended(first)
	second := waitRun(t, started)
	waitCurrent(t, p, second)
	mu.Lock()
	if len(pods) != 2 || pods[0] != "coder-7f9c" || pods[1] != "coder-7f9c" || first == second {
		t.Errorf("runs started for %v (%s, %s)", pods, first, second)
	}
	mu.Unlock()

	// No run: the edge refuses before anything reaches the gateway.
	var reached int
	gw := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	t.Cleanup(gw.Close)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		GatewayURL: gw.URL, Hosts: map[string]string{"api.github.com": "github"}, RunSource: func() string { return "" },
		Key: key, Token: func() string { return "workload-token" }, Log: pclog.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	proxy, _ := url.Parse(ps.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(e.CACertificate())
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	res, err := c.Get("https://api.github.com/repos/acme/app")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(b), "edge_has_no_run") || reached != 0 {
		t.Errorf("without a run: %d %s, gateway reached %d times", res.StatusCode, b, reached)
	}
	if _, err := New(Options{
		GatewayURL: gw.URL, Hosts: map[string]string{"api.github.com": "github"}, RunSource: func() string { return "" }, Run: ids.NewV7().String(),
		Key: key, Token: func() string { return "t" },
	}); err == nil {
		t.Error("a run source beside a fixed run was accepted")
	}
}

// TestHR737_ARefusedRunServesNothing: when StartPodRun is refused (no run
// grant), the edge keeps no run.
func TestHR737_ARefusedRunServesNothing(t *testing.T) {
	f := &fakeServer{
		state:    pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED,
		refuseAt: connect.NewError(connect.CodeFailedPrecondition, "K8S_NO_RUN_GRANT"),
	}
	w, _ := podWorkload(t, f)
	w.token = "workload-token"
	if run, err := w.startPodRun(t.Context(), "coder-1"); err == nil || run != "" {
		t.Fatalf("a refused StartPodRun gave %q, %v", run, err)
	}
	called := make(chan struct{}, 8)
	p := newPodRuns("coder-1", func(ctx context.Context, pod string) (string, error) {
		called <- struct{}{}
		return w.startPodRun(ctx, pod)
	}, pclog.Discard())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go p.Run(ctx)
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("no run start")
	}
	if p.Current() != "" {
		t.Errorf("a refused start left run %q", p.Current())
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.auths) == 0 || !strings.HasPrefix(f.auths[0], "PAP ") {
		t.Errorf("StartPodRun carried %v, want the workload token", f.auths)
	}
}

func waitRun(t *testing.T, c chan string) string {
	t.Helper()
	select {
	case r := <-c:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no run started")
		return ""
	}
}

func waitCurrent(t *testing.T, p *podRuns, run string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for p.Current() != run {
		if time.Now().After(deadline) {
			t.Fatalf("current run %q, want %q", p.Current(), run)
		}
		runtime.Gosched()
	}
}

// probeReport is an unsigned report as the probe posts it.
func probeReport() report.Report {
	now := time.Now().UTC()
	return report.Report{
		Format: report.Format, Session: "chosen-by-the-probe", Kind: report.KindSandbox, StartedAt: now, FinishedAt: now,
		Images:  report.Images{Edge: "sha256:" + strings.Repeat("0", 64)},
		Engine:  report.Engine{Runtime: report.RuntimeKubernetes},
		Network: report.Network{Name: "other-namespace"},
		Config:  report.Config{Checks: []report.Check{}}, Canary: report.Canary{Hits: []report.Hit{}},
		Results: []report.Result{{Name: "kube_api", Role: report.RoleProbe, Expect: report.Blocked, Observed: report.Blocked, Detail: "10.96.0.1:443"}},
	}
}

// TestHR738_TheReportEndpointSignsOnlyAProbeReportForThisPod: a probe
// report posted to the edge gets a fresh nonce for the pod's namespace, the
// pod as its session and namespace, no image digests, and the pod key's
// signature, and is submitted with the workload token; anything else is
// refused unsigned.
func TestHR738_TheReportEndpointSignsOnlyAProbeReportForThisPod(t *testing.T) {
	f := &fakeServer{state: pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED}
	w, _ := podWorkload(t, f)
	w.token = "workload-token"
	rp := &reporter{w: w, pod: "probe-29384-abcde", namespace: "agents", log: pclog.Discard()}
	post := func(method string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:3128"+ReportPath, bytes.NewReader(body))
		r.URL.Host = "" // a direct request, as the probe sends it
		rec := httptest.NewRecorder()
		rp.ServeHTTP(rec, r)
		return rec
	}
	body, err := json.Marshal(probeReport())
	if err != nil {
		t.Fatal(err)
	}
	rec := post(http.MethodPost, body)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"passed":true`) {
		t.Fatalf("a probe report: %d %s", rec.Code, rec.Body.String())
	}
	if len(f.nonces) != 1 || f.nonces[0] != "agents" || len(f.submits) != 1 {
		t.Fatalf("nonces %v, submits %d", f.nonces, len(f.submits))
	}
	pub, _ := w.key.Public().(ed25519.PublicKey)
	signed, err := report.Verify(f.submits[0], pub)
	if err != nil {
		t.Fatalf("the submitted report does not verify with the pod key: %v", err)
	}
	if signed.Session != "probe-29384-abcde" || signed.Network.Name != "agents" || signed.Images != (report.Images{}) || len(signed.Nonce) != 43 {
		t.Errorf("signed report %+v", signed)
	}
	for _, a := range f.auths {
		if !strings.HasPrefix(a, "PAP ") {
			t.Errorf("a KubernetesService call carried %q, want the workload token", a)
		}
	}

	for name, c := range map[string]struct {
		method string
		body   []byte
		status int
	}{
		"a GET":            {http.MethodGet, nil, http.StatusMethodNotAllowed},
		"not JSON":         {http.MethodPost, []byte("{"), http.StatusBadRequest},
		"an unknown field": {http.MethodPost, []byte(`{"format":"x","sign_this":"anything"}`), http.StatusBadRequest},
		"too large":        {http.MethodPost, bytes.Repeat([]byte("a"), maxReportBody+1), http.StatusRequestEntityTooLarge},
		"an invalid report": {http.MethodPost, func() []byte {
			r := probeReport()
			r.Engine.Runtime = "runc-but-not-really"
			b, _ := json.Marshal(r)
			return b
		}(), http.StatusUnprocessableEntity},
	} {
		if rec := post(c.method, c.body); rec.Code != c.status {
			t.Errorf("%s: %d %s, want %d", name, rec.Code, rec.Body.String(), c.status)
		}
	}
	if len(f.submits) != 1 {
		t.Errorf("%d reports submitted, want only the probe's", len(f.submits))
	}
}

// TestHR738_ProxyRequestsNeverReachTheReportEndpoint: an absolute-URL proxy
// request or a CONNECT naming the report path goes to the edge's proxy,
// which refuses it; only a direct request reaches the endpoint.
func TestHR738_ProxyRequestsNeverReachTheReportEndpoint(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		GatewayURL: "https://gateway.example.test", Hosts: map[string]string{"api.github.com": "github"}, RunSource: func() string { return "" },
		Key: key, Token: func() string { return "t" }, Log: pclog.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var reached int
	h := kubeHandler(e, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached++; w.WriteHeader(http.StatusTeapot) }))
	for _, target := range []string{"http://127.0.0.1:3128" + ReportPath, "http://api.github.com" + ReportPath} {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code == http.StatusTeapot {
			t.Errorf("the proxy request %s reached the report endpoint", target)
		}
	}
	r := httptest.NewRequest(http.MethodConnect, "http://127.0.0.1:3128", nil)
	r.URL = &url.URL{Host: "127.0.0.1:3128", Path: ReportPath}
	h.ServeHTTP(httptest.NewRecorder(), r)
	direct := httptest.NewRequest(http.MethodPost, ReportPath, strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, direct)
	if rec.Code != http.StatusTeapot || reached != 1 {
		t.Errorf("the direct request: %d, reached %d times", rec.Code, reached)
	}
}
