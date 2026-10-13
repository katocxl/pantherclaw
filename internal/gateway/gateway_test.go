// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/httpproxy"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

const (
	// gatewayMark marks control-plane calls made by the gateway under test.
	gatewayMark = "Test gw-test"
	connID      = "01920000-0000-7000-8000-0000000000d1"
	// testSecret is a test credential (not a real provider key).
	testSecret = "pc-test-credential-not-real"
)

// marked adds gatewayMark as the Authorization header the fake records.
type marked struct{ base http.RoundTripper }

func (m marked) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", gatewayMark)
	return m.base.RoundTrip(r)
}

// claims mirrors the Authority's permit payload.
type claims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Pap struct {
		V     int    `json:"v"`
		Org   string `json:"org"`
		Txn   string `json:"txn"`
		Act   string `json:"act"`
		Epoch int64  `json:"epoch"`
		// Approval is set by tamper for HR-038 (approvals_test.go).
		Approval *proof.Approval `json:"approval,omitzero"`
	} `json:"pap"`
}

// fakeAuthority signs real permits with a real key registry.
type fakeAuthority struct {
	pantherclawv1connect.UnimplementedAuthorityServiceHandler
	t        *testing.T
	reg      *keys.Registry
	decision pb.Decision
	mode     pb.DispatchMode
	noPermit bool
	repeat   bool
	beginErr error
	// token is the action token BeginDispatch returns.
	token string
	// obligations and effective (the effective action's hash, from the
	// requested action) model a clamping decision.
	obligations []*pb.Obligation
	effective   func(actionir.Parsed) string
	// tamper edits the permit claims before signing; signWith picks the key.
	tamper   func(*claims)
	signWith keys.Purpose

	mu        sync.Mutex
	authorize int
	begins    []*pb.BeginDispatchRequest
	records   []*pb.RecordExecutionRequest
	txn       string
	auth      string
	// identity, when set, is the PAP-Error code of an unverifiable workload.
	identity string
	creds    *pb.WorkloadCredentials
	reports  []*pb.ReportUnknownWorkloadRequest
	actions  []actionir.Parsed
	verifies int
	// verifiedRuns are the runs VerifyWorkload was asked about; endedRuns
	// are refused as run_mismatch.
	verifiedRuns []string
	endedRuns    map[string]bool
}

// VerifyWorkload verifies every workload unless identity is set, as the
// test instance with testJKT; a named run verifies unless it is in
// endedRuns, and expires an hour from now.
func (f *fakeAuthority) VerifyWorkload(_ context.Context, req *pb.VerifyWorkloadRequest) (*pb.VerifyWorkloadResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifies++
	f.creds = req.GetWorkload()
	f.verifiedRuns = append(f.verifiedRuns, req.GetRunId())
	if f.identity != "" {
		return &pb.VerifyWorkloadResponse{ErrorCode: f.identity, Nonce: "nonce-2"}, nil
	}
	if f.endedRuns[req.GetRunId()] {
		return &pb.VerifyWorkloadResponse{ErrorCode: "run_mismatch", Nonce: "nonce-2"}, nil
	}
	res := &pb.VerifyWorkloadResponse{Verified: true, InstanceId: testAgent, EnvironmentId: testEnv, Jkt: testJKT, Nonce: "nonce-4"}
	if req.GetRunId() != "" {
		res.RunExpiresAt = timestamppb.New(time.Now().Add(time.Hour))
	}
	return res, nil
}

func newFakeAuthority(t *testing.T) *fakeAuthority {
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposePermits, keys.PurposeReceipts} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	return &fakeAuthority{
		t: t, reg: reg, decision: pb.Decision_DECISION_ALLOW, mode: pb.DispatchMode_DISPATCH_MODE_ENFORCE, signWith: keys.PurposePermits,
	}
}

func (f *fakeAuthority) Authorize(ctx context.Context, req *pb.AuthorizeRequest) (*pb.AuthorizeResponse, error) {
	p, err := actionir.Parse(req.GetActionIr())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, "bad action")
	}
	info, _ := connect.CallInfoForServerContext(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.authorize++
	f.auth = info.RequestHeader().Get("Authorization")
	f.creds = req.GetWorkload()
	f.actions = append(f.actions, p)
	if f.identity != "" {
		return &pb.AuthorizeResponse{Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE, Nonce: "nonce-2", Reasons: []*pb.Reason{{
			Code: "IDENTITY_UNVERIFIED", Detail: f.identity, Decisive: true,
		}}}, nil
	}
	f.txn = ids.NewV7().String()
	res := &pb.AuthorizeResponse{
		Decision: f.decision, TransactionId: f.txn, ActionHash: p.HashHex(), Nonce: "nonce-1", Mode: f.mode, Repeat: f.repeat,
		Obligations: f.obligations,
	}
	monitor := f.mode == pb.DispatchMode_DISPATCH_MODE_MONITOR
	if f.decision != pb.Decision_DECISION_ALLOW {
		res.Reasons = []*pb.Reason{{Code: "GRANT_AMOUNT_EXCEEDED", Decisive: true}}
	}
	if f.noPermit || (f.decision != pb.Decision_DECISION_ALLOW && !monitor) {
		return res, nil
	}
	act := p.HashHex()
	if f.effective != nil && !monitor {
		act = f.effective(p)
		if act != p.HashHex() {
			res.EffectiveActionHash = act
		}
	}
	res.PermitId, res.Epoch = ids.NewV7().String(), 1
	var c claims
	now := time.Now().Unix()
	c.Iss, c.Aud, c.Jti, c.Iat, c.Exp = "pantherclaw", "gw:gw-test", res.PermitId, now, now+5
	c.Pap.V, c.Pap.Org, c.Pap.Txn, c.Pap.Act, c.Pap.Epoch = 1, testOrg, f.txn, act, 1
	if f.tamper != nil {
		f.tamper(&c)
	}
	b, _ := json.Marshal(c)
	s, err := f.reg.Signer(f.signWith)
	if err != nil {
		return nil, err
	}
	res.Permit, _ = s.Sign("pap-permit+jwt", b)
	return res, nil
}

func (f *fakeAuthority) GetNonce(context.Context, *pb.GetNonceRequest) (*pb.GetNonceResponse, error) {
	return &pb.GetNonceResponse{Nonce: "nonce-0"}, nil
}

func (f *fakeAuthority) ReportUnknownWorkload(_ context.Context, req *pb.ReportUnknownWorkloadRequest) (*pb.ReportUnknownWorkloadResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, req)
	f.creds = req.GetWorkload()
	return &pb.ReportUnknownWorkloadResponse{DiscoveryId: ids.NewV7().String(), Nonce: "nonce-3"}, nil
}

func (f *fakeAuthority) BeginDispatch(_ context.Context, req *pb.BeginDispatchRequest) (*pb.BeginDispatchResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begins = append(f.begins, req)
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return &pb.BeginDispatchResponse{ActionToken: f.token}, nil
}

func (f *fakeAuthority) RecordExecution(_ context.Context, req *pb.RecordExecutionRequest) (*pb.RecordExecutionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, req)
	return &pb.RecordExecutionResponse{Receipt: "receipt-jws"}, nil
}

type authSnap struct {
	authorize int
	begins    []*pb.BeginDispatchRequest
	records   []*pb.RecordExecutionRequest
	reports   []*pb.ReportUnknownWorkloadRequest
	actions   []actionir.Parsed
	txn, auth string
	creds     *pb.WorkloadCredentials
}

func (f *fakeAuthority) snap() authSnap {
	f.mu.Lock()
	defer f.mu.Unlock()
	return authSnap{
		authorize: f.authorize, begins: append([]*pb.BeginDispatchRequest(nil), f.begins...),
		records: append([]*pb.RecordExecutionRequest(nil), f.records...), reports: append([]*pb.ReportUnknownWorkloadRequest(nil), f.reports...),
		actions: append([]actionir.Parsed(nil), f.actions...), txn: f.txn, auth: f.auth, creds: f.creds,
	}
}

func (s authSnap) outcome() pb.Outcome {
	if len(s.records) != 1 {
		return pb.Outcome_OUTCOME_UNSPECIFIED
	}
	return s.records[0].GetOutcome()
}

// fakeTarget records what reached it.
type fakeTarget struct {
	status int
	hang   bool
	// echo makes the target answer with what it received in this header.
	echo string

	mu      sync.Mutex
	bodies  []string
	headers []http.Header
}

func (ft *fakeTarget) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	ft.mu.Lock()
	ft.bodies = append(ft.bodies, string(b))
	ft.headers = append(ft.headers, r.Header.Clone())
	ft.mu.Unlock()
	if ft.hang {
		<-r.Context().Done()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", "req_1")
	w.Header().Set("Set-Cookie", "session=target")
	w.WriteHeader(ft.status)
	if ft.echo != "" {
		_, _ = io.WriteString(w, `{"you_sent":"`+r.Header.Get(ft.echo)+`"}`)
		return
	}
	_, _ = io.WriteString(w, `{"id":"re_1","status":"succeeded","simulated":true}`)
}

func (ft *fakeTarget) calls() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.bodies)
}

func (ft *fakeTarget) req(i int) (string, http.Header) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.bodies[i], ft.headers[i]
}

// fakeContainment is a containment view the test sets.
type fakeContainment struct {
	mu    sync.Mutex
	epoch int64
	err   error
	conns map[string]string
	ready chan struct{}
	// after, when set, applies once the first check passed (containment
	// changing while the Authority decides).
	after func(*fakeContainment)
}

func newFakeContainment() *fakeContainment {
	ready := make(chan struct{})
	close(ready)
	return &fakeContainment{epoch: 1, ready: ready, conns: map[string]string{}}
}

func (f *fakeContainment) Check() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, err := f.epoch, f.err
	if f.after != nil && err == nil {
		f.after(f)
		f.after = nil
	}
	return e, err
}

func (f *fakeContainment) Connection(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns[id]
}

func (f *fakeContainment) Ready() <-chan struct{} { return f.ready }

// fakeConfig is a configuration store, loaded unless ready is open.
type fakeConfig struct {
	cfg   *control.Config
	ready chan struct{}
}

func newFakeConfig(conns ...*control.Connection) *fakeConfig {
	ready := make(chan struct{})
	close(ready)
	cfg := &control.Config{Version: 1, Org: testOrg, ByName: map[string]*control.Connection{}, ByID: map[string]*control.Connection{}}
	for _, c := range conns {
		cfg.ByName[c.GetName()], cfg.ByID[c.GetId()] = c, c
	}
	return &fakeConfig{cfg: cfg, ready: ready}
}

func (f *fakeConfig) Current() *control.Config { return f.cfg }
func (f *fakeConfig) Ready() <-chan struct{}   { return f.ready }

type harness struct {
	auth        *fakeAuthority
	target      *fakeTarget
	containment *fakeContainment
	// conn is the "payments" connection; options may change it.
	conn *control.Connection
	// targetURL, when set, is the connection's base URL instead of the
	// fake target.
	targetURL string
	// authorityURL, when set, is where the gateway calls the Authority.
	authorityURL string
	// mutatePkg edits the mock-payments package before it is compiled.
	mutatePkg func([]byte) []byte
	// pkgFile, when set, is the package compiled instead of mock-payments.
	pkgFile string
	broker  *Broker
	// circuits records the gateway's circuit reports.
	circuitMu sync.Mutex
	circuits  []string
	// drifts records the gateway's drift reports (under circuitMu).
	drifts []string
	gw     *Gateway
	url    string
	// approverKeys is the gateway's approvals.approver_keys_file.
	approverKeys string
}

// compile decodes and compiles a package file (mock-payments when empty).
func compile(t *testing.T, file string, mutate func([]byte) []byte) (*control.Connection, error) {
	t.Helper()
	if file == "" {
		file = "../../packages/mock-payments/package.yaml"
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		raw = mutate(raw)
	}
	p, err := manifest.Decode(raw)
	if err != nil {
		return nil, err
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		return nil, err
	}
	return &control.Connection{Package: p, Mapper: m}, nil
}

// setup starts the fakes and the gateway; opts configure the fakes and the
// connection before any server goroutine starts.
func setup(t *testing.T, opts ...func(*harness)) *harness {
	t.Helper()
	h := &harness{auth: newFakeAuthority(t), target: &fakeTarget{status: http.StatusOK}, containment: newFakeContainment()}
	h.conn = &control.Connection{
		GatewayConnection: &pb.GatewayConnection{
			Id: connID, Name: "payments", Kind: "http", Package: "pc.mock-payments", PackageVersion: "1.0.0",
			AllowedHosts: []string{"127.0.0.1"}, DestinationClass: "internal", AccessMode: "none", DefaultMode: "enforce",
			MaxResponseBytes: 1 << 20, TimeoutMs: 500, State: "ACTIVE", Revision: 1,
		},
		Modes: map[string]string{},
	}
	for _, o := range opts {
		o(h)
	}
	c, err := compile(t, h.pkgFile, h.mutatePkg)
	if err != nil {
		t.Fatal(err)
	}
	h.conn.Package, h.conn.Mapper = c.Package, c.Mapper
	s, err := rpc.NewServer(rpc.Options{Logger: pclog.Discard(), Authenticate: func(ctx context.Context, _ *connect.CallInfo, _ connect.Spec) (context.Context, error) {
		return ctx, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAuthorityServiceHandler(s, h.auth)
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	mux.HandleFunc("GET /.well-known/pantherclaw/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		h.auth.mu.Lock()
		b, _ := h.auth.reg.JWKS()
		h.auth.mu.Unlock()
		_, _ = w.Write(b)
	})
	as := httptest.NewServer(mux)
	t.Cleanup(as.Close)
	if h.targetURL == "" {
		ts := httptest.NewServer(h.target)
		t.Cleanup(ts.Close)
		h.targetURL = ts.URL
	}
	if h.conn.BaseUrl == "" {
		h.conn.BaseUrl = h.targetURL
	}
	if h.authorityURL == "" {
		h.authorityURL = as.URL
	}
	cfg := DefaultConfig()
	cfg.Control.IdentityDir = t.TempDir()
	cfg.Egress.AllowedPrefixes = []string{"127.0.0.1/32"}
	cfg.Approvals.ApproverKeysFile = h.approverKeys
	// The control plane is reached over mTLS in production (internal/gateway/
	// control and the end-to-end tests); here the fakes take plain calls,
	// marked so that the test can tell they came from the gateway.
	hc := &http.Client{Timeout: 5 * time.Second, Transport: marked{http.DefaultTransport}}
	h.gw, err = newGateway(&cfg, Deps{
		Org: testOrg, GatewayID: "gw-test",
		Authority: pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(hc, h.authorityURL))),
		JWKSURL:   as.URL + "/.well-known/pantherclaw/jwks.json", JWKSClient: hc, Containment: h.containment,
		Configuration: newFakeConfig(h.conn), Broker: h.broker,
		ReportCircuit: func(_ context.Context, conn string, unknown, total int32) error {
			h.circuitMu.Lock()
			defer h.circuitMu.Unlock()
			h.circuits = append(h.circuits, fmt.Sprintf("%s %d/%d", conn, unknown, total))
			return nil
		},
		ReportDrift: func(_ context.Context, conn string, d dispatch.Drift) error {
			h.circuitMu.Lock()
			defer h.circuitMu.Unlock()
			h.drifts = append(h.drifts, fmt.Sprintf("%s %s %s %s", conn, d.Tool, d.Expected, d.Observed))
			return nil
		},
	}, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	gs := httptest.NewServer(h.gw.Handler())
	t.Cleanup(gs.Close)
	h.url = gs.URL
	return h
}

const (
	refunds = "/payments/v1/refunds"
	inbound = `{ "reason":"duplicate",  "currency":"USD","amount":"30.00","charge":"ch_1" }`
	// outbound is the body the template builds from the action: the
	// refund's fields, keys sorted.
	outbound = `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
)

// reply is the gateway's answer.
type reply struct {
	code int
	hdr  http.Header
	body string
	// refusal is the decoded body of a refusal.
	refusal httpproxy.Refusal
}

func (h *harness) do(t *testing.T, method, path, body string, hdr map[string]string) reply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+path, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set(HeaderActionID, ids.NewV7().String())
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	r := reply{code: resp.StatusCode, hdr: resp.Header, body: string(b)}
	if resp.StatusCode >= 300 {
		if err := json.Unmarshal(b, &r.refusal); err != nil {
			t.Fatalf("refusal %d %q: %v", resp.StatusCode, b, err)
		}
	}
	return r
}

func (h *harness) post(t *testing.T, body string, hdr map[string]string) reply {
	t.Helper()
	return h.do(t, http.MethodPost, refunds, body, hdr)
}

// TestHR075_OutboundIsReSerialized: the target gets the body the reviewed
// template builds from the canonical action, never the agent's bytes or
// headers; the agent gets the target's answer with PantherClaw's facts.
func TestHR075_OutboundIsReSerialized(t *testing.T) {
	h := setup(t)
	r := h.post(t, inbound, map[string]string{"X-Forward-Me": "1"})
	if r.code != http.StatusOK || r.body != `{"id":"re_1","status":"succeeded","simulated":true}` ||
		r.hdr.Get(httpproxy.HeaderOutcome) != "ACCEPTED" || r.hdr.Get(httpproxy.HeaderReceipt) != "receipt-jws" ||
		r.hdr.Get(httpproxy.HeaderTransaction) != h.auth.snap().txn || r.hdr.Get(httpproxy.HeaderMode) != "enforce" {
		t.Fatalf("refund = %d %q %v", r.code, r.body, r.hdr)
	}
	body, sent := h.target.req(0)
	if body != outbound {
		t.Fatalf("outbound body %q is not the re-serialized action", body)
	}
	for _, name := range []string{"X-Forward-Me", "Authorization", HeaderProof, HeaderRunID, HeaderActionID} {
		if v := sent.Get(name); v != "" {
			t.Errorf("inbound header %s forwarded: %q", name, v)
		}
	}
	// Only the Content-Type and the request id come back from the target.
	if r.hdr.Get("Content-Type") != "application/json" || r.hdr.Get(httpproxy.HeaderTargetRequestID) != "req_1" || r.hdr.Get("Set-Cookie") != "" {
		t.Errorf("target headers passed back: %v", r.hdr)
	}
	s := h.auth.snap()
	if s.auth != gatewayMark {
		t.Error("the Authority was not called through the gateway's control client")
	}
	if a := s.actions[0].Action; a.Connection != connID || a.Route != "payments-refund" || a.Channel != "http" || a.Org != testOrg {
		t.Errorf("mapped action %+v", a)
	}
	if !strings.Contains(strings.Join(r.hdr.Values("Server-Timing"), ","), "authz;dur=") {
		t.Errorf("Server-Timing = %v", r.hdr.Values("Server-Timing"))
	}
	// Extra inbound fields are refused before anything is authorized.
	r = h.post(t, strings.Replace(inbound, "}", `,"to":"acct_x"}`, 1), nil)
	if r.code != http.StatusBadRequest || r.refusal.ErrorClass != "cannot_authorize" || h.auth.snap().authorize != 1 {
		t.Fatalf("unknown field = %d %+v, authorize calls %d", r.code, r.refusal, h.auth.snap().authorize)
	}
}

// TestPN003_RoutesComeFromTheConnectionsPackage: an unknown connection or
// a route the package does not map is refused before anything is
// authorized; a reviewed GET route maps and dispatches.
func TestPN003_RoutesComeFromTheConnectionsPackage(t *testing.T) {
	h := setup(t)
	for path, code := range map[string]string{
		"/other/v1/refunds":     "unknown_connection",
		"/payments/v1/charges":  "unknown_route",
		"/payments/v1/refunds/": "unknown_route",
		"/payments":             "unknown_connection",
	} {
		r := h.do(t, http.MethodPost, path, inbound, nil)
		if r.code != http.StatusNotFound || r.refusal.Error != code {
			t.Errorf("%s = %d %+v", path, r.code, r.refusal)
		}
	}
	before := h.auth.snap().authorize
	r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil)
	if r.code != http.StatusOK || h.auth.snap().authorize != before+1 {
		t.Fatalf("GET refund = %d %q", r.code, r.body)
	}
	if a := h.auth.snap().actions[before].Action; a.Operation != "payments.refund.get" || a.Target.ID != "re_1" {
		t.Fatalf("mapped %+v", a)
	}
}

// TestHR008_IdempotencyKeyFromTransaction: the target's idempotency key is
// derived from the server-minted transaction id, never from the agent.
func TestHR008_IdempotencyKeyFromTransaction(t *testing.T) {
	h := setup(t)
	run, act := ids.NewV7().String(), ids.NewV7().String()
	if r := h.post(t, inbound, map[string]string{HeaderRunID: run, HeaderActionID: act, "Idempotency-Key": "agent-chosen"}); r.code != http.StatusOK {
		t.Fatalf("refund = %d", r.code)
	}
	_, sent := h.target.req(0)
	if got, txn := sent.Get("Idempotency-Key"), h.auth.snap().txn; got != "pc-"+txn {
		t.Fatalf("Idempotency-Key = %q, want pc-%s (the server-minted transaction id)", got, txn)
	}
}

// TestHR001_BeginDispatchCommitsTheExactOutboundRequest: BeginDispatch
// carries the method, URL and body hash of what is then sent, and the
// action token it returns goes to the target in PAP-Action (HR-188).
func TestHR001_BeginDispatchCommitsTheExactOutboundRequest(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.token = "action-token-jws" })
	if r := h.post(t, inbound, nil); r.code != http.StatusOK {
		t.Fatalf("refund = %d %q", r.code, r.body)
	}
	b := h.auth.snap().begins[0]
	sent, hdr := h.target.req(0)
	if b.GetOutboundMethod() != http.MethodPost || b.GetOutboundUrl() != h.targetURL+"/v1/refunds" ||
		!bytes.Equal(b.GetOutboundBodySha256(), sha(sent)) {
		t.Fatalf("BeginDispatch %+v for body %q", b, sent)
	}
	if hdr.Get("PAP-Action") != "action-token-jws" {
		t.Fatalf("PAP-Action = %q", hdr.Get("PAP-Action"))
	}
	// A bodiless route commits the hash of the empty body.
	if r := h.do(t, http.MethodGet, "/payments/v1/refunds/re_1", "", nil); r.code != http.StatusOK {
		t.Fatalf("GET = %d", r.code)
	}
	if b := h.auth.snap().begins[1]; b.GetOutboundMethod() != http.MethodGet || !bytes.Equal(b.GetOutboundBodySha256(), sha("")) {
		t.Fatalf("GET BeginDispatch %+v", b)
	}
}

// The full claim table is TestHR009_PermitVerification; this checks that a
// rejected permit stops the request before the commit point.
func TestHR009_BadPermitStopsBeforeDispatch(t *testing.T) {
	for name, mod := range map[string]func(*fakeAuthority){
		"action":      func(f *fakeAuthority) { f.tamper = func(c *claims) { c.Pap.Act = strings.Repeat("0", 64) } },
		"receipt key": func(f *fakeAuthority) { f.signWith = keys.PurposeReceipts },
	} {
		t.Run(name, func(t *testing.T) {
			h := setup(t, func(h *harness) { mod(h.auth) })
			r := h.post(t, inbound, nil)
			if r.code != http.StatusBadGateway || r.refusal.ErrorClass != "enforcement_failed" || r.refusal.Error != "permit_invalid" {
				t.Fatalf("= %d %+v, want 502 permit_invalid", r.code, r.refusal)
			}
			if s := h.auth.snap(); len(s.begins) != 0 || h.target.calls() != 0 {
				t.Fatalf("bad permit reached BeginDispatch (%d) or the target (%d)", len(s.begins), h.target.calls())
			}
		})
	}
}

// TestF642_OutcomesAreTyped: 2xx is accepted and passed through; a 4xx is
// failed and keeps its status; a 5xx or a timeout is unknown; a refused
// dial is failed, because nothing was sent.
func TestF642_OutcomesAreTyped(t *testing.T) {
	for _, tc := range []struct {
		status  int
		hang    bool
		code    int
		class   string
		outcome pb.Outcome
	}{
		{status: http.StatusOK, code: http.StatusOK, outcome: pb.Outcome_OUTCOME_ACCEPTED},
		{status: http.StatusPaymentRequired, code: http.StatusPaymentRequired, class: "tool_failed", outcome: pb.Outcome_OUTCOME_FAILED},
		{status: http.StatusInternalServerError, code: http.StatusGatewayTimeout, class: "uncertain", outcome: pb.Outcome_OUTCOME_UNKNOWN},
		{hang: true, code: http.StatusGatewayTimeout, class: "uncertain", outcome: pb.Outcome_OUTCOME_UNKNOWN},
	} {
		h := setup(t, func(h *harness) { h.target.status, h.target.hang = tc.status, tc.hang })
		r := h.post(t, inbound, nil)
		if s := h.auth.snap(); r.code != tc.code || r.refusal.ErrorClass != tc.class || s.outcome() != tc.outcome {
			t.Errorf("target %d hang=%v: gateway %d %+v, records %v", tc.status, tc.hang, r.code, r.refusal, s.records)
		}
		if tc.class == "tool_failed" && (r.refusal.TargetStatus != tc.status || len(r.refusal.Response) == 0 || r.refusal.Outcome != "FAILED") {
			t.Errorf("tool failure body %+v", r.refusal)
		}
	}
	// Nothing listening: the dial fails, nothing was sent, so FAILED.
	h := setup(t, func(h *harness) { h.targetURL = deadURL(t) })
	if r := h.post(t, inbound, nil); r.code != http.StatusBadGateway || r.refusal.Error != "target_unreachable" ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("dial failure = %d %+v %v", r.code, r.refusal, h.auth.snap().records)
	}
}

func deadURL(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := "http://" + ln.Addr().String()
	_ = ln.Close()
	return u
}

// TestNothingDispatchedWithoutACommit: every decision without a permit,
// and a refused BeginDispatch, sends nothing, with its error class.
func TestNothingDispatchedWithoutACommit(t *testing.T) {
	cases := map[string]struct {
		mod   func(*fakeAuthority)
		code  int
		class string
		err   string
	}{
		"deny":     {func(f *fakeAuthority) { f.decision = pb.Decision_DECISION_DENY }, http.StatusForbidden, "policy_denied", "GRANT_AMOUNT_EXCEEDED"},
		"approval": {func(f *fakeAuthority) { f.decision = pb.Decision_DECISION_REQUIRE_APPROVAL }, http.StatusForbidden, "held", "GRANT_AMOUNT_EXCEEDED"},
		"cannot": {
			func(f *fakeAuthority) { f.decision = pb.Decision_DECISION_CANNOT_AUTHORIZE }, http.StatusForbidden, "cannot_authorize", "GRANT_AMOUNT_EXCEEDED",
		},
		"duplicate": {func(f *fakeAuthority) { f.noPermit, f.repeat = true, true }, http.StatusConflict, "cannot_authorize", "duplicate_action"},
		"begin refused": {func(f *fakeAuthority) {
			f.beginErr = connect.NewError(connect.CodeFailedPrecondition, "PERMIT_EXPIRED")
		}, http.StatusConflict, "enforcement_failed", "dispatch_refused"},
	}
	for name, tc := range cases {
		h := setup(t, func(h *harness) { tc.mod(h.auth) })
		r := h.post(t, inbound, nil)
		if r.code != tc.code || r.refusal.ErrorClass != tc.class || r.refusal.Error != tc.err || h.target.calls() != 0 ||
			len(h.auth.snap().records) != 0 {
			t.Errorf("%s: %d %+v, target calls %d", name, r.code, r.refusal, h.target.calls())
		}
		if name == "deny" && (r.refusal.Decision != "DENY" || len(r.refusal.Reasons) != 1 || r.refusal.TransactionID == "") {
			t.Errorf("deny body %+v", r.refusal)
		}
	}
}

// TestHR184_MonitorModeDispatchesWhateverTheDecision: in monitor mode the
// permit, not the decision, says whether to dispatch; the answer says
// monitor and the hypothetical decision, never that anything was
// prevented. Containment still stops it.
func TestHR184_MonitorModeDispatchesWhateverTheDecision(t *testing.T) {
	h := setup(t, func(h *harness) {
		h.auth.mode, h.auth.decision = pb.DispatchMode_DISPATCH_MODE_MONITOR, pb.Decision_DECISION_DENY
	})
	r := h.post(t, inbound, nil)
	if r.code != http.StatusOK || r.hdr.Get(httpproxy.HeaderMode) != "monitor" || r.hdr.Get(httpproxy.HeaderDecision) != "DENY" ||
		h.target.calls() != 1 || h.auth.snap().outcome() != pb.Outcome_OUTCOME_ACCEPTED {
		t.Fatalf("monitor = %d %v, target %d", r.code, r.hdr, h.target.calls())
	}
	h.containment.mu.Lock()
	h.containment.err = control.ErrKillSwitch
	h.containment.mu.Unlock()
	if r := h.post(t, inbound, nil); r.code != http.StatusForbidden || r.refusal.Error != "kill_switch" || h.target.calls() != 1 {
		t.Fatalf("monitor under the kill switch = %d %+v", r.code, r.refusal)
	}
}

// clampPkg adds an integer batch parameter that a policy may clamp, sent
// to the target in the body.
func clampPkg(raw []byte) []byte {
	raw = bytes.Replace(raw, []byte("    effects:"), []byte("      batch:\n        type: integer\n        material: true\n        unit: count\n    effects:"), 1)
	raw = bytes.Replace(raw, []byte("      - kind: amount_max\n        param: amount\n"),
		[]byte("      - kind: amount_max\n        param: amount\n      - kind: count_max\n        param: batch\n        clamp: true\n"), 1)
	raw = bytes.Replace(raw, []byte("            reason: input.reason\n      - channel: mcp"),
		[]byte("            reason: input.reason\n            batch: input.batch\n      - channel: mcp"), 1)
	return bytes.Replace(raw, []byte("          reason: params.reason\n"), []byte("          reason: params.reason\n          batch: params.batch\n"), 1)
}

// TestF107_TheGatewayDispatchesTheEffectiveAction: a clamping obligation is
// applied before the permit is checked, and the target gets the clamped
// value; an effective action the gateway cannot reproduce, or an
// obligation it cannot apply, sends nothing.
func TestF107_TheGatewayDispatchesTheEffectiveAction(t *testing.T) {
	clamp := []*pb.Obligation{{Rule: "small-batches", Kind: "count_max", Param: "batch", Max: "5", Clamp: true, Timing: "before_execution"}}
	var h *harness
	effective := func(p actionir.Parsed) string {
		// The Authority's effective action: the same request with batch 5.
		in := strings.Replace(inbound, "}", `,"batch":5}`, 1)
		a := p.Action
		e, err := h.conn.Mapper.HTTP(context.Background(), mapping.Context{
			Org: a.Org, Env: a.Env, RunID: a.RunID, ActionID: a.ActionID, AgentInstance: a.AgentInstance, Connection: a.Connection,
		}, http.MethodPost, "/v1/refunds", "", []byte(in))
		if err != nil {
			t.Error(err)
		}
		return e.HashHex()
	}
	h = setup(t, func(h *harness) {
		h.mutatePkg, h.auth.decision = clampPkg, pb.Decision_DECISION_ALLOW
		h.auth.obligations, h.auth.effective = clamp, effective
	})
	if r := h.post(t, strings.Replace(inbound, "}", `,"batch":9}`, 1), nil); r.code != http.StatusOK {
		t.Fatalf("clamped = %d %+v", r.code, r.refusal)
	}
	if body, _ := h.target.req(0); !strings.Contains(body, `"batch":5`) {
		t.Fatalf("outbound %q is not the effective action", body)
	}
	for name, mod := range map[string]func(*fakeAuthority){
		"another effective action": func(f *fakeAuthority) { f.effective = func(actionir.Parsed) string { return strings.Repeat("ab", 32) } },
		"unknown obligation": func(f *fakeAuthority) {
			f.obligations = []*pb.Obligation{{Kind: "field_filter", Param: "reason", Timing: "before_execution"}}
		},
	} {
		h = setup(t, func(h *harness) {
			h.mutatePkg = clampPkg
			h.auth.obligations, h.auth.effective = clamp, effective
			mod(h.auth)
		})
		r := h.post(t, strings.Replace(inbound, "}", `,"batch":9}`, 1), nil)
		if r.code != http.StatusBadGateway || r.refusal.ErrorClass != "enforcement_failed" || len(h.auth.snap().begins) != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %d %+v", name, r.code, r.refusal)
		}
	}
}

// withCredential gives the connection a sealed credential for its hosts
// and the gateway a registered broker key that opens it.
func withCredential(t *testing.T, hosts []string) func(*harness) {
	return func(h *harness) {
		dir := t.TempDir()
		kek := filepath.Join(dir, "kek")
		if err := keys.GenerateKEKFile(kek); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "broker.json")
		if _, err := broker.Generate(t.Context(), path, []string{kek}); err != nil {
			t.Fatal(err)
		}
		key, err := broker.Load(t.Context(), path, []string{kek})
		if err != nil {
			t.Fatal(err)
		}
		h.broker = NewBroker(key, nil, nil)
		h.broker.id = "bk-1"
		pub, _ := pccrypto.ParseSealPublicKey(key.PublicKey())
		bind := domain.Binding{Org: testOrg, Connection: connID, Version: 1, AllowedHosts: hosts, BrokerKey: "bk-1", Header: "Authorization", Scheme: "Bearer"}
		blob, err := pccrypto.Seal(pub, bind.Info(), domain.AAD, []byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		h.conn.AccessMode = "pantherclaw_held"
		h.conn.Credential = &pb.SealedCredential{
			Id: ids.NewV7().String(), ConnectionId: connID, Version: 1, BrokerKeyId: "bk-1", Sealed: blob, AllowedHosts: hosts,
			Header: "Authorization", Scheme: "Bearer",
		}
	}
}

// TestHR061_TheCredentialIsPlacedJustInTimeAndNeverReturned: the target
// gets the opened credential in its header; the agent never sees it, even
// when the target echoes it (HR-076).
func TestHR061_TheCredentialIsPlacedJustInTimeAndNeverReturned(t *testing.T) {
	h := setup(t, withCredential(t, []string{"127.0.0.1"}), func(h *harness) { h.target.echo = "Authorization" })
	r := h.post(t, inbound, nil)
	if r.code != http.StatusOK {
		t.Fatalf("refund = %d %+v", r.code, r.refusal)
	}
	if _, hdr := h.target.req(0); hdr.Get("Authorization") != "Bearer "+testSecret {
		t.Fatalf("target got Authorization %q", hdr.Get("Authorization"))
	}
	if strings.Contains(r.body, testSecret) || !strings.Contains(r.body, "[REDACTED]") {
		t.Fatalf("the credential came back: %q", r.body)
	}
}

// TestHR060_ACredentialThatCannotBeUsedSendsNothing: a credential bound to
// other hosts, or none at all, fails the dispatch before any byte is sent;
// the outcome is recorded FAILED.
func TestHR060_ACredentialThatCannotBeUsedSendsNothing(t *testing.T) {
	for name, opt := range map[string]func(*harness){
		"other hosts":   withCredential(t, []string{"payments.example.test"}),
		"no credential": func(h *harness) { h.conn.AccessMode = "pantherclaw_held" },
	} {
		h := setup(t, opt)
		r := h.post(t, inbound, nil)
		if r.code != http.StatusBadGateway || r.refusal.Error != "credential_unavailable" || h.target.calls() != 0 ||
			h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
			t.Errorf("%s: %d %+v, target %d, records %v", name, r.code, r.refusal, h.target.calls(), h.auth.snap().records)
		}
	}
}

// TestHR010_AQuarantinedConnectionDispatchesNothing: the configuration or
// the containment stream saying quarantined stops a request before the
// Authority is asked.
func TestHR010_AQuarantinedConnectionDispatchesNothing(t *testing.T) {
	for name, opt := range map[string]func(*harness){
		"configuration": func(h *harness) { h.conn.State = "QUARANTINED" },
		"stream":        func(h *harness) { h.containment.conns[connID] = "QUARANTINED" },
	} {
		h := setup(t, opt)
		r := h.post(t, inbound, nil)
		if r.code != http.StatusForbidden || r.refusal.Error != "connection_quarantined" || h.auth.snap().authorize != 0 {
			t.Errorf("%s: %d %+v", name, r.code, r.refusal)
		}
	}
}

// testWorkloadToken is a token-shaped string naming testAgent in testEnv.
// The gateway reads it without verifying; the Authority verifies it.
func testWorkloadToken() string { return workloadTokenFor(testAgent) }

// testJKT is the key thumbprint testWorkloadToken is bound to.
const testJKT = "jkt-of-the-test-workload-key-0000000000000"

// workloadTokenFor is an unsigned workload token naming instance, bound to
// testJKT.
func workloadTokenFor(instance string) string { return workloadTokenWith(instance, testJKT) }

// workloadTokenWith is an unsigned workload token naming instance, bound
// to the key thumbprint jkt.
func workloadTokenWith(instance, jkt string) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload := `{"sub":"pc:org/` + testOrg + `/agent/01920000-0000-7000-8000-0000000000b1/inst/` + instance +
		`","cnf":{"jkt":"` + jkt + `"},"pap":{"v":1,"env":"` + testEnv + `"}}`
	return enc([]byte(`{"alg":"EdDSA"}`)) + "." + enc([]byte(payload)) + ".sig"
}

// TestHR091_GatewayForwardsPAPCredentials: the gateway hashes the raw body,
// forwards token, proof, method and its configured URL, and puts the
// token's instance and environment in the action; the Authority decides.
func TestHR091_GatewayForwardsPAPCredentials(t *testing.T) {
	h := setup(t)
	r := h.post(t, inbound, nil)
	if r.code != http.StatusOK || r.hdr.Get(HeaderNonce) != "nonce-1" {
		t.Fatalf("refund = %d, nonce %q", r.code, r.hdr.Get(HeaderNonce))
	}
	c := h.auth.snap().creds
	if c.GetWorkloadToken() != testWorkloadToken() || c.GetProof() == "" || !bytes.Equal(c.GetBodySha256(), sha(inbound)) ||
		c.GetHtm() != "POST" || c.GetHtu() != "http://127.0.0.1:8090"+refunds {
		t.Fatalf("forwarded credentials: %+v", c)
	}
	if a := h.auth.snap().actions[0].Action; a.AgentInstance != testAgent || a.Env != testEnv {
		t.Fatalf("action identity %+v", a)
	}
	// An unverifiable workload gets a PAP-Error and a fresh nonce.
	h.auth.mu.Lock()
	h.auth.identity = "use_nonce"
	h.auth.mu.Unlock()
	r = h.post(t, inbound, nil)
	if r.code != http.StatusUnauthorized || r.hdr.Get(HeaderError) != "use_nonce" || r.hdr.Get(HeaderNonce) != "nonce-2" ||
		r.refusal.ErrorClass != "authentication_failed" {
		t.Fatalf("unverified = %d %q %q", r.code, r.hdr.Get(HeaderError), r.hdr.Get(HeaderNonce))
	}
}

// TestHR148_GatewayRefusesWithoutPAP: no proof is use_nonce; a key-only
// proof is reported as an unknown workload with its route; a malformed
// token and missing run or action ids never reach Authorize.
func TestHR148_GatewayRefusesWithoutPAP(t *testing.T) {
	h := setup(t)
	r := h.post(t, inbound, map[string]string{HeaderProof: ""})
	if r.code != http.StatusUnauthorized || r.hdr.Get(HeaderError) != "use_nonce" || r.hdr.Get(HeaderNonce) != "nonce-0" {
		t.Errorf("no proof = %d %q %q", r.code, r.hdr.Get(HeaderError), r.hdr.Get(HeaderNonce))
	}
	r = h.post(t, inbound, map[string]string{"Authorization": ""})
	if rs := h.auth.snap().reports; r.code != http.StatusUnauthorized || r.hdr.Get(HeaderError) != "instance_not_admitted" || len(rs) != 1 ||
		rs[0].GetRoute() != "payments-refund" {
		t.Errorf("key-only = %d %q, reports %v", r.code, r.hdr.Get(HeaderError), rs)
	}
	if r := h.post(t, inbound, map[string]string{"Authorization": "PAP not-a-token"}); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "invalid_token" {
		t.Errorf("malformed token = %d %q", r.code, r.hdr.Get(HeaderError))
	}
	for _, hdr := range []string{HeaderRunID, HeaderActionID} {
		if r := h.post(t, inbound, map[string]string{hdr: ""}); r.code != http.StatusBadRequest {
			t.Errorf("without %s: %d", hdr, r.code)
		}
	}
	if h.auth.snap().authorize != 0 {
		t.Fatal("an unidentified request reached Authorize")
	}
}

// TestS09_AuthorityDownFailsClosed: CANNOT_AUTHORIZE, nothing dispatched.
func TestS09_AuthorityDownFailsClosed(t *testing.T) {
	h := setup(t, func(h *harness) { h.authorityURL = deadURL(t) })
	if r := h.post(t, inbound, nil); r.code != http.StatusServiceUnavailable || r.refusal.ErrorClass != "cannot_authorize" ||
		r.refusal.Decision != "CANNOT_AUTHORIZE" || h.target.calls() != 0 {
		t.Fatalf("authority down = %d %+v, target calls %d", r.code, r.refusal, h.target.calls())
	}
}

func sha(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// TestHR078_UnknownOutcomesOpenTheCircuitAndStopDispatch: five UNKNOWN
// outcomes in a row open the connection's circuit; the gateway reports it
// and refuses every further request before the Authority is asked.
func TestHR078_UnknownOutcomesOpenTheCircuitAndStopDispatch(t *testing.T) {
	h := setup(t, func(h *harness) { h.target.status = http.StatusBadGateway })
	for range 5 {
		if r := h.post(t, inbound, nil); r.code != http.StatusGatewayTimeout || r.refusal.ErrorClass != "uncertain" {
			t.Fatalf("unknown outcome = %d %+v", r.code, r.refusal)
		}
	}
	r := h.post(t, inbound, nil)
	if r.code != http.StatusServiceUnavailable || r.refusal.ErrorClass != "enforcement_failed" || r.refusal.Error != "circuit_open" ||
		h.auth.snap().authorize != 5 || h.target.calls() != 5 {
		t.Fatalf("open circuit = %d %+v, authorize %d, target %d", r.code, r.refusal, h.auth.snap().authorize, h.target.calls())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h.circuitMu.Lock()
		got := append([]string(nil), h.circuits...)
		h.circuitMu.Unlock()
		if len(got) == 1 && got[0] == connID+" 5/5" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("circuit reports %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
