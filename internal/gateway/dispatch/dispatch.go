// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package dispatch is the gateway's one dispatch path (G0 M6 design
// decision 10, ARCHITECTURE §9). Every channel maps its call to ActionIR
// through the connection's reviewed package and hands it to
// Engine.Dispatch, which:
//
//  1. refuses at once when containment is stale, the kill switch is on or
//     the connection is quarantined (HR-010);
//  2. asks the Authority and goes on only with a permit;
//  3. applies the decision's obligations, checks that the result is the
//     action the permit binds, and verifies the permit (HR-009);
//  4. builds the outbound request from the definition's template (HR-073,
//     HR-075) and commits it with BeginDispatch before any byte is sent
//     (HR-001), which returns an action token for a target-enforced
//     connection (HR-188);
//  5. opens the connection's credential just in time and places it only
//     for its hosts (HR-060, HR-061);
//  6. sends the request through the connection's egress client,
//     classifies the outcome, removes the credential from the response
//     (HR-076) and records the outcome.
//
// Monitor mode (HR-184) takes the same path with the requested action: the
// permit, not the decision, says whether to dispatch. Every refusal has a
// Class (design decision 18, F642).
package dispatch

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Class is the type of a refusal or failure (G0 M6 design decision 18,
// F642). The zero value is success.
type Class string

// Classes.
const (
	// PolicyDenied: the decision was DENY.
	PolicyDenied Class = "policy_denied"
	// CannotAuthorize: the action could not be decided (CANNOT_AUTHORIZE,
	// the Authority unreachable, a request that does not map).
	CannotAuthorize Class = "cannot_authorize"
	// Held: REQUIRE_APPROVAL or REQUIRE_STEP_UP, with the transaction id.
	Held Class = "held"
	// AuthenticationFailed: the workload could not be verified (a
	// PAP-Error).
	AuthenticationFailed Class = "authentication_failed"
	// EnforcementFailed: the gateway could not enforce the decision, and
	// nothing was sent.
	EnforcementFailed Class = "enforcement_failed"
	// ToolFailed: the target refused.
	ToolFailed Class = "tool_failed"
	// Uncertain: the outcome is UNKNOWN. Do not retry; reconciliation
	// follows.
	Uncertain Class = "uncertain"
)

// Codes the gateway sets itself (Result.Code); a decision's code is its
// decisive reason.
const (
	CodeAuthorityUnavailable  = "authority_unavailable"
	CodeContainmentStale      = "containment_stale"
	CodeKillSwitch            = "kill_switch"
	CodeGatewayRevoked        = "gateway_revoked"
	CodeConnectionQuarantined = "connection_quarantined"
	CodeCircuitOpen           = "circuit_open"
	CodeDuplicate             = "duplicate_action"
	CodeObligation            = "obligation_unsupported"
	CodeEffective             = "effective_action_mismatch"
	CodePermitInvalid         = "permit_invalid"
	CodeEpochStale            = "epoch_stale"
	CodeDispatchRefused       = "dispatch_refused"
	CodeRequest               = "request_not_built"
	CodeCredential            = "credential_unavailable" //nolint:gosec // G101: an error code, not a credential
	CodeEgressDenied          = "egress_denied"
	CodeTargetUnreachable     = "target_unreachable"
	CodeTargetRefused         = "target_refused"
	CodeTargetUncertain       = "target_uncertain"
	CodeNotRecorded           = "outcome_not_recorded"
	// An upstream MCP tool reported an error (isError).
	CodeToolError = "tool_error"
	// An upstream MCP server asked for input the gateway never gives
	// (HR-082).
	CodeInputRequired = "upstream_input_required"
	// An upstream MCP tool no longer matches its reviewed definition
	// (HR-081).
	CodeUpstreamDrift = "upstream_drift"
	// An upstream MCP tool's pinned definition declares x-mcp-header
	// parameters the specification forbids, so no client may call it.
	CodeUpstreamInvalid = "upstream_tool_invalid"
)

// Containment is the gateway's containment view (control.Containment).
type Containment interface {
	// Check reports whether dispatch is allowed now, with the current epoch.
	Check() (int64, error)
	// Connection is a connection's state on the stream ("" when unnamed).
	Connection(id string) string
}

// Opener opens a sealed credential with the gateway's registered broker
// key (gateway.Broker).
type Opener interface {
	Open(org, connection string, allowedHosts []string, s broker.Sealed) ([]byte, error)
}

// Options configure an Engine.
type Options struct {
	// Org and GatewayID come from the gateway's certificate.
	Org, GatewayID string
	Authority      pantherclawv1connect.AuthorityServiceClient
	// JWKSURL and JWKSClient fetch the permit keys.
	JWKSURL     string
	JWKSClient  *http.Client
	Containment Containment
	// Broker opens credentials; nil without a broker key.
	Broker Opener
	// AllowedPrefixes are the operator's egress.allowed_prefixes (HR-077).
	AllowedPrefixes []netip.Prefix
	// ReportCircuit tells the server a connection's circuit opened
	// (HR-078); nil reports nothing.
	ReportCircuit Reporter
	// OnDrift is told of each drifted upstream tool that a call's own check
	// finds (CheckDrift returns what it finds instead); nil tells nothing.
	OnDrift func(ctx context.Context, connection string, d Drift)
	// Now is the breaker's clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
}

// Engine dispatches mapped actions.
type Engine struct {
	org         string
	authority   pantherclawv1connect.AuthorityServiceClient
	permits     *permitVerifier
	containment Containment
	broker      Opener
	allowed     []netip.Prefix
	breaker     *breaker
	log         *slog.Logger
	nonces      nonces
	onDrift     func(ctx context.Context, connection string, d Drift)

	mu      sync.Mutex
	clients map[string]clientEntry
	// drift is what the last check of each kind-mcp connection found.
	drift map[string]driftEntry
}

// clientEntry is a connection's egress client for one revision of it, and
// for a kind-mcp connection its MCP client, which keeps the server's
// version and session.
type clientEntry struct {
	revision int32
	base     string
	client   *egress.Client
	mcp      *upstream.Client
}

// New returns an Engine.
func New(o Options) (*Engine, error) {
	if o.Org == "" || o.GatewayID == "" || o.Authority == nil || o.JWKSClient == nil || o.Containment == nil {
		return nil, errors.New("dispatch: incomplete options")
	}
	if o.Log == nil {
		o.Log = pclog.Discard()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Engine{
		org: o.Org, authority: o.Authority, permits: newPermitVerifier(o.JWKSURL, o.JWKSClient, o.GatewayID, o.Org),
		containment: o.Containment, broker: o.Broker, allowed: o.AllowedPrefixes, breaker: newBreaker(o.Now, o.ReportCircuit, o.Log),
		log: o.Log, onDrift: o.OnDrift, clients: map[string]clientEntry{}, drift: map[string]driftEntry{},
	}, nil
}

// Call is one mapped action.
type Call struct {
	// Connection is the connection the call came through.
	Connection *control.Connection
	// Action is the mapped action, its connection set.
	Action actionir.Parsed
	// Workload is the request's PAP/1 credentials.
	Workload *pb.WorkloadCredentials
}

// Result is what happened to a call.
type Result struct {
	// Class is empty when the action was dispatched and the target
	// accepted it.
	Class Class
	// Code says why: the decisive reason of a decision, or a gateway code.
	Code     string
	Decision pb.Decision
	// Reasons are the decision's reason codes, decisive first.
	Reasons       []string
	TransactionID string
	// Monitor: the route runs in monitor mode, so Decision is hypothetical
	// and nothing about the action was prevented (HR-184).
	Monitor bool
	// Outcome is what was recorded; UNSPECIFIED when nothing was committed.
	Outcome pb.Outcome
	// Response is the target's response, the credential removed; nil when
	// there was none.
	Response *egress.Response
	// ToolResult: Response.Body is an upstream MCP server's CallToolResult
	// (a kind-mcp connection).
	ToolResult bool
	// Receipt is the execution receipt.
	Receipt string
	// Nonce is the org's current nonce, for the PAP-Nonce header.
	Nonce string
	// PAPError is the PAP-Error code of an AuthenticationFailed result.
	PAPError pap.Code
	// Timings are the steps' durations (the Server-Timing header).
	Timings []Lap
}

// Lap is one step's duration.
type Lap struct {
	Name string
	D    time.Duration
}

type timer struct {
	mark time.Time
	laps []Lap
}

func (t *timer) lap(name string) {
	now := time.Now()
	t.laps = append(t.laps, Lap{Name: name, D: now.Sub(t.mark)})
	t.mark = now
}

// contained checks containment and the connection's state: the current
// epoch, or a refusal.
func (e *Engine) contained(conn *control.Connection) (int64, Class, string) {
	epoch, err := e.containment.Check()
	switch {
	case errors.Is(err, control.ErrKillSwitch):
		return 0, EnforcementFailed, CodeKillSwitch
	case errors.Is(err, control.ErrRevoked):
		return 0, EnforcementFailed, CodeGatewayRevoked
	case err != nil:
		return 0, EnforcementFailed, CodeContainmentStale
	}
	// The stream is fresher than the configuration; either one saying
	// quarantined is enough.
	if s := e.containment.Connection(conn.GetId()); (s != "" && s != "ACTIVE") || conn.GetState() != "ACTIVE" {
		return 0, EnforcementFailed, CodeConnectionQuarantined
	}
	return epoch, "", ""
}

// Dispatch runs one call down the dispatch path.
func (e *Engine) Dispatch(ctx context.Context, c Call) Result {
	t := &timer{mark: time.Now()}
	r := e.dispatch(ctx, c, t)
	r.Timings = t.laps
	return r
}

func (e *Engine) dispatch(ctx context.Context, c Call, t *timer) Result {
	conn := c.Connection
	if _, class, code := e.contained(conn); class != "" {
		return Result{Class: class, Code: code}
	}
	if e.breaker.open(ctx, conn) {
		return Result{Class: EnforcementFailed, Code: CodeCircuitOpen}
	}
	if code := e.refusedUpstream(conn, c.Action.Action.Operation); code != "" {
		return Result{Class: EnforcementFailed, Code: code}
	}
	ar, err := e.authority.Authorize(ctx, &pb.AuthorizeRequest{ActionIr: c.Action.Canonical, Workload: c.Workload})
	t.lap("authz")
	if err != nil {
		e.log.ErrorContext(ctx, "gateway.authority_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		return Result{Class: CannotAuthorize, Code: CodeAuthorityUnavailable, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	e.nonces.set(ar.GetNonce(), time.Time{})
	r := Result{
		Decision: ar.GetDecision(), TransactionID: ar.GetTransactionId(), Nonce: ar.GetNonce(),
		Monitor: ar.GetMode() == pb.DispatchMode_DISPATCH_MODE_MONITOR,
	}
	for _, rs := range ar.GetReasons() {
		r.Reasons = append(r.Reasons, rs.GetCode())
	}
	if rs := ar.GetReasons(); r.Decision == pb.Decision_DECISION_CANNOT_AUTHORIZE && len(rs) > 0 && rs[0].GetCode() == "IDENTITY_UNVERIFIED" {
		// The workload could not be verified: a PAP-Error, so it can retry
		// with a fresh nonce or token (PAP-1 §12).
		r.Class, r.PAPError, r.Code = AuthenticationFailed, pap.Code(rs[0].GetDetail()), rs[0].GetDetail()
		return r
	}
	if ar.GetPermit() == "" {
		return refused(r)
	}
	if !r.Monitor && !allows(r.Decision) {
		return r.fail(EnforcementFailed, CodePermitInvalid)
	}
	def, ok := conn.Package.Definition(c.Action.Action.Operation)
	if !ok || ar.GetActionHash() != c.Action.HashHex() {
		return r.fail(EnforcementFailed, CodePermitInvalid)
	}
	// The permit binds the effective action (the requested one with the
	// obligations applied) or, in monitor mode, the requested one.
	bound := c.Action
	if !r.Monitor {
		if conn.GetKind() == "local" && len(ar.GetObligations()) > 0 {
			// A cooperative client runs the action as it asked: it can
			// honor no obligation (HR-186).
			return r.fail(EnforcementFailed, CodeObligation)
		}
		eff, err := effective(def, c.Action, ar.GetObligations())
		if err != nil {
			return r.fail(EnforcementFailed, CodeObligation)
		}
		want := ar.GetEffectiveActionHash()
		if want == "" {
			want = c.Action.HashHex()
		}
		if eff.HashHex() != want {
			return r.fail(EnforcementFailed, CodeEffective)
		}
		bound = eff
	}
	want := permitWant{PermitID: ar.GetPermitId(), Txn: ar.GetTransactionId(), Act: bound.HashHex(), Epoch: ar.GetEpoch()}
	if err := e.permits.verify(ctx, ar.GetPermit(), want); err != nil {
		e.log.ErrorContext(ctx, "security.permit_rejected", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return r.fail(EnforcementFailed, CodePermitInvalid)
	}
	t.lap("verify")
	// Containment may have changed while the Authority decided: a permit
	// from an older epoch, or a view gone stale, dispatches nothing.
	// BeginDispatch stays the authoritative check (HR-001).
	epoch, class, code := e.contained(conn)
	if class != "" {
		return r.fail(class, code)
	}
	if want.Epoch < epoch {
		return r.fail(EnforcementFailed, CodeEpochStale)
	}
	switch conn.GetKind() {
	case "mcp":
		return e.sendMCP(ctx, r, conn, def, bound, want, t)
	case "local":
		return e.delegate(ctx, r, want, t)
	}
	return e.send(ctx, r, conn, def, bound, want, t)
}

// delegate commits and records a cooperative channel's permitted action
// (the Claude Code hook; HR-186): BeginDispatch, so containment, the kill
// switch and the epoch apply as for any action, then RecordExecution with
// outcome DELEGATED. The agent's own machine performs the action; the
// gateway sends nothing, and the receipt says so.
func (e *Engine) delegate(ctx context.Context, r Result, want permitWant, t *timer) Result {
	_, err := e.authority.BeginDispatch(ctx, &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch})
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	return e.record(context.WithoutCancel(ctx), r, want, pb.Outcome_OUTCOME_DELEGATED, 0, nil, 0, "", "", t)
}

// allows reports whether a decision lets an enforce-mode action proceed.
func allows(d pb.Decision) bool {
	return d == pb.Decision_DECISION_ALLOW || d == pb.Decision_DECISION_ALLOW_WITH_OBLIGATIONS
}

// refused classifies a decision that came without a permit.
func refused(r Result) Result {
	if len(r.Reasons) > 0 {
		r.Code = r.Reasons[0]
	}
	switch r.Decision {
	case pb.Decision_DECISION_DENY:
		r.Class = PolicyDenied
	case pb.Decision_DECISION_REQUIRE_APPROVAL, pb.Decision_DECISION_REQUIRE_STEP_UP:
		r.Class = Held
	case pb.Decision_DECISION_ALLOW, pb.Decision_DECISION_ALLOW_WITH_OBLIGATIONS:
		// A retried action gets its stored decision, never a second
		// permit (HR-005).
		r.Class, r.Code = CannotAuthorize, CodeDuplicate
	case pb.Decision_DECISION_CANNOT_AUTHORIZE, pb.Decision_DECISION_UNSPECIFIED:
		r.Class = CannotAuthorize
	}
	return r
}

func (r Result) fail(class Class, code string) Result {
	r.Class, r.Code = class, code
	return r
}

// errUnsupported reports an obligation the gateway cannot apply.
var errUnsupported = errors.New("dispatch: unsupported obligation")

// effective applies the decision's obligations to the action (F104, F107):
// the only kind the Authority sets is count_max with clamping, before
// execution. Any other obligation is not applied, and nothing is sent.
func effective(def *defs.Definition, p actionir.Parsed, obligations []*pb.Obligation) (actionir.Parsed, error) {
	if len(obligations) == 0 {
		return p, nil
	}
	vals, err := def.DecodeParams(p.Action.Params)
	if err != nil {
		return actionir.Parsed{}, err
	}
	changed := false
	for _, o := range obligations {
		if o.GetKind() != string(defs.ConstraintCountMax) || !o.GetClamp() || (o.GetTiming() != "" && o.GetTiming() != "before_execution") {
			return actionir.Parsed{}, errUnsupported
		}
		limit, err := strconv.ParseInt(o.GetMax(), 10, 64)
		v, present := vals[o.GetParam()]
		if err != nil || (present && v.Type != defs.TypeInteger) {
			return actionir.Parsed{}, errUnsupported
		}
		if !present || v.Int <= limit {
			continue
		}
		v.Int = limit
		vals[o.GetParam()] = v
		changed = true
	}
	if !changed {
		return p, nil
	}
	raw, err := def.EncodeParams(vals)
	if err != nil {
		return actionir.Parsed{}, err
	}
	a := p.Action
	a.Params = raw
	return actionir.Encode(a)
}

// client returns the connection's egress client, new for each revision.
func (e *Engine) client(conn *control.Connection) (*egress.Client, error) {
	ce, err := e.entry(conn)
	return ce.client, err
}

// entry returns the connection's clients, new for each revision.
func (e *Engine) entry(conn *control.Connection) (clientEntry, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.clients[conn.GetId()]; ok && ce.revision == conn.GetRevision() && ce.base == conn.GetBaseUrl() {
		return ce, nil
	}
	timeout := time.Duration(conn.GetTimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := egress.NewClient(conn.GetBaseUrl(), timeout, conn.GetMaxResponseBytes(), e.allowed)
	if err != nil {
		return clientEntry{}, err
	}
	ce := clientEntry{revision: conn.GetRevision(), base: conn.GetBaseUrl(), client: c}
	if conn.GetKind() == "mcp" {
		ce.mcp = upstream.New(conn.GetBaseUrl(), c)
	}
	e.clients[conn.GetId()] = ce
	return ce, nil
}

// prepared is the outbound request, built and checked.
type prepared struct {
	out    egress.Request
	req    *http.Request
	client *egress.Client
}

func (e *Engine) prepare(ctx context.Context, conn *control.Connection, def *defs.Definition, a actionir.Parsed, txn string) (prepared, error) {
	if conn.GetKind() != "http" {
		return prepared{}, fmt.Errorf("%w: a %s connection", egress.ErrBuild, conn.GetKind())
	}
	out, err := egress.Build(conn.GetBaseUrl(), def, a.Action, txn)
	if err != nil {
		return prepared{}, err
	}
	c, err := e.client(conn)
	if err != nil {
		return prepared{}, err
	}
	req, err := c.HTTPRequest(ctx, out)
	if err != nil {
		return prepared{}, err
	}
	req.Header.Set("User-Agent", "pantherclaw-gateway")
	return prepared{out: out, req: req, client: c}, nil
}

// send builds, commits, sends and records.
func (e *Engine) send(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	p, buildErr := e.prepare(ctx, conn, def, a, want.Txn)
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if buildErr == nil {
		// The exact body, empty included, is what an action token binds.
		sum := sha256.Sum256(p.out.Body)
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = p.out.Method, p.out.URL.String(), sum[:]
	}
	bd, err := e.authority.BeginDispatch(ctx, begin)
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	// Committed: the agent going away must not stop dispatch or recording.
	ctx = context.WithoutCancel(ctx)
	if buildErr != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	if tok := bd.GetActionToken(); tok != "" {
		p.req.Header.Set(HeaderAction, tok)
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		s, err := e.credential(conn, p.req)
		if err != nil {
			e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("transaction_id", want.Txn),
				slog.String("connection_id", conn.GetId()), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeCredential, t)
		}
		secret = s
		defer clear(secret)
	}
	start := time.Now()
	res, err := p.client.Do(p.req)
	elapsed := time.Since(start)
	t.lap("target")
	outcome, class, code := classify(res.Status, err)
	e.breaker.record(ctx, conn, outcome)
	if err != nil && res.Status == 0 {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
	}
	var digest []byte
	ref := ""
	if res.Status != 0 {
		// The digest is of what the target sent; the agent gets it without
		// the credential.
		sum := sha256.Sum256(res.Body)
		digest = sum[:]
		if outcome == pb.Outcome_OUTCOME_ACCEPTED {
			ref = targetRef(def, res.Body, secret)
		}
		res.Body = egress.Redacted(res.Body, secret)
		res.ContentType = string(egress.Redacted([]byte(res.ContentType), secret))
		res.RequestID = string(egress.Redacted([]byte(res.RequestID), secret))
		r.Response = &res
	}
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t, ref)
}

// maxTargetRef is the longest reference the Authority accepts.
const maxTargetRef = 256

// targetRef reads the created object's identifier from an accepted answer
// at the place the definition's verifier names (G0 M7 design decision 5):
// printable ASCII only, never one that contains the credential. It is the
// only part of a response body the gateway sends to the Authority.
func targetRef(def *defs.Definition, body, secret []byte) string {
	v := def.Verifier
	if v == nil || v.Reference == nil {
		return ""
	}
	s, ok := defs.PointerValue(body, v.Reference.FromResponse)
	if !ok || s == "" || len(s) > maxTargetRef || strings.ContainsFunc(s, func(c rune) bool { return c < '!' || c > '~' }) ||
		(len(secret) > 0 && strings.Contains(s, string(secret))) {
		return ""
	}
	return s
}

// credential opens the connection's sealed credential and places it on req.
func (e *Engine) credential(conn *control.Connection, req *http.Request) ([]byte, error) {
	secret, err := e.openCredential(conn)
	if err != nil {
		return nil, err
	}
	if err := placeCredential(conn, req, secret); err != nil {
		clear(secret)
		return nil, err
	}
	return secret, nil
}

// openCredential opens the connection's sealed credential; the caller
// clears it.
func (e *Engine) openCredential(conn *control.Connection) ([]byte, error) {
	cred := conn.Credential
	if cred == nil {
		return nil, errors.New("the connection has no active credential")
	}
	if e.broker == nil {
		return nil, broker.ErrNoBroker
	}
	return e.broker.Open(e.org, conn.GetId(), cred.GetAllowedHosts(), broker.Sealed{
		Version: cred.GetVersion(), BrokerKey: cred.GetBrokerKeyId(), Blob: cred.GetSealed(), Header: cred.GetHeader(), Scheme: cred.GetScheme(),
	})
}

// placeCredential places an opened credential on req, for the
// credential's allowed hosts only.
func placeCredential(conn *control.Connection, req *http.Request, secret []byte) error {
	cred := conn.Credential
	return broker.Place(req, cred.GetAllowedHosts(), cred.GetHeader(), cred.GetScheme(), secret)
}

// classify maps a target's answer to an outcome (design decision 10): 2xx
// accepted; 4xx failed; a refused dial failed, because nothing was sent;
// anything else, including a timeout after sending, unknown.
func classify(status int, err error) (pb.Outcome, Class, string) {
	switch {
	case status >= 200 && status < 300:
		return pb.Outcome_OUTCOME_ACCEPTED, "", ""
	case status >= 400 && status < 500:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	case status != 0:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case errors.Is(err, httpx.ErrDestinationDenied):
		return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeEgressDenied
	case errors.Is(err, egress.ErrHost):
		return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeRequest
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetUnreachable
	}
	return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
}

// record records the outcome (RecordExecution). A failed record leaves the
// permit DISPATCHING, which the Authority's sweeper marks UNKNOWN: the
// reservation stays held.
func (e *Engine) record(ctx context.Context, r Result, want permitWant, outcome pb.Outcome, status int, digest []byte,
	elapsed time.Duration, class Class, code string, t *timer, targetRef ...string,
) Result {
	req := &pb.RecordExecutionRequest{
		PermitId: want.PermitID, Outcome: outcome, TargetStatus: int32(min(status, 599)), ResponseDigest: digest, //nolint:gosec // G115: clamped
		DispatchMs: int32(min(elapsed.Milliseconds(), 600000)), //nolint:gosec // G115: clamped
	}
	if len(targetRef) > 0 {
		req.TargetRef = targetRef[0]
	}
	rec, err := e.authority.RecordExecution(ctx, req)
	t.lap("record")
	r.Outcome, r.Receipt = outcome, rec.GetReceipt()
	if err != nil {
		e.log.ErrorContext(ctx, "gateway.outcome_not_recorded", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return r.fail(Uncertain, CodeNotRecorded)
	}
	return r.fail(class, code)
}
