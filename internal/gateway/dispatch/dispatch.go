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
	"maps"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/simcheck"
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
	CodeAuthorityUnavailable = "authority_unavailable"
	// CodeFactsUnreported: the facts the decision needs could not be
	// reported to the control plane, so no decision was asked for.
	CodeFactsUnreported       = "facts_unreported"
	CodeContainmentStale      = "containment_stale"
	CodeKillSwitch            = "kill_switch"
	CodeGatewayRevoked        = "gateway_revoked"
	CodeConnectionQuarantined = "connection_quarantined"
	CodeCircuitOpen           = "circuit_open"
	CodeDuplicate             = "duplicate_action"
	CodeObligation            = "obligation_unsupported"
	// CodeObligationFailed: the action breaks an obligation the gateway
	// checks, such as a disclosure param over its size or entropy limit
	// (HR-079); nothing is dispatched.
	CodeObligationFailed = "obligation_failed"
	CodeEffective        = "effective_action_mismatch"
	CodePermitInvalid    = "permit_invalid"
	CodeEpochStale       = "epoch_stale"
	CodeDispatchRefused  = "dispatch_refused"
	CodeRequest          = "request_not_built"
	CodeCredential       = "credential_unavailable" //nolint:gosec // G101: an error code, not a credential
	// CodeScopeMismatch: GitHub granted a wider token than requested; it
	// was revoked and nothing was sent (ADR-0021 item 3).
	CodeScopeMismatch     = "credential_scope_mismatch"
	CodeEgressDenied      = "egress_denied"
	CodeTargetUnreachable = "target_unreachable"
	CodeTargetRefused     = "target_refused"
	CodeTargetUncertain   = "target_uncertain"
	CodeNotRecorded       = "outcome_not_recorded"
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
	// An approved action's approval does not verify against the pinned
	// approver keys, or none are pinned (HR-038).
	CodeApprovalUnverified = "approval_unverified"
)

// Approvers verifies the approval a permit carries against the approver
// keys the gateway's operator pinned (proof.Pinned, HR-038).
type Approvers interface {
	Verify(a *proof.Approval, w proof.Want) error
}

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
	// ReportCircuitReason tells the server a connection's circuit opened
	// for a reason, without the thresholds (G0 M14 D54); nil reports nothing.
	ReportCircuitReason ReasonReporter
	// OnDrift is told of each drifted upstream tool that a call's own check
	// finds (CheckDrift returns what it finds instead); nil tells nothing.
	OnDrift func(ctx context.Context, connection string, d Drift)
	// Now is the breaker's clock; nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
	// Approvers verifies approvals (HR-038); nil refuses every action
	// whose permit carries one.
	Approvers Approvers
	// Connectors are the gateway's running connectors (G0 M9 track C);
	// nil when connectors are not enabled on it.
	Connectors Connectors
	// ReportFacts reports the github.* facts a GitHub App connection's
	// action needs, read just before its decision (G0 M8 decision 5); nil
	// reads none.
	ReportFacts FactReporter
	// FactTimeout bounds those reads; zero is DefaultFactTimeout.
	FactTimeout time.Duration
	// ReportRevocation tells the server that a token minted for a fact
	// read, a verification read or a scan could not be revoked (ADR-0021
	// item 6, R-18); nil only logs it. A dispatch's is reported with its
	// outcome.
	ReportRevocation RevocationReporter
	// ReportLocalRefusal tells the server an action was refused locally as
	// secret_in_payload or elicitation_refused, with machine metadata only,
	// so detections see it (G0 M12, HR-225; G0 M15 D40); nil only logs it.
	ReportLocalRefusal LocalRefusalReporter
	// GitHubAPIURL is GitHub's REST API (gateway configuration
	// github.api_url), where a GitHub App connection to GitHub's MCP server
	// mints its tokens and reads its facts; a connection to the REST API
	// uses its own base URL. Empty is DefaultGitHubAPIURL.
	GitHubAPIURL string
}

// DefaultGitHubAPIURL is GitHub's REST API.
const DefaultGitHubAPIURL = "https://api.github.com"

// RevocationReporter reports an installation token that was not revoked,
// with what it was for: facts, verification, org_scan or drift.
type RevocationReporter func(ctx context.Context, connection, purpose string, a broker.Access) error

// LocalRefusalReporter reports an action the gateway refused on its own:
// the connection, the refusal code, the operation and the run, never the
// payload or a secret; for an elicitation refusal also its reason and the
// question's SHA-256 (G0 M15 D40).
type LocalRefusalReporter func(ctx context.Context, connection, code, operation, run string, detail RefusalDetail) error

// RefusalDetail is what an elicitation refusal adds (G0 M15 D40): its
// reason (empty when none fits) and the question's SHA-256 (nil when
// none), never the question.
type RefusalDetail struct {
	ElicitationReason string
	QuestionSHA256    []byte
}

// Engine dispatches mapped actions.
type Engine struct {
	org           string
	authority     pantherclawv1connect.AuthorityServiceClient
	permits       *permitVerifier
	containment   Containment
	broker        Opener
	allowed       []netip.Prefix
	breaker       *breaker
	log           *slog.Logger
	nonces        nonces
	onDrift       func(ctx context.Context, connection string, d Drift)
	approvers     Approvers
	connectors    Connectors
	reportFacts   FactReporter
	factTimeout   time.Duration
	revocations   RevocationReporter
	localRefusals LocalRefusalReporter
	sims          *simcheck.Checker
	githubAPI     string

	mu      sync.Mutex
	clients map[string]clientEntry
	// apis are the GitHub API clients of kind-mcp connections (gitHubAPI).
	apis map[string]clientEntry
	// tokenClients are the token endpoint clients of oauth_client
	// credentials, one per connection revision (G0 M20 D254).
	tokenClients map[string]clientEntry
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
	if o.FactTimeout <= 0 {
		o.FactTimeout = DefaultFactTimeout
	}
	if o.GitHubAPIURL == "" {
		o.GitHubAPIURL = DefaultGitHubAPIURL
	}
	return &Engine{
		org: o.Org, authority: o.Authority, permits: newPermitVerifier(o.JWKSURL, o.JWKSClient, o.GatewayID, o.Org),
		containment: o.Containment, broker: o.Broker, allowed: o.AllowedPrefixes, breaker: newBreaker(o.Now, o.ReportCircuit, o.Log).withReason(o.ReportCircuitReason),
		log: o.Log, onDrift: o.OnDrift, clients: map[string]clientEntry{}, drift: map[string]driftEntry{}, approvers: o.Approvers,
		connectors:  o.Connectors,
		reportFacts: o.ReportFacts, factTimeout: o.FactTimeout, revocations: o.ReportRevocation, localRefusals: o.ReportLocalRefusal,
		sims: simcheck.New(), githubAPI: strings.TrimSuffix(o.GitHubAPIURL, "/"), apis: map[string]clientEntry{}, tokenClients: map[string]clientEntry{},
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
	// Wait is a held action's wait handle (PAP-1 §8); nil otherwise.
	Wait *pb.WaitInfo
	// Delegated is the request an SDK sends itself to a target-enforced
	// connection (HR-201); nil otherwise.
	Delegated *Delegated
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
	// Explanation is the Authority's agent-safe explanation (F330,
	// HR-400); nil when no decision was asked for.
	Explanation *pb.AgentExplanation
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
	cs := &callSecret{conn: conn.GetId()}
	defer cs.clear()
	ctx = context.WithValue(ctx, callSecretKey{}, cs)
	if _, class, code := e.contained(conn); class != "" {
		return Result{Class: class, Code: code}
	}
	if code := kindRefusal(conn); code != "" {
		return Result{Class: CannotAuthorize, Code: code, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	if e.breaker.open(ctx, conn) {
		return Result{Class: EnforcementFailed, Code: CodeCircuitOpen}
	}
	if code := e.refusedUpstream(conn, c.Action.Action.Operation); code != "" {
		return Result{Class: EnforcementFailed, Code: code}
	}
	if code := e.simulatorRefusal(ctx, conn); code != "" {
		return Result{Class: CannotAuthorize, Code: code, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	refusedPayload, findings := e.outboundCheck(ctx, conn, c.Action.Action)
	if refusedPayload {
		return Result{Class: CannotAuthorize, Code: CodeSecretInPayload, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	if code := accountRefusal(conn, c.Action.Action); code != "" {
		return Result{Class: CannotAuthorize, Code: code, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	if read, unreported := e.reportGitHubFacts(ctx, conn, c.Action.Action); read {
		t.lap("facts")
		if unreported != nil {
			// The facts it read, or could not, never reached the server, which
			// may still hold a fresh earlier observation: no decision is asked
			// for, so that observation cannot decide (#353 review).
			return Result{Class: CannotAuthorize, Code: CodeFactsUnreported, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
		}
	}
	if res, stop := e.stripeFacts(ctx, conn, c.Action.Action, t); stop {
		return res
	}
	if read, unreported := e.reportSlackFacts(ctx, conn, c.Action.Action); read && unreported != nil {
		return Result{Class: CannotAuthorize, Code: CodeFactsUnreported, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	if read, unreported := e.reportTeamsFacts(ctx, conn, c.Action.Action); read && unreported != nil {
		return Result{Class: CannotAuthorize, Code: CodeFactsUnreported, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	ar, err := e.authority.Authorize(ctx, &pb.AuthorizeRequest{ActionIr: c.Action.Canonical, Workload: c.Workload, PayloadFindings: findings})
	t.lap("authz")
	if err != nil {
		e.log.ErrorContext(ctx, "gateway.authority_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		return Result{Class: CannotAuthorize, Code: CodeAuthorityUnavailable, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	e.nonces.set(ar.GetNonce(), time.Time{})
	r := Result{
		Decision: ar.GetDecision(), TransactionID: ar.GetTransactionId(), Nonce: ar.GetNonce(),
		Monitor: ar.GetMode() == pb.DispatchMode_DISPATCH_MODE_MONITOR, Wait: ar.GetWait(),
		Explanation: ar.GetAgentExplanation(),
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
		if (conn.GetKind() == "local" || cooperative(c)) && len(ar.GetObligations()) > 0 {
			// A cooperative client runs the action as it asked: it can
			// honor no obligation (HR-186).
			return r.fail(EnforcementFailed, CodeObligation)
		}
		eff, err := effective(def, c.Action, ar.GetObligations())
		if errors.Is(err, errDisclosure) {
			return r.fail(EnforcementFailed, CodeObligationFailed)
		} else if err != nil {
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
	approval, err := e.permits.verify(ctx, ar.GetPermit(), want)
	if err != nil {
		e.log.ErrorContext(ctx, "security.permit_rejected", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return r.fail(EnforcementFailed, CodePermitInvalid)
	}
	if err := e.approved(approval, c.Action, bound); err != nil {
		e.log.ErrorContext(ctx, "security.approval_unverified", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return r.fail(EnforcementFailed, CodeApprovalUnverified)
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
	ctx, scopeCode := withScope(ctx, conn, def, ar.GetObligations())
	if scopeCode != "" {
		return r.fail(EnforcementFailed, scopeCode)
	}
	if cooperative(c) {
		return e.delegateSDK(ctx, r, conn, def, bound, want, t)
	}
	switch conn.GetKind() {
	case "mcp", "mcp_container":
		return e.sendMCP(ctx, r, conn, def, bound, want, t)
	case "local":
		return e.delegate(ctx, r, want, t)
	case "http":
		return e.send(ctx, r, conn, def, bound, want, t)
	}
	if send, ok := kindSenders[conn.GetKind()]; ok {
		return send(e, ctx, r, conn, def, bound, want, t) // G0 M14 D75
	}
	return r.fail(EnforcementFailed, CodeKindNotImplemented)
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
var (
	errUnsupported = errors.New("dispatch: unsupported obligation")
	// errDisclosure: a disclosure param over its limits (HR-079).
	errDisclosure = errors.New("dispatch: disclosure limit exceeded")
)

// errKind refuses to place a credential that is not static.
var errKind = errors.New("dispatch: a credential of a minted kind (a GitHub App, an OAuth client) is never placed as sealed")

// errPEM refuses to place a static credential that holds a private key in
// any common form (a PEM block, base64 PEM, a bare PEM body, DER), such as an
// App's private key sealed without --github-app: it would go to the target.
var errPEM = errors.New("dispatch: a credential holding a private key is never placed")

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
		if scopeObligation(o) {
			continue // applied to the answer by the scope engine (scope.go)
		}
		if o.GetKind() == string(defs.ConstraintDisclosureLimits) {
			if err := disclosed(vals, o); err != nil {
				return actionir.Parsed{}, err
			}
			continue
		}
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

// disclosed checks a disclosure_limits obligation (HR-079, G0 M10 D56):
// the param's bytes first, then their Shannon entropy in bits per byte.
// An absent param discloses nothing; a malformed limit is unsupported.
func disclosed(vals defs.Values, o *pb.Obligation) error {
	if o.GetTiming() != "" && o.GetTiming() != "before_execution" {
		return errUnsupported
	}
	maxBytes, err := strconv.Atoi(o.GetMax())
	if err != nil || maxBytes < 1 {
		return errUnsupported
	}
	maxEntropy, err := strconv.ParseFloat(o.GetMaxEntropy(), 64)
	if err != nil || maxEntropy <= 0 || maxEntropy > 8 {
		return errUnsupported
	}
	v, present := vals[o.GetParam()]
	if !present {
		return nil
	}
	b := v.Disclosed()
	if len(b) > maxBytes || defs.Entropy(b) > maxEntropy {
		return errDisclosure
	}
	return nil
}

// client returns the connection's egress client, new for each revision.
func (e *Engine) client(conn *control.Connection) (*egress.Client, error) {
	ce, err := e.entry(conn)
	return ce.client, err
}

// entry returns the connection's clients, new for each revision.
func (e *Engine) entry(conn *control.Connection) (clientEntry, error) {
	if kindNotImplemented(conn.GetKind()) {
		return clientEntry{}, errKindNotImplemented
	}
	if conn.GetKind() == "mcp_container" {
		return e.connectorEntry(conn)
	}
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

// gitHubAPI is where a GitHub App connection mints its tokens and reads
// GitHub (ADR-0021): a connection to the REST API at its own base URL,
// with its own client; a connection to GitHub's MCP server at the gateway's
// github.api_url, with a client of its own for that URL under the
// connection's timeout and response cap and the egress allow-list.
func (e *Engine) gitHubAPI(conn *control.Connection) (string, *egress.Client, error) {
	if conn.GetKind() != "mcp" {
		c, err := e.client(conn)
		return strings.TrimSuffix(conn.GetBaseUrl(), "/"), c, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.apis[conn.GetId()]; ok && ce.revision == conn.GetRevision() && ce.base == e.githubAPI {
		return ce.base, ce.client, nil
	}
	timeout := time.Duration(conn.GetTimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := egress.NewClient(e.githubAPI, timeout, conn.GetMaxResponseBytes(), e.allowed)
	if err != nil {
		return "", nil, err
	}
	e.apis[conn.GetId()] = clientEntry{revision: conn.GetRevision(), base: e.githubAPI, client: c}
	return e.githubAPI, c, nil
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
	revoke := func() {}
	access := func() *pb.CredentialAccess { return nil }
	if conn.GetAccessMode() == "pantherclaw_held" {
		s, release, used, err := e.credential(ctx, conn, def, a.Action.Target, p.req, p.client, "")
		if err != nil {
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		secret = s
		access = used
		// A minted token is revoked as soon as its answer is read, before
		// the outcome is recorded (HR-203); the deferred call covers every
		// other path.
		var once sync.Once
		done := func() { once.Do(release) }
		defer done()
		revoke = done
	}
	start := time.Now()
	res, err := p.client.Do(p.req)
	elapsed := time.Since(start)
	e.stripeAnswerLive(ctx, conn, res.Body, "dispatch")
	t.lap("target")
	outcome, class, code := classify(res.Status, err)
	if res.Status != 0 {
		if o, c, k := checkSuccess(def, outcome, res.Body); o != outcome {
			outcome, class, code = o, c, k
		}
	}
	e.breaker.record(ctx, conn, outcome)
	if err != nil && res.Status == 0 {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
	}
	var digest []byte
	ref := ""
	var response *[]byte
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
		class, code = e.scopeHTTP(ctx, conn, def, &res, class, code)
		r.Response = &res
		response = &res.Body
	}
	// Bodies an active capture profile asks for, never headers (HR-199).
	caps := captures(conn, def.Operation, r.Monitor, p.out.Body, response, secret, time.Now())
	revoke()
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t, func(req *pb.RecordExecutionRequest) {
		req.TargetRef, req.Captures, req.CredentialAccess = ref, caps, access()
		req.DataScope = appliedScope(ctx) // D102
	})
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

// credential opens the connection's sealed credential and places on req
// what the action on target under def may use. A static credential is
// placed as sealed. An OAuth client credential never is: the gateway mints
// an access token for this dispatch at its token endpoint and places that
// (G0 M20 D254, HR-524), and an AWS one signs only an AssumeRole narrowed to
// the dispatch's one action, whose session signs the request (HR-525).
// Nor is a GitHub App credential: the gateway mints an
// installation token for exactly the target's repository and def's
// declared permissions and places that (HR-203, HR-204). The caller keeps
// secret, which it scrubs from what goes back to the agent, until it calls
// release, which clears it and, for a minted token, revokes it at GitHub;
// access then says what the minted token allowed (nil for a static
// credential). A read (a verification or fact read included) gets a
// read-only token.
//
// purpose is what a read's token is for (verification), whose revocation
// failure is reported here; a dispatch's (empty) is reported with its
// outcome.
func (e *Engine) credential(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target,
	req *http.Request, c broker.Sender, purpose string,
) (secret []byte, release func(), access func() *pb.CredentialAccess, err error) {
	switch kind := conn.Credential.GetKind(); kind {
	case credentials.KindGitHubApp:
		if err := CheckCredentialPattern(def, kind, nil); err != nil {
			return nil, nil, nil, err // a pattern is for a static credential
		}
	case credentials.KindOAuthClient:
		// A token minted for this dispatch is placed, never the client
		// secret (G0 M20 D254, HR-524).
		if err := CheckCredentialPattern(def, kind, nil); err != nil {
			return nil, nil, nil, err
		}
		tok, err := e.clientToken(ctx, conn)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := tok.Place(req); err != nil {
			tok.Clear()
			return nil, nil, nil, err
		}
		return tok.Token(), tok.Clear, func() *pb.CredentialAccess { return nil }, nil
	case credentials.KindAWSSigV4:
		// Signed with a session assumed for this dispatch and narrowed to
		// its one action, never with the base key (G0 M20 D254, HR-525).
		if err := CheckCredentialPattern(def, kind, nil); err != nil {
			return nil, nil, nil, err
		}
		s, err := e.signAWS(ctx, conn, def, target, req)
		if err != nil {
			return nil, nil, nil, err
		}
		return s.Secret(), s.Clear, func() *pb.CredentialAccess { return nil }, nil
	default:
		plain, err := e.openStatic(ctx, conn)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := CheckCredentialPattern(def, conn.Credential.GetKind(), plain); err != nil {
			// Checked before any byte is sent (G0 M14 D8, HR-301).
			clear(plain)
			return nil, nil, nil, err
		}
		if err := placeCredential(conn, req, plain); err != nil {
			clear(plain)
			return nil, nil, nil, err
		}
		return plain, func() { clear(plain) }, func() *pb.CredentialAccess { return nil }, nil
	}
	tok, release, err := e.actionToken(ctx, conn, def, target, conn.GetBaseUrl(), c, purpose)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := tok.Place(req); err != nil {
		release()
		return nil, nil, nil, err
	}
	return tok.Token(), release, func() *pb.CredentialAccess { return accessOf(tok.Access()) }, nil
}

// actionToken mints, at the GitHub API base, the installation token an
// action on target under def may use: exactly the target's repository and
// def's declared permissions, read-only for a read (HR-203). release
// revokes it through c and clears it; a revocation that fails is logged
// and, with a purpose, reported (a dispatch's goes on its receipt).
func (e *Engine) actionToken(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target, base string,
	c broker.Sender, purpose string,
) (*broker.Installation, func(), error) {
	if def.Access == defs.AccessRead && !broker.ReadOnly(def.Scopes()) {
		return nil, nil, broker.ErrScope // every read is read-only (HR-203)
	}
	owner, _ := def.Target.Part(target.ID, "owner")
	repo, _ := def.Target.Part(target.ID, "repo")
	tok, err := e.mint(ctx, conn, base, owner, repo, def.Scopes(), c)
	if err != nil {
		return nil, nil, err
	}
	return tok, func() {
		if err := tok.Revoke(ctx, c); err != nil {
			e.log.WarnContext(ctx, "gateway.installation_token_not_revoked", slog.String("connection_id", conn.GetId()), pclog.Err(err))
			if purpose != "" {
				e.revokeFailed(ctx, conn, purpose, tok)
			}
		}
	}, nil
}

// credentialFailed records a committed dispatch whose credential could not
// be used: nothing was sent. A wider grant than requested is
// credential_scope_mismatch, with what GitHub granted and whether it was
// revoked on the refused dispatch's receipt (ADR-0021 items 3 and 6).
func (e *Engine) credentialFailed(ctx context.Context, r Result, conn *control.Connection, want permitWant, err error, t *timer) Result {
	e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("transaction_id", want.Txn),
		slog.String("connection_id", conn.GetId()), pclog.Err(err))
	code := CodeCredential
	var granted []func(*pb.RecordExecutionRequest)
	if errors.Is(err, ErrCredentialPattern) {
		code = CodeCredentialPattern
	}
	if sm := (*broker.ScopeMismatchError)(nil); errors.As(err, &sm) {
		code = CodeScopeMismatch
		granted = append(granted, func(req *pb.RecordExecutionRequest) { req.CredentialAccess = accessOf(sm.Access) })
	} else if errors.Is(err, broker.ErrScopeMismatch) {
		code = CodeScopeMismatch
	}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, code, t, granted...)
}

// revokeFailed reports a token minted for purpose that could not be
// revoked; a report that fails is only logged.
func (e *Engine) revokeFailed(ctx context.Context, conn *control.Connection, purpose string, tok *broker.Installation) {
	if e.revocations == nil {
		return
	}
	if err := e.revocations(context.WithoutCancel(ctx), conn.GetId(), purpose, tok.Access()); err != nil {
		e.log.WarnContext(ctx, "gateway.revocation_failure_not_reported", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
}

// maxGrant is the most permissions a receipt's access names.
const maxGrant = 32

var (
	grantName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	grantLevel = regexp.MustCompile(`^[a-z]{1,16}$`)
)

// clampGrant keeps the well-formed permissions of a grant, at most
// maxGrant of them: first those that made it wider than requested (not
// requested, or at another level), so the receipt shows why it was
// refused, then the rest, each by name (#353 review). incomplete reports
// that some were left out.
func clampGrant(g, requested map[string]string) (out map[string]string, incomplete bool) {
	if len(g) == 0 {
		return g, false
	}
	wider := func(k string) bool { r, ok := requested[k]; return !ok || r != g[k] }
	names := slices.Sorted(maps.Keys(g))
	slices.SortStableFunc(names, func(x, y string) int {
		switch wx, wy := wider(x), wider(y); {
		case wx && !wy:
			return -1
		case wy && !wx:
			return 1
		}
		return 0
	})
	out = map[string]string{}
	for _, k := range names {
		switch {
		case !grantName.MatchString(k) || !grantLevel.MatchString(g[k]):
			incomplete = true
		case len(out) == maxGrant:
			incomplete = true
		default:
			out[k] = g[k]
		}
	}
	return out, incomplete
}

// accessOf is what a minted token allowed, for the execution receipt
// (ADR-0021 item 5).
//
// GitHub's grant is clamped to what the receipt's schema allows (#313
// review follow-up): a refused wider grant may name anything, and a grant
// the schema refused would leave a transaction UNKNOWN although nothing was
// sent.
func accessOf(a broker.Access) *pb.CredentialAccess {
	out := &pb.CredentialAccess{
		InstallationId: a.Installation, Repository: a.Repository, RepositoryId: max(a.RepositoryID, 0), Requested: a.Requested,
		Revocation: a.Revocation,
	}
	out.Granted, out.GrantedIncomplete = clampGrant(a.Granted, a.Requested)
	if !a.Expires.IsZero() {
		out.ExpireTime = timestamppb.New(a.Expires)
	}
	return out
}

// openStatic opens the connection's sealed credential when it is static.
// Another kind is refused before anything is decrypted, so an App's key is
// opened only on the path that mints with it (HR-204).
func (e *Engine) openStatic(ctx context.Context, conn *control.Connection) ([]byte, error) {
	if cs, ok := ctx.Value(callSecretKey{}).(*callSecret); ok && cs.conn == conn.GetId() {
		// The call has opened it already (the outbound check): decrypt once,
		// hand each caller its own copy to clear.
		cs.once.Do(func() { cs.b, cs.err = e.openStaticUncached(conn) })
		return slices.Clone(cs.b), cs.err
	}
	return e.openStaticUncached(conn)
}

func (e *Engine) openStaticUncached(conn *control.Connection) ([]byte, error) {
	if k := conn.Credential.GetKind(); k != "" && k != credentials.KindStatic {
		return nil, errKind
	}
	return e.openCredential(conn)
}

// callSecretKey carries a call's callSecret in its context.
type callSecretKey struct{}

// callSecret is a call's opened static credential, opened at most once and
// cleared when the call ends.
type callSecret struct {
	// conn is the connection the secret belongs to; any other connection
	// opens its own.
	conn string
	once sync.Once
	b    []byte
	err  error
}

func (cs *callSecret) clear() { clear(cs.b) }

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
		Kind: cred.GetKind(),
	})
}

// placeCredential places an opened static credential on req, for the
// credential's allowed hosts only. A GitHub App credential is never placed:
// it holds the App's key, from which the gateway mints a token per action
// (HR-203, HR-204). Nor is a static one holding a private key.
func placeCredential(conn *control.Connection, req *http.Request, secret []byte) error {
	cred := conn.Credential
	if k := cred.GetKind(); k != "" && k != credentials.KindStatic {
		return errKind
	}
	if credentials.HoldsPrivateKey(secret) {
		return errPEM
	}
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
	elapsed time.Duration, class Class, code string, t *timer, extra ...func(*pb.RecordExecutionRequest),
) Result {
	req := &pb.RecordExecutionRequest{
		PermitId: want.PermitID, Outcome: outcome, TargetStatus: int32(min(status, 599)), ResponseDigest: digest, //nolint:gosec // G115: clamped
		DispatchMs: int32(min(elapsed.Milliseconds(), 600000)), //nolint:gosec // G115: clamped
	}
	for _, f := range extra {
		f(req)
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
