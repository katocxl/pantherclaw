// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/outbound"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/modelapi"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// The model path (G0 M29 D812–D820, HR-690..HR-695): a call over a model
// connection is not mapped through a template. internal/gateway/modelconn
// strictly parses the agent's body with internal/modelapi and builds the
// action from its metadata and the hash of the body it forwards; the engine
// gates provider-side tools, scans every string of the prompt for secrets,
// asks the Authority, commits, places the held key and sends exactly that
// body, and modelconn streams the answer back while it is read.

// ModelConnTimeout bounds one call over a model connection, its stream
// included, on the gateway as on the edge (D814).
const ModelConnTimeout = 10 * time.Minute

// Codes of the model path.
const (
	// CodeServerToolNotAllowed: the request names a provider-side tool its
	// connection does not allow (D813, HR-696); nothing was asked or sent.
	CodeServerToolNotAllowed = "MODEL_SERVER_TOOL_NOT_ALLOWED"
	// CodePayloadNotScannable: the prompt is past the model-path scan
	// limits (D817); nothing was asked or sent.
	CodePayloadNotScannable = "payload_not_scannable"
	// localModelServerTool is the refusal's report code (G0 M12 style).
	localModelServerTool = "model_server_tool_not_allowed"
	// modelSimKind is the handshake kind of pantherclaw-sim model (D826).
	modelSimKind = "model"
)

// ModelAdmit runs the checks that come before a model request is parsed
// (D812): containment and the connection's state, its model settings, the
// circuit breaker and, for a simulated connection, the simulator handshake.
// ok is false with the refusal when the call may not go on.
func (e *Engine) ModelAdmit(ctx context.Context, conn *control.Connection) (Result, bool) {
	if _, class, code := e.contained(conn); class != "" {
		return Result{Class: class, Code: code}, false
	}
	if conn.GetKind() != KindModel || conn.GetModel() == nil || conn.Package == nil {
		return Result{Class: CannotAuthorize, Code: CodeKindConfigMissing, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}, false
	}
	if e.breaker.open(ctx, conn) {
		return Result{Class: EnforcementFailed, Code: CodeCircuitOpen}, false
	}
	if code := e.simulatorRefusal(ctx, conn); code != "" {
		return Result{Class: CannotAuthorize, Code: code, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}, false
	}
	return Result{}, true
}

// modelSimRefusal verifies a simulated model connection's target: it must
// answer the handshake as pantherclaw-sim model, on a loopback or private
// literal (HR-221, D826).
func (e *Engine) modelSimRefusal(ctx context.Context, conn *control.Connection) string {
	ce, err := e.entry(conn)
	if err != nil {
		return CodeSimulatorUnverified
	}
	if err := e.sims.VerifyKind(ctx, conn.GetId(), conn.GetBaseUrl(), modelSimKind, ce.client); err != nil {
		e.log.WarnContext(ctx, "gateway.simulator_unverified", slog.String("connection_id", conn.GetId()), slog.String("reason", err.Error()))
		return CodeSimulatorUnverified
	}
	return ""
}

// ModelCall is one call over a model connection, parsed and mapped by
// modelconn.
type ModelCall struct {
	Connection *control.Connection
	// Action is the call's action: target {model, <model id>} and the
	// params of D813, body_sha256 binding Request.Body.
	Action   actionir.Parsed
	Workload *pb.WorkloadCredentials
	// Request is the parsed body; nil for a read, which has none.
	Request *modelapi.Request
	// Method and URL are the outbound request's: the base URL plus the
	// operation's fixed path and the allowed query (D812).
	Method string
	URL    *url.URL
	// Header holds the allow-listed request headers (D812); the engine
	// places the credential after.
	Header http.Header
	// Answer passes the provider's answer on to the agent as it is read and
	// says how it ended. The engine calls it at most once, after the
	// request is sent, and records the outcome after it returns.
	Answer func(ModelStart) ModelAnswer
}

// ModelStart is what Answer gets: the provider's response, whose body it
// reads; the decision's facts for the agent's headers; and the placed
// secret, which it must never pass on (HR-076).
type ModelStart struct {
	Response      *http.Response
	Secret        []byte
	TransactionID string
	Decision      pb.Decision
	Monitor       bool
	Nonce         string
	// Keep is how many bytes of the reply Answer keeps for capture (G0 M30
	// D945b); zero keeps none.
	Keep int
}

// ModelAnswer is how passing an answer on ended (D818).
type ModelAnswer struct {
	// Complete: the whole answer was read and passed on, a JSON body that
	// parses or a stream that ended with its API's terminal event.
	Complete bool
	// Errored: the stream carried an error event.
	Errored bool
	// Err is a read or write error: the cap, the time limit, a cut
	// connection.
	Err error
	// Usage is what the answer reported.
	Usage modelapi.Usage
	// Digest is the SHA-256 of the bytes the provider sent.
	Digest []byte
	// Kept is the first ModelStart.Keep bytes of the reply, unredacted,
	// and Size the reply's whole length (G0 M30 D945b).
	Kept []byte
	Size int64
}

// DispatchModel runs one model call down the model path (D812): the
// provider-side tool gate, the secret scan, the decision, BeginDispatch, the
// held key, the send, the answer and RecordExecution with its usage.
func (e *Engine) DispatchModel(ctx context.Context, c ModelCall) Result {
	t := &timer{mark: time.Now()}
	r := e.dispatchModel(ctx, c, t)
	r.Timings = t.laps
	return r
}

func (e *Engine) dispatchModel(ctx context.Context, c ModelCall, t *timer) Result {
	conn := c.Connection
	cs := &callSecret{conn: conn.GetId()}
	defer cs.clear()
	ctx = context.WithValue(ctx, callSecretKey{}, cs)
	a := c.Action.Action
	cannot := func(code string) Result {
		return Result{Class: CannotAuthorize, Code: code, Decision: pb.Decision_DECISION_CANNOT_AUTHORIZE}
	}
	if c.Request != nil {
		if tools := notAllowed(c.Request.ServerTools, conn.GetModel().GetAllowedServerTools()); len(tools) > 0 {
			// Refused before the Authority is asked (D813, HR-696).
			e.log.WarnContext(ctx, "gateway.model_server_tool_refused", slog.String("connection_id", conn.GetId()),
				slog.String("run_id", a.RunID), slog.String("operation", a.Operation), slog.Any("server_tools", tools))
			e.reportLocalRefusal(ctx, conn, localModelServerTool, a, RefusalDetail{})
			return cannot(CodeServerToolNotAllowed)
		}
	}
	findings, code := e.modelScan(ctx, conn, c)
	if code != "" {
		return cannot(code)
	}
	call := Call{Connection: conn, Action: c.Action, Workload: c.Workload}
	ctx, content, scan := e.outboundContent(ctx, call)
	ctx, d, r, ok := e.decide(ctx, call, findings, content, scan, t)
	if !ok {
		return r
	}
	if d.bound.HashHex() != c.Action.HashHex() {
		// An obligation changed the action, but the body it binds is the
		// agent's: the gateway never rewrites a prompt (D812).
		return r.fail(EnforcementFailed, CodeObligation)
	}
	return e.sendModel(ctx, r, c, d, t)
}

// notAllowed are the provider-side tools of a request its connection does
// not allow.
func notAllowed(tools, allowed []string) []string {
	var out []string
	for _, tool := range tools {
		if !slices.Contains(allowed, tool) {
			out = append(out, tool)
		}
	}
	return out
}

// modelScan scans a model call (D817, HR-694): every string of the prompt
// and the model id, or a read's target. A secret the gateway holds for the
// connection refuses it; a known format comes back as findings for the
// Authority; a prompt past the scan limits is not scannable.
func (e *Engine) modelScan(ctx context.Context, conn *control.Connection, c ModelCall) ([]*pb.PayloadFinding, string) {
	var held [][]byte
	if secret, err := e.openStatic(ctx, conn); err == nil {
		defer clear(secret)
		held = append(held, secret)
	} else if conn.Credential != nil {
		e.log.DebugContext(ctx, "gateway.held_secret_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
	}
	a := c.Action.Action
	var res outbound.Result
	if c.Request != nil {
		var err error
		if res, err = outbound.ScanModel(c.Request.Body, c.Request.Model, held); err != nil {
			e.log.WarnContext(ctx, "gateway.payload_not_scannable", slog.String("connection_id", conn.GetId()),
				slog.String("run_id", a.RunID), slog.String("operation", a.Operation), slog.Int("input_bytes", len(c.Request.Body)))
			return nil, CodePayloadNotScannable
		}
	} else {
		res = outbound.Scan(outbound.Input{Path: a.Target.ID}, held)
	}
	if res.HeldSecret {
		e.log.WarnContext(ctx, "gateway.secret_in_payload", slog.String("connection_id", conn.GetId()), slog.String("run_id", a.RunID),
			slog.String("operation", a.Operation))
		e.reportLocalRefusal(ctx, conn, CodeSecretInPayload, a, RefusalDetail{})
		return nil, CodeSecretInPayload
	}
	var out []*pb.PayloadFinding
	for _, f := range res.Findings {
		out = append(out, &pb.PayloadFinding{Kind: f.Kind, Location: f.Location})
	}
	return out, ""
}

// sendModel commits the call, places the held key, sends exactly the parsed
// body and records the outcome with its usage (D812, D814, D818).
func (e *Engine) sendModel(ctx context.Context, r Result, c ModelCall, d decided, t *timer) Result {
	conn, want := c.Connection, d.want
	var body []byte
	if c.Request != nil {
		body = c.Request.Body
	}
	cl, clientErr := e.client(conn)
	sum := sha256.Sum256(body)
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if clientErr == nil {
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = c.Method, c.URL.String(), sum[:]
	}
	_, err := e.authority.BeginDispatch(ctx, begin)
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	usage := modelUsageOf(d.def.Access != defs.AccessRead)
	// Committed: the agent going away must not stop recording.
	ctx = context.WithoutCancel(ctx)
	if clientErr != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(clientErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t, usage(ModelAnswer{}, false))
	}
	sendCtx, cancel := context.WithTimeout(ctx, ModelConnTimeout)
	defer cancel()
	req, err := cl.HTTPRequest(sendCtx, egress.Request{Method: c.Method, URL: c.URL, Body: body})
	if err != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t, usage(ModelAnswer{}, false))
	}
	for name, vs := range c.Header {
		req.Header[name] = slices.Clone(vs)
	}
	secret, release, _, err := e.credential(ctx, conn, d.def, c.Action.Action.Target, req, cl, "")
	if err != nil {
		return e.credentialFailed(ctx, r, conn, want, err, t)
	}
	var once sync.Once
	done := func() { once.Do(release) }
	defer done()
	start := time.Now()
	res, err := cl.Open(req)
	if err != nil {
		elapsed := time.Since(start)
		t.lap("target")
		outcome, class, code := classify(0, err)
		e.breaker.record(ctx, conn, outcome)
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
		done()
		return e.record(ctx, r, want, outcome, 0, nil, elapsed, class, code, t, usage(ModelAnswer{}, false))
	}
	ans := c.Answer(ModelStart{
		Response: res, Secret: secret, TransactionID: r.TransactionID, Decision: r.Decision, Monitor: r.Monitor, Nonce: r.Nonce,
		Keep: modelKeep(conn, c.Action.Action.Operation, r.Monitor, secret, time.Now()),
	})
	_ = res.Body.Close()
	elapsed := time.Since(start)
	t.lap("target")
	// Bodies an active capture profile asks for, redacted while the secret
	// is still held (G0 M30 D945b).
	caps := modelCaptures(conn, c.Action.Action.Operation, r.Monitor, body, ans.Kept, ans.Size, secret, time.Now())
	done()
	outcome, class, code := modelOutcome(res.StatusCode, ans)
	e.breaker.record(ctx, conn, outcome)
	// Metadata only, never a body (D820, HR-695): a body is kept only as a
	// capture (G0 M30 D945b).
	e.log.InfoContext(ctx, "gateway.model_call", slog.String("connection_id", conn.GetId()), slog.String("transaction_id", want.Txn),
		slog.String("operation", c.Action.Action.Operation), slog.String("model", c.Action.Action.Target.ID),
		slog.Int("input_bytes", len(body)), slog.Int("status", res.StatusCode), slog.String("outcome", outcome.String()),
		slog.Int64("input_tokens", ans.Usage.Input), slog.Int64("output_tokens", ans.Usage.Output),
		slog.Int64("cache_read_tokens", ans.Usage.CacheRead), slog.Int64("cache_write_tokens", ans.Usage.CacheWrite),
		slog.Bool("usage_reported", ans.Usage.Reported))
	if ans.Err != nil {
		e.log.WarnContext(ctx, "gateway.model_answer_cut", slog.String("transaction_id", want.Txn), pclog.Err(ans.Err))
	}
	return e.record(ctx, r, want, outcome, res.StatusCode, ans.Digest, elapsed, class, code, t,
		usage(ans, outcome == pb.Outcome_OUTCOME_ACCEPTED), func(req *pb.RecordExecutionRequest) { req.Captures = caps })
}

// modelUsageOf returns what a model call's record carries (D818, D825):
// for a create or count operation (write) its usage, the reported numbers
// only when the call was accepted and zeros otherwise; nothing for a read.
func modelUsageOf(write bool) func(ModelAnswer, bool) func(*pb.RecordExecutionRequest) {
	return func(ans ModelAnswer, accepted bool) func(*pb.RecordExecutionRequest) {
		return func(req *pb.RecordExecutionRequest) {
			if !write {
				return
			}
			u := &pb.ModelUsage{}
			if accepted && ans.Usage.Reported {
				u.InputTokens, u.OutputTokens = ans.Usage.Input, ans.Usage.Output
				u.CacheReadTokens, u.CacheWriteTokens, u.Reported = ans.Usage.CacheRead, ans.Usage.CacheWrite, true
			}
			req.ModelUsage = u
		}
	}
}

// modelOutcome maps how an answer ended to an outcome (D818): a complete
// 2xx answer ACCEPTED; a complete 4xx or 5xx one FAILED (providers do not
// bill a rejected call); anything cut, broken, errored or late UNKNOWN.
func modelOutcome(status int, ans ModelAnswer) (pb.Outcome, Class, string) {
	switch {
	case ans.Err != nil || !ans.Complete:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case status >= 200 && status < 300 && !ans.Errored:
		return pb.Outcome_OUTCOME_ACCEPTED, "", ""
	case status >= 400 && status < 600:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	}
	return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
}
