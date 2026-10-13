// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
)

// sendMCP builds, commits, calls and records an action through a kind-mcp
// connection (G0 M6 design decision 14): the reviewed upstream tool with
// arguments built from the permitted action. BeginDispatch binds the
// canonical {name, arguments} (upstream.Params), whatever protocol version
// and JSON-RPC id carry it. The credential and the action token go on every
// request of the call (discovery, the session's initialize, the call
// itself, answers to the server), within the credential's hosts.
//
// To a 2026-07-28 server the call also carries an Mcp-Param-{Name} header
// for each argument the tool's pinned definition marks x-mcp-header: the
// declarations come from the definition the last drift check found
// matching upstream_digest, never from the agent or from an unchecked
// listing, and the values from the arguments built above, so the body that
// BeginDispatch binds also fixes them. With no check of this connection
// revision yet, the call checks first (with the credential only); a tool
// that drifted, or whose declarations break the specification, is not
// called.
//
// Outcomes: a result is ACCEPTED; a tool error (isError), a JSON-RPC
// error, an input_required result (HR-082) and an HTTP 4xx are FAILED; a
// call that never left the gateway is FAILED; anything after it left
// without an answer is UNKNOWN.
func (e *Engine) sendMCP(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	tool, args, buildErr := egress.BuildMCP(def, a.Action)
	var params []byte
	if buildErr == nil {
		params, buildErr = upstream.Params(tool, args)
	}
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if buildErr == nil {
		sum := sha256.Sum256(params)
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = http.MethodPost, conn.GetBaseUrl(), sum[:]
	}
	bd, err := e.authority.BeginDispatch(ctx, begin)
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	ctx = context.WithoutCancel(ctx)
	ce, err := e.entry(conn)
	if buildErr == nil && err != nil {
		buildErr = err
	}
	if buildErr != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		if secret, err = e.openStatic(conn); err != nil {
			e.log.WarnContext(ctx, "gateway.credential_unavailable", slog.String("transaction_id", want.Txn),
				slog.String("connection_id", conn.GetId()), pclog.Err(err))
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeCredential, t)
		}
		defer clear(secret)
	}
	token := bd.GetActionToken()
	decorate := func(req *http.Request) error {
		if token != "" {
			req.Header.Set(HeaderAction, token)
		}
		if secret != nil {
			return placeCredential(conn, req, secret)
		}
		return nil
	}
	declared, refusal, err := e.pinnedParams(ctx, conn, ce, tool, secret)
	switch {
	case err != nil:
		// The server could not be listed: the call was never sent.
		outcome, class, code := classifyMCP(upstream.Result{}, fmt.Errorf("%w: listing the tools: %w", upstream.ErrNotSent, err))
		e.breaker.record(ctx, conn, outcome)
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
		return e.record(ctx, r, want, outcome, 0, nil, 0, class, code, t)
	case refusal != "":
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, refusal, t)
	}
	if err := mirrorable(conn, declared, args); err != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(err))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	start := time.Now()
	res, err := ce.mcp.Call(ctx, tool, args, declared, decorate)
	elapsed := time.Since(start)
	t.lap("target")
	outcome, class, code := classifyMCP(res, err)
	e.breaker.record(ctx, conn, outcome)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
	}
	if res.Error != nil && res.Error.Code == upstream.CodeHeaderMismatch {
		// The server's tool may have changed under its pin: check it again
		// before the next call is sent.
		e.recheck(conn)
	}
	var digest []byte
	if body := answerBody(res); body != nil {
		// The digest is of what the server sent; the agent gets it without
		// the credential.
		sum := sha256.Sum256(body)
		digest = sum[:]
		r.Response = &egress.Response{
			Status: res.Status, Body: egress.Redacted(body, secret), ContentType: "application/json",
			RequestID: string(egress.Redacted([]byte(res.RequestID), secret)),
		}
		r.ToolResult = res.Error == nil && !res.InputRequired
	}
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t)
}

// Drift is an upstream tool that no longer matches the definition the
// connection's package was reviewed against (HR-081): Observed is the
// digest the server lists now, empty when the tool is gone.
type Drift struct {
	Tool, Expected, Observed string
}

// CheckDrift lists a kind-mcp connection's upstream tools, with its
// credential, and compares each reviewed tool with what the server lists
// now (G0 M6 design decision 14). Until a later check finds them matching
// again, or the connection changes, the gateway refuses the drifted tools
// itself (upstream_drift), so nothing runs against a changed tool while
// the server quarantines the package. Of each tool that matches, it keeps
// the x-mcp-header declarations, which calls mirror; a tool whose
// declarations break the specification's constraints is refused too
// (upstream_tool_invalid), as a conforming client leaves it out.
func (e *Engine) CheckDrift(ctx context.Context, conn *control.Connection) ([]Drift, error) {
	if conn.GetKind() != "mcp" || len(reviewedTools(conn)) == 0 {
		return nil, nil
	}
	ce, err := e.entry(conn)
	if err != nil {
		return nil, err
	}
	var secret []byte
	if conn.GetAccessMode() == "pantherclaw_held" {
		if secret, err = e.openStatic(conn); err != nil {
			return nil, err
		}
		defer clear(secret)
	}
	return e.check(ctx, conn, ce, secret)
}

// reviewedTools are a connection's upstream tools, each with the digests
// the package pins it to.
func reviewedTools(conn *control.Connection) map[string][]string {
	reviewed := map[string][]string{}
	for i := range conn.Package.Definitions {
		if m := mcpTemplate(&conn.Package.Definitions[i]); m != nil && !slices.Contains(reviewed[m.Tool], m.UpstreamDigest) {
			reviewed[m.Tool] = append(reviewed[m.Tool], m.UpstreamDigest)
		}
	}
	return reviewed
}

// check lists the upstream tools with the opened credential (no action
// token: the list belongs to no call) and records what it found for the
// connection's revision.
func (e *Engine) check(ctx context.Context, conn *control.Connection, ce clientEntry, secret []byte) ([]Drift, error) {
	reviewed := reviewedTools(conn)
	tools, err := ce.mcp.ListTools(ctx, func(req *http.Request) error {
		if secret != nil {
			return placeCredential(conn, req, secret)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	type definition struct {
		digest string
		schema jsontext.Value
	}
	listed := map[string][]definition{}
	for _, t := range tools {
		var n struct {
			Name        string         `json:"name"`
			InputSchema jsontext.Value `json:"inputSchema"`
		}
		d, err := upstream.ToolDigest(t)
		if err != nil || json.Unmarshal(t, &n) != nil {
			return nil, fmt.Errorf("%w: a tool definition does not decode", upstream.ErrProtocol)
		}
		listed[n.Name] = append(listed[n.Name], definition{digest: d, schema: n.InputSchema})
	}
	var drifts []Drift
	entry := driftEntry{revision: conn.GetRevision(), tools: map[string]bool{}, pinned: map[string]pinned{}}
	for _, tool := range slices.Sorted(maps.Keys(reviewed)) {
		got := listed[tool]
		for _, want := range reviewed[tool] {
			other := slices.IndexFunc(got, func(d definition) bool { return d.digest != want })
			switch {
			case len(got) == 0:
				drifts = append(drifts, Drift{Tool: tool, Expected: want})
			case other >= 0:
				// A changed definition, or the name listed more than once.
				drifts = append(drifts, Drift{Tool: tool, Expected: want, Observed: got[other].digest})
			default:
				continue
			}
			entry.tools[tool] = true
		}
		if entry.tools[tool] {
			continue
		}
		params, err := mcpheader.Parse(got[0].schema)
		if err != nil {
			e.log.WarnContext(ctx, "security.upstream_tool_invalid", slog.String("connection_id", conn.GetId()),
				slog.String("upstream_tool", tool), pclog.Err(err))
			entry.pinned[tool] = pinned{invalid: err.Error()}
			continue
		}
		entry.pinned[tool] = pinned{params: params}
	}
	e.mu.Lock()
	e.drift[conn.GetId()] = entry
	e.mu.Unlock()
	return drifts, nil
}

// driftEntry is what the last check of one revision of a connection found:
// the drifted tools and, of each other tool, its pinned declarations.
type driftEntry struct {
	revision int32
	tools    map[string]bool
	pinned   map[string]pinned
	// stale: the server has refused a call's headers since (HeaderMismatch),
	// so the next call checks again before it is sent.
	stale bool
}

// pinned is an upstream tool whose listed definition matched its pin.
type pinned struct {
	// params are its x-mcp-header declarations.
	params []mcpheader.Param
	// invalid says how the declarations break the specification; such a
	// tool is never called.
	invalid string
}

// refusedUpstream says why an operation's upstream tool must not be
// called, on the last check's evidence: upstream_drift,
// upstream_tool_invalid or "".
func (e *Engine) refusedUpstream(conn *control.Connection, operation string) string {
	def, ok := conn.Package.Definition(operation)
	m := mcpTemplate(def)
	if !ok || m == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.drift[conn.GetId()]
	switch {
	case !ok || d.revision != conn.GetRevision():
		return ""
	case d.tools[m.Tool]:
		return CodeUpstreamDrift
	case d.pinned[m.Tool].invalid != "":
		return CodeUpstreamInvalid
	}
	return ""
}

// pinnedParams are the x-mcp-header declarations of an upstream tool's
// pinned definition, from the last check of the connection's revision.
// With none yet, or a stale one, it checks first. refusal says the tool
// must not be called; err that the server could not be listed.
func (e *Engine) pinnedParams(ctx context.Context, conn *control.Connection, ce clientEntry, tool string, secret []byte,
) (params []mcpheader.Param, refusal string, err error) {
	e.mu.Lock()
	d, ok := e.drift[conn.GetId()]
	e.mu.Unlock()
	if !ok || d.revision != conn.GetRevision() || d.stale {
		drifts, err := e.check(ctx, conn, ce, secret)
		if err != nil {
			return nil, "", err
		}
		for _, dr := range drifts {
			if e.onDrift != nil {
				e.onDrift(ctx, conn.GetId(), dr)
			}
		}
		e.mu.Lock()
		d = e.drift[conn.GetId()]
		e.mu.Unlock()
	}
	p, matched := d.pinned[tool]
	switch {
	case d.tools[tool] || !matched:
		return nil, CodeUpstreamDrift, nil
	case p.invalid != "":
		return nil, CodeUpstreamInvalid, nil
	}
	return p.params, "", nil
}

// recheck makes the next call through the connection check its tools
// again before it is sent.
func (e *Engine) recheck(conn *control.Connection) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if d, ok := e.drift[conn.GetId()]; ok && d.revision == conn.GetRevision() {
		d.stale = true
		e.drift[conn.GetId()] = d
	}
}

// mirrorable checks that a call's arguments can go in the headers its
// tool declares, and that no such header is where the connection places
// its credential.
func mirrorable(conn *control.Connection, params []mcpheader.Param, args jsontext.Value) error {
	if _, err := mcpheader.Mirror(params, args); err != nil {
		return err
	}
	if h := conn.Credential.GetHeader(); h != "" && slices.ContainsFunc(params, func(p mcpheader.Param) bool {
		return strings.EqualFold(p.Header(), h)
	}) {
		return fmt.Errorf("the credential is placed in %s, which the upstream tool mirrors an argument into", h)
	}
	return nil
}

func mcpTemplate(d *defs.Definition) *defs.MCPDispatch {
	if d == nil || d.Dispatch == nil {
		return nil
	}
	return d.Dispatch.MCP
}

// answerBody is what the server answered: the CallToolResult, an
// input_required result, or the JSON-RPC error.
func answerBody(res upstream.Result) []byte {
	switch {
	case res.Error != nil:
		b, err := json.Marshal(res.Error)
		if err != nil {
			return nil
		}
		return b
	case len(res.Result) > 0:
		return res.Result
	}
	return nil
}

// classifyMCP maps an upstream answer to an outcome.
func classifyMCP(res upstream.Result, err error) (pb.Outcome, Class, string) {
	switch {
	case errors.Is(err, upstream.ErrNotSent):
		var op *net.OpError
		switch {
		case errors.Is(err, httpx.ErrDestinationDenied):
			return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeEgressDenied
		case errors.Is(err, egress.ErrHost):
			return pb.Outcome_OUTCOME_FAILED, EnforcementFailed, CodeRequest
		case errors.As(err, &op) && op.Op == "dial":
			return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetUnreachable
		}
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	case err != nil:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case res.InputRequired:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeInputRequired
	case res.Error != nil || (res.Status >= 400 && res.Status < 500):
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeTargetRefused
	case res.Status < 200 || res.Status >= 300 || len(res.Result) == 0:
		return pb.Outcome_OUTCOME_UNKNOWN, Uncertain, CodeTargetUncertain
	case res.IsError:
		return pb.Outcome_OUTCOME_FAILED, ToolFailed, CodeToolError
	}
	return pb.Outcome_OUTCOME_ACCEPTED, "", ""
}
