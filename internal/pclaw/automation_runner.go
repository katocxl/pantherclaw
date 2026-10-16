// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
)

// `pclaw automation runner` (G0 M11 part 2 D33; HR-285) is the PantherClaw
// runner agent: an ordinary enrolled workload that claims its own agent's
// automation launches and performs each launch's declared calls through
// the gateway, in the launch's run, signed with its own key. Tool calls
// reach targets only this way: the server never calls a tool (F3,
// HR-279). Every call is decided, held and receipted like any agent
// action. The runner stops at the first call that is denied, held, failed
// or whose outcome is unknown, never sends a call twice once the gateway
// may have acted on it, and reports each call's result when it completes
// the launch.

const (
	// runnerMaxCalls bounds a launch's declared calls (D33).
	runnerMaxCalls = 10
	// runnerTimeout bounds one call to the gateway.
	runnerTimeout = 2 * time.Minute
	// runnerMaxAnswer bounds one answer from the gateway.
	runnerMaxAnswer = 16 << 20
	// runnerMaxInput bounds one call's rendered input (the HTTP face reads
	// 64 KiB, the MCP face 256 KiB with the envelope).
	runnerMaxInput = 64 << 10
	// runnerMCPVersion is the stateless MCP revision the runner speaks.
	runnerMCPVersion = "2026-07-28"
	// runnerOnceTries bounds the attempts to report a launch with --once.
	runnerOnceTries = 3
)

// Faces of a declared call.
const (
	faceMCP  = "MCP"
	faceHTTP = "HTTP"
)

// runnerCall is one declared call of a launch, its input rendered by the
// server from the reviewed version (D33): an MCP tools/call, or an HTTP
// request to the connection's reviewed routes.
type runnerCall struct {
	Connection string
	Face       string
	// Tool is the MCP tool.
	Tool string
	// Method and Path are the HTTP request; Path starts with "/".
	Method, Path string
	// Input is a JSON object: the tool's arguments, or the HTTP body (the
	// query for GET).
	Input jsontext.Value
}

// callStatus is what became of one call.
type callStatus string

const (
	// callSucceeded: allowed and the target answered with success.
	callSucceeded callStatus = "SUCCEEDED"
	// callDenied: the decision was DENY.
	callDenied callStatus = "DENIED"
	// callHeld: held for approval or step-up; the runner does not wait.
	callHeld callStatus = "HELD"
	// callFailed: not performed, or the target refused; the outcome is
	// known.
	callFailed callStatus = "FAILED"
	// callUnknown: the gateway may have acted and the outcome is unknown;
	// never sent again (reconciliation follows).
	callUnknown callStatus = "UNKNOWN"
)

// callResult is one call's result for CompleteLaunch.
type callResult struct {
	Index         int
	Status        callStatus
	TransactionID string
	ErrorCode     string
}

// launchOutcome is a launch's outcome for CompleteLaunch.
type launchOutcome string

const (
	launchSucceeded launchOutcome = "SUCCEEDED"
	launchFailed    launchOutcome = "FAILED"
	launchPartial   launchOutcome = "PARTIAL"
)

// callRunner performs one launch's calls through the gateway in its run.
type callRunner struct {
	// gateway is the gateway's base URL.
	gateway string
	// run is the launch's run (PAP-Run-Id).
	run string
	// client signs every request with the workload key and never follows
	// redirects.
	client *http.Client
	log    io.Writer

	// declared are the x-mcp-header parameters of each connection's tools,
	// from its last tool list.
	declared map[string]map[string][]mcpheader.Param
	lists    int
}

// runCalls performs calls in order and stops at the first that did not
// succeed. It returns the results of the calls it attempted and the
// launch's outcome. A list that does not validate runs nothing.
func (c *callRunner) runCalls(ctx context.Context, calls []runnerCall) ([]callResult, launchOutcome) {
	if len(calls) > runnerMaxCalls {
		return []callResult{{Index: runnerMaxCalls, Status: callFailed, ErrorCode: "too_many_calls"}}, launchFailed
	}
	for i, call := range calls {
		if err := checkCall(call); err != nil {
			c.logf("call %d: %v", i, err)
			return []callResult{{Index: i, Status: callFailed, ErrorCode: "invalid_call"}}, launchFailed
		}
	}
	results := make([]callResult, 0, len(calls))
	for i, call := range calls {
		var r callResult
		if call.Face == faceMCP {
			r = c.mcpCall(ctx, i, call)
		} else {
			r = c.httpCall(ctx, i, call)
		}
		results = append(results, r)
		if r.Status != callSucceeded {
			break
		}
	}
	return results, outcomeOf(results, len(calls))
}

// outcomeOf is SUCCEEDED when every call succeeded, PARTIAL when some did
// before one did not, and FAILED otherwise.
func outcomeOf(results []callResult, n int) launchOutcome {
	ok := 0
	for _, r := range results {
		if r.Status == callSucceeded {
			ok++
		}
	}
	switch {
	case ok == n:
		return launchSucceeded
	case ok > 0:
		return launchPartial
	}
	return launchFailed
}

// checkCall checks a call before anything is sent.
func checkCall(call runnerCall) error {
	if call.Connection == "" || strings.ContainsAny(call.Connection, "/?#") || call.Connection == "." || call.Connection == ".." {
		return errors.New("the connection name is not one path segment")
	}
	if len(call.Input) > runnerMaxInput {
		return errors.New("the input is too large")
	}
	if len(call.Input) > 0 && call.Input.Kind() != '{' {
		return errors.New("the input is not a JSON object")
	}
	switch call.Face {
	case faceMCP:
		if call.Tool == "" {
			return errors.New("an MCP call names its tool")
		}
	case faceHTTP:
		switch call.Method {
		case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			return fmt.Errorf("method %q is not one the runner sends", call.Method)
		}
		u, err := url.Parse(call.Path)
		if err != nil || !strings.HasPrefix(call.Path, "/") || strings.HasPrefix(call.Path, "//") ||
			u.RawQuery != "" || u.Fragment != "" || u.Host != "" || u.Scheme != "" || dotSegment(u.Path) {
			return errors.New("the path must be an absolute path without a query, fragment or dot segments")
		}
	default:
		return fmt.Errorf("face %q is not MCP or HTTP", call.Face)
	}
	return nil
}

// dotSegment reports whether a path has a "." or ".." segment.
func dotSegment(p string) bool {
	for s := range strings.SplitSeq(p, "/") {
		if s == "." || s == ".." {
			return true
		}
	}
	return false
}

func (c *callRunner) logf(format string, args ...any) {
	if c.log != nil {
		_, _ = fmt.Fprintf(c.log, "pclaw automation runner: "+format+"\n", args...)
	}
}

// send posts one request. A transport error after the request may have
// left is reported as err; the caller decides what it means.
func (c *callRunner) send(req *http.Request) (int, http.Header, []byte, error) {
	res, err := c.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, runnerMaxAnswer+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(b) > runnerMaxAnswer {
		return 0, nil, nil, errors.New("the gateway's answer is too large")
	}
	return res.StatusCode, res.Header, b, nil
}

// httpCall sends one call to the HTTP face, {gateway}/{connection}{path}.
func (c *callRunner) httpCall(ctx context.Context, i int, call runnerCall) callResult {
	ctx, cancel := context.WithTimeout(ctx, runnerTimeout)
	defer cancel()
	target := c.gateway + "/" + url.PathEscape(call.Connection) + call.Path
	var body io.Reader
	if call.Method == http.MethodGet || call.Method == http.MethodDelete {
		q, err := queryOf(call.Input)
		if err != nil {
			c.logf("call %d: %v", i, err)
			return callResult{Index: i, Status: callFailed, ErrorCode: "invalid_call"}
		}
		if q != "" {
			target += "?" + q
		}
	} else {
		in := call.Input
		if len(in) == 0 {
			in = jsontext.Value("{}")
		}
		body = bytes.NewReader(in)
	}
	req, err := http.NewRequestWithContext(ctx, call.Method, target, body)
	if err != nil {
		c.logf("call %d: %v", i, err)
		return callResult{Index: i, Status: callFailed, ErrorCode: "invalid_call"}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("PAP-Run-Id", c.run)
	req.Header.Set("PC-Action-Id", ids.NewV7().String())
	status, header, b, err := c.send(req)
	if err != nil {
		// The request may have reached the gateway: never sent again.
		c.logf("call %d: %v", i, err)
		return callResult{Index: i, Status: callUnknown, ErrorCode: "gateway_unreachable"}
	}
	return classifyHTTP(i, status, header, b)
}

// queryOf encodes a GET or DELETE call's input as a query: scalar members
// only, in name order.
func queryOf(in jsontext.Value) (string, error) {
	if len(in) == 0 {
		return "", nil
	}
	var m map[string]jsontext.Value
	if err := json.Unmarshal(in, &m); err != nil {
		return "", err
	}
	q := url.Values{}
	for k, v := range m {
		switch v.Kind() {
		case jsontext.KindString:
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return "", err
			}
			q.Set(k, s)
		case jsontext.KindNumber, jsontext.KindTrue, jsontext.KindFalse:
			q.Set(k, string(v))
		case jsontext.KindNull:
		case jsontext.KindInvalid, jsontext.KindBeginObject, jsontext.KindEndObject, jsontext.KindBeginArray, jsontext.KindEndArray:
			return "", fmt.Errorf("query member %q is not a scalar", k)
		}
	}
	return q.Encode(), nil
}

// httpRefusal is what the runner reads of the HTTP face's refusal body.
type httpRefusal struct {
	ErrorClass    string `json:"error_class"`
	Error         string `json:"error"`
	TransactionID string `json:"transaction_id"`
}

// classifyHTTP reads the HTTP face's answer: a target answer carries
// PC-Decision; a refusal is JSON with an error_class. Anything else did
// not come from the dispatch path and its outcome is unknown.
func classifyHTTP(i, status int, header http.Header, body []byte) callResult {
	r := callResult{Index: i, TransactionID: header.Get("PC-Transaction-Id")}
	if header.Get("PC-Decision") != "" {
		if status >= 200 && status < 300 {
			r.Status = callSucceeded
			return r
		}
		r.Status, r.ErrorCode = callFailed, "target_status_"+strconv.Itoa(status)
		return r
	}
	var ref httpRefusal
	if ct, _, _ := mime.ParseMediaType(header.Get("Content-Type")); ct == "application/json" &&
		json.Unmarshal(body, &ref) == nil && ref.ErrorClass != "" {
		if r.TransactionID == "" {
			r.TransactionID = ref.TransactionID
		}
		r.Status, r.ErrorCode = statusOfClass(ref.ErrorClass), codeOf(ref.ErrorClass, ref.Error)
		return r
	}
	r.Status, r.ErrorCode = callUnknown, "unrecognized_answer"
	return r
}

// statusOfClass maps a gateway error class (F642) to a call status.
func statusOfClass(class string) callStatus {
	switch class {
	case "policy_denied":
		return callDenied
	case "held":
		return callHeld
	case "cannot_authorize", "authentication_failed", "enforcement_failed", "tool_failed":
		return callFailed
	}
	// "uncertain", and any class this runner does not know: the gateway
	// may have acted.
	return callUnknown
}

// codeOf is the error code reported for a refusal: the gateway's code, or
// its class.
func codeOf(class, code string) string {
	c := class
	if code != "" {
		c = code
	}
	if len(c) > 64 {
		c = c[:64]
	}
	return c
}

// mcpCall sends one tools/call to the MCP face, {gateway}/mcp/{connection},
// with the tool's declared parameter headers from the connection's tool
// list. When the gateway refuses the headers (HeaderMismatch, decided
// before anything is dispatched), it lists the tools again and sends the
// call once more.
func (c *callRunner) mcpCall(ctx context.Context, i int, call runnerCall) callResult {
	if _, ok := c.declared[call.Connection]; !ok {
		c.listTools(ctx, call.Connection)
	}
	action := ids.NewV7().String()
	args := call.Input
	if len(args) == 0 {
		args = jsontext.Value("{}")
	}
	id := "pclaw-runner-" + strconv.Itoa(i)
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": call.Tool, "arguments": args, "_meta": runnerMeta()},
	}, json.Deterministic(true))
	if err != nil {
		return callResult{Index: i, Status: callFailed, ErrorCode: "invalid_call"}
	}
	for attempt := 0; ; attempt++ {
		mirrored, _ := mcpheader.Mirror(c.declared[call.Connection][call.Tool], args)
		status, header, b, err := c.postMCP(ctx, call.Connection, "tools/call", call.Tool, action, mirrored, body)
		if err != nil {
			c.logf("call %d: %v", i, err)
			return callResult{Index: i, Status: callUnknown, ErrorCode: "gateway_unreachable"}
		}
		if attempt == 0 && status == http.StatusBadRequest && headerMismatch(b) {
			c.listTools(ctx, call.Connection)
			continue
		}
		return classifyMCP(i, id, header, b)
	}
}

// runnerMeta is the _meta of every request: the protocol version and the
// client.
func runnerMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion": runnerMCPVersion,
		"io.modelcontextprotocol/clientInfo":      map[string]any{"name": "pclaw-automation-runner", "version": "1"},
	}
}

// postMCP posts one 2026-07-28 request with the headers it implies.
func (c *callRunner) postMCP(ctx context.Context, conn, method, name, action string, extra http.Header, body []byte) (int, http.Header, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, runnerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.gateway+"/mcp/"+url.PathEscape(conn), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("PAP-Run-Id", c.run)
	req.Header.Set("MCP-Protocol-Version", runnerMCPVersion)
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", mcpheader.Encode(name))
	}
	if action != "" {
		req.Header.Set("PC-Action-Id", action)
	}
	for k, vs := range extra {
		req.Header[k] = vs
	}
	return c.send(req)
}

// listTools learns the x-mcp-header parameters of a connection's tools. A
// failed list leaves none: the call then goes without, and the gateway
// says what is wrong.
func (c *callRunner) listTools(ctx context.Context, conn string) {
	if c.declared == nil {
		c.declared = map[string]map[string][]mcpheader.Param{}
	}
	c.declared[conn] = map[string][]mcpheader.Param{}
	c.lists++
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "pclaw-runner-list-" + strconv.Itoa(c.lists), "method": "tools/list",
		"params": map[string]any{"_meta": runnerMeta()},
	}, json.Deterministic(true))
	if err != nil {
		return
	}
	status, header, b, err := c.postMCP(ctx, conn, "tools/list", "", "", nil, body)
	if err != nil || status != http.StatusOK {
		c.logf("listing the tools of %s: HTTP %d %v", conn, status, err)
		return
	}
	for _, a := range answersOf(header, b) {
		var r struct {
			Result *struct {
				Tools []struct {
					Name        string         `json:"name"`
					InputSchema jsontext.Value `json:"inputSchema"`
				} `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(a, &r) != nil || r.Result == nil {
			continue
		}
		for _, t := range r.Result.Tools {
			params, err := mcpheader.Parse(t.InputSchema)
			if err != nil {
				c.logf("tool %q: %v", t.Name, err)
				continue
			}
			c.declared[conn][t.Name] = params
		}
	}
}

// mcpAnswer is what the runner reads of a tools/call answer.
type mcpAnswer struct {
	ID    jsontext.Value `json:"id"`
	Error *struct {
		Code int `json:"code"`
	} `json:"error"`
	Result *struct {
		IsError bool `json:"isError"`
		Meta    struct {
			Result *struct {
				TransactionID string `json:"transaction_id"`
			} `json:"io.pantherclaw/result"`
			Error *struct {
				ErrorClass    string `json:"error_class"`
				Error         string `json:"error"`
				TransactionID string `json:"transaction_id"`
			} `json:"io.pantherclaw/error"`
		} `json:"_meta"`
	} `json:"result"`
}

// classifyMCP reads the MCP face's answer to a tools/call. A JSON-RPC
// error is a refusal made before dispatch; a tool result says what the
// dispatch path did in _meta. No answer to this call means the outcome is
// unknown.
func classifyMCP(i int, id string, header http.Header, body []byte) callResult {
	want, _ := json.Marshal(id)
	for _, a := range answersOf(header, body) {
		var m mcpAnswer
		if json.Unmarshal(a, &m) != nil || !bytes.Equal(m.ID, want) {
			continue
		}
		switch {
		case m.Error != nil:
			return callResult{Index: i, Status: callFailed, ErrorCode: "mcp_" + strconv.Itoa(m.Error.Code)}
		case m.Result == nil:
			continue
		case !m.Result.IsError:
			r := callResult{Index: i, Status: callSucceeded}
			if m.Result.Meta.Result != nil {
				r.TransactionID = m.Result.Meta.Result.TransactionID
			}
			return r
		case m.Result.Meta.Error != nil:
			e := m.Result.Meta.Error
			return callResult{Index: i, Status: statusOfClass(e.ErrorClass), TransactionID: e.TransactionID, ErrorCode: codeOf(e.ErrorClass, e.Error)}
		}
		return callResult{Index: i, Status: callFailed, ErrorCode: "tool_error"}
	}
	return callResult{Index: i, Status: callUnknown, ErrorCode: "unrecognized_answer"}
}

// claimedLaunch is a launch the runner claimed (ClaimLaunch, D26).
type claimedLaunch struct {
	ID, RunID string
	Calls     []runnerCall
}

// launchSource claims the runner's launches and completes them. Claim
// returns nil when no launch is waiting.
type launchSource interface {
	Claim(ctx context.Context) (*claimedLaunch, error)
	Complete(ctx context.Context, launch string, outcome launchOutcome, results []callResult, note string) error
}

// completion is a finished launch whose report has not reached the server
// yet. It is sent again until it does; its calls are never sent again.
type completion struct {
	launch  string
	outcome launchOutcome
	results []callResult
	note    string
}

// launchRunner claims launches and performs their calls.
type launchRunner struct {
	src launchSource
	// caller returns the call runner for a launch's run.
	caller func(run string) *callRunner
	poll   time.Duration
	log    io.Writer

	pending *completion
}

// step completes the pending report, or claims and performs one launch.
// It reports whether it did any work, so a caller polls only when idle.
func (l *launchRunner) step(ctx context.Context) (bool, error) {
	if l.pending != nil {
		p := l.pending
		if err := l.src.Complete(ctx, p.launch, p.outcome, p.results, p.note); err != nil {
			return false, fmt.Errorf("completing launch %s: %w", p.launch, err)
		}
		l.pending = nil
		return true, nil
	}
	launch, err := l.src.Claim(ctx)
	if err != nil {
		return false, fmt.Errorf("claiming a launch: %w", err)
	}
	if launch == nil {
		return false, nil
	}
	var results []callResult
	outcome := launchFailed
	var note string
	if _, perr := ids.ParseUUID(launch.RunID); perr != nil {
		note = "the launch has no run"
	} else {
		results, outcome = l.caller(launch.RunID).runCalls(ctx, launch.Calls)
		note = noteOf(results, outcome)
	}
	l.pending = &completion{launch: launch.ID, outcome: outcome, results: results, note: note}
	if err := l.src.Complete(ctx, launch.ID, outcome, results, note); err != nil {
		return true, fmt.Errorf("completing launch %s: %w", launch.ID, err)
	}
	l.pending = nil
	return true, nil
}

// noteOf is a launch's note: which call stopped it, and why.
func noteOf(results []callResult, outcome launchOutcome) string {
	if outcome == launchSucceeded || len(results) == 0 {
		return ""
	}
	last := results[len(results)-1]
	return fmt.Sprintf("stopped at call %d: %s %s", last.Index, last.Status, last.ErrorCode)
}

// run claims and performs launches until ctx ends, or, with once, until
// no launch is waiting. Errors are reported and retried after the poll
// interval (with once, a report that cannot be sent is tried
// runnerOnceTries times); a launch's calls are never performed twice.
func (l *launchRunner) run(ctx context.Context, once bool) error {
	tries := 0
	for {
		worked, err := l.step(ctx)
		switch {
		case ctx.Err() != nil:
			//nolint:nilerr // ctx ended: a step error is the shutdown, not a failure
			return nil
		case err == nil && worked:
			tries = 0
			continue
		case err == nil && once:
			return nil
		case err != nil && once && l.pending == nil:
			return err
		case err != nil && once:
			if tries++; tries >= runnerOnceTries {
				return err
			}
			_, _ = fmt.Fprintf(l.log, "pclaw automation runner: %v\n", err)
		case err != nil:
			_, _ = fmt.Fprintf(l.log, "pclaw automation runner: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(l.poll):
		}
	}
}
