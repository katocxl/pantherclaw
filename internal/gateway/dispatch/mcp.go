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
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
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
	if m := mcpTemplate(def); m != nil && m.Resource != "" {
		return e.sendResource(ctx, r, conn, def, a, want, t)
	}
	tool, args, buildErr := egress.BuildMCP(def, a.Action)
	var params []byte
	var extra map[string]any
	if buildErr == nil {
		// A retry's answers come from the permitted action only (G0 M15 D33).
		if extra, buildErr = retryParams(ctx, def, a.Action); buildErr == nil {
			params, buildErr = upstream.ParamsWith(tool, args, extra)
		}
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
	cred := &upstreamCredential{}
	if conn.GetAccessMode() == "pantherclaw_held" {
		if cred, err = e.mcpCredential(ctx, conn, def, a.Action.Target); err != nil {
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		// A minted token is revoked as soon as the answer is read, before the
		// outcome is recorded (HR-203); the deferred call covers every other
		// path.
		defer cred.release()
	}
	secret := cred.secret
	token := bd.GetActionToken()
	decorate := func(req *http.Request) error {
		if token != "" {
			req.Header.Set(HeaderAction, token)
		}
		return cred.place(req)
	}
	callCtx, cancel := callWindow(ctx, conn)
	defer cancel()
	// The listing a check needs first belongs to no call: a GitHub App
	// connection lists with a metadata-read token of its own, never the
	// action's (ADR-0021 item 2); a static credential lists as it calls.
	list := func(context.Context) (*upstreamCredential, error) { return &upstreamCredential{put: cred.place}, nil }
	if conn.GetAccessMode() == "pantherclaw_held" && conn.GetKind() == "mcp" && conn.Credential.GetKind() == credentials.KindGitHubApp {
		list = func(ctx context.Context) (*upstreamCredential, error) { return e.listCredential(ctx, conn) }
	}
	declared, refusal, err := e.pinnedParams(callCtx, conn, ce, tool, list)
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
	land, access, err := e.fly(callCtx, conn, a, want)
	if err != nil {
		// The connector took no call: nothing was sent.
		outcome, class, code := classifyMCP(upstream.Result{}, fmt.Errorf("%w: %w", upstream.ErrNotSent, err))
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
		return e.record(ctx, r, want, outcome, 0, nil, 0, class, code, t)
	}
	res, err := ce.mcp.CallWith(callCtx, tool, args, extra, declared, decorate)
	land()
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
	cred.release()
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t, func(req *pb.RecordExecutionRequest) {
		// A connector's write went out with a credential placed here, and a
		// call to GitHub's MCP server with a token minted for it: what it was
		// given is on the call's receipt, as on a dispatch (ADR-0021).
		req.CredentialAccess = access()
		if minted := cred.granted(); minted != nil {
			req.CredentialAccess = minted
		}
	})
}

// upstreamCredential is what a kind-mcp call places on its requests to the
// server: put places it, secret is what is scrubbed from the answer, done
// clears it and revokes a minted token, and access is what a minted token
// allowed. The zero value places nothing.
type upstreamCredential struct {
	secret []byte
	put    func(*http.Request) error
	done   func()
	access func() *pb.CredentialAccess
	once   sync.Once
}

func (c *upstreamCredential) place(req *http.Request) error {
	if c.put == nil {
		return nil
	}
	return c.put(req)
}

// release clears the credential and revokes a minted token, once.
func (c *upstreamCredential) release() {
	c.once.Do(func() {
		if c.done != nil {
			c.done()
		}
	})
}

// granted is what a minted token allowed; nil for a static credential.
func (c *upstreamCredential) granted() *pb.CredentialAccess {
	if c.access == nil {
		return nil
	}
	return c.access()
}

// mcpCredential opens what a pantherclaw_held kind-mcp connection places on
// an action's requests. A static credential is placed as sealed. A GitHub
// App credential never is (HR-204): as on the HTTP face, the gateway mints
// at GitHub's API (github.api_url) an installation token for exactly the
// action's repository and the operation's declared permissions, places it
// as a bearer token on the requests to GitHub's MCP server, within the
// credential's hosts, and revokes it when the answer is read (ADR-0021 item
// 2, HR-203). A connector (mcp_container) is never given an App.
func (e *Engine) mcpCredential(ctx context.Context, conn *control.Connection, def *defs.Definition, target actionir.Target,
) (*upstreamCredential, error) {
	if conn.GetKind() != "mcp" || conn.Credential.GetKind() != credentials.KindGitHubApp {
		secret, err := e.openStatic(ctx, conn)
		if err != nil {
			return nil, err
		}
		if err := CheckCredentialPattern(def, conn.Credential.GetKind(), secret); err != nil {
			// Checked before any byte is sent (G0 M14 D85, HR-301).
			clear(secret)
			return nil, err
		}
		return &upstreamCredential{
			secret: secret, put: func(req *http.Request) error { return placeCredential(conn, req, secret) }, done: func() { clear(secret) },
		}, nil
	}
	if err := CheckCredentialPattern(def, credentials.KindGitHubApp, nil); err != nil {
		return nil, err // a pattern is for a static credential
	}
	base, c, err := e.gitHubAPI(conn)
	if err != nil {
		return nil, err
	}
	tok, release, err := e.actionToken(ctx, conn, def, target, base, c, "")
	if err != nil {
		return nil, err
	}
	return &upstreamCredential{
		secret: tok.Token(), put: func(req *http.Request) error { return placeBearer(conn, req, tok.Token()) }, done: release,
		access: func() *pb.CredentialAccess { return accessOf(tok.Access()) },
	}, nil
}

// placeBearer places a minted installation token on a request to GitHub's
// MCP server as "Authorization: Bearer", for the credential's hosts only.
// Unlike a REST call's (Installation.Place), it leaves the request's
// media type to the MCP client.
func placeBearer(conn *control.Connection, req *http.Request, token []byte) error {
	return broker.Place(req, conn.Credential.GetAllowedHosts(), credentials.GitHubAppHeader, credentials.GitHubAppScheme, token)
}

// Drift is an upstream tool that no longer matches the definition the
// connection's package was reviewed against (HR-081): Observed is the
// digest the server lists now, empty when the tool is gone.
type Drift struct {
	Tool, Expected, Observed string
	// Description is the changed tool's description as listed now, for the
	// server's instruction-like content scan (G0 M10 D47); nil when the tool
	// is gone or listed no description.
	Description *string
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
	cred := &upstreamCredential{}
	if conn.GetAccessMode() == "pantherclaw_held" {
		if cred, err = e.listCredential(ctx, conn); err != nil {
			return nil, err
		}
		defer cred.release()
	}
	return e.check(ctx, conn, ce, cred.place)
}

// listCredential is what a check outside any call lists the tools with: a
// static credential as sealed, or, for a GitHub App connection to GitHub's
// MCP server, a token of its own with metadata: read only, minted for the
// listing and revoked after it (purpose drift), as the organization scan
// lists repositories (ADR-0021 item 2).
func (e *Engine) listCredential(ctx context.Context, conn *control.Connection) (*upstreamCredential, error) {
	if conn.Credential.GetKind() != credentials.KindGitHubApp {
		return e.mcpCredential(ctx, conn, nil, actionir.Target{})
	}
	base, c, err := e.gitHubAPI(conn)
	if err != nil {
		return nil, err
	}
	app, err := e.openApp(conn)
	if err != nil {
		return nil, err
	}
	tok, err := broker.MintScanToken(ctx, c, base, conn.Credential.GetAllowedHosts(), app, nil, map[string]string{"metadata": "read"}, time.Now())
	app.Clear()
	if err != nil {
		return nil, err
	}
	return &upstreamCredential{
		secret: tok.Token(), put: func(req *http.Request) error { return placeBearer(conn, req, tok.Token()) }, done: func() {
			if err := tok.Revoke(ctx, c); err != nil {
				e.log.WarnContext(ctx, "gateway.installation_token_not_revoked", slog.String("connection_id", conn.GetId()), pclog.Err(err))
				e.revokeFailed(ctx, conn, "drift", tok)
			}
		},
	}, nil
}

// reviewedTools are a connection's upstream tools, each with the digests
// the package pins it to.
func reviewedTools(conn *control.Connection) map[string][]string {
	reviewed := map[string][]string{}
	for i := range conn.Package.Definitions {
		if m := mcpTemplate(&conn.Package.Definitions[i]); m != nil && m.Resource == "" && !slices.Contains(reviewed[m.Tool], m.UpstreamDigest) {
			reviewed[m.Tool] = append(reviewed[m.Tool], m.UpstreamDigest)
		}
	}
	return reviewed
}

// check lists the upstream tools with the credential place puts on each
// request (no action token: the list belongs to no call) and records what
// it found for the connection's revision.
func (e *Engine) check(ctx context.Context, conn *control.Connection, ce clientEntry, place func(*http.Request) error) ([]Drift, error) {
	reviewed := reviewedTools(conn)
	tools, err := ce.mcp.ListTools(ctx, place)
	if err != nil {
		return nil, err
	}
	type definition struct {
		digest      string
		schema      jsontext.Value
		description *string
	}
	listed := map[string][]definition{}
	for _, t := range tools {
		var n struct {
			Name        string         `json:"name"`
			Description jsontext.Value `json:"description"`
			InputSchema jsontext.Value `json:"inputSchema"`
		}
		d, err := upstream.ToolDigest(t)
		if err != nil || json.Unmarshal(t, &n) != nil {
			return nil, fmt.Errorf("%w: a tool definition does not decode", upstream.ErrProtocol)
		}
		listed[n.Name] = append(listed[n.Name], definition{digest: d, schema: n.InputSchema, description: descriptionOf(n.Description)})
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
				drifts = append(drifts, Drift{Tool: tool, Expected: want, Observed: got[other].digest, Description: got[other].description})
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
	if !ok || m == nil || m.Resource != "" {
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
// With none yet, or a stale one, it checks first, with the credential
// list gives for the listing. refusal says the tool must not be called;
// err that the server could not be listed.
func (e *Engine) pinnedParams(ctx context.Context, conn *control.Connection, ce clientEntry, tool string,
	list func(context.Context) (*upstreamCredential, error),
) (params []mcpheader.Param, refusal string, err error) {
	e.mu.Lock()
	d, ok := e.drift[conn.GetId()]
	e.mu.Unlock()
	if !ok || d.revision != conn.GetRevision() || d.stale {
		cred, err := list(ctx)
		if err != nil {
			return nil, "", err
		}
		drifts, err := e.check(ctx, conn, ce, cred.place)
		cred.release()
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

// descriptionOf reads a listed tool's description leniently (G0 M10 D59
// H4): only a JSON string is a description. Anything else (an object, an
// array, a number) is left out here and changes the tool's digest, so it
// is reported as drift rather than failing the whole listing.
func descriptionOf(v jsontext.Value) *string {
	if len(v) == 0 || v.Kind() != '"' {
		return nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return nil
	}
	return &s
}

// sendResource builds, commits, reads and records a resource read through
// a kind-mcp connection (G0 M15 D31, HR-419): the URI is built from the
// definition's reviewed upstream template and the permitted action alone,
// each value percent-encoded, so no value changes the scheme or the
// authority the template fixes; the request goes to the connection's own
// endpoint. BeginDispatch binds the canonical {uri} (upstream.ReadParams).
// A resource template has no listing to check here: discovery reports it
// (S15b), and the reviewed package pins it.
func (e *Engine) sendResource(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed,
	want permitWant, t *timer,
) Result {
	uri, buildErr := ResourceURI(def, a.Action)
	var params []byte
	if buildErr == nil {
		params, buildErr = upstream.ReadParams(uri)
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
	cred := &upstreamCredential{}
	if conn.GetAccessMode() == "pantherclaw_held" {
		if cred, err = e.mcpCredential(ctx, conn, def, a.Action.Target); err != nil {
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		defer cred.release()
	}
	secret := cred.secret
	token := bd.GetActionToken()
	decorate := func(req *http.Request) error {
		if token != "" {
			req.Header.Set(HeaderAction, token)
		}
		return cred.place(req)
	}
	callCtx, cancel := callWindow(ctx, conn)
	defer cancel()
	start := time.Now()
	land, access, err := e.fly(callCtx, conn, a, want)
	if err != nil {
		outcome, class, code := classifyMCP(upstream.Result{}, fmt.Errorf("%w: %w", upstream.ErrNotSent, err))
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
		return e.record(ctx, r, want, outcome, 0, nil, 0, class, code, t)
	}
	res, err := ce.mcp.ReadResource(callCtx, uri, decorate)
	land()
	elapsed := time.Since(start)
	t.lap("target")
	outcome, class, code := classifyMCP(res, err)
	e.breaker.record(ctx, conn, outcome)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
	}
	var digest []byte
	if body := answerBody(res); body != nil {
		sum := sha256.Sum256(body)
		digest = sum[:]
		r.Response = &egress.Response{
			Status: res.Status, Body: egress.Redacted(body, secret), ContentType: "application/json",
			RequestID: string(egress.Redacted([]byte(res.RequestID), secret)),
		}
	}
	cred.release()
	return e.record(ctx, r, want, outcome, res.Status, digest, elapsed, class, code, t, func(req *pb.RecordExecutionRequest) {
		req.CredentialAccess = access()
		if minted := cred.granted(); minted != nil {
			req.CredentialAccess = minted
		}
	})
}

// ResourceURI builds a resource read's upstream URI from the definition's
// reviewed template and the action (HR-419): each variable is a canonical
// reference to the target or an identifier, enum or integer param, and
// its value is percent-encoded.
func ResourceURI(def *defs.Definition, a actionir.ActionIR) (string, error) {
	m := mcpTemplate(def)
	tmpl, ok := m.DispatchTemplate()
	if !ok {
		return "", fmt.Errorf("%w: %s has no resource template", egress.ErrBuild, def.Operation)
	}
	vals, err := def.DecodeParams(a.Params)
	if err != nil {
		return "", fmt.Errorf("%w: %w", egress.ErrBuild, err)
	}
	out := make(map[string]string, len(tmpl.Vars))
	for _, ref := range tmpl.Vars {
		var v string
		switch group, isPart := strings.CutPrefix(ref, "target.id."); {
		case ref == "target.id":
			v = a.Target.ID
		case ref == "target.account":
			v = a.Target.Account
		case isPart:
			v, _ = def.Target.Part(a.Target.ID, group)
		default:
			name, _ := strings.CutPrefix(ref, "params.")
			p, ok := vals[name]
			switch {
			case !ok:
			case p.Type == defs.TypeInteger:
				v = strconv.FormatInt(p.Int, 10)
			case p.Type == defs.TypeIdentifier || p.Type == defs.TypeEnum:
				v = p.Str
			}
		}
		if v == "" {
			return "", fmt.Errorf("%w: %s has no value for the resource template", egress.ErrBuild, ref)
		}
		out[ref] = v
	}
	uri, ok := tmpl.Expand(out)
	if !ok {
		return "", fmt.Errorf("%w: the resource template does not expand", egress.ErrBuild)
	}
	return uri, nil
}

// CodeElicitationRefused is the local refusal of an upstream server's
// elicitation that the reviewed mapping does not allow (G0 M15 D33).
const CodeElicitationRefused = "elicitation_refused"

// ReportElicitationRefused tells the server an upstream elicitation was
// refused (G0 M15 D33, D40): machine metadata, the reason and the
// question's SHA-256 only, never the question.
func (e *Engine) ReportElicitationRefused(ctx context.Context, conn *control.Connection, a actionir.ActionIR, detail RefusalDetail) {
	e.reportLocalRefusal(ctx, conn, CodeElicitationRefused, a, detail)
}

// InputResponses is how a retry answers an upstream server's input
// requests (G0 M15 D33): for each of its request keys, the agent's action
// and, when it accepted, the fields its answer filled. The answers
// themselves travel only as the action's elicitation.<field> params, so
// what reaches the server is what the Authority permitted. RequestState is
// the server's opaque state, passed back as it sent it.
type InputResponses struct {
	Keys         map[string]InputResponse
	RequestState string
}

// InputResponse is the answer to one input request.
type InputResponse struct {
	// Action is accept, decline or cancel.
	Action string
	// Fields are the elicitation fields an accepted answer filled.
	Fields []string
}

type inputResponsesKey struct{}

// WithInputResponses marks a call as the retry of an input_required
// result.
func WithInputResponses(ctx context.Context, ir InputResponses) context.Context {
	return context.WithValue(ctx, inputResponsesKey{}, ir)
}

// retryParams are the extra tools/call params of a retry: inputResponses
// built from the permitted action's elicitation params, and requestState;
// nil for any other call.
func retryParams(ctx context.Context, def *defs.Definition, a actionir.ActionIR) (map[string]any, error) {
	ir, ok := ctx.Value(inputResponsesKey{}).(InputResponses)
	if !ok {
		return nil, nil
	}
	vals, err := def.DecodeParams(a.Params)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", egress.ErrBuild, err)
	}
	responses := make(map[string]any, len(ir.Keys))
	for key, resp := range ir.Keys {
		out := map[string]any{"action": resp.Action}
		if resp.Action == "accept" {
			content := make(map[string]any, len(resp.Fields))
			for _, f := range resp.Fields {
				v, ok := vals[defs.ElicitationPrefix+f]
				if !ok {
					return nil, fmt.Errorf("%w: the permitted action has no answer for %s", egress.ErrBuild, f)
				}
				content[f] = elicitValue(v)
			}
			out["content"] = content
		}
		responses[key] = out
	}
	extra := map[string]any{"inputResponses": responses}
	if ir.RequestState != "" {
		extra["requestState"] = ir.RequestState
	}
	return extra, nil
}

// elicitValue is an answer in the JSON type of an elicitation form field.
func elicitValue(v defs.Value) any {
	switch v.Type {
	case defs.TypeInteger:
		return v.Int
	case defs.TypeDecimal:
		return jsontext.Value(v.Decimal.String())
	case defs.TypeBoolean:
		return v.Bool
	case defs.TypeEnum, defs.TypeIdentifier, defs.TypeContent, defs.TypeMoney, defs.TypeIdentifierList, defs.TypeText, defs.TypeCommand,
		defs.TypePath, defs.TypeQueryFilter:
	}
	return v.Str
}
