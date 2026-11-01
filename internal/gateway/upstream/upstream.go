// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package upstream is the gateway's MCP client for kind-mcp connections
// (G0 M6 design decision 14; HR-082, HR-083): it calls a remote MCP
// server's reviewed tools over Streamable HTTP, through the connection's
// hardened egress client.
//
// It speaks MCP 2026-07-28 (stateless) or 2025-11-25 (sessions), whichever
// the server does; it learns which with a request that decides nothing
// (server/discover), so a tools/call is never sent twice to find out. It
// declares no client capability: no elicitation, sampling or roots. A
// 2025-11-25 server that asks for one on a stream is answered with a
// decline (elicitation) or "method not found" (anything else), and a
// 2026-07-28 input_required result is reported as such, for the caller to
// relay through the elicitation gate or turn into a tool error (G0 M15
// D33); a retry's answers go out with CallWith. JSON-RPC ids are the gateway's own, per client,
// never the agent's.
package upstream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Protocol versions the client speaks.
const (
	Modern = "2026-07-28"
	Legacy = "2025-11-25"
)

// Request headers.
const (
	headerVersion = "MCP-Protocol-Version"
	headerSession = "Mcp-Session-Id"
	headerMethod  = "Mcp-Method"
	headerName    = "Mcp-Name"
)

// JSON-RPC error codes the client recognizes.
const (
	codeMethodNotFound     = -32601
	codeUnsupportedVersion = -32022
	// CodeHeaderMismatch: a 2026-07-28 server found the request headers
	// differ from the body, and ran nothing.
	CodeHeaderMismatch = -32020
)

// ErrNotSent wraps a failure before the tools/call left the gateway:
// nothing ran upstream.
var ErrNotSent = errors.New("upstream: the tool call was not sent")

// ErrProtocol reports an answer that is not MCP as this client speaks it.
var ErrProtocol = errors.New("upstream: the server's answer is not valid MCP")

// Sender sends a connection's requests (egress.Client).
type Sender interface {
	Open(req *http.Request) (*http.Response, error)
}

// Decorate places what every request to the server carries, such as the
// connection's credential.
type Decorate func(*http.Request) error

// RPCError is a JSON-RPC error.
type RPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    jsontext.Value `json:"data,omitzero"`
}

// Result is the server's answer to a tools/call.
type Result struct {
	// Status is the HTTP status of the answer.
	Status int
	// Result is the CallToolResult as the server sent it; nil with Error.
	Result jsontext.Value
	// IsError: the tool reported an error (CallToolResult.isError).
	IsError bool
	// InputRequired: a 2026-07-28 server asked for input the gateway never
	// gives (HR-082).
	InputRequired bool
	// Error is a JSON-RPC error the server answered with.
	Error *RPCError
	// Declined lists the server-to-client requests answered with a
	// decline or "method not found" while the call ran (HR-082).
	Declined []string
	// RequestID is the server's request id, from response headers.
	RequestID string
}

// Client is one connection's MCP client.
type Client struct {
	endpoint string
	send     Sender

	mu      sync.Mutex
	version string
	session string
	next    uint64
}

// New returns the client of the MCP server at endpoint (the connection's
// base URL), sending through s.
func New(endpoint string, s Sender) *Client { return &Client{endpoint: endpoint, send: s} }

// Version is the protocol version learned from the server, or "".
func (c *Client) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Params is the canonical form of a tools/call, independent of the
// protocol version and the JSON-RPC id: what BeginDispatch records and an
// action token binds.
func Params(tool string, args jsontext.Value) ([]byte, error) { return ParamsWith(tool, args, nil) }

// ParamsWith is Params of a tools/call that also carries extra params: a
// retry's inputResponses and requestState (G0 M15 D33), which the body
// BeginDispatch binds then fixes too.
func ParamsWith(tool string, args jsontext.Value, extra map[string]any) ([]byte, error) {
	p := map[string]any{"name": tool, "arguments": args}
	for k, v := range extra {
		p[k] = v
	}
	b, err := json.Marshal(p, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return nil, err
	}
	return v, nil
}

// Call sends tools/call for tool with args (a JSON object). params are the
// x-mcp-header declarations of the tool's pinned definition: to a
// 2026-07-28 server, each argument they name present also goes in its
// Mcp-Param-{Name} header, encoded (Custom Headers from Tool Parameters).
// An error wrapping ErrNotSent means the call never left the gateway; any
// other error may have left it, and its outcome is unknown.
func (c *Client) Call(ctx context.Context, tool string, args jsontext.Value, params []mcpheader.Param, decorate Decorate) (Result, error) {
	return c.CallWith(ctx, tool, args, nil, params, decorate)
}

// CallWith is Call with extra tools/call params (ParamsWith).
func (c *Client) CallWith(ctx context.Context, tool string, args jsontext.Value, extra map[string]any, params []mcpheader.Param,
	decorate Decorate,
) (Result, error) {
	mirrored, err := mcpheader.Mirror(params, args)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrNotSent, err)
	}
	p := map[string]any{"name": tool, "arguments": args}
	for k, v := range extra {
		p[k] = v
	}
	ex, err := c.do(ctx, "tools/call", tool, p, mirrored, decorate)
	if err != nil {
		return Result{}, err
	}
	return ex.result(), nil
}

// Bounds on a tool list.
const (
	maxPages = 20
	maxTools = 1000
)

// ListTools lists the server's tools as it defines them (tools/list,
// every page): what the gateway compares with the reviewed definitions
// (HR-081).
func (c *Client) ListTools(ctx context.Context, decorate Decorate) ([]jsontext.Value, error) {
	var out []jsontext.Value
	cursor := ""
	for range maxPages {
		p := map[string]any{}
		if cursor != "" {
			p["cursor"] = cursor
		}
		ex, err := c.do(ctx, "tools/list", "", p, nil, decorate)
		if err != nil {
			return nil, err
		}
		if ex.reply == nil || ex.reply.Error != nil || ex.status != http.StatusOK {
			return nil, fmt.Errorf("%w: tools/list answered HTTP %d", ErrProtocol, ex.status)
		}
		var page struct {
			Tools []jsontext.Value `json:"tools"`
			Next  string           `json:"nextCursor"`
		}
		if err := json.Unmarshal(ex.reply.Result, &page); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
		}
		out = append(out, page.Tools...)
		if len(out) > maxTools {
			return nil, fmt.Errorf("%w: more than %d tools", ErrProtocol, maxTools)
		}
		if page.Next == "" {
			return out, nil
		}
		cursor = page.Next
	}
	return nil, fmt.Errorf("%w: more than %d pages of tools", ErrProtocol, maxPages)
}

// do sends one request in the server's version: in 2025-11-25 in the
// session, opening a new one once when the server ended it (it then ran
// nothing). An error wrapping ErrNotSent means the request never left.
func (c *Client) do(ctx context.Context, method, name string, params map[string]any, mirrored http.Header, decorate Decorate) (exchanged, error) {
	v, err := c.negotiate(ctx, decorate)
	if err != nil {
		return exchanged{}, fmt.Errorf("%w: %w", ErrNotSent, err)
	}
	for attempt := 0; ; attempt++ {
		session := ""
		if v == Legacy {
			if session, err = c.ensureSession(ctx, decorate); err != nil {
				return exchanged{}, fmt.Errorf("%w: %w", ErrNotSent, err)
			}
		}
		id := c.newID()
		p := maps.Clone(params)
		if v == Modern {
			p["_meta"] = modernMeta()
		}
		body, err := request(id, method, p)
		if err != nil {
			return exchanged{}, fmt.Errorf("%w: %w", ErrNotSent, err)
		}
		ex, err := c.exchange(ctx, v, session, method, name, mirrored, id, body, decorate)
		if err != nil {
			return ex, err
		}
		if v == Legacy && session != "" && ex.status == http.StatusNotFound && attempt == 0 {
			c.dropSession(session)
			continue
		}
		return ex, nil
	}
}

// negotiate learns the server's version once with server/discover, which
// decides nothing: a 2026-07-28 server answers it; a 2025-11-25 server
// refuses a request outside a session with a status and no recognized
// 2026-07-28 error (the specification's backward-compatibility rule).
func (c *Client) negotiate(ctx context.Context, decorate Decorate) (string, error) {
	if v := c.Version(); v != "" {
		return v, nil
	}
	id := c.newID()
	body, err := request(id, "server/discover", map[string]any{"_meta": modernMeta()})
	if err != nil {
		return "", err
	}
	ex, err := c.exchange(ctx, Modern, "", "server/discover", "", nil, id, body, decorate)
	if err != nil {
		return "", err
	}
	v := ""
	switch {
	case ex.reply != nil && ex.reply.Error == nil && ex.status == http.StatusOK:
		var d struct {
			Supported []string `json:"supportedVersions"`
		}
		if json.Unmarshal(ex.reply.Result, &d) == nil && slices.Contains(d.Supported, Modern) {
			v = Modern
		} else if slices.Contains(d.Supported, Legacy) {
			v = Legacy
		}
	case ex.reply != nil && ex.reply.Error != nil && ex.reply.Error.Code == codeUnsupportedVersion:
		var d struct {
			Supported []string `json:"supported"`
		}
		if json.Unmarshal(ex.reply.Error.Data, &d) == nil && slices.Contains(d.Supported, Legacy) {
			v = Legacy
		}
	case ex.reply != nil && ex.reply.Error != nil && ex.reply.Error.Code == codeMethodNotFound && ex.status == http.StatusNotFound:
		v = Modern // a 2026-07-28 server without discovery
	case ex.status == http.StatusBadRequest || ex.status == http.StatusNotFound || ex.status == http.StatusMethodNotAllowed:
		v = Legacy
	}
	if v == "" {
		return "", fmt.Errorf("%w: the server speaks neither %s nor %s (HTTP %d)", ErrProtocol, Modern, Legacy, ex.status)
	}
	c.mu.Lock()
	c.version = v
	c.mu.Unlock()
	return v, nil
}

// ensureSession returns the current 2025-11-25 session, initializing one
// (and announcing it initialized) when there is none. The client declares
// no capabilities.
func (c *Client) ensureSession(ctx context.Context, decorate Decorate) (string, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != "" {
		return s, nil
	}
	id := c.newID()
	body, err := request(id, "initialize", map[string]any{
		"protocolVersion": Legacy, "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "pantherclaw-gateway", "version": version.Get().Version},
	})
	if err != nil {
		return "", err
	}
	ex, err := c.exchange(ctx, "", "", "initialize", "", nil, id, body, decorate)
	if err != nil {
		return "", err
	}
	if ex.reply == nil || ex.reply.Error != nil || ex.status != http.StatusOK {
		return "", fmt.Errorf("%w: initialize answered HTTP %d", ErrProtocol, ex.status)
	}
	var r struct {
		Version string `json:"protocolVersion"`
	}
	if json.Unmarshal(ex.reply.Result, &r) != nil || r.Version != Legacy {
		return "", fmt.Errorf("%w: initialize agreed on another version", ErrProtocol)
	}
	s = ex.header.Get(headerSession)
	if s != "" && !visibleASCII(s) {
		return "", fmt.Errorf("%w: a malformed session id", ErrProtocol)
	}
	note, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err != nil {
		return "", err
	}
	nx, err := c.exchange(ctx, Legacy, s, "notifications/initialized", "", nil, nil, note, decorate)
	if err != nil {
		return "", err
	}
	if nx.status/100 != 2 {
		return "", fmt.Errorf("%w: notifications/initialized answered HTTP %d", ErrProtocol, nx.status)
	}
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	return s, nil
}

func (c *Client) dropSession(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == s {
		c.session = ""
	}
}

func (c *Client) newID() jsontext.Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	return jsontext.Value(strconv.Quote("pc-" + strconv.FormatUint(c.next, 10)))
}

func modernMeta() map[string]any {
	return map[string]any{
		"io.modelcontextprotocol/protocolVersion":    Modern,
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		"io.modelcontextprotocol/clientInfo":         map[string]string{"name": "pantherclaw-gateway", "version": version.Get().Version},
	}
}

func request(id jsontext.Value, method string, params any) ([]byte, error) {
	return json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, json.Deterministic(true))
}

// message is one JSON-RPC message from the server.
type message struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Method  string         `json:"method,omitzero"`
	Result  jsontext.Value `json:"result,omitzero"`
	Error   *RPCError      `json:"error,omitzero"`
}

// exchanged is one request's answer.
type exchanged struct {
	status    int
	header    http.Header
	reply     *message
	declined  []string
	requestID string
}

func (e exchanged) result() Result {
	out := Result{Status: e.status, Declined: e.declined, RequestID: e.requestID}
	if e.reply == nil {
		return out
	}
	if e.reply.Error != nil {
		out.Error = e.reply.Error
		return out
	}
	var r struct {
		ResultType string `json:"resultType"`
		IsError    bool   `json:"isError"`
	}
	_ = json.Unmarshal(e.reply.Result, &r)
	out.Result, out.IsError, out.InputRequired = e.reply.Result, r.IsError, r.ResultType == "input_required"
	return out
}

// exchange posts one message and reads its answer: one JSON object, or an
// event stream on which the server may ask the client things before it
// answers. v is the version whose headers the request carries ("" for
// initialize); mirrored are its Mcp-Param-* headers; id is nil for a
// notification.
func (c *Client) exchange(ctx context.Context, v, session, method, name string, mirrored http.Header, id jsontext.Value,
	body []byte, decorate Decorate,
) (exchanged, error) {
	req, err := c.post(ctx, v, session, method, name, mirrored, body, decorate)
	if err != nil {
		return exchanged{}, err
	}
	res, err := c.send.Open(req)
	if err != nil {
		return exchanged{}, err
	}
	defer func() { _ = res.Body.Close() }()
	out := exchanged{status: res.StatusCode, header: res.Header, requestID: egress.RequestID(res.Header)}
	if id == nil || res.StatusCode == http.StatusAccepted {
		_, _ = io.Copy(io.Discard, res.Body)
		return out, nil
	}
	ct, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	switch ct {
	case "text/event-stream":
		out.reply, out.declined, err = c.stream(ctx, v, session, res.Body, id, decorate)
	case "application/json":
		var m message
		if err = json.UnmarshalRead(res.Body, &m); err == nil {
			out.reply = &m
		}
	default:
		// Not a JSON-RPC answer (a legacy server refusing a 2026-07-28
		// request may answer plain text).
		_, err = io.Copy(io.Discard, res.Body)
		return out, err
	}
	if err != nil {
		return out, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if out.reply != nil && !sameID(out.reply.ID, id) && (out.reply.Error == nil || !isNull(out.reply.ID)) {
		// An error without an id (an authentication failure, a parse
		// error) answers this request; anything else is another's.
		return out, fmt.Errorf("%w: an answer to another request", ErrProtocol)
	}
	return out, nil
}

// post prepares one POST with the version's headers: in 2026-07-28 the
// method, the name and the mirrored parameters; in 2025-11-25, which has
// no request metadata, the session.
func (c *Client) post(ctx context.Context, v, session, method, name string, mirrored http.Header, body []byte,
	decorate Decorate,
) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "pantherclaw-gateway")
	switch v {
	case Modern:
		req.Header.Set(headerVersion, Modern)
		req.Header.Set(headerMethod, method)
		if name != "" {
			req.Header.Set(headerName, mcpheader.Encode(name))
		}
		for k, vs := range mirrored {
			req.Header[k] = slices.Clone(vs)
		}
	case Legacy:
		req.Header.Set(headerVersion, Legacy)
		if session != "" {
			req.Header.Set(headerSession, session)
		}
	}
	if decorate != nil {
		if err := decorate(req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// stream reads an event stream until the answer to id, answering what the
// server asks on the way (2025-11-25): an elicitation is declined, anything
// else is "method not found". Notifications are ignored.
func (c *Client) stream(ctx context.Context, v, session string, body io.Reader, id jsontext.Value, decorate Decorate) (*message, []string, error) {
	var declined []string
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), egress.MaxResponse)
	var data bytes.Buffer
	for {
		more := sc.Scan()
		line := sc.Text()
		if more && line != "" {
			if field, value, _ := strings.Cut(line, ":"); field == "data" {
				data.WriteString(strings.TrimPrefix(value, " "))
				data.WriteByte('\n')
			}
			continue
		}
		if data.Len() > 0 {
			var m message
			if err := json.Unmarshal(bytes.TrimSuffix(data.Bytes(), []byte("\n")), &m); err != nil {
				return nil, declined, err
			}
			data.Reset()
			switch {
			case m.Method != "" && len(m.ID) > 0:
				declined = append(declined, m.Method)
				if err := c.answer(ctx, v, session, m, decorate); err != nil {
					return nil, declined, err
				}
			case m.Method == "" && sameID(m.ID, id):
				return &m, declined, nil
			}
		}
		if !more {
			if err := sc.Err(); err != nil {
				return nil, declined, err
			}
			return nil, declined, errors.New("the stream ended without an answer")
		}
	}
}

// answer refuses a server-to-client request (HR-082): the client declared
// no capability, so an elicitation is declined and anything else is not
// found.
func (c *Client) answer(ctx context.Context, v, session string, m message, decorate Decorate) error {
	reply := map[string]any{"jsonrpc": "2.0", "id": m.ID}
	if m.Method == "elicitation/create" {
		reply["result"] = map[string]string{"action": "decline"}
	} else {
		reply["error"] = map[string]any{"code": codeMethodNotFound, "message": "PantherClaw does not offer " + m.Method}
	}
	body, err := json.Marshal(reply, json.Deterministic(true))
	if err != nil {
		return err
	}
	req, err := c.post(ctx, v, session, "", "", nil, body, decorate)
	if err != nil {
		return err
	}
	res, err := c.send.Open(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res.Body.Close()
}

// sameID compares JSON-RPC ids; the client's are always strings.
func sameID(a, b jsontext.Value) bool {
	var x, y string
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && x == y
}

func isNull(id jsontext.Value) bool { return len(id) == 0 || string(id) == "null" }

func visibleASCII(s string) bool {
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return utf8.ValidString(s)
}

// ToolDigest is "sha256:<hex>" of a tool definition as an upstream server
// lists it, without its _meta, in canonical JSON (RFC 8785): what a
// package's upstream_digest pins (HR-081). A change to the name, title,
// description, schemas or annotations changes it.
func ToolDigest(tool jsontext.Value) (string, error) {
	var m map[string]jsontext.Value
	if err := json.Unmarshal(tool, &m); err != nil {
		return "", err
	}
	delete(m, "_meta")
	b, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// listedFields are the rest of a listing an agent reads, each with its own
// limit in bytes, so padding one cannot hide another (G0 M24 D270). Together
// they fit a report's 16 KiB for them.
var listedFields = []struct {
	key   string
	limit int
}{{"title", 1 << 10}, {"annotations", 2 << 10}, {"outputSchema", 12 << 10}}

// ListedExtra is the rest of a tool's listing an agent reads, beside its
// description and input schema: a JSON object of its title, annotations and
// output schema, empty when it lists none of them (G0 M24 D245). UNTRUSTED. A
// field over its limit is left out, and the second result says one was.
func ListedExtra(tool jsontext.Value) (jsontext.Value, bool) {
	var m map[string]jsontext.Value
	if json.Unmarshal(tool, &m) != nil {
		return nil, false
	}
	keep, cut := map[string]jsontext.Value{}, false
	for _, f := range listedFields {
		v, ok := m[f.key]
		switch {
		case !ok:
		case len(v) > f.limit:
			cut = true
		default:
			keep[f.key] = v
		}
	}
	if len(keep) == 0 {
		return nil, cut
	}
	b, err := json.Marshal(keep, json.Deterministic(true))
	if err != nil {
		return nil, true
	}
	return b, cut
}

// SchemaDigest is "sha256:<hex>" of a tool's canonical input schema (G0 M24
// D211).
func SchemaDigest(schema jsontext.Value) (string, error) {
	v := schema.Clone()
	if err := v.Canonicalize(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
