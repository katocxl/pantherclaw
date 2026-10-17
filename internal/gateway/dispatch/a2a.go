// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// A2A dispatch (G0 M14 D31, HR-323, HR-327): the gateway rebuilds every
// request to a peer agent from the ActionIR alone (a text message, a task
// or context the run was answered), sends it over the binding the
// connection pins, and hands back the A2A result object, whichever binding
// carried it. A stream is relayed event by event to the face, within the
// connection's answer cap and stream time.

// Codes of A2A dispatch.
const (
	// CodeA2AAnswer: the peer answered 2xx with something that is not
	// what the method answers; nothing of it is relayed.
	CodeA2AAnswer = "a2a_answer_invalid"
	// CodeA2AStream: the stream broke off, ran over its cap or time, or
	// carried an event that is not one.
	CodeA2AStream = "a2a_stream_cut"
	// CodeA2ANotPinned: the connection carries no pinned interface.
	CodeA2ANotPinned = "a2a_not_pinned"
)

// Limits of A2A dispatch.
const (
	defaultA2AStreamSeconds = 300
	maxA2AEventBytes        = 1 << 20
)

// A2APeer is the pinned interface of an a2a connection and its caps.
type A2APeer struct {
	Binding, URL     string
	MaxAnswerBytes   int32
	MaxStreamSeconds int32
}

// a2aPeerOf returns the connection's pinned interface. The gateway
// configuration carries it once the a2a configuration field lands (G0 M14
// D64); until then no a2a connection is dispatched (fail closed).
func a2aPeerOf(conn *control.Connection) (A2APeer, bool) {
	_ = conn
	return A2APeer{}, false
}

// a2aStreamKey carries the face's event sink.
type a2aStreamKey struct{}

// A2ASink receives one streamed A2A event: the StreamResponse object as
// the peer sent it. An error stops the stream (the agent went away).
type A2ASink func(event []byte) error

// WithA2AStream returns ctx carrying the sink a streamed A2A call relays
// its events to.
func WithA2AStream(ctx context.Context, sink A2ASink) context.Context {
	return context.WithValue(ctx, a2aStreamKey{}, sink)
}

// a2aRequest is an outbound A2A call, built from the ActionIR.
type a2aRequest struct {
	method     string // the A2A method
	httpMethod string
	url        string
	body       []byte // nil for a GET
	stream     bool
}

// buildA2A rebuilds a definition's A2A call from the action (D31): the
// message is the text of a content param `text` with the transaction as
// its id; a task id (`task_id`) and context id (`context_id`) are params;
// nothing the agent sent beyond them is ever part of it.
func buildA2A(def *defs.Definition, a actionir.ActionIR, txn string, p A2APeer) (a2aRequest, error) {
	if def.Dispatch == nil || def.Dispatch.A2A == nil {
		return a2aRequest{}, fmt.Errorf("%w: %s has no A2A dispatch", egress.ErrBuild, def.Operation)
	}
	vals, err := def.DecodeParams(a.Params)
	if err != nil {
		return a2aRequest{}, fmt.Errorf("%w: %w", egress.ErrBuild, err)
	}
	str := func(name string, types ...defs.ParamType) (string, error) {
		v, ok := vals[name]
		if !ok {
			return "", nil
		}
		for _, t := range types {
			if v.Type == t {
				return v.Str, nil
			}
		}
		// Untrusted text is never sent (HR-023): a message is content.
		return "", fmt.Errorf("%w: params.%s is a %s", egress.ErrBuild, name, v.Type)
	}
	task, err := str("task_id", defs.TypeIdentifier)
	if err != nil {
		return a2aRequest{}, err
	}
	ctxID, err := str("context_id", defs.TypeIdentifier)
	if err != nil {
		return a2aRequest{}, err
	}
	method := a2aMethod(def, a.Route)
	var params any
	switch method {
	case wire.MethodSendMessage, wire.MethodSendStreamingMessage:
		text, err := str("text", defs.TypeContent)
		if err != nil {
			return a2aRequest{}, err
		}
		if text == "" {
			return a2aRequest{}, fmt.Errorf("%w: a message needs params.text", egress.ErrBuild)
		}
		params = wire.SendMessageRequest{Message: wire.Message{
			MessageID: txn, ContextID: ctxID, TaskID: task, Role: wire.RoleUser, Parts: []wire.Part{wire.TextPart(text)},
		}}
	case wire.MethodGetTask, wire.MethodCancelTask, wire.MethodSubscribeToTask:
		if !wire.ValidID(task) {
			return a2aRequest{}, fmt.Errorf("%w: %s needs params.task_id", egress.ErrBuild, method)
		}
		params = wire.TaskIDRequest{ID: task}
	case wire.MethodListTasks:
		if !wire.ValidID(ctxID) {
			return a2aRequest{}, fmt.Errorf("%w: ListTasks needs params.context_id", egress.ErrBuild)
		}
		params = wire.ListTasksRequest{ContextID: ctxID}
	default:
		return a2aRequest{}, fmt.Errorf("%w: A2A method %q", egress.ErrBuild, method)
	}
	r := a2aRequest{method: method, stream: wire.Streaming(method)}
	switch p.Binding {
	case wire.BindingJSONRPC:
		r.httpMethod, r.url = http.MethodPost, p.URL
		r.body, err = json.Marshal(wire.RPCRequest{JSONRPC: "2.0", ID: txn, Method: method, Params: params}, json.Deterministic(true))
	case wire.BindingHTTPJSON:
		hm, path, ok := wire.Path(method, task)
		if !ok {
			return a2aRequest{}, fmt.Errorf("%w: A2A method %q over HTTP+JSON", egress.ErrBuild, method)
		}
		r.httpMethod, r.url = hm, strings.TrimSuffix(p.URL, "/")+path
		switch method {
		case wire.MethodListTasks:
			r.url += "?" + url.Values{"contextId": {ctxID}}.Encode()
		case wire.MethodSendMessage, wire.MethodSendStreamingMessage, wire.MethodCancelTask, wire.MethodSubscribeToTask:
			r.body, err = json.Marshal(params, json.Deterministic(true))
		}
	default:
		return a2aRequest{}, fmt.Errorf("%w: binding %q", egress.ErrBuild, p.Binding)
	}
	if err != nil {
		return a2aRequest{}, fmt.Errorf("%w: %w", egress.ErrBuild, err)
	}
	return r, nil
}

// a2aMethod is the A2A method a call is sent with: the method of the
// definition's a2a mapping for the action's route (the route is in the
// action, and so in its hash), or the definition's dispatch method. A
// package gives each method its own route (pc.a2a: SendMessage and
// SendStreamingMessage share an operation, not a route).
func a2aMethod(def *defs.Definition, route string) string {
	for _, m := range def.Mappings {
		if m.Channel == defs.ChannelA2A && m.Route == route {
			return m.Method
		}
	}
	return def.Dispatch.A2A.Method
}

// httpRequest is the outbound request with the A2A headers.
func (r a2aRequest) httpRequest(ctx context.Context, binding string) (*http.Request, error) {
	var body io.Reader = http.NoBody
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.httpMethod, r.url, body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", egress.ErrBuild, err)
	}
	ct := "application/json"
	if binding == wire.BindingHTTPJSON {
		ct = wire.ContentType
	}
	if r.body != nil {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", ct)
	if r.stream {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set(wire.HeaderVersion, wire.Version)
	req.Header.Set("Accept-Encoding", "identity")
	return req, nil
}

// a2aAnswer reads a peer's single answer: the A2A result object, or the
// peer's refusal as a code. ok is false for an answer that is neither.
func a2aAnswer(binding string, status int, body []byte) (result []byte, peerCode string, ok bool) {
	if binding == wire.BindingJSONRPC {
		var env struct {
			JSONRPC string         `json:"jsonrpc"`
			Result  jsontext.Value `json:"result"`
			Error   *wire.RPCError `json:"error"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &env) != nil || env.JSONRPC != "2.0" || (len(env.Result) == 0) == (env.Error == nil) {
			if status >= 400 && status < 500 {
				return nil, "a2a_http_" + strconv.Itoa(status), true
			}
			return nil, "", false
		}
		if env.Error != nil {
			return nil, "a2a_" + strconv.Itoa(-env.Error.Code), true
		}
		return env.Result, "", true
	}
	if status >= 200 && status < 300 {
		if !jsontext.Value(body).IsValid() || jsontext.Value(body).Kind() != '{' {
			return nil, "", false
		}
		return body, "", true
	}
	var st struct {
		Error struct {
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	code := "a2a_http_" + strconv.Itoa(status)
	if json.Unmarshal(body, &st) == nil {
		for _, d := range st.Error.Details {
			if c := sanitizeCode(d.Reason); c != "" {
				code = "a2a_" + c
				break
			}
		}
	}
	return nil, code, status < 500
}

// a2aClients caches one egress client per connection revision and peer.
var a2aClients sync.Map // a2aClientKey → *egress.Client

type a2aClientKey struct {
	e        *Engine
	conn     string
	revision int32
	url      string
	max      int32
}

func (e *Engine) a2aClient(conn *control.Connection, p A2APeer) (*egress.Client, error) {
	limit := p.MaxAnswerBytes
	if limit <= 0 {
		limit = conn.GetMaxResponseBytes()
	}
	k := a2aClientKey{e: e, conn: conn.GetId(), revision: conn.GetRevision(), url: p.URL, max: limit}
	if c, ok := a2aClients.Load(k); ok {
		return c.(*egress.Client), nil //nolint:forcetypeassert // only *egress.Client is stored
	}
	timeout := time.Duration(conn.GetTimeoutMs()) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	c, err := egress.NewClient(p.URL, timeout, limit, e.allowed)
	if err != nil {
		return nil, err
	}
	a2aClients.Store(k, c)
	return c, nil
}

// sendA2A sends a permitted A2A call to the peer and records its outcome.
func (e *Engine) sendA2A(ctx context.Context, r Result, conn *control.Connection, def *defs.Definition, a actionir.Parsed, want permitWant,
	t *timer,
) Result {
	peer, pinned := a2aPeerOf(conn)
	out, buildErr := buildA2A(def, a.Action, want.Txn, peer)
	if !pinned {
		buildErr = errors.New(CodeA2ANotPinned)
	}
	begin := &pb.BeginDispatchRequest{PermitId: want.PermitID, Epoch: want.Epoch}
	if buildErr == nil {
		sum := sha256.Sum256(out.body)
		begin.OutboundMethod, begin.OutboundUrl, begin.OutboundBodySha256 = out.httpMethod, out.url, sum[:]
	}
	bd, err := e.authority.BeginDispatch(ctx, begin)
	t.lap("begin")
	if err != nil {
		r.Reasons = append(r.Reasons, strings.ToUpper(connect.CodeOf(err).String()))
		return r.fail(EnforcementFailed, CodeDispatchRefused)
	}
	sink, _ := ctx.Value(a2aStreamKey{}).(A2ASink)
	ctx = context.WithoutCancel(ctx)
	var client *egress.Client
	if buildErr == nil {
		client, buildErr = e.a2aClient(conn, peer)
	}
	var req *http.Request
	if buildErr == nil {
		req, buildErr = out.httpRequest(ctx, peer.Binding)
	}
	if buildErr == nil && out.stream && sink == nil {
		buildErr = errors.New("a stream with nowhere to relay it")
	}
	if buildErr != nil {
		e.log.WarnContext(ctx, "gateway.request_not_built", slog.String("transaction_id", want.Txn), pclog.Err(buildErr))
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, 0, nil, 0, EnforcementFailed, CodeRequest, t)
	}
	var secret []byte
	if conn.Credential != nil && conn.GetAccessMode() == "pantherclaw_held" {
		plain, err := e.openStatic(ctx, conn)
		if err == nil && !def.Dispatch.CredentialMatches(plain) {
			clear(plain)
			err = errCredentialPattern
		}
		if err == nil {
			err = placeCredential(conn, req, plain)
		}
		if err != nil {
			clear(plain)
			return e.credentialFailed(ctx, r, conn, want, err, t)
		}
		secret = plain
		defer clear(secret)
	}
	if tok := bd.GetActionToken(); tok != "" {
		req.Header.Set(HeaderAction, tok)
	}
	if out.stream {
		return e.streamA2A(ctx, r, conn, peer, client, req, sink, secret, want, t)
	}
	start := time.Now()
	res, err := client.Do(req)
	elapsed := time.Since(start)
	t.lap("target")
	outcome, class, code := classify(res.Status, err)
	e.breaker.record(ctx, conn, outcome)
	if err != nil {
		e.log.WarnContext(ctx, "gateway.target_error", slog.String("transaction_id", want.Txn), slog.String("outcome", outcome.String()),
			pclog.Err(err))
		return e.record(ctx, r, want, outcome, res.Status, nil, elapsed, class, code, t)
	}
	sum := sha256.Sum256(res.Body)
	result, peerCode, ok := a2aAnswer(peer.Binding, res.Status, res.Body)
	switch {
	case res.Truncated || (!ok && outcome == pb.Outcome_OUTCOME_ACCEPTED):
		// The peer took the call, but its answer is not one: the call
		// happened, nothing of the answer is relayed (HR-327).
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, res.Status, sum[:], elapsed, EnforcementFailed, CodeA2AAnswer, t)
	case peerCode != "":
		// The peer refused it (a JSON-RPC error, or a 4xx).
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, res.Status, sum[:], elapsed, ToolFailed, peerCode, t)
	case !ok:
		return e.record(ctx, r, want, outcome, res.Status, sum[:], elapsed, class, code, t)
	}
	r.Response = &egress.Response{Status: res.Status, Body: egress.Redacted(result, secret), ContentType: "application/json", RequestID: res.RequestID}
	return e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, res.Status, sum[:], elapsed, "", "", t)
}

// streamA2A relays a streamed answer. The outcome is recorded when the
// first event arrives (the peer took the call); the events then go to the
// sink one by one until the stream ends, its cap or time runs out, or the
// agent goes away.
func (e *Engine) streamA2A(ctx context.Context, r Result, conn *control.Connection, peer A2APeer, client *egress.Client, req *http.Request,
	sink A2ASink, secret []byte, want permitWant, t *timer,
) Result {
	secs := peer.MaxStreamSeconds
	if secs <= 0 {
		secs = defaultA2AStreamSeconds
	}
	sctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()
	req = req.WithContext(sctx)
	start := time.Now()
	res, err := client.Open(req)
	t.lap("target")
	if err != nil {
		outcome, class, code := classify(0, err)
		e.breaker.record(ctx, conn, outcome)
		return e.record(ctx, r, want, outcome, 0, nil, time.Since(start), class, code, t)
	}
	defer func() { _ = res.Body.Close() }()
	mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if res.StatusCode != http.StatusOK || mt != "text/event-stream" {
		// An error answer instead of a stream.
		body, _ := io.ReadAll(io.LimitReader(res.Body, maxA2AEventBytes))
		outcome, class, code := classify(res.StatusCode, nil)
		e.breaker.record(ctx, conn, outcome)
		sum := sha256.Sum256(body)
		if _, peerCode, ok := a2aAnswer(peer.Binding, res.StatusCode, body); ok && peerCode != "" {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, res.StatusCode, sum[:], time.Since(start), ToolFailed, peerCode, t)
		}
		if outcome == pb.Outcome_OUTCOME_ACCEPTED {
			return e.record(ctx, r, want, outcome, res.StatusCode, sum[:], time.Since(start), EnforcementFailed, CodeA2AAnswer, t)
		}
		return e.record(ctx, r, want, outcome, res.StatusCode, sum[:], time.Since(start), class, code, t)
	}
	e.breaker.record(ctx, conn, pb.Outcome_OUTCOME_ACCEPTED)
	events := sseEvents(res.Body)
	first, peerCode, err := nextA2AEvent(events, peer.Binding)
	if err != nil || peerCode != "" {
		if peerCode != "" {
			return e.record(ctx, r, want, pb.Outcome_OUTCOME_FAILED, res.StatusCode, nil, time.Since(start), ToolFailed, peerCode, t)
		}
		// A stream that carried no event: the peer may have acted.
		return e.record(ctx, r, want, pb.Outcome_OUTCOME_UNKNOWN, res.StatusCode, nil, time.Since(start), Uncertain, CodeA2AStream, t)
	}
	sum := sha256.Sum256(first)
	r.Response = &egress.Response{Status: res.StatusCode, ContentType: "text/event-stream", RequestID: egress.RequestID(res.Header)}
	r = e.record(ctx, r, want, pb.Outcome_OUTCOME_ACCEPTED, res.StatusCode, sum[:], time.Since(start), "", "", t)
	if r.Class != "" {
		return r
	}
	for ev := first; ; {
		if sink(egress.Redacted(ev, secret)) != nil {
			return r
		}
		ev, peerCode, err = nextA2AEvent(events, peer.Binding)
		if err != nil || peerCode != "" {
			if !errors.Is(err, io.EOF) {
				// Cut short, over its cap or time, or a broken event: the
				// agent saw everything before it; the outcome stands.
				e.log.WarnContext(ctx, "gateway.a2a_stream_cut", slog.String("transaction_id", want.Txn), slog.String("peer_code", peerCode),
					pclog.Err(err))
				r.Code = CodeA2AStream
			}
			return r
		}
	}
}

// sseEvents yields the data of each server-sent event.
func sseEvents(body io.Reader) func() ([]byte, error) {
	br := bufio.NewReaderSize(body, 64<<10)
	return func() ([]byte, error) {
		var data []byte
		for {
			line, err := br.ReadSlice('\n')
			if errors.Is(err, bufio.ErrBufferFull) {
				// Accumulate an over-long line within the event cap.
				rest := append([]byte(nil), line...)
				for errors.Is(err, bufio.ErrBufferFull) {
					line, err = br.ReadSlice('\n')
					rest = append(rest, line...)
					if len(rest) > maxA2AEventBytes {
						return nil, errors.New("dispatch: an A2A event over its cap")
					}
				}
				line = rest
			}
			if err != nil && len(line) == 0 {
				if errors.Is(err, io.EOF) && len(data) > 0 {
					return data, nil
				}
				return nil, err
			}
			l := bytes.TrimRight(line, "\r\n")
			switch {
			case len(l) == 0:
				if len(data) > 0 {
					return data, nil
				}
			case bytes.HasPrefix(l, []byte("data:")):
				d := bytes.TrimPrefix(bytes.TrimPrefix(l, []byte("data:")), []byte(" "))
				if len(data) > 0 {
					data = append(data, '\n')
				}
				data = append(data, d...)
				if len(data) > maxA2AEventBytes {
					return nil, errors.New("dispatch: an A2A event over its cap")
				}
			}
			if err != nil {
				if len(data) > 0 {
					return data, nil
				}
				return nil, err
			}
		}
	}
}

// nextA2AEvent reads the next StreamResponse: unwrapped from its JSON-RPC
// envelope, exactly one member set. A JSON-RPC error event is the peer's
// refusal, as a code.
func nextA2AEvent(next func() ([]byte, error), binding string) ([]byte, string, error) {
	data, err := next()
	if err != nil {
		return nil, "", err
	}
	if binding == wire.BindingJSONRPC {
		result, peerCode, ok := a2aAnswer(binding, http.StatusOK, data)
		if !ok {
			return nil, "", errors.New("dispatch: an A2A event that is not a JSON-RPC response")
		}
		if peerCode != "" {
			return nil, peerCode, nil
		}
		data = result
	}
	var ev wire.StreamResponse
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, "", fmt.Errorf("dispatch: an A2A event: %w", err)
	}
	n := 0
	for _, set := range []bool{ev.Task != nil, ev.Message != nil, ev.StatusUpdate != nil, ev.ArtifactUpdate != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return nil, "", errors.New("dispatch: an A2A event without exactly one member")
	}
	return data, "", nil
}
