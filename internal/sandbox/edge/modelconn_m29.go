// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Model connections (G0 M29 D814, D815): an agent host mapped to a model
// connection goes to the gateway's HTTP face for it, `/{conn}{path}?{query}`,
// like every other mapped host, but with the model path's limits: the
// request up to 16 MiB, the answer streamed back as it arrives up to
// 16 MiB, one call in at most 10 minutes. Credentials are stripped and
// reported as on every route, except the session's placeholder (D815). The
// campaign route (model.go) is unchanged.
const (
	// MaxModelConnBody is the most a model connection's request or answer
	// may carry.
	MaxModelConnBody = 16 << 20
	// modelConnTimeout bounds one call, its stream included.
	modelConnTimeout = 10 * time.Minute
)

// modelConnRequestHeaders are the only request headers sent on (D812):
// never a credential, cookie, proxy or forwarding header.
var modelConnRequestHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// modelConnAnswerHeaders are the answer headers passed back besides Pc-*
// and those with modelConnAnswerPrefixes (D812).
var modelConnAnswerHeaders = []string{"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id"}

var modelConnAnswerPrefixes = []string{"Anthropic-Ratelimit-", "X-Ratelimit-", "Pc-"}

// modelConnections checks Options.ModelConnections: each one a connection
// some agent host maps to.
func modelConnections(o Options) (map[string]bool, error) {
	if len(o.ModelConnections) == 0 {
		return nil, nil //nolint:nilnil // no model connection
	}
	if o.Binding != nil {
		return nil, errors.New("edge: a connector's edge has no model connection")
	}
	mapped := map[string]bool{}
	for _, c := range o.Hosts {
		mapped[c] = true
	}
	out := map[string]bool{}
	for _, c := range o.ModelConnections {
		if !mapped[c] {
			return nil, fmt.Errorf("edge: model connection %q serves no agent host", c)
		}
		out[c] = true
	}
	return out, nil
}

// forwardModelConnection sends one call over a model connection to the
// gateway and streams the answer back (D814). A cut answer breaks the
// agent's connection rather than read as whole.
func (e *Edge) forwardModelConnection(w http.ResponseWriter, r *http.Request, host, conn string) {
	e.strip(r, host)
	query := e.stripQuery(r, host)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxModelConnBody+1))
	if err != nil || len(body) > MaxModelConnBody {
		e.answer(w, r, host, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if e.token() == "" {
		e.answer(w, r, host, http.StatusServiceUnavailable, "edge_has_no_workload_token")
		return
	}
	target := e.gateway + "/" + url.PathEscape(conn) + r.URL.EscapedPath()
	if query != "" {
		target += "?" + query
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelConnTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body)) //nolint:gosec // G704: scheme and host are the configured gateway's; the agent supplies only the path and query
	if err != nil {
		e.answer(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, h := range modelConnRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	key := fingerprint(r.Method, target, body)
	action := e.held.action(key)
	out.Header.Set(headerRunID, e.run)
	out.Header.Set(headerAction, action)
	if e.session != "" {
		out.Header.Set(headerSession, e.session)
	}
	res, err := e.modelConn.Do(out) //nolint:gosec // G704: only the configured gateway (see above)
	e.heldAnswer(key, action, res, err)
	if err != nil {
		e.log.WarnContext(r.Context(), "edge.gateway_unreachable", "connection", conn, "error", err.Error())
		e.answer(w, r, host, http.StatusBadGateway, "gateway_unreachable")
		return
	}
	defer func() { _ = res.Body.Close() }()
	for k, vs := range res.Header {
		if modelConnAnswerHeader(k) && k != http.CanonicalHeaderKey(HeaderRefusedBy) {
			w.Header()[k] = vs
		}
	}
	// Metadata only, never a prompt or a reply (D820).
	e.log.InfoContext(r.Context(), "edge.forwarded", "method", r.Method, "connection", conn, "action", action, "status", res.StatusCode,
		"request_bytes", len(body))
	w.WriteHeader(res.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, rerr := res.Body.Read(buf)
		if k > 0 {
			if n += int64(k); n > MaxModelConnBody {
				panic(http.ErrAbortHandler) // a cut answer must not read as whole
			}
			if _, werr := w.Write(buf[:k]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if errors.Is(rerr, io.EOF) {
			return
		}
		if rerr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

func modelConnAnswerHeader(k string) bool {
	if slices.Contains(modelConnAnswerHeaders, k) {
		return true
	}
	for _, p := range modelConnAnswerPrefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}
