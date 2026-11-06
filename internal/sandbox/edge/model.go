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
	"strings"
	"time"
)

// A campaign's model route (G0 M25 D313): the agent's calls to the one model
// host go to the gateway's model face, `/model/{relay}/{host}/…`, signed with
// PAP/1 like every other request, and the answer streams back. The edge still
// dials only the gateway; the gateway asks the server about every call and
// sends it to the campaign's relay, which alone holds the model key.
const (
	// MaxModelBody is the most a model request or answer may carry.
	MaxModelBody = 8 << 20
	// modelTimeout bounds one model call, its stream included.
	modelTimeout = 5 * time.Minute
	// modelPrefix is the gateway's model face.
	modelPrefix = "/model/"
)

// modelRequestHeaders are the only request headers sent on: never a
// credential, cookie, proxy or forwarding header.
var modelRequestHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// modelAnswerHeaders are the only answer headers passed back.
var modelAnswerHeaders = []string{"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id"}

type modelRoute struct{ host, conn string }

func newModelRoute(o Options) (*modelRoute, error) {
	if o.ModelHost == "" && o.ModelConnection == "" {
		return nil, nil //nolint:nilnil // no model route
	}
	switch {
	case o.Binding != nil:
		return nil, errors.New("edge: a connector's edge has no model route")
	case !validHost(o.ModelHost), o.ModelConnection == "", strings.ContainsAny(o.ModelConnection, "/?#%"):
		return nil, fmt.Errorf("edge: model host %q → %q", o.ModelHost, o.ModelConnection)
	}
	if _, ok := o.Hosts[o.ModelHost]; ok {
		return nil, fmt.Errorf("edge: the model host %q is also an agent host", o.ModelHost)
	}
	return &modelRoute{host: o.ModelHost, conn: o.ModelConnection}, nil
}

// forwardModel sends one model call to the gateway's model face and streams
// its answer back. Credentials are stripped and reported, as on every route,
// unless they are the campaign's placeholder.
func (e *Edge) forwardModel(w http.ResponseWriter, r *http.Request, host string) {
	e.strip(r, host)
	query := e.stripQuery(r, host)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxModelBody+1))
	if err != nil || len(body) > MaxModelBody {
		e.answer(w, r, host, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if e.token() == "" {
		e.answer(w, r, host, http.StatusServiceUnavailable, "edge_has_no_workload_token")
		return
	}
	target := e.gateway + modelPrefix + url.PathEscape(e.model.conn) + "/" + host + r.URL.EscapedPath()
	if query != "" {
		target += "?" + query
	}
	ctx, cancel := context.WithTimeout(r.Context(), modelTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body)) //nolint:gosec // G704: scheme and host are the configured gateway's; the agent supplies only the path and query
	if err != nil {
		e.answer(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, h := range modelRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	key := fingerprint(r.Method, target, body)
	action := e.held.action(key)
	out.Header.Set(headerRunID, e.currentRun())
	out.Header.Set(headerAction, action)
	if e.session != "" {
		out.Header.Set(headerSession, e.session)
	}
	res, err := e.stream.Do(out) //nolint:gosec // G704: only the configured gateway (see above)
	e.heldAnswer(key, action, res, err)
	if err != nil {
		e.log.WarnContext(r.Context(), "edge.gateway_unreachable", "connection", e.model.conn, "error", err.Error())
		e.answer(w, r, host, http.StatusBadGateway, "gateway_unreachable")
		return
	}
	defer func() { _ = res.Body.Close() }()
	for _, k := range modelAnswerHeaders {
		if v := res.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	for k, vs := range res.Header {
		if strings.HasPrefix(k, "Pc-") && k != http.CanonicalHeaderKey(HeaderRefusedBy) {
			w.Header()[k] = vs
		}
	}
	e.log.InfoContext(r.Context(), "edge.forwarded", "method", r.Method, "connection", e.model.conn, "action", action, "status", res.StatusCode)
	w.WriteHeader(res.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	var n int64
	for {
		k, rerr := res.Body.Read(buf)
		if k > 0 {
			if n += int64(k); n > MaxModelBody {
				panic(http.ErrAbortHandler) // a cut answer must not read as whole
			}
			if _, werr := w.Write(buf[:k]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if errors.Is(rerr, io.EOF) {
			return
		}
		if rerr != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
