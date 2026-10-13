// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Connector mode (G0 M9 track C, the edge protocol): the edge in front of
// a connector's container sends each request it intercepted to the
// gateway's egress listener, which maps it to the call in flight, places
// the egress connection's credential and dispatches it (design decisions 6
// and 18). The connector and its edge never hold a credential.
const (
	// EgressPath is the egress listener's path.
	EgressPath = "/edge/v1/egress"
	// HeaderBinding carries the binding token the gateway generated for the
	// connector's container and keeps in memory.
	HeaderBinding = "PC-Connector-Binding"
	// MaxEgressBody bounds one egress request's body.
	MaxEgressBody = 1 << 20
)

// Egress is an intercepted request as the egress listener receives it.
type Egress struct {
	// Connection names the egress connection the request's host maps to.
	Connection string `json:"connection"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	// Path is escaped; Query is raw, with credentials stripped.
	Path    string            `json:"path"`
	Query   string            `json:"query,omitzero"`
	Headers map[string]string `json:"headers,omitzero"`
	Body    []byte            `json:"body,omitzero"`
}

// egress sends one intercepted request to the gateway's egress listener and
// answers with its answer. Only the method, the path and query, the body,
// Content-Type and Accept go on; credentials are stripped and reported, as
// in sandbox mode.
func (e *Edge) egress(w http.ResponseWriter, r *http.Request, host, conn string) {
	e.strip(r, host)
	query := e.stripQuery(r, host)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxEgressBody+1))
	if err != nil || len(body) > MaxEgressBody {
		e.answer(w, r, host, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	binding := e.binding()
	if binding == "" {
		e.answer(w, r, host, http.StatusServiceUnavailable, "edge_has_no_binding")
		return
	}
	in := Egress{Connection: conn, Method: r.Method, Host: host, Path: r.URL.EscapedPath(), Query: query, Body: body}
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			if in.Headers == nil {
				in.Headers = map[string]string{}
			}
			in.Headers[h] = v
		}
	}
	b, err := json.Marshal(in)
	if err != nil {
		e.answer(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, e.gateway+EgressPath, bytes.NewReader(b))
	if err != nil {
		e.answer(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set(HeaderBinding, binding)
	action := ids.NewV7().String()
	out.Header.Set(headerAction, action)
	res, err := e.client.Do(out) //nolint:bodyclose // relay closes the body
	e.relay(w, r, host, conn, action, res, err)
}

// onlyPlaceholder reports whether a credential value carries only the
// connector's placeholder, alone or after an authorization scheme.
func (e *Edge) onlyPlaceholder(v string) bool {
	if e.placeholder == "" {
		return false
	}
	f := strings.Fields(v)
	return (len(f) == 1 || len(f) == 2) && f[len(f)-1] == e.placeholder
}

// nonRoutable reports whether host is an address the binding token may
// cross in clear: a loopback, private or link-local IP address, or the
// name Docker gives the host.
func nonRoutable(host string) bool {
	if host == "host.docker.internal" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}
