// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// The Lambda Runtime API (version 2018-06-01).
const (
	runtimeVersion      = "/2018-06-01"
	headerRequestID     = "Lambda-Runtime-Aws-Request-Id"
	headerDeadline      = "Lambda-Runtime-Deadline-Ms"
	headerClientContext = "Lambda-Runtime-Client-Context"
	// clientGatewayARN is the client context member that names the
	// AgentCore gateway.
	clientGatewayARN = "GATEWAY_ARN"
	// maxReadEvent is how much of an event is read: one byte past the
	// largest the gateway's face takes, so a larger one is denied.
	maxReadEvent = maxEvent + 1
)

// headerGateway is the header that names the AgentCore gateway, on --local
// and on the request to the gateway's face (D994).
const headerGateway = "PC-Runtime-Gateway"

// runtimeClient is the Runtime API's HTTP client: the endpoint is the
// Lambda sandbox's own, reached without a proxy, and the next invocation
// is a long poll with no timeout.
func runtimeClient() *http.Client {
	return &http.Client{
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext},
		CheckRedirect: noRedirect,
	}
}

// serveLambda runs the Runtime API loop until ctx ends: take the next
// invocation, answer it, and post the answer. Every invocation gets an
// answer; an error answers with a deny, never the Runtime API's error path,
// so AgentCore never forwards an undecided request.
func (ic *interceptor) serveLambda(ctx context.Context, api string) error {
	if strings.ContainsAny(api, "/?#@") {
		return fmt.Errorf("%s %q is not a host and port", envRuntimeAPI, api)
	}
	base := "http://" + api + runtimeVersion
	hc := runtimeClient()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		id, arn, deadline, event, err := nextInvocation(ctx, hc, base)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ic.log.Error("interceptor.runtime_next", "error", err.Error())
			if !sleep(ctx, time.Second) {
				return ctx.Err()
			}
			continue
		}
		out := ic.answer(ctx, arn, event, deadline)
		if err := postResponse(ctx, hc, base, id, out); err != nil {
			ic.log.Error("interceptor.runtime_response", "request", id, "error", err.Error())
		}
	}
}

// nextInvocation takes the next invocation: its request id, the gateway
// ARN from its client context, its deadline and its event (at most
// maxReadEvent bytes).
func nextInvocation(ctx context.Context, hc *http.Client, base string) (id, arn string, deadline time.Time, event []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/runtime/invocation/next", nil)
	if err != nil {
		return "", "", time.Time{}, nil, err
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", "", time.Time{}, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", "", time.Time{}, nil, fmt.Errorf("the Runtime API answered HTTP %d", res.StatusCode)
	}
	id = res.Header.Get(headerRequestID)
	if id == "" || strings.ContainsAny(id, "/?#") {
		return "", "", time.Time{}, nil, errors.New("the invocation has no usable request id")
	}
	if ms, perr := strconv.ParseInt(res.Header.Get(headerDeadline), 10, 64); perr == nil && ms > 0 {
		deadline = time.UnixMilli(ms)
	}
	arn = clientContextGateway(res.Header.Get(headerClientContext))
	event, err = io.ReadAll(io.LimitReader(res.Body, maxReadEvent))
	if err != nil {
		// The invocation still gets an answer: a deny.
		event = bytes.Repeat([]byte{' '}, maxReadEvent)
	}
	return id, arn, deadline, event, nil
}

// clientContextGateway reads GATEWAY_ARN from the Lambda client context
// (JSON, or base64 JSON): from its custom members, its env members, or the
// top level. "" when it carries none.
func clientContextGateway(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var cc map[string]any
	if json.Unmarshal([]byte(raw), &cc) != nil {
		b, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || json.Unmarshal(b, &cc) != nil {
			return ""
		}
	}
	for _, scope := range []string{"custom", "env"} {
		if m, ok := cc[scope].(map[string]any); ok {
			if s, ok := m[clientGatewayARN].(string); ok && s != "" {
				return s
			}
		}
	}
	if s, ok := cc[clientGatewayARN].(string); ok {
		return s
	}
	return ""
}

// postResponse posts an invocation's answer.
func postResponse(ctx context.Context, hc *http.Client, base, id string, out []byte) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, base+"/runtime/invocation/"+id+"/response", bytes.NewReader(out))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	_ = res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("the Runtime API answered HTTP %d", res.StatusCode)
	}
	return nil
}

// serveLocal serves POST /invoke on a loopback address until ctx ends: the
// body is the event and PC-Runtime-Gateway names the gateway (D995, for the
// simulator and end-to-end tests).
func (ic *interceptor) serveLocal(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /invoke", func(w http.ResponseWriter, r *http.Request) {
		event, err := io.ReadAll(io.LimitReader(r.Body, maxReadEvent))
		if err != nil {
			event = bytes.Repeat([]byte{' '}, maxReadEvent)
		}
		out := ic.answer(r.Context(), r.Header.Get(headerGateway), event, time.Time{})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(out)
	})
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().IsLoopback() {
		return fmt.Errorf("--local listens on a loopback address only, not %q", addr)
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", ap.String())
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 32 << 10}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	ic.log.Info("interceptor.local", "listen", ln.Addr().String())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return ctx.Err()
}
