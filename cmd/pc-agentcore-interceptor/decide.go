// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The gateway's runtime face (internal/gateway/runtime, D994).
const (
	facePath = "/runtime/agentcore"
	// headerRunID is PAP/1's run header.
	headerRunID = "PAP-Run-Id"
	// headerRunEnded marks an answer whose run is no longer active.
	headerRunEnded = "PC-Run-Ended"
	// maxAnswer bounds the face's answer: the original body and an envelope.
	maxAnswer = maxEvent + 64<<10
)

// startRun starts the Lambda's run (RuntimeService.StartRuntimeRun, D992)
// under the run grant of the Lambda role's issuer entry.
func (ic *interceptor) startRun(ctx context.Context, name string) (string, error) {
	rc := pantherclawv1connect.NewRuntimeServiceClient(connect.NewClient(connecthttp.NewTransport(ic.withToken, ic.c.server)))
	res, err := rc.StartRuntimeRun(ctx, &pantherclawv1.StartRuntimeRunRequest{Name: name})
	if err != nil {
		return "", fmt.Errorf("start runtime run: %w", err)
	}
	if _, err := ids.ParseUUID(res.GetRunId()); err != nil {
		return "", errors.New("start runtime run: the server sent no run id")
	}
	return res.GetRunId(), nil
}

// decide asks the gateway's face about one event (a PAP/1 POST of the event
// as is) and returns its interceptor output. Anything but a readable output
// from the face is an error, which the caller answers with a deny.
func (ic *interceptor) decide(ctx context.Context, gatewayARN string, event []byte) ([]byte, error) {
	if gatewayARN == "" {
		return nil, errors.New("the invocation names no AgentCore gateway")
	}
	if ic.Token() == "" {
		return nil, errors.New("no workload token yet")
	}
	run := ic.Run()
	if run == "" {
		return nil, errors.New("no run yet")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ic.c.gateway+facePath, bytes.NewReader(event))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerGateway, gatewayARN)
	req.Header.Set(headerRunID, run)
	res, err := ic.withToken.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.Header.Get(headerRunEnded) != "" {
		ic.RunEnded(run)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the gateway answered HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil || len(b) > maxAnswer {
		return nil, errors.New("the gateway's answer is unreadable or too large")
	}
	var out struct {
		Version string         `json:"interceptorOutputVersion"`
		MCP     map[string]any `json:"mcp"`
	}
	if json.Unmarshal(b, &out) != nil || out.Version != outputVersion || len(out.MCP) != 1 {
		return nil, errors.New("the gateway's answer is not an interceptor output")
	}
	if _, pass := out.MCP["transformedGatewayRequest"]; !pass {
		if _, resp := out.MCP["transformedGatewayResponse"]; !resp {
			return nil, errors.New("the gateway's answer is not an interceptor output")
		}
	}
	return b, nil
}
