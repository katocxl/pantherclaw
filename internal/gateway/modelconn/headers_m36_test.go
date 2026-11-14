// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelconn

import (
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/internal/modelapi"
)

// TestHR785_ModelRequestsDoNotForwardTraceHeaders: the model connection
// rebuilds the upstream headers from its allow-list. A caller-supplied
// traceparent is read earlier for the span and is not sent to the provider.
// Covers: HR-785
func TestHR785_ModelRequestsDoNotForwardTraceHeaders(t *testing.T) {
	in := http.Header{}
	in.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	in.Set("tracestate", "vendor=secret")
	in.Set("Anthropic-Version", "2023-06-01")
	out := requestHeaders(modelapi.AnthropicMessages, in, true)
	if out.Get("traceparent") != "" || out.Get("tracestate") != "" {
		t.Fatalf("trace headers forwarded: %v", out)
	}
	if out.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("allowed header dropped: %v", out)
	}
}
