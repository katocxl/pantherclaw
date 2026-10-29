// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sim"
)

// TestPerf_M15_MCPToolsCall measures MCP tools/call latency through the
// stack's gateway with `pantherclaw-sim load --mcp` (G0 M15 D15,
// docs/perf/M15.md). It runs only with PC_PERF_M15_OUT set to a directory
// for the JSON summaries; PC_PERF_M15_RATES (default "10 25") and
// PC_PERF_M15_DURATION (default 30s) shape the load. The same file runs
// on the commit before D14, side by side, for the comparison.
func TestPerf_M15_MCPToolsCall(t *testing.T) {
	out := os.Getenv("PC_PERF_M15_OUT")
	if out == "" {
		t.Skip("PC_PERF_M15_OUT not set")
	}
	rates := strings.Fields(os.Getenv("PC_PERF_M15_RATES"))
	if len(rates) == 0 {
		rates = []string{"10", "25"}
	}
	duration := os.Getenv("PC_PERF_M15_DURATION")
	if duration == "" {
		duration = "30s"
	}
	s := start(t, options{budget: "100000000.00"})
	for _, rate := range rates {
		if _, err := strconv.Atoi(rate); err != nil {
			t.Fatalf("rate %q", rate)
		}
		file := filepath.Join(out, "mcp-r"+rate+".json")
		var stdout, stderr bytes.Buffer
		if code := sim.Run(context.Background(), []string{
			"load", "--mcp", "--unique", "--gateway", s.gateway, "--connection", "payments", "--workload-file", s.keyFile,
			"--facts-key-file", s.factsKey, "--rate", rate, "--duration", duration, "--warmup", "5s", "--out", file,
		}, &stdout, &stderr); code != 0 {
			t.Fatalf("load at %s rps: %d %s", rate, code, stderr.String())
		}
		t.Logf("%s rps:\n%s", rate, stdout.String())
	}
}
