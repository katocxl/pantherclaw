// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"
	"os"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/google"
	"github.com/katocxl/pantherclaw/internal/sim/vertexagent"
)

// runVertexAgent serves the simulated Vertex AI Agent Engine
// (reasoningEngines) with a JWT-bearer token endpoint (G0 M34 D998).
func runVertexAgent(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("vertex-agent-engine", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["vertex-agent-engine"], "listen address (loopback)")
	accountFile := fs.String("service-account-file", "", "service account JSON key file whose key alone signs accepted assertions (otherwise any well-formed RS256 assertion is)")
	rate := fs.Int("rate-limit", 0, "answer the first N API requests with 429 and Retry-After")
	invalidGrant := fs.Bool("invalid-grant", false, "refuse every token request (a disabled key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var account *google.Account
	if *accountFile != "" {
		b, err := os.ReadFile(*accountFile)
		if err != nil {
			return err
		}
		if account, err = google.ParseAccount(b); err != nil {
			return err
		}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := vertexagent.New(account, *invalidGrant, vertexagent.Faults{RateLimit: *rate}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.vertex_agent_engine_listening")
}
