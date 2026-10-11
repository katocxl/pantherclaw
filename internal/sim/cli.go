// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sim implements pantherclaw-sim: simulated targets and a load
// driver for tests, demos and latency measurements. Everything it does is
// SIMULATED.
package sim

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
)

const usage = `pantherclaw-sim — simulated targets and load driver (everything is SIMULATED)

Usage:
  pantherclaw-sim payments [--addr 127.0.0.1:9090] [--latency 0s] [--decline-rate 0] [--hang-rate 0] [--lose-response-rate 0]
                           [--short-rate 0] [--settle-after 0s] [--redirect-to URL]
                           [--token-file FILE] [--require-action-tokens --jwks-url URL --audience CONNECTION]
  pantherclaw-sim mcp [--addr 127.0.0.1:9091] [--legacy] [--stream] [--ask LIST] [--input-required] [--tool-error] [--description TEXT] [--token-file FILE]
  pantherclaw-sim load --workload-file FILE [--token-file FILE] [--run ID] [--gateway URL] [--connection payments] [--rate 1000] [--duration 30s]
                       [--warmup 5s] [--max-in-flight 2048] [--amount 1.00 | --unique] [--facts-key-file FILE] [--out FILE]
  pantherclaw-sim version
`

// Run executes pantherclaw-sim.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, version.Get().String("pantherclaw-sim"))
		return 0
	case "payments":
		err = runPayments(ctx, args[1:], stderr)
	case "mcp":
		err = runMCP(ctx, args[1:], stderr)
	case "load":
		err = runLoad(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-sim: %v\n", err)
		return 1
	}
	return 0
}

func runPayments(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("payments", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9090", "listen address (loopback)")
	latency := fs.Duration("latency", 0, "added latency per request")
	decline := fs.Float64("decline-rate", 0, "probability of a 402 decline (no effect)")
	hang := fs.Float64("hang-rate", 0, "probability of never answering, refunding nothing (unknown outcome, no effect)")
	lose := fs.Float64("lose-response-rate", 0, "probability of refunding and then never answering (unknown outcome, effect happened)")
	shortRate := fs.Float64("short-rate", 0, "probability of recording a refund one minor unit short of what was asked (a conflicting observation)")
	settle := fs.Duration("settle-after", 0, "how long a new refund stays pending before it succeeds")
	redirect := fs.String("redirect-to", "", "answer every refund with a 307 redirect to this URL")
	tokenFile := fs.String("token-file", "", "file holding the bearer token every request must carry (the credential PantherClaw holds)")
	actionTokens := fs.Bool("require-action-tokens", false, "require a valid PAP-Action token on every refund (with --jwks-url and --audience)")
	jwksURL := fs.String("jwks-url", "", "the PantherClaw server's /.well-known/pantherclaw/jwks.json")
	audience := fs.String("audience", "", "the connection id action tokens must be addressed to")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var req payments.Require
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		req.Token = strings.TrimSpace(string(b))
	}
	if *actionTokens {
		if *jwksURL == "" || *audience == "" {
			return errors.New("--require-action-tokens needs --jwks-url and --audience")
		}
		req.ActionTokens = &payments.ActionVerifier{JWKSURL: *jwksURL, Audience: *audience}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := payments.New(payments.Faults{
		Latency: *latency, DeclineRate: *decline, HangRate: *hang, LoseRate: *lose, ShortRate: *shortRate, SettleAfter: *settle, RedirectTo: *redirect,
	}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.payments_listening")
}

func runMCP(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9091", "listen address (loopback)")
	legacy := fs.Bool("legacy", false, "speak MCP 2025-11-25 with sessions instead of 2026-07-28")
	stream := fs.Bool("stream", false, "answer tool calls as event streams")
	ask := fs.String("ask", "", "comma-separated requests to send the client during a 2025-11-25 call (elicitation/create, sampling/createMessage, roots/list)")
	inputRequired := fs.Bool("input-required", false, "answer 2026-07-28 tool calls with input_required")
	toolError := fs.Bool("tool-error", false, "fail create_refund with isError")
	description := fs.String("description", "", "replace get_refund's description (drift)")
	tokenFile := fs.String("token-file", "", "file holding the bearer token every request must carry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	f := mcpsim.Faults{Legacy: *legacy, Stream: *stream, InputRequired: *inputRequired, ToolError: *toolError, Description: *description}
	if *ask != "" {
		f.Ask = strings.Split(*ask, ",")
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		f.Token = strings.TrimSpace(string(b))
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	return serve(ctx, *addr, mcpsim.New(f).Handler(), log, "sim.mcp_listening")
}

// serve serves h on addr until ctx ends.
func serve(ctx context.Context, addr string, h http.Handler, log *slog.Logger, event string) error {
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: addr, Handler: h, Logger: log})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	log.InfoContext(ctx, event, slog.String("addr", ln.Addr().String()))
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
