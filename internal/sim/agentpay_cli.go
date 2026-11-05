// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/agentpay"
)

// runAgentPay serves the simulated AP2 merchant and credentials provider,
// with fixed development keys, over https on loopback with the fixed
// development certificate (G0 M39 D1124, D1124c).
func runAgentPay(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("agentpay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["agentpay"], "listen address (loopback)")
	mismatch := fs.Bool("mismatch", false, "sign mandates for one minor unit more than the checkout")
	expired := fs.Bool("expired", false, "sign mandates that expired a minute ago")
	decline := fs.Bool("decline", false, "answer every checkout as declined")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := agentpay.New(agentpay.Faults{Mismatch: *mismatch, Expired: *expired, Decline: *decline}, log)
	return serveTLS(ctx, *addr, sim.Handler(), log, "sim.agentpay_listening")
}

// serveTLS is serve over https with the simulator's development
// certificate (TLS 1.3).
func serveTLS(ctx context.Context, addr string, h http.Handler, log *slog.Logger, event string) error {
	cert, err := agentpay.DevCertificate()
	if err != nil {
		return err
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: addr, Handler: h, Logger: log})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	log.InfoContext(ctx, event, slog.String("addr", ln.Addr().String()), slog.String("scheme", "https"))
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
