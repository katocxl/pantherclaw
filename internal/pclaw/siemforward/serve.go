// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package siemforward

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// ShutdownGrace is how long batches in flight get to finish once the
// forwarder is told to stop.
const ShutdownGrace = 30 * time.Second

// ServeConfig is how the forwarder listens.
type ServeConfig struct {
	// Listen is the address (DefaultListen when empty).
	Listen string
	// TLS serves HTTPS. Without it the address must be loopback.
	TLS *tls.Config
	Log *slog.Logger
	// Ready, when set, is told the bound address once listening.
	Ready func(addr string)
}

// Loopback reports whether addr (host:port) names a loopback host. An
// empty host listens on every interface, so it is not loopback.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

// ErrNeedsTLS refuses a plain-HTTP listener on a non-loopback address.
var ErrNeedsTLS = errors.New("a non-loopback --listen address needs --tls-cert and --tls-key")

// newServer is the hardened server Serve runs (SB-8 timeouts, the
// exporter's batch size as the body limit, so httpx.LimitBody refuses a
// declared oversize body before h sees it).
func newServer(h http.Handler, sc ServeConfig, log *slog.Logger) (*http.Server, error) {
	if sc.TLS == nil && !Loopback(sc.Listen) {
		return nil, ErrNeedsTLS
	}
	return httpx.NewServer(httpx.ServerConfig{Addr: sc.Listen, Handler: h, TLS: sc.TLS, BodyLimit: MaxBody, Logger: log})
}

// Serve runs h on the hardened server until ctx ends, then stops taking
// connections and lets batches in flight finish, for up to ShutdownGrace.
func Serve(ctx context.Context, h http.Handler, sc ServeConfig) error {
	if sc.Listen == "" {
		sc.Listen = DefaultListen
	}
	log := sc.Log
	if log == nil {
		log = pclog.Discard()
	}
	srv, err := newServer(h, sc, log)
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", sc.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", sc.Listen, err)
	}
	addr := ln.Addr().String()
	log.InfoContext(ctx, "siem.forward.listening", slog.String("addr", addr), slog.Bool("tls", sc.TLS != nil))
	if sc.Ready != nil {
		sc.Ready(addr)
	}
	done := make(chan error, 1)
	go func() {
		if sc.TLS != nil {
			done <- srv.ServeTLS(ln, "", "")
		} else {
			done <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	log.InfoContext(ctx, "siem.forward.stopping", slog.String("grace", ShutdownGrace.String()))
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ShutdownGrace)
	defer cancel()
	err = srv.Shutdown(sctx)
	if serr := <-done; !errors.Is(serr, http.ErrServerClosed) && serr != nil {
		return serr
	}
	return err
}
