// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// ErrAdminNotLoopback refuses an admin address that is not a loopback IP
// address and port (HR-382).
var ErrAdminNotLoopback = errors.New("admin.addr must be a loopback IP address and port, for example 127.0.0.1:6060")

// CheckAdminAddr checks admin.addr (G0 M13 D30, HR-382): empty is off;
// anything else must be a loopback IP literal with a port. Host names
// (even localhost), unspecified and other addresses are refused.
func CheckAdminAddr(addr string) error {
	if addr == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ErrAdminNotLoopback
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() || a.Zone() != "" {
		return ErrAdminNotLoopback
	}
	return nil
}

// Profiling and collection bounds.
const (
	maxProfileSeconds = 60
	adminWriteTimeout = (maxProfileSeconds + 10) * time.Second
)

// AdminHandler serves the private profiling and metrics endpoints:
// /debug/pprof/{profile,trace,heap,goroutine,allocs,block,mutex,threadcreate}
// and /metrics (Prometheus text). It never registers anything on
// http.DefaultServeMux.
func AdminHandler(reader *sdkmetric.ManualReader) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		var rm metricdata.ResourceMetrics
		if reader == nil {
			http.Error(w, "metrics are off", http.StatusNotFound)
			return
		}
		if err := reader.Collect(r.Context(), &rm); err != nil {
			http.Error(w, "collect failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = writeText(w, &rm)
	})
	mux.HandleFunc("GET /debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		d := seconds(r, 30)
		w.Header().Set("Content-Type", "application/octet-stream")
		if err := pprof.StartCPUProfile(w); err != nil {
			http.Error(w, "a CPU profile is already running", http.StatusConflict)
			return
		}
		sleep(r.Context(), d)
		pprof.StopCPUProfile()
	})
	mux.HandleFunc("GET /debug/pprof/trace", func(w http.ResponseWriter, r *http.Request) {
		d := seconds(r, 1)
		w.Header().Set("Content-Type", "application/octet-stream")
		if err := trace.Start(w); err != nil {
			http.Error(w, "a trace is already running", http.StatusConflict)
			return
		}
		sleep(r.Context(), d)
		trace.Stop()
	})
	for _, name := range []string{"heap", "goroutine", "allocs", "block", "mutex", "threadcreate"} {
		mux.HandleFunc("GET /debug/pprof/"+name, func(w http.ResponseWriter, r *http.Request) {
			p := pprof.Lookup(name)
			if p == nil {
				http.NotFound(w, r)
				return
			}
			if name == "heap" && r.URL.Query().Get("gc") == "1" {
				runtime.GC()
			}
			debug, _ := strconv.Atoi(r.URL.Query().Get("debug"))
			if debug > 0 {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			} else {
				w.Header().Set("Content-Type", "application/octet-stream")
			}
			_ = p.WriteTo(w, min(max(debug, 0), 2))
		})
	}
	return mux
}

func seconds(r *http.Request, def int) time.Duration {
	s, err := strconv.Atoi(r.URL.Query().Get("seconds"))
	if err != nil || s <= 0 {
		s = def
	}
	return time.Duration(min(s, maxProfileSeconds)) * time.Second
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// ListenAdmin binds the admin listener on addr after CheckAdminAddr, and
// checks the bound address is loopback too (HR-382). The caller serves it
// with Serve.
func ListenAdmin(ctx context.Context, addr string) (net.Listener, error) {
	if addr == "" {
		return nil, errors.New("telemetry: the admin listener is off")
	}
	if err := CheckAdminAddr(addr); err != nil {
		return nil, err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("telemetry: admin listener: %w", err)
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		_ = ln.Close()
		return nil, ErrAdminNotLoopback
	}
	return ln, nil
}

// NewAdminServer returns the admin listener's HTTP server.
func NewAdminServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: adminWriteTimeout, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
	}
}
