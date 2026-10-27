// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package httpx provides PantherClaw's hardened HTTP building blocks: the
// server every listener uses (SB-8) and the egress client every outbound
// request to a target uses (HR-070..074). net/http's defaults (no timeouts,
// redirects followed, proxies from the environment) are never used directly;
// forbidigo bans http.Get, http.DefaultClient and http.ListenAndServe.
package httpx

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Server limits (SB-8).
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 30 * time.Second
	WriteTimeout      = 60 * time.Second
	IdleTimeout       = 120 * time.Second
	MaxHeaderBytes    = 32 << 10
	DefaultBodyLimit  = 1 << 20
)

// ServerConfig configures a hardened server.
type ServerConfig struct {
	Addr    string
	Handler http.Handler
	// TLS enables HTTPS. Without it the address must be loopback unless
	// PlaintextBehindProxy is set (TLS terminated by a trusted proxy/mesh).
	TLS                  *tls.Config
	PlaintextBehindProxy bool
	// BodyLimit caps request bodies; default 1 MiB.
	BodyLimit int64
	Logger    *slog.Logger
}

// NewServer returns an *http.Server with SB-8 timeouts, limits, security
// headers and panic recovery.
func NewServer(cfg ServerConfig) (*http.Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("httpx: handler is required")
	}
	if cfg.TLS == nil && !cfg.PlaintextBehindProxy && !loopbackAddr(cfg.Addr) {
		return nil, fmt.Errorf("httpx: %s is not loopback; configure TLS or declare a TLS-terminating proxy", cfg.Addr)
	}
	log := cfg.Logger
	if log == nil {
		log = pclog.Discard()
	}
	limit := cfg.BodyLimit
	if limit <= 0 {
		limit = DefaultBodyLimit
	}
	h := Recover(log, SecurityHeaders(cfg.TLS != nil || cfg.PlaintextBehindProxy, LimitBody(limit, cfg.Handler)))
	return &http.Server{
		Addr:              cfg.Addr,
		Handler:           h,
		TLSConfig:         cfg.TLS,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}, nil
}

func loopbackAddr(addr string) bool {
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

// ServerTLSConfig returns the external TLS profile: TLS 1.3 only, with Go's
// default key exchanges (CurvePreferences nil: hybrid post-quantum first,
// and in FIPS mode only approved groups; SB-3, G0 M13 D35). A listener that
// only PantherClaw components reach adds ComponentLinkTLS.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

// SecurityHeaders sets the API response headers from SB-8. HSTS is sent only
// when the connection is served over TLS (directly or by a proxy).
func SecurityHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// LimitBody caps request bodies at n bytes.
func LimitBody(n int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > n {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, n)
		next.ServeHTTP(w, r)
	})
}

// Recover turns a panic in a handler into a generic 500. The stack goes to
// the operational log; nothing about it reaches the client.
func Recover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			if v == http.ErrAbortHandler { //nolint:errorlint // sentinel compared by identity, as net/http does
				panic(v)
			}
			log.ErrorContext(ctx, "http.panic",
				slog.String("path", r.URL.Path), slog.Any("panic", fmt.Sprint(v)), slog.String("stack", string(debug.Stack())))
			http.Error(w, "internal error", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}
