// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// Config is the edge's configuration file. `pclaw sandbox run` writes it and
// mounts it, the workload key file and the token directory read-only into
// the edge container only (HR-213).
type Config struct {
	// Listen is the proxy's address on the sandbox network, ":3128".
	Listen      string `json:"listen"`
	GatewayURL  string `json:"gateway_url"`
	GatewayAddr string `json:"gateway_addr,omitzero"`
	// GatewayCAFile verifies an HTTPS gateway with a private CA.
	GatewayCAFile string  `json:"gateway_ca_file,omitzero"`
	Routes        []Route `json:"routes"`
	Run           string  `json:"run"`
	KeyFile       string  `json:"key_file"`
	// TokenFile holds the current workload token; pclaw renews it outside
	// the sandbox, and the edge reads it for every request.
	TokenFile string `json:"token_file"`
	// CAValiditySeconds bounds the session CA; 24 h when zero.
	CAValiditySeconds int64 `json:"ca_validity_seconds,omitzero"`
}

// ReadConfig reads a configuration file strictly.
func ReadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the sandbox's own configuration
	if err != nil {
		return Config{}, fmt.Errorf("edge: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, fmt.Errorf("edge: %s: %w", path, err)
	}
	if c.Listen == "" || c.KeyFile == "" || c.TokenFile == "" {
		return Config{}, errors.New("edge: listen, key_file and token_file are required")
	}
	return c, nil
}

// Ready is the line the edge writes once it listens. pclaw reads it from
// outside the sandbox, records the fingerprint and mounts the certificate
// read-only into the agent's container; the CA key stays in the edge's
// memory (HR-213).
type Ready struct {
	Event    string `json:"event"`
	Listen   string `json:"listen"`
	CASHA256 string `json:"ca_sha256"`
	CAPEM    string `json:"ca_pem"`
}

// ReadyEvent is Ready's event name.
const ReadyEvent = "edge.ready"

// Run serves the edge until ctx ends: it creates the session CA, listens,
// writes Ready to out, and logs every request it forwards or refuses to
// log.
func Run(ctx context.Context, c Config, out io.Writer, log *slog.Logger) error {
	kf, err := workloadclient.ReadKeyFile(c.KeyFile)
	if err != nil {
		return err
	}
	key, err := kf.Key()
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if c.GatewayCAFile != "" {
		b, err := os.ReadFile(c.GatewayCAFile)
		if err != nil {
			return fmt.Errorf("edge: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return errors.New("edge: gateway_ca_file has no certificate")
		}
	}
	e, err := New(Options{
		GatewayURL: c.GatewayURL, GatewayAddr: c.GatewayAddr, GatewayRoots: roots, Routes: c.Routes, Run: c.Run, Key: key,
		Token: func() string {
			b, err := os.ReadFile(c.TokenFile)
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(b))
		},
		CAValidity: time.Duration(c.CAValiditySeconds) * time.Second, Log: log,
	})
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	srv := &http.Server{
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      requestTimeout + 10*time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	ready := Ready{Event: ReadyEvent, Listen: ln.Addr().String(), CASHA256: e.CAFingerprint(), CAPEM: string(e.CACertificate())}
	if err := json.MarshalWrite(out, ready); err != nil {
		_ = ln.Close()
		return err
	}
	_, _ = io.WriteString(out, "\n")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.InfoContext(ctx, "edge.stopped", "refused", e.Refused())
	return nil
}
