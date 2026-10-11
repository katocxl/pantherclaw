// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"context"
	"encoding/json/v2"
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

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// ConfigFormat names the edge's configuration format (G0 M9 edge protocol).
const ConfigFormat = "pantherclaw.edge/v1"

// Modes. The connector mode arrives with the connector runtime (track C).
const (
	ModeSandbox   = "sandbox"
	ModeConnector = "connector"
)

// Config is the edge's configuration file. `pclaw sandbox run` writes it and
// mounts it, the workload key file and the token directory read-only into
// the edge container alone (HR-213).
type Config struct {
	Format  string `json:"format"`
	Mode    string `json:"mode"`
	Session string `json:"session"`
	// Listen is the proxy's address on the sandbox network, ":3128".
	Listen     string `json:"listen"`
	GatewayURL string `json:"gateway_url"`
	// GatewayAddr is the host:port dialed for the gateway URL when the
	// gateway's public address is not reachable from the edge's uplink
	// (a gateway on the host's loopback: host.docker.internal:<port>).
	GatewayAddr  string `json:"gateway_addr,omitzero"`
	GatewayCAPin string `json:"gateway_ca_pin,omitzero"`
	// Hosts maps each agent host to its connection.
	Hosts   map[string]string `json:"hosts"`
	Run     string            `json:"run"`
	KeyFile string            `json:"key_file"`
	// TokenFile holds the instance's current workload token. The edge dials
	// only the gateway, so pclaw renews the token outside the sandbox and
	// the edge reads it for every request.
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
	switch {
	case c.Format != ConfigFormat:
		return Config{}, fmt.Errorf("edge: format %q, want %s", c.Format, ConfigFormat)
	case c.Mode == ModeConnector:
		return Config{}, errors.New("edge: connector mode is not available in this build")
	case c.Mode != ModeSandbox:
		return Config{}, fmt.Errorf("edge: mode %q", c.Mode)
	case c.Listen == "" || c.KeyFile == "" || c.TokenFile == "":
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
	// HostAddrs are the addresses host.docker.internal resolves to on the
	// edge's uplink: the host as containers see it, where the canary
	// listens. Resolving is not dialing; the edge dials only the gateway.
	HostAddrs []string `json:"host_addrs"`
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
	e, err := New(Options{
		Session: c.Session, GatewayURL: c.GatewayURL, GatewayAddr: c.GatewayAddr, GatewayCAPin: c.GatewayCAPin, Hosts: c.Hosts,
		Run: c.Run, Key: key,
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
	ready := Ready{Event: ReadyEvent, Listen: ln.Addr().String(), CASHA256: e.CAFingerprint(), CAPEM: string(e.CACertificate()), HostAddrs: hostAddrs(ctx)}
	if err := json.MarshalWrite(out, ready); err != nil {
		_ = ln.Close()
		return err
	}
	_, _ = io.WriteString(out, "\n")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.InfoContext(ctx, "edge.stopped", "refused", e.Refused(), "credentials_stripped", e.Stripped())
	return nil
}

// Main is `pantherclaw-edge --config FILE`. The ready line and the log (a
// record of every request it forwards or refuses, and of every credential
// it strips) go to stdout as JSON lines, which pclaw collects from outside
// the sandbox; errors go to stderr.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pantherclaw-edge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "the edge configuration file ("+ConfigFormat+")")
	if err := fs.Parse(args); err != nil || *config == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: pantherclaw-edge --config FILE   (inside a sandbox's edge container; started by pclaw sandbox run)")
		return 2
	}
	c, err := ReadConfig(*config)
	if err == nil {
		err = Run(ctx, c, stdout, pclog.New(stdout, pclog.Options{Service: "pantherclaw-edge", Version: version.Get().Version}))
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-edge: %v\n", err)
		return 1
	}
	return 0
}

// hostAddrs resolves host.docker.internal; none on an engine without it.
func hostAddrs(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, "host.docker.internal")
	if err != nil {
		return []string{}
	}
	return addrs
}
