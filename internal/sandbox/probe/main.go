// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// ConfigFormat names the probe's configuration format.
const ConfigFormat = "pantherclaw.probe/v1"

// Config is what pclaw tells the probe container, as a read-only file
// mount. Addresses are as a container sees them.
type Config struct {
	Format string `json:"format"`
	// Kind is report.KindSandbox (the catalog, on the sandbox network) or
	// report.KindControl (its positive twins, on an open network).
	Kind string `json:"kind"`
	// KeyFile is the session's probe key, mounted read-only, with which a
	// sandbox run signs its report. A control run has none: it prints its
	// report unsigned and pclaw signs it with the session's host key, which
	// never enters a container (HR-215).
	KeyFile string `json:"key_file,omitzero"`
	// Report carries pclaw's facts into the signed report: the session, a
	// fresh server nonce (whose marker every canary probe carries), the
	// images, engine, network and configuration checks.
	Report report.Report `json:"report"`
	// Edge is the edge's host:port and CAFile its session CA (sandbox).
	Edge   string `json:"edge,omitzero"`
	CAFile string `json:"ca_file,omitzero"`
	// AgentHosts are the mapped hosts; MappedAddrs their real addresses,
	// resolved by pclaw on the host.
	AgentHosts  []string `json:"agent_hosts,omitzero"`
	MappedAddrs []string `json:"mapped_addrs,omitzero"`
	Canary      Target   `json:"canary"`
	// HostAddrs are the host's own addresses and HostPorts the ports of
	// its services (the gateway): only the edge may reach them.
	HostAddrs []string `json:"host_addrs,omitzero"`
	HostPorts []int    `json:"host_ports,omitzero"`
}

// ReadConfig reads a configuration file strictly.
func ReadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the sandbox's own configuration
	if err != nil {
		return Config{}, fmt.Errorf("probe: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, fmt.Errorf("probe: %s: %w", path, err)
	}
	switch {
	case c.Format != ConfigFormat:
		return Config{}, fmt.Errorf("probe: format %q, want %s", c.Format, ConfigFormat)
	case c.Kind != report.KindSandbox && c.Kind != report.KindControl:
		return Config{}, fmt.Errorf("probe: kind %q", c.Kind)
	case len(c.Canary.Addrs) == 0:
		return Config{}, errors.New("probe: the canary is required")
	case (c.Kind == report.KindSandbox) != (c.KeyFile != ""):
		return Config{}, errors.New("probe: a sandbox run has the probe key and a control run none")
	case c.Kind == report.KindSandbox && (c.Edge == "" || c.CAFile == "" || len(c.AgentHosts) == 0):
		return Config{}, errors.New("probe: a sandbox run needs the edge, its CA and the agent hosts")
	}
	for _, a := range append(append(append([]string{}, c.Canary.Addrs...), c.MappedAddrs...), c.HostAddrs...) {
		if _, err := netip.ParseAddr(a); err != nil {
			return Config{}, fmt.Errorf("probe: %q is not an IP address", a)
		}
	}
	return c, nil
}

// Probe runs the probes and returns their report. It runs only in a
// sandbox's Linux containers: anywhere else its results would mean nothing.
func Probe(ctx context.Context, c Config) (report.Report, error) {
	if runtime.GOOS != "linux" {
		return report.Report{}, errors.New("probe: runs only inside a sandbox's Linux probe container")
	}
	r := c.Report
	r.Format, r.Kind, r.StartedAt = report.Format, c.Kind, time.Now().UTC()
	r.Results = Run(ctx, c)
	r.FinishedAt = time.Now().UTC()
	r.Canary = report.Canary{Hits: []report.Hit{}}
	return r, nil
}

// Main is `pantherclaw-probe --config FILE`: the report goes to stdout,
// which pclaw reads from outside the sandbox, signed with the probe key
// for a sandbox run and as one JSON line for a control run; errors go to
// stderr.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pantherclaw-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "the probe configuration file ("+ConfigFormat+")")
	if err := fs.Parse(args); err != nil || *config == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: pantherclaw-probe --config FILE   (inside a sandbox's probe container; started by pclaw sandbox run)")
		return 2
	}
	c, err := ReadConfig(*config)
	var out string
	if err == nil {
		out, err = run(ctx, c)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-probe: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, out)
	return 0
}

// run probes and renders the report: signed, or unsigned JSON for pclaw
// to sign.
func run(ctx context.Context, c Config) (string, error) {
	r, err := Probe(ctx, c)
	if err != nil {
		return "", err
	}
	if c.KeyFile == "" {
		b, err := json.Marshal(r)
		return string(b), err
	}
	kf, err := workloadclient.ReadKeyFile(c.KeyFile)
	if err != nil {
		return "", err
	}
	key, err := kf.Key()
	if err != nil {
		return "", err
	}
	return report.Sign(key, r)
}

// bridgeGateway is the first address of the container's IPv4 network,
// where a bridge in NAT mode has its address: on an isolated network
// nothing answers there.
func bridgeGateway() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		p, err := netip.ParsePrefix(n.String())
		if err != nil || !p.Addr().Is4() || p.Addr().IsLoopback() {
			continue
		}
		return p.Masked().Addr().Next().String()
	}
	return ""
}

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
