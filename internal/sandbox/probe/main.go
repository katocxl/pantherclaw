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
	// report.KindControl (the canary probes, on an open network).
	Kind string `json:"kind"`
	// KeyFile is the session's probe key, mounted read-only.
	KeyFile string `json:"key_file"`
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
	case c.KeyFile == "" || len(c.Canary.Addrs) == 0:
		return Config{}, errors.New("probe: key_file and the canary are required")
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

// Probe runs the probes and returns the signed report. It runs only in a
// sandbox's Linux containers: anywhere else its results would mean nothing.
func Probe(ctx context.Context, c Config) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("probe: runs only inside a sandbox's Linux probe container")
	}
	kf, err := workloadclient.ReadKeyFile(c.KeyFile)
	if err != nil {
		return "", err
	}
	key, err := kf.Key()
	if err != nil {
		return "", err
	}
	r := c.Report
	r.Format, r.Kind, r.StartedAt = report.Format, c.Kind, time.Now().UTC()
	r.Results = Run(ctx, c)
	r.FinishedAt = time.Now().UTC()
	r.Canary = report.Canary{Hits: []report.Hit{}}
	return report.Sign(key, r)
}

// Main is `pantherclaw-probe --config FILE`: the signed report goes to
// stdout, which pclaw reads from outside the sandbox; errors go to stderr.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pantherclaw-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	config := fs.String("config", "", "the probe configuration file ("+ConfigFormat+")")
	if err := fs.Parse(args); err != nil || *config == "" || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: pantherclaw-probe --config FILE   (inside a sandbox's probe container; started by pclaw sandbox run)")
		return 2
	}
	c, err := ReadConfig(*config)
	var signed string
	if err == nil {
		signed, err = Probe(ctx, c)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-probe: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, signed)
	return 0
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
