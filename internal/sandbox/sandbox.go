// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sandbox assembles one containment sandbox on the local Docker
// engine (G0 M9 decisions 1 and 2): an internal network in isolated gateway
// mode, an uplink bridge, and the edge on both (internal/sandbox/edge), the
// agent's only route. Probe proves the sandbox closed. The probe container
// runs the catalogue on the internal network (internal/sandbox/probe) and a
// control run on the uplink aims at the canary, which pclaw runs on the host
// (internal/sim/canary). Each signs its report with the session's probe key
// (internal/sandbox/report), which pclaw created outside every container;
// the server verifies them (B4). Everything here runs outside the sandbox.
package sandbox

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sim/canary"
)

// Paths inside the sandbox's own containers, and their users: a distinct
// non-root uid per role (G0 M9 design decision 8).
const (
	configPath = "/pc/config.json"
	keyPath    = "/pc/key/key.json"
	tokenDir   = "/pc/token"
	caPath     = "/pc/ca/ca.pem"
	edgePort   = "3128"
	EdgeUser   = "65530:65530"
	ProbeUser  = "65531:65531"
	probeGID   = 65531
)

// Timeouts.
const (
	readyTimeout = time.Minute
	probeTimeout = 3 * time.Minute
	seenTimeout  = 5 * time.Second
)

// Options describe one sandbox.
type Options struct {
	// Session is the server's sandbox session id, the label on everything
	// this sandbox creates.
	Session string
	// EdgeImage and ProbeImage are the sandbox's images (by digest or local
	// id, task sandbox:images); AgentImage is recorded (B5 runs the agent).
	EdgeImage, ProbeImage, AgentImage string
	// GatewayURL is the gateway's public URL; GatewayAddr the address the
	// edge dials for it; GatewayCAPin pins an HTTPS gateway's CA.
	GatewayURL, GatewayAddr, GatewayCAPin string
	// Hosts maps each agent host to its connection; MappedAddrs are the
	// hosts' real addresses, resolved on this host, which the probes try.
	Hosts       map[string]string
	MappedAddrs []string
	Run         string
	// KeyFile is the sandbox instance's workload key file and TokenFile its
	// token file, renewed outside; only the edge mounts them. Both must be
	// readable by EdgeUser.
	KeyFile, TokenFile string
	// ProbeKey is the session's probe key, created outside every container.
	ProbeKey ed25519.PrivateKey
	// Canary is running on this host on CanaryPorts.
	Canary      *canary.Canary
	CanaryPorts canary.Ports
	// HostPorts are the ports of the host's services (the gateway's), which
	// only the edge may reach.
	HostPorts []int
	// Dir is a private directory (0700) for the files the containers mount;
	// Docker must be able to share it.
	Dir string
}

// Sandbox is a running sandbox: its networks and edge.
type Sandbox struct {
	c       *docker.Client
	engine  docker.Engine
	o       Options
	runtime string
	labels  map[string]string

	// Internal and Uplink are the networks; Edge is the edge container and
	// EdgeAddr its proxy address on Internal.
	Internal, Uplink, Edge, EdgeAddr string
	// CAFile is the session CA certificate on this host, CASHA256 its
	// fingerprint.
	CAFile, CASHA256 string
	// HostAddrs are the host's addresses as containers see them; the
	// canary listens there.
	HostAddrs []string

	containers, networks []string
	base                 report.Report
}

// Start creates the networks and the edge and waits until the edge is
// ready. Close removes everything, also after a failed Start.
func Start(ctx context.Context, c *docker.Client, e docker.Engine, o Options) (*Sandbox, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if len(o.ProbeKey) != ed25519.PrivateKeySize || o.Canary == nil || len(o.Hosts) == 0 {
		return nil, errors.New("sandbox: a probe key, the canary and agent hosts are required")
	}
	id := strings.ToLower(o.Session)
	s := &Sandbox{
		c: c, engine: e, o: o, runtime: e.Runtime(), labels: map[string]string{docker.LabelSession: id},
		Internal: "pc-sbx-" + short(id), Uplink: "pc-up-" + short(id), Edge: "pc-edge-" + short(id),
	}
	s.EdgeAddr = s.Edge + ":" + edgePort
	return s, s.start(ctx)
}

// short is the part of a session id in names: its last 16 hex digits.
func short(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	return id[max(0, len(id)-16):]
}

func (s *Sandbox) start(ctx context.Context) error {
	var internal docker.NetworkInfo
	for _, n := range []docker.Network{{Name: s.Internal, Internal: true, Labels: s.labels}, {Name: s.Uplink, Labels: s.labels}} {
		info, err := s.c.CreateNetwork(ctx, n)
		if err != nil {
			return err
		}
		s.networks = append(s.networks, n.Name)
		if n.Internal {
			internal = info
		}
	}
	cfg := edge.Config{
		Format: edge.ConfigFormat, Mode: edge.ModeSandbox, Session: s.o.Session, Listen: ":" + edgePort,
		GatewayURL: s.o.GatewayURL, GatewayAddr: s.o.GatewayAddr, GatewayCAPin: s.o.GatewayCAPin, Hosts: s.o.Hosts, Run: s.o.Run,
		KeyFile: keyPath, TokenFile: tokenDir + "/" + filepath.Base(s.o.TokenFile),
	}
	path, err := s.writeJSON("edge.json", cfg)
	if err != nil {
		return err
	}
	info, err := s.container(ctx, docker.Container{
		Name: s.Edge, Image: s.o.EdgeImage, User: EdgeUser, Args: []string{"--config", configPath},
		Networks: []string{s.Internal, s.Uplink},
		Mounts: []docker.Mount{
			{Kind: docker.Bind, Source: path, Target: configPath},
			{Kind: docker.Bind, Source: s.o.KeyFile, Target: keyPath},
			{Kind: docker.Bind, Source: filepath.Dir(s.o.TokenFile), Target: tokenDir},
		},
		Limits: docker.Limits{PIDs: 128, MemoryMiB: 256, MilliCPUs: 1000},
	})
	if err != nil {
		return err
	}
	if err := s.c.Start(ctx, s.Edge); err != nil {
		return err
	}
	ready, err := s.waitReady(ctx)
	if err != nil {
		return err
	}
	s.CASHA256 = "sha256:" + ready.CASHA256
	if s.CAFile, err = s.write("ca.pem", []byte(ready.CAPEM)); err != nil {
		return err
	}
	for _, a := range ready.HostAddrs {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
			s.HostAddrs = append(s.HostAddrs, ip.String())
		}
	}
	if len(s.HostAddrs) == 0 {
		return errors.New("sandbox: the engine has no host.docker.internal; the canary cannot be placed")
	}
	digest, err := s.configDigest()
	if err != nil {
		return err
	}
	s.base = report.Report{
		Format: report.Format, Session: s.o.Session,
		Images: report.Images{Agent: s.o.AgentImage, Edge: digestOf(s.o.EdgeImage), Probe: digestOf(s.o.ProbeImage)},
		Engine: engine(s.engine.Evidence(info.Runtime())),
		Network: report.Network{
			Name: internal.Name, Internal: internal.Internal, GatewayModeIPv4: internal.Options["com.docker.network.bridge.gateway_mode_ipv4"],
			IPv6: internal.EnableIPv6,
		},
		Config: report.Config{Digest: digest, Checks: checks()},
	}
	return nil
}

func engine(ev docker.Evidence) report.Engine {
	return report.Engine{Version: ev.Version, APIVersion: ev.APIVersion, Runtime: ev.Runtime, Desktop: ev.Desktop}
}

// digestOf is the sha256 digest of an image reference.
func digestOf(image string) string {
	if i := strings.LastIndex(image, "@"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// checks are the configuration checks pclaw made with docker inspect: the
// isolation self-check, which every network and container passed or was
// removed (HR-218), so each holds.
func checks() []report.Check {
	var out []report.Check
	for _, id := range []string{
		"network_internal", "network_isolated_gateway", "network_ipv6_off", "read_only_root", "capabilities_dropped",
		"no_new_privileges", "seccomp_builtin", "non_root_user", "no_docker_socket", "no_host_namespaces", "runtime_named",
		"limits_set", "no_icmp_sockets", "no_ip_forwarding",
	} {
		out = append(out, report.Check{ID: id, OK: true})
	}
	return out
}

// configDigest is the digest of what makes this sandbox's configuration,
// not of what changes per session: the agent hosts, the gateway, the
// images and the runtime. A session with another digest than the agent's
// last closure invalidates it (sandbox_config).
func (s *Sandbox) configDigest() (string, error) {
	b, err := json.Marshal(map[string]any{
		"hosts": s.o.Hosts, "gateway_url": s.o.GatewayURL, "runtime": s.runtime,
		"images": []string{s.o.AgentImage, s.o.EdgeImage, s.o.ProbeImage},
	})
	if err != nil {
		return "", err
	}
	v := jsontext.Value(b)
	if err := v.Canonicalize(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(v)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// container creates a hardened container with the sandbox's runtime and
// labels.
func (s *Sandbox) container(ctx context.Context, ct docker.Container) (docker.ContainerInfo, error) {
	ct.Runtime, ct.Labels = s.runtime, s.labels
	info, err := s.c.CreateContainer(ctx, ct)
	if err == nil {
		s.containers = append(s.containers, ct.Name)
	}
	return info, err
}

// write writes a file the containers mount into the private directory.
func (s *Sandbox) write(name string, b []byte) (string, error) {
	path := filepath.Join(s.o.Dir, short(s.o.Session)+"-"+name)
	// Read by the container's uid; the directory is private.
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // G306: see above
		return "", err
	}
	return path, nil
}

func (s *Sandbox) writeJSON(name string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return s.write(name, b)
}

// waitReady waits for the edge's ready line.
func (s *Sandbox) waitReady(ctx context.Context) (edge.Ready, error) {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if out, err := s.c.Logs(ctx, s.Edge); err == nil {
			for line := range strings.Lines(string(out)) {
				var r edge.Ready
				if json.Unmarshal([]byte(line), &r) == nil && r.Event == edge.ReadyEvent && r.CAPEM != "" {
					return r, nil
				}
			}
		}
		if info, err := s.c.InspectContainer(ctx, s.Edge); err == nil && info.State.Status == "exited" {
			return edge.Ready{}, fmt.Errorf("sandbox: the edge exited with code %d before it was ready", info.State.ExitCode)
		}
		select {
		case <-ctx.Done():
			return edge.Ready{}, fmt.Errorf("sandbox: the edge was not ready within %s", readyTimeout)
		case <-tick.C:
		}
	}
}

// Nonces are fresh single-use server nonces, one per report.
type Nonces struct {
	Sandbox, Control, Canary string
}

// Evidence is one probe run: the three signed reports, which the server
// verifies, and the results as pclaw reads them (the server computes its
// own).
type Evidence struct {
	Sandbox, Control, Canary string
	Results                  []report.Result
}

// Passed reports whether every result is as expected.
func (ev Evidence) Passed() bool {
	if len(ev.Results) == 0 {
		return false
	}
	for _, r := range ev.Results {
		if !r.Passed() {
			return false
		}
	}
	return true
}

// Probe runs the catalogue on the internal network and the control on the
// uplink, then signs the canary's report of both markers.
func (s *Sandbox) Probe(ctx context.Context, n Nonces) (Evidence, error) {
	pub, _ := s.o.ProbeKey.Public().(ed25519.PublicKey)
	keyFile, err := s.writeJSON("probe-key.json", map[string]string{"private_key": base64.RawURLEncoding.EncodeToString(s.o.ProbeKey.Seed())})
	if err != nil {
		return Evidence{}, err
	}
	ca := probe.Target{Addrs: s.HostAddrs, DNS: s.o.CanaryPorts.DNS, HTTPS: s.o.CanaryPorts.HTTPS, SSH: s.o.CanaryPorts.SSH}
	cfg := probe.Config{
		Format: probe.ConfigFormat, Kind: report.KindSandbox, KeyFile: keyPath, Report: s.base, Edge: s.EdgeAddr, CAFile: caPath,
		AgentHosts: slices.Sorted(maps.Keys(s.o.Hosts)), MappedAddrs: s.o.MappedAddrs, Canary: ca, HostAddrs: s.HostAddrs, HostPorts: s.o.HostPorts,
	}
	cfg.Report.Nonce = n.Sandbox
	var ev Evidence
	if ev.Sandbox, err = s.probe(ctx, "probe", s.Internal, cfg, keyFile, true); err != nil {
		return Evidence{}, err
	}
	sandbox, err := report.Verify(ev.Sandbox, pub)
	if err != nil {
		return Evidence{}, err
	}
	control := probe.Config{Format: probe.ConfigFormat, Kind: report.KindControl, KeyFile: keyPath, Report: s.base, Canary: ca}
	control.Report.Nonce = n.Control
	if ev.Control, err = s.probe(ctx, "control", s.Uplink, control, keyFile, false); err != nil {
		return Evidence{}, err
	}
	pm, cm := report.Marker(n.Sandbox), report.Marker(n.Control)
	s.waitHits(ctx, cm)
	base := s.base
	base.Nonce, base.StartedAt, base.FinishedAt = n.Canary, sandbox.StartedAt, time.Now().UTC()
	if ev.Canary, err = s.o.Canary.Report(s.o.ProbeKey, base, pm, cm); err != nil {
		return Evidence{}, err
	}
	ev.Results = append(sandbox.Results,
		report.Result{Name: "external_canary", Role: report.RoleCanary, Expect: report.Blocked, Observed: observed(len(s.o.Canary.Hits(pm)) > 0)},
		report.Result{Name: "canary_control", Role: report.RolePositive, Expect: report.Reachable, Observed: observed(len(s.o.Canary.Hits(cm)) > 0)},
	)
	return ev, nil
}

func observed(reached bool) string {
	if reached {
		return report.Reachable
	}
	return report.Blocked
}

// waitHits waits briefly for the control marker to reach the canary.
func (s *Sandbox) waitHits(ctx context.Context, marker string) {
	ctx, cancel := context.WithTimeout(ctx, seenTimeout)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for len(s.o.Canary.Hits(marker)) == 0 {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// probe runs one probe container to completion and returns its signed
// report.
func (s *Sandbox) probe(ctx context.Context, kind, network string, cfg probe.Config, keyFile string, sandbox bool) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	path, err := s.writeJSON(kind+".json", cfg)
	if err != nil {
		return "", err
	}
	name := "pc-" + kind + "-" + short(s.o.Session)
	mounts := []docker.Mount{{Kind: docker.Bind, Source: path, Target: configPath}, {Kind: docker.Bind, Source: keyFile, Target: keyPath}}
	if sandbox {
		mounts = append(mounts, docker.Mount{Kind: docker.Bind, Source: s.CAFile, Target: caPath})
	}
	if _, err := s.container(ctx, docker.Container{
		Name: name, Image: s.o.ProbeImage, User: ProbeUser, Args: []string{"--config", configPath}, Networks: []string{network},
		Mounts: mounts, PingGID: probeGID, Limits: docker.Limits{PIDs: 128, MemoryMiB: 256, MilliCPUs: 1000},
	}); err != nil {
		return "", err
	}
	if err := s.c.Start(ctx, name); err != nil {
		return "", err
	}
	code, err := s.c.Wait(ctx, name)
	if err != nil {
		return "", err
	}
	out, err := s.c.Logs(ctx, name)
	if err != nil {
		return "", err
	}
	signed := strings.TrimSpace(string(out))
	if code != 0 || signed == "" || strings.ContainsAny(signed, " \n") {
		return "", fmt.Errorf("sandbox: the %s container exited %d without a report", kind, code)
	}
	return signed, nil
}

// Close removes everything this sandbox created, by its label, and its
// files.
func (s *Sandbox) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	ctx = context.WithoutCancel(ctx)
	errs := []error{s.c.RemoveLabelled(ctx, s.labels[docker.LabelSession])}
	matches, _ := filepath.Glob(filepath.Join(s.o.Dir, short(s.o.Session)+"-*"))
	for _, m := range matches {
		errs = append(errs, os.Remove(m))
	}
	return errors.Join(errs...)
}
