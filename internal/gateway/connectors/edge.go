// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
	"github.com/katocxl/pantherclaw/internal/sandbox/relay"
)

// Paths and users of a connector's edge.
const (
	edgeUser      = "65530:65530"
	edgePort      = "3128"
	edgeConfig    = "/pc/config.json"
	bindingDir    = "/pc/binding"
	caPath        = "/pc/ca/ca.pem"
	readyTimeout  = time.Minute
	readyInterval = 250 * time.Millisecond
	// edgeCAValidity is how long a connector edge's CA is valid; the
	// connector is replaced an hour before it ends.
	edgeCAValidity = 24 * time.Hour
)

// caEnv points the usual TLS clients at the edge's CA, the only root a
// connector with egress needs: its only route out is the edge.
var caEnv = []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}

// mediated is what a connector with an egress connection runs behind: an
// edge in connector mode on its internal network and an uplink, with the
// binding token only the edge mounts (G0 M9 design decisions 4 and 6).
type mediated struct {
	dir, binding string
	// renew is when the edge's CA nears its end.
	renew time.Time
	// relay is the connector edge's path to the egress listener on a native
	// Linux engine (HR-228); closed with the connector.
	relay  *relay.Relay
	env    []string
	mounts []docker.Mount
}

// startEdge starts the edge of a connector with an egress connection and
// returns what the connector's container needs: the proxy and CA
// environment and the CA certificate's mount.
func (s *Supervisor) startEdge(ctx context.Context, id, short string, egressConn *control.Connection, internal string,
	labels map[string]string,
) (mediated, error) {
	if s.cfg.EdgeImage == "" || s.cfg.EgressListen == "" || (s.cfg.EgressAddr == "" && !s.engine.UsesRelay()) {
		return mediated{}, errors.New("connectors: a connector with egress needs connectors.edge_image, egress_listen and egress_addr")
	}
	dir, err := os.MkdirTemp("", "pc-connector-")
	if err != nil {
		return mediated{}, err
	}
	if dir, err = filepath.EvalSymlinks(dir); err != nil {
		return mediated{}, err
	}
	m := mediated{dir: dir}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return m, err
	}
	m.binding = hex.EncodeToString(b[:])
	if err := os.Mkdir(filepath.Join(dir, "binding"), 0o755); err != nil { //nolint:gosec // G301: read by the edge's uid; dir is private
		return m, err
	}
	if err := os.WriteFile(filepath.Join(dir, "binding", "binding"), []byte(m.binding), 0o644); err != nil { //nolint:gosec // G306: read by the edge's uid; dir is private
		return m, err
	}
	hosts, err := egressHosts(egressConn)
	if err != nil {
		return m, err
	}
	uplink := "pc-cup-" + short
	info, err := s.c.InspectNetwork(ctx, internal)
	if err != nil {
		return m, err
	}
	upInfo, err := s.c.CreateNetwork(ctx, docker.Network{Name: uplink, Labels: labels})
	if err != nil {
		return m, err
	}
	egressAddr := s.cfg.EgressAddr
	if s.engine.UsesRelay() {
		// A native Linux engine has no host.docker.internal and no container
		// may be given one (HR-228): the edge reaches the egress listener
		// through a relay on the host's address on its uplink network, which
		// takes this edge's connections only.
		if m.relay, err = s.openRelay(ctx, upInfo); err != nil {
			return m, err
		}
		egressAddr = m.relay.Addr()
	}
	cfg, err := json.Marshal(edge.Config{
		Format: edge.ConfigFormat, Mode: edge.ModeConnector, Session: id, Listen: ":" + edgePort, Subnet: info.Subnet(),
		GatewayURL: "http://" + egressAddr, Hosts: hosts, BindingFile: bindingDir + "/binding", Placeholder: Placeholder,
		CAValiditySeconds: int64(edgeCAValidity / time.Second),
	})
	if err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(dir, "edge.json"), cfg, 0o644); err != nil { //nolint:gosec // G306: read by the edge's uid; dir is private
		return m, err
	}
	name := "pc-cedge-" + short
	if _, err := s.c.CreateContainer(ctx, docker.Container{
		Name: name, Image: s.cfg.EdgeImage, User: edgeUser, Args: []string{"--config", edgeConfig}, Networks: []string{internal, uplink},
		Mounts: []docker.Mount{
			{Kind: docker.Bind, Source: filepath.Join(dir, "edge.json"), Target: edgeConfig},
			{Kind: docker.Bind, Source: filepath.Join(dir, "binding"), Target: bindingDir},
		},
		BindRoot: dir, Runtime: s.engine.Runtime(), Labels: labels, Limits: docker.Limits{PIDs: 128, MemoryMiB: 256, MilliCPUs: 1000},
	}); err != nil {
		return m, err
	}
	if err := s.c.Start(ctx, name); err != nil {
		return m, err
	}
	if m.relay != nil {
		if err := s.allowEdge(ctx, m.relay, name, uplink); err != nil {
			return m, err
		}
	}
	ready, err := s.waitReady(ctx, name)
	if err != nil {
		return m, err
	}
	m.renew = time.Now().Add(edgeCAValidity - time.Hour)
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte(ready.CAPEM), 0o644); err != nil { //nolint:gosec // G306: read by the connector's uid; dir is private
		return m, err
	}
	proxy := "http://" + name + ":" + edgePort
	m.env = []string{"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy, "HTTP_PROXY=" + proxy, "http_proxy=" + proxy, "NO_PROXY=", "no_proxy="}
	for _, v := range caEnv {
		m.env = append(m.env, v+"="+caPath)
	}
	m.mounts = []docker.Mount{{Kind: docker.Bind, Source: ca, Target: caPath}}
	return m, nil
}

// egressHosts are the host names a connector may reach through its egress
// connection, each mapped to it: the base URL's host unless it is an IP
// literal, which the edge never intercepts, and the agent hosts.
func egressHosts(conn *control.Connection) (map[string]string, error) {
	u, err := url.Parse(conn.GetBaseUrl())
	if err != nil || u.Hostname() == "" || conn.GetKind() != "http" {
		return nil, fmt.Errorf("connectors: the egress connection %s is not an http connection", conn.GetName())
	}
	hosts := map[string]string{}
	if h := strings.ToLower(u.Hostname()); net.ParseIP(h) == nil {
		hosts[h] = conn.GetName()
	}
	for _, h := range conn.GetAgentHosts() {
		hosts[h] = conn.GetName()
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("connectors: the egress connection %s names no host a connector can address", conn.GetName())
	}
	return hosts, nil
}

// waitReady waits for the edge's ready line.
func (s *Supervisor) waitReady(ctx context.Context, name string) (edge.Ready, error) {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	t := time.NewTicker(readyInterval)
	defer t.Stop()
	for {
		if out, err := s.c.Logs(ctx, name); err == nil {
			for line := range strings.Lines(string(out)) {
				var r edge.Ready
				if json.Unmarshal([]byte(line), &r) == nil && r.Event == edge.ReadyEvent && r.CAPEM != "" {
					return r, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return edge.Ready{}, fmt.Errorf("connectors: the edge %s was not ready within %s", name, readyTimeout)
		case <-t.C:
		}
	}
}

// cleanup removes the edge's directory and closes its relay, after a start
// that failed.
func (m mediated) cleanup() {
	if m.relay != nil {
		_ = m.relay.Close()
	}
	if m.dir != "" {
		_ = os.RemoveAll(m.dir)
	}
}

// openRelay opens the relay from the uplink network's gateway address to the
// egress listener (HR-228).
func (s *Supervisor) openRelay(ctx context.Context, uplink docker.NetworkInfo) (*relay.Relay, error) {
	if len(uplink.IPAM.Config) == 0 || uplink.IPAM.Config[0].Gateway == "" {
		return nil, errors.New("connectors: the uplink network has no gateway address")
	}
	return relay.Listen(ctx, uplink.IPAM.Config[0].Gateway, s.cfg.EgressListen, s.log)
}

// allowEdge names the started edge's address on its uplink network as the
// only source the relay takes.
func (s *Supervisor) allowEdge(ctx context.Context, r *relay.Relay, edge, uplink string) error {
	started, err := s.c.InspectContainer(ctx, edge)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(started.Address(uplink))
	if err != nil {
		return fmt.Errorf("connectors: the edge has no address on its uplink network: %w", err)
	}
	r.Allow(ip)
	return nil
}
