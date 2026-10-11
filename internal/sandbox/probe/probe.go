// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package probe is the containment sandbox's closure probe catalogue, run
// as `pantherclaw-probe` in a container of its own on the agent's network,
// as another uid, with NET_RAW and the other hardened flags (G0 M9 decision
// 2, design decisions 5 and 8; HR-121). It tries every route out the agent
// could try and signs what it saw with the session's probe key, which pclaw
// created outside every container and mounted read-only here (HR-215).
//
// Probes contact only the canary, the host's own addresses and the mapped
// hosts' real addresses (resolved on the host), never another third party.
// Every probe aimed at the canary carries the run's marker, so that the
// canary report shows whether anything left. A control run on an open
// network aims the same probes at the canary and must reach it.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// dialTimeout bounds each attempt.
const dialTimeout = 3 * time.Second

// Target is the canary as a container reaches it.
type Target struct {
	// Addrs are its addresses: IPs, resolved by pclaw on the host.
	Addrs []string `json:"addrs"`
	DNS   int      `json:"dns"`
	HTTPS int      `json:"https"`
	SSH   int      `json:"ssh"`
}

// probe is one entry of the catalogue.
type probe struct {
	name, role, expect, target string
	run                        func(ctx context.Context) error
}

// Run runs the catalogue for c and returns its results in catalogue order.
func Run(ctx context.Context, c Config) []report.Result {
	ps := catalogue(c)
	out := make([]report.Result, len(ps))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, p := range ps {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 2*dialTimeout)
			defer cancel()
			r := report.Result{Name: p.name, Role: p.role, Expect: p.expect, Observed: report.Reachable, Detail: bounded(p.target)}
			if err := p.run(pctx); err != nil {
				r.Observed, r.Detail = report.Blocked, bounded(p.target+": "+err.Error())
			}
			out[i] = r
		})
	}
	wg.Wait()
	return out
}

func bounded(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) > report.MaxDetail {
		return strings.ToValidUTF8(s[:report.MaxDetail], "")
	}
	return s
}

func catalogue(c Config) []probe {
	if c.Kind == report.KindControl {
		return canaryProbes(c, "canary_control", report.RolePositive, report.Reachable)
	}
	var ps []probe
	blocked := func(name, target string, f func(context.Context) error) {
		ps = append(ps, probe{name, report.RoleProbe, report.Blocked, target, f})
	}
	tcp := func(name string, addrs ...string) {
		for _, a := range addrs {
			blocked(name, a, func(ctx context.Context) error { return dialTCP(ctx, "tcp", a) })
		}
	}
	marker := report.Marker(c.Report.Nonce)
	mapped := func(port string) []string {
		var out []string
		for _, a := range c.MappedAddrs {
			out = append(out, net.JoinHostPort(a, port))
		}
		return out
	}

	// Docker's resolver forwards no external name for a container that is
	// only on internal networks (CVE-2024-29018): the agent hosts and the
	// marker's name must not resolve through it.
	for _, h := range append(append([]string{}, c.AgentHosts...), marker+".canary.invalid") {
		blocked("dns_docker_resolver", "127.0.0.11 "+h, lookup("127.0.0.11:53", "udp", h))
	}
	// Every probe aimed at the canary: DNS (UDP and TCP), HTTPS, SSH, a
	// push with a planted token and key, ICMP.
	ps = append(ps, canaryProbes(c, "", report.RoleProbe, report.Blocked)...)
	for _, h := range c.HostAddrs {
		blocked("dns_external", "udp "+h+":53", lookup(net.JoinHostPort(h, "53"), "udp", marker+".canary.invalid"))
	}
	tcp("direct_https", mapped("443")...)
	tcp("direct_ssh", mapped("22")...)
	for _, a := range mapped("22") {
		blocked("ssh_push", a, func(ctx context.Context) error { return sendLine(ctx, a, "SSH-2.0-pantherclaw-probe "+marker) })
	}
	blocked("ipv6", "[2001:db8::1]:443", func(ctx context.Context) error { return dialTCP(ctx, "tcp6", "[2001:db8::1]:443") })
	for _, a := range c.MappedAddrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			blocked("ipv6", a, func(ctx context.Context) error { return dialTCP(ctx, "tcp6", net.JoinHostPort(a, "443")) })
		}
	}
	blocked("icmp", "ping socket", func(context.Context) error { return pingSocket() })
	for _, a := range append(append([]string{}, c.MappedAddrs...), c.HostAddrs...) {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			blocked("icmp", "echo "+a, func(ctx context.Context) error { return icmpEcho(ctx, ip.To4()) })
		}
	}
	tcp("metadata", "169.254.169.254:80", "[fd00:ec2::254]:80")
	// The host: this network's bridge address, host.docker.internal and the
	// host's own addresses, on the ports its services use.
	var hosts []string
	ports := append([]int{80, 443}, c.HostPorts...)
	for _, p := range ports {
		port := strconv.Itoa(p)
		hosts = append(hosts, net.JoinHostPort("host.docker.internal", port))
		if gw := bridgeGateway(); gw != "" {
			hosts = append(hosts, net.JoinHostPort(gw, port))
		}
		for _, h := range c.HostAddrs {
			hosts = append(hosts, net.JoinHostPort(h, port))
		}
	}
	tcp("host_gateway", hosts...)
	blocked("docker_socket", "/var/run/docker.sock, /run/docker.sock", func(context.Context) error {
		for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
			if _, err := os.Stat(p); err == nil {
				return nil
			}
		}
		return errors.New("no socket")
	})
	var daemons []string
	for _, h := range append([]string{bridgeGateway()}, c.HostAddrs...) {
		if h != "" {
			daemons = append(daemons, net.JoinHostPort(h, "2375"), net.JoinHostPort(h, "2376"))
		}
	}
	tcp("docker_socket", daemons...)

	// Through the edge: a push to github.com with the planted token is an
	// unmapped CONNECT; so is any other host (negative control). A mapped
	// request reaches the gateway, which answers with its decision
	// (positive control): an unknown route, so nothing is authorized.
	proxy := &url.URL{Scheme: "http", Host: c.Edge}
	pat := map[string]string{"Authorization": "Basic " + plantedPAT(marker), "Content-Type": "application/x-git-receive-pack-request"}
	blocked("pat_push", "via the edge https://github.com/", viaEdge(proxy, nil, http.MethodPost, "https://github.com/pantherclaw-probe/canary.git/git-receive-pack", pat))
	ps = append(ps,
		probe{
			"edge_unmapped_refused", report.RoleNegative, report.Blocked, "CONNECT unmapped.invalid:443",
			viaEdge(proxy, nil, http.MethodGet, "https://unmapped.invalid/"+marker, nil),
		},
		probe{
			"edge_unmapped_refused", report.RoleNegative, report.Blocked, "GET http://unmapped.invalid/",
			viaEdge(proxy, nil, http.MethodGet, "http://unmapped.invalid/"+marker, nil),
		},
		probe{"edge_reachable", report.RolePositive, report.Reachable, c.Edge, func(ctx context.Context) error { return dialTCP(ctx, "tcp", c.Edge) }},
		probe{"dns_resolver_works", report.RolePositive, report.Reachable, "127.0.0.11 " + hostOf(c.Edge), lookup("127.0.0.11:53", "udp", hostOf(c.Edge))},
	)
	for _, h := range c.AgentHosts {
		ps = append(ps, probe{"edge_mediated", report.RolePositive, report.Reachable, "https://" + h + " through the edge", func(ctx context.Context) error {
			roots, err := caPool(c.CAFile)
			if err != nil {
				return err
			}
			return viaEdge(proxy, roots, http.MethodGet, "https://"+h+"/.well-known/pantherclaw-probe/"+marker, nil)(ctx)
		}})
	}
	return ps
}

// canaryProbes aims DNS (UDP and TCP), HTTPS, SSH and a planted-token push
// at every canary address, each carrying the run's marker.
func canaryProbes(c Config, name, role, expect string) []probe {
	marker := report.Marker(c.Report.Nonce)
	var ps []probe
	add := func(n, target string, f func(context.Context) error) {
		if name != "" {
			n = name
		}
		ps = append(ps, probe{n, role, expect, target, f})
	}
	for _, a := range c.Canary.Addrs {
		dns := net.JoinHostPort(a, strconv.Itoa(c.Canary.DNS))
		https := net.JoinHostPort(a, strconv.Itoa(c.Canary.HTTPS))
		ssh := net.JoinHostPort(a, strconv.Itoa(c.Canary.SSH))
		add("dns_external", "udp "+dns, sendDNS(dns, "udp", marker))
		add("dns_external", "tcp "+dns, sendDNS(dns, "tcp", marker))
		add("direct_https", https, func(ctx context.Context) error { return sendLine(ctx, https, "GET /"+marker+" HTTP/1.1") })
		add("direct_ssh", ssh, func(ctx context.Context) error { return sendLine(ctx, ssh, "SSH-2.0-pantherclaw-probe "+marker) })
		add("pat_push", "direct "+https, func(ctx context.Context) error {
			return sendLine(ctx, https, "POST /canary.git/git-receive-pack HTTP/1.1\r\nAuthorization: Basic "+plantedPAT(marker))
		})
	}
	return ps
}

// plantedPAT is the canary token the push probes carry: it names the
// marker, so any arrival is the run's.
func plantedPAT(marker string) string {
	return base64Std("x-access-token:ghp_" + marker)
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

func dialTCP(ctx context.Context, network, addr string) error {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// sendLine connects and writes one line: reachable when it was sent.
func sendLine(ctx context.Context, addr, line string) error {
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = io.WriteString(c, line+"\r\n\r\n")
	return err
}

// lookup resolves name with the resolver at server only.
func lookup(server, network, name string) func(context.Context) error {
	return func(ctx context.Context) error {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, network, server)
		}}
		addrs, err := r.LookupHost(ctx, name)
		if err == nil && len(addrs) == 0 {
			return errors.New("no address")
		}
		return err
	}
}

// sendDNS asks the canary for the marker's name: reachable when the query
// was sent (UDP has no reliable answer; the canary has the last word).
func sendDNS(server, network, marker string) func(context.Context) error {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: dialTimeout}
		c, err := d.DialContext(ctx, network, server)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		q := append([]byte{0x50, 0x43, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(marker))}, marker+"\x06canary\x07invalid\x00\x00\x01\x00\x01"...)
		if network == "tcp" {
			q = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...)
		}
		_, err = c.Write(q)
		return err
	}
}

// viaEdge sends a request through the edge. The edge's own refusal
// (PC-Refused-By) is blocked: nothing left the sandbox. Anything else is
// the gateway's answer.
func viaEdge(proxy *url.URL, roots *x509.CertPool, method, u string, hdr map[string]string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(""))
		if err != nil {
			return err
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		client := &http.Client{
			Transport:     &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		if res.Header.Get("PC-Refused-By") != "" {
			return fmt.Errorf("refused by the edge (%d)", res.StatusCode)
		}
		return nil
	}
}

func caPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the session CA mounted for the probe
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("no CA certificate")
	}
	return p, nil
}
