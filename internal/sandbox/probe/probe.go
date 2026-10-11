// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package probe is the containment sandbox's closure probe catalog, run
// as `pantherclaw-probe` in a container of its own on the agent's network,
// as another uid, with the hardened flags and its own group allowed to
// ping (G0 M9 decision 2, design decisions 5 and 8; HR-121). It tries every
// route out the agent could try and signs what it saw with the session's
// probe key, which pclaw created outside every container and mounted
// read-only here (HR-215).
//
// Probes contact only the canary, the host's own addresses and the mapped
// hosts' real addresses (resolved on the host), never another third party.
// Every probe aimed at the canary carries the run's marker, so that the
// canary report shows whether anything left. A control run on an open
// network runs each probe again where it has a live target, as a positive
// twin that must reach it: a probe that cannot see an open route proves
// nothing about a closed one.
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
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// probe is one entry of the catalog.
type probe struct {
	name, role, expect, target string
	run                        func(ctx context.Context) error
}

// closed is a probe's own finding that its route is closed: the edge
// refused, a name did not resolve, no echo reply came.
type closed struct{ why string }

func (c closed) Error() string { return c.why }

// failed is a probe that could not run (no ICMP socket, no CA file): its
// result is an error, which never passes.
type failed struct{ err error }

func (f failed) Error() string { return f.err.Error() }
func (f failed) Unwrap() error { return f.err }

// observe is what a probe saw (HR-121). Anything that answered is
// reachable: a connection, a reset, an ICMP port unreachable, any DNS
// answer. Only silence is blocked: a timeout, no route, a name that does
// not resolve, the probe's own finding. A probe that failed to run, or an
// error nothing explains, is an error, which never passes.
func observe(err error) string {
	var c closed
	var f failed
	var dns *net.DNSError
	var ne net.Error
	switch {
	case err == nil:
		return report.Reachable
	case errors.As(err, &f):
		return report.Error
	case errors.As(err, &c):
		return report.Blocked
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ECONNRESET):
		return report.Reachable
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.EADDRNOTAVAIL),
		errors.Is(err, syscall.EAFNOSUPPORT):
		return report.Blocked
	case errors.As(err, &dns):
		return report.Blocked
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return report.Blocked
	}
	return report.Error
}

// Run runs the catalog for c and returns its results in catalog order.
func Run(ctx context.Context, c Config) []report.Result {
	ps := catalog(c)
	out := make([]report.Result, len(ps))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, p := range ps {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 2*dialTimeout)
			defer cancel()
			err := p.run(pctx)
			r := report.Result{Name: p.name, Role: p.role, Expect: p.expect, Observed: observe(err), Detail: bounded(p.target)}
			if err != nil {
				r.Detail = bounded(p.target + ": " + err.Error())
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

func catalog(c Config) []probe {
	if c.Kind == report.KindControl {
		return twins(c)
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
		blocked("dns_docker_resolver", "127.0.0.11 "+h, resolves("127.0.0.11:53", h))
	}
	// Every probe aimed at the canary: DNS (UDP and TCP), HTTPS, SSH, a
	// push with a planted token and key, ICMP.
	ps = append(ps, canaryProbes(c, report.RoleProbe, report.Blocked)...)
	for _, h := range c.HostAddrs {
		blocked("dns_external", "udp "+h+":53", answers(net.JoinHostPort(h, "53"), "udp", marker))
	}
	tcp("direct_https", mapped("443")...)
	tcp("direct_ssh", mapped("22")...)
	for _, a := range mapped("22") {
		blocked("ssh_push", a, func(ctx context.Context) error { return sendLine(ctx, a, "SSH-2.0-pantherclaw-probe "+marker) })
	}
	blocked("ipv6", "an IPv6 address or default route", func(context.Context) error { return ipv6Route() })
	for _, a := range c.MappedAddrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			blocked("ipv6", a, func(ctx context.Context) error { return dialTCP(ctx, "tcp6", net.JoinHostPort(a, "443")) })
		}
	}
	for _, a := range append(append([]string{}, c.MappedAddrs...), c.HostAddrs...) {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			blocked("icmp", "echo "+a, func(ctx context.Context) error { return icmpEcho(ctx, ip.To4()) })
		}
	}
	tcp("metadata", "169.254.169.254:80", "[fd00:ec2::254]:80")
	// The host: this network's bridge address (none in isolated gateway
	// mode), host.docker.internal and the host's own addresses, on the
	// ports its services use.
	var hosts []string
	ports := append([]int{80, 443}, c.HostPorts...)
	for _, p := range ports {
		port := strconv.Itoa(p)
		hosts = append(hosts, net.JoinHostPort("host.docker.internal", port))
		if gw := c.BridgeGateway; gw != "" {
			hosts = append(hosts, net.JoinHostPort(gw, port))
		}
		for _, h := range c.HostAddrs {
			hosts = append(hosts, net.JoinHostPort(h, port))
		}
	}
	tcp("host_gateway", hosts...)
	// The engine's API over TCP. Whether the agent holds the engine's
	// socket is pclaw's configuration check (agent_no_docker_socket), from
	// its inspect of the agent's container: this container's own file
	// system says nothing about the agent's.
	var daemons []string
	for _, h := range append([]string{c.BridgeGateway}, c.HostAddrs...) {
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
		probe{"dns_resolver_works", report.RolePositive, report.Reachable, "127.0.0.11 " + hostOf(c.Edge), resolves("127.0.0.11:53", hostOf(c.Edge))},
	)
	for _, h := range c.AgentHosts {
		ps = append(ps, probe{"edge_mediated", report.RolePositive, report.Reachable, "https://" + h + " through the edge", func(ctx context.Context) error {
			roots, err := caPool(c.CAFile)
			if err != nil {
				return failed{err}
			}
			return viaEdge(proxy, roots, http.MethodGet, "https://"+h+"/.well-known/pantherclaw-probe/"+marker, nil)(ctx)
		}})
	}
	return ps
}

// twins is the control run's catalog: on an open network, each probe that
// has a live target there runs again under its own name as a positive
// control that must reach it (G0 M9 design decision 15). ipv6, metadata
// and docker_socket have none: no IPv6, metadata service or engine API is
// known to answer on the control network.
func twins(c Config) []probe {
	ps := canaryProbes(c, report.RolePositive, report.Reachable)
	add := func(name, target string, f func(context.Context) error) {
		ps = append(ps, probe{name, report.RolePositive, report.Reachable, target, f})
	}
	for _, a := range c.Canary.Addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			add("icmp", "echo "+a, func(ctx context.Context) error { return icmpEcho(ctx, ip.To4()) })
		}
	}
	hosts := c.HostAddrs
	if len(hosts) == 0 {
		hosts = []string{"host.docker.internal"}
	}
	for _, p := range c.HostPorts {
		for _, h := range hosts {
			a := net.JoinHostPort(h, strconv.Itoa(p))
			add("host_gateway", a, func(ctx context.Context) error { return dialTCP(ctx, "tcp", a) })
		}
	}
	// Docker's resolver forwards names on the open network: one of the
	// agent hosts, or host.docker.internal, resolves.
	names := append(slices.Clone(c.AgentHosts), "host.docker.internal")
	add("dns_docker_resolver", "127.0.0.11 "+strings.Join(names, " or "), func(ctx context.Context) error {
		var errs []error
		for _, n := range names {
			err := resolves("127.0.0.11:53", n)(ctx)
			if err == nil {
				return nil
			}
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	})
	return ps
}

// canaryProbes aims DNS (UDP and TCP), HTTPS, SSH and planted-token and
// planted-key pushes at every canary address, each carrying the run's
// marker.
func canaryProbes(c Config, role, expect string) []probe {
	marker := report.Marker(c.Report.Nonce)
	var ps []probe
	add := func(name, target string, f func(context.Context) error) {
		ps = append(ps, probe{name, role, expect, target, f})
	}
	for _, a := range c.Canary.Addrs {
		dns := net.JoinHostPort(a, strconv.Itoa(c.Canary.DNS))
		https := net.JoinHostPort(a, strconv.Itoa(c.Canary.HTTPS))
		ssh := net.JoinHostPort(a, strconv.Itoa(c.Canary.SSH))
		add("dns_external", "udp "+dns, sendDNS(dns, "udp", marker))
		add("dns_external", "tcp "+dns, sendDNS(dns, "tcp", marker))
		add("direct_https", https, func(ctx context.Context) error { return sendLine(ctx, https, "GET /"+marker+" HTTP/1.1") })
		add("direct_ssh", ssh, func(ctx context.Context) error { return sendLine(ctx, ssh, "SSH-2.0-pantherclaw-probe "+marker) })
		add("ssh_push", "push "+ssh, func(ctx context.Context) error {
			return sendLine(ctx, ssh, "SSH-2.0-pantherclaw-probe-push "+marker)
		})
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

// resolves asks the resolver at server for name: reachable when it gives
// an address, blocked when it gives none (whatever it answered) or never
// answers.
func resolves(server, name string) func(context.Context) error {
	return func(ctx context.Context) error {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, network, server)
		}}
		addrs, err := r.LookupHost(ctx, name)
		var dns *net.DNSError
		switch {
		case errors.As(err, &dns):
			return closed{"does not resolve: " + dns.Err}
		case err != nil:
			return err
		case len(addrs) == 0:
			return closed{"no address"}
		}
		return nil
	}
}

// answers sends a DNS query for the marker's name to server and waits for
// any answer: an answer, even NXDOMAIN or a refusal, is reachable.
func answers(server, network, marker string) func(context.Context) error {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: dialTimeout}
		c, err := d.DialContext(ctx, network, server)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		deadline := time.Now().Add(dialTimeout)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = c.SetDeadline(deadline)
		if _, err := c.Write(query(network, marker)); err != nil {
			return err
		}
		_, err = c.Read(make([]byte, 512))
		return err
	}
}

// sendDNS asks the canary for the marker's name: reachable when the query
// was sent (the canary does not answer; its hits have the last word).
func sendDNS(server, network, marker string) func(context.Context) error {
	return func(ctx context.Context) error {
		d := net.Dialer{Timeout: dialTimeout}
		c, err := d.DialContext(ctx, network, server)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write(query(network, marker))
		return err
	}
}

// query is a DNS query for <marker>.canary.invalid, framed for network.
func query(network, marker string) []byte {
	q := append([]byte{0x50, 0x43, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(marker))}, marker+"\x06canary\x07invalid\x00\x00\x01\x00\x01"...) //nolint:gosec // G115: a marker is 34 bytes, a DNS label at most 63
	if network == "tcp" {
		q = append([]byte{byte(len(q) >> 8), byte(len(q))}, q...) //nolint:gosec // G115: the query is under 100 bytes
	}
	return q
}

// ipv6Route finds IPv6 beyond the loopback: an address that is neither
// loopback nor link-local, or a default route on an interface.
func ipv6Route() error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return failed{err}
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err == nil && p.Addr().Is6() && !p.Addr().Is4In6() && !p.Addr().IsLoopback() && !p.Addr().IsLinkLocalUnicast() {
			return nil
		}
	}
	// destination, its prefix length, source, its prefix length, next hop,
	// metric, references, use, flags, device.
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		for line := range strings.Lines(string(b)) {
			if f := strings.Fields(line); len(f) == 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
				return nil
			}
		}
	}
	return closed{"no IPv6 address or default route"}
}

// viaEdge sends a request through the edge. The edge's own refusal
// (PC-Refused-By) is blocked: nothing left the sandbox. Anything else is
// the gateway's answer. An edge that cannot be reached is a failure, not a
// closed route.
func viaEdge(proxy *url.URL, roots *x509.CertPool, method, u string, hdr map[string]string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(""))
		if err != nil {
			return failed{err}
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
				// A refused CONNECT is no response to the request: its
				// answer is seen here.
				OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, res *http.Response) error {
					if res.StatusCode != http.StatusOK && res.Header.Get("PC-Refused-By") != "" {
						return closed{fmt.Sprintf("CONNECT refused by the edge (%d)", res.StatusCode)}
					}
					return nil
				},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		res, err := client.Do(req)
		var c closed
		if errors.As(err, &c) {
			return c
		} else if err != nil {
			return failed{err}
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		if res.Header.Get("PC-Refused-By") != "" {
			return closed{fmt.Sprintf("refused by the edge (%d)", res.StatusCode)}
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
