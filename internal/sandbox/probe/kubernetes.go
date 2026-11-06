// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// ProfileKubernetes is the probe's catalog for an agent pod in an enforced
// namespace (G0 M32 D970): `pantherclaw-probe --profile kubernetes`. It
// runs in a pod of its own with the edge as its native sidecar, reads what
// it probes from the environment, and POSTs its unsigned report to the
// edge's loopback-only /__pc/report, which adds the server nonce, signs it
// with the pod's attested workload key and submits it (D966). A control
// run, in the release namespace, runs the positive twins on its open
// network.
const ProfileKubernetes = "kubernetes"

// The environment of a kubernetes probe run (the chart's probe CronJobs,
// G0 M32 D969, D970a). KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
// are the ones the kubelet sets. PC_HOST_IP and PC_CANARY_IP are required;
// the others are optional, and what they leave empty in the report is the
// edge's to fill before it signs.
const (
	EnvHostIP     = "PC_HOST_IP"            // the node IP (downward API status.hostIP)
	EnvCanaryIP   = "PC_CANARY_IP"          // the pantherclaw-canary Service clusterIP
	EnvPodName    = "PC_POD_NAME"           // downward API metadata.name
	EnvNamespace  = "PC_NAMESPACE"          // downward API metadata.namespace
	EnvAgentHosts = "PC_AGENT_HOSTS"        // the edge's mapped hosts, comma-separated
	EnvEdgeImage  = "PC_EDGE_IMAGE_DIGEST"  // sha256:<hex>
	EnvProbeImage = "PC_PROBE_IMAGE_DIGEST" // sha256:<hex>
)

// The edge in the pod and the canary (G0 M32 D964, D966, D970a).
const (
	kubeEdge     = "127.0.0.1:3128"
	kubeCAFile   = "/pc-edge/ca.crt"
	kubeReport   = "http://" + kubeEdge + "/__pc/report"
	resolvConf   = "/etc/resolv.conf"
	canaryPort   = "8080"
	maxKubeReply = 64 << 10
)

// KubeConfig is a kubernetes probe run's configuration: its kind from
// `--kind` (sandbox by default, control for the twin in the release
// namespace), the rest from its environment.
type KubeConfig struct {
	Kind      string
	Pod       string
	Namespace string
	// APIServer is the cluster's API server, host:port.
	APIServer string
	HostIP    string
	// CanaryService is the canary Service's clusterIP:8080.
	CanaryService string
	// Nameservers are the pod's resolvers from resolv.conf.
	Nameservers []string
	AgentHosts  []string
	Images      report.Images
	Edge        string
	CAFile      string
}

// KubeConfigFromEnv reads a kubernetes run's configuration for kind. A
// sandbox run without agent hosts still runs: its edge_mediated control
// fails, which never passes.
func KubeConfigFromEnv(kind string, getenv func(string) string) (KubeConfig, error) {
	c := KubeConfig{
		Kind: kind, Pod: getenv(EnvPodName), Namespace: getenv(EnvNamespace), HostIP: getenv(EnvHostIP),
		Images: report.Images{Edge: getenv(EnvEdgeImage), Probe: getenv(EnvProbeImage)},
		Edge:   kubeEdge, CAFile: kubeCAFile,
	}
	if h, p := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT"); h != "" && p != "" {
		c.APIServer = net.JoinHostPort(h, p)
	}
	canary := getenv(EnvCanaryIP)
	if net.ParseIP(canary) != nil {
		c.CanaryService = net.JoinHostPort(canary, canaryPort)
	}
	for h := range strings.SplitSeq(getenv(EnvAgentHosts), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.AgentHosts = append(c.AgentHosts, h)
		}
	}
	switch {
	case c.Kind != report.KindSandbox && c.Kind != report.KindControl:
		return KubeConfig{}, fmt.Errorf("probe: --kind %q, want sandbox or control", c.Kind)
	case net.ParseIP(c.HostIP) == nil:
		return KubeConfig{}, fmt.Errorf("probe: %s %q is not an IP address", EnvHostIP, c.HostIP)
	case c.CanaryService == "":
		return KubeConfig{}, fmt.Errorf("probe: %s %q is not an IP address", EnvCanaryIP, canary)
	case c.APIServer == "":
		return KubeConfig{}, errors.New("probe: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT are not set")
	}
	return c, nil
}

// nameservers are resolv.conf's nameservers.
func nameservers(path string) []string {
	f, err := os.Open(path) //nolint:gosec // G304: the pod's own resolv.conf
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	s := bufio.NewScanner(io.LimitReader(f, 64<<10))
	for s.Scan() {
		if fs := strings.Fields(s.Text()); len(fs) >= 2 && fs[0] == "nameserver" && net.ParseIP(fs[1]) != nil {
			out = append(out, fs[1])
		}
	}
	return out
}

// kubeCatalog is the kubernetes profile's catalog: every route out of the
// pod but the edge, expected blocked, the edge's positive and negative
// controls, or for a control run their positive twins.
func kubeCatalog(c KubeConfig, marker string) []probe {
	role, expect := report.RoleProbe, report.Blocked
	if c.Kind == report.KindControl {
		role, expect = report.RolePositive, report.Reachable
	}
	var ps []probe
	add := func(name, target string, f func(context.Context) error) {
		ps = append(ps, probe{name, role, expect, target, f})
	}
	tcp := func(name string, addrs ...string) {
		for _, a := range addrs {
			add(name, a, func(ctx context.Context) error { return dialTCP(ctx, "tcp", a) })
		}
	}
	missing := func(name, what string) {
		add(name, what, func(context.Context) error { return failed{fmt.Errorf("%s is not known", what)} })
	}
	tcp("kube_api", c.APIServer)
	tcp("kubelet", net.JoinHostPort(c.HostIP, "10250"), net.JoinHostPort(c.HostIP, "10255"))
	tcp("node_ip", net.JoinHostPort(c.HostIP, "22"), net.JoinHostPort(c.HostIP, "443"))
	tcp("service_other", c.CanaryService)
	tcp("direct_https", "1.1.1.1:443")
	for _, network := range []string{"udp", "tcp"} {
		add("dns_external", network+" 8.8.8.8:53", answers("8.8.8.8:53", network, marker))
	}
	if len(c.Nameservers) == 0 {
		missing("dns_cluster", "a nameserver in "+resolvConf)
	}
	for _, ns := range c.Nameservers {
		a := net.JoinHostPort(ns, "53")
		for _, network := range []string{"udp", "tcp"} {
			add("dns_cluster", network+" "+a, answers(a, network, marker))
		}
	}
	if c.Kind == report.KindControl {
		// No metadata service or IPv6 need answer on the control network:
		// those probes close on their blocked result alone.
		return ps
	}
	tcp("metadata", "169.254.169.254:80", "[fd00:ec2::254]:80")
	add("ipv6", "an IPv6 address or default route", func(context.Context) error { return ipv6Route() })

	// Through the edge: an unmapped host is refused (negative control); a
	// mapped one reaches the gateway, which answers (positive control).
	proxy := &url.URL{Scheme: "http", Host: c.Edge}
	ps = append(ps,
		probe{
			"edge_unmapped_refused", report.RoleNegative, report.Blocked, "CONNECT unmapped.invalid:443",
			viaEdge(proxy, nil, http.MethodGet, "https://unmapped.invalid/"+marker, nil),
		},
		probe{
			"edge_unmapped_refused", report.RoleNegative, report.Blocked, "GET http://unmapped.invalid/",
			viaEdge(proxy, nil, http.MethodGet, "http://unmapped.invalid/"+marker, nil),
		},
	)
	if len(c.AgentHosts) == 0 {
		ps = append(ps, probe{"edge_mediated", report.RolePositive, report.Reachable, EnvAgentHosts, func(context.Context) error {
			return failed{errors.New("no mapped host to reach through the edge")}
		}})
	}
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

// ProbeKubernetes runs the kubernetes catalog and returns its unsigned
// report: the edge adds the server nonce and signs it.
func ProbeKubernetes(ctx context.Context, c KubeConfig) (report.Report, error) {
	if runtime.GOOS != "linux" {
		return report.Report{}, errors.New("probe: runs only inside a Linux probe container")
	}
	r := report.Report{
		Format: report.Format, Session: c.Pod, Kind: c.Kind, StartedAt: time.Now().UTC(),
		Images:  c.Images,
		Engine:  report.Engine{Runtime: report.RuntimeKubernetes},
		Network: report.Network{Name: c.Namespace},
		Config:  report.Config{Checks: []report.Check{}},
		Canary:  report.Canary{Hits: []report.Hit{}},
	}
	// The run's marker: the server nonce is the edge's to add, so the
	// marker here only tags this run's requests.
	marker := report.Marker(c.Namespace + "/" + c.Pod + "/" + r.StartedAt.Format(time.RFC3339Nano))
	r.Results = runProbes(ctx, kubeCatalog(c, marker))
	r.FinishedAt = time.Now().UTC()
	return r, nil
}

// postReport hands the report to the edge and returns its answer.
func postReport(ctx context.Context, r report.Report) (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, kubeReport, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("probe: the edge's report endpoint: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxKubeReply))
	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("probe: the edge answered %d: %s", res.StatusCode, bounded(string(body)))
	}
	return strings.TrimSpace(string(body)), nil
}

// kubeMain is `pantherclaw-probe --profile kubernetes`.
func kubeMain(ctx context.Context, kind string, stdout, stderr io.Writer) int {
	c, err := KubeConfigFromEnv(kind, os.Getenv)
	var out string
	if err == nil {
		c.Nameservers = nameservers(resolvConf)
		var r report.Report
		if r, err = ProbeKubernetes(ctx, c); err == nil {
			out, err = postReport(ctx, r)
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pantherclaw-probe: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, out)
	return 0
}
