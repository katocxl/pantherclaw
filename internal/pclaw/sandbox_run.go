// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/workspace"
	"github.com/katocxl/pantherclaw/internal/sim/canary"
)

// `pclaw sandbox run` (G0 M9 track B, PN-008.1) runs an agent in the
// containment sandbox and proves the sandbox closed. In order, it checks
// Docker (≥ 28, HR-218); resolves the images by digest, refusing a tag;
// opens the session with a probe key and a host key it creates here,
// outside every container; enrolls the sandbox instance with a key only
// the edge gets, and admits it as the launching person (HR-094); starts
// the run; creates the networks and the edge; copies the workspace into a
// volume; starts the agent with no credential (HR-213); runs the probes,
// the control and the canary and submits their signed reports (HR-121,
// HR-215); streams the agent's output; copies the workspace out; and
// removes everything it created, also on interruption. It prints the
// coverage outcome.

func init() {
	commands["sandbox run"] = command{
		usage: "sandbox run --agent ID --connection ID... --grant ID --gateway URL --image REF@sha256:… [--edge-image REF] [--probe-image REF] " +
			"[--gateway-addr HOST:PORT] [--workspace DIR] [--out DIR] [--canary-listen ADDR] [--ttl DURATION] [-- COMMAND ARGS...]",
		run: sandboxRun,
	}
}

type sandboxRunFlags struct {
	agent, grant, gateway, gatewayAddr, image, edgeImage, probeImage, workspace, out, canaryListen string
	connections                                                                                    list
	ttl                                                                                            time.Duration
	args                                                                                           []string
}

func parseSandboxRun(a *app, args []string) (sandboxRunFlags, error) {
	var f sandboxRunFlags
	fs := flag.NewFlagSet("sandbox run", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	edge, _ := a.env("PANTHERCLAW_SANDBOX_EDGE_IMAGE")
	probe, _ := a.env("PANTHERCLAW_SANDBOX_PROBE_IMAGE")
	fs.StringVar(&f.agent, "agent", "", "the agent to run")
	fs.Var(&f.connections, "connection", "a connection the sandbox maps (repeat)")
	fs.StringVar(&f.grant, "grant", "", "the grant the run uses")
	fs.StringVar(&f.gateway, "gateway", "", "the gateway's public URL")
	fs.StringVar(&f.gatewayAddr, "gateway-addr", "", "host:port the edge dials for the gateway (default: host.docker.internal for a loopback gateway)")
	fs.StringVar(&f.image, "image", "", "the agent's image, pinned by digest")
	fs.StringVar(&f.edgeImage, "edge-image", edge, "the edge image id or digest (task sandbox:images; PANTHERCLAW_SANDBOX_EDGE_IMAGE)")
	fs.StringVar(&f.probeImage, "probe-image", probe, "the probe image id or digest (PANTHERCLAW_SANDBOX_PROBE_IMAGE)")
	fs.StringVar(&f.workspace, "workspace", "", "a directory copied into the sandbox (its repository cleaned: objects and refs only)")
	fs.StringVar(&f.out, "out", "", "an empty or new directory that gets the agent's changes as a patch (changes.patch, changes.txt, binary/)")
	fs.StringVar(&f.canaryListen, "canary-listen", "127.0.0.1", "where the canary listens on this host")
	fs.DurationVar(&f.ttl, "ttl", 2*time.Hour, "how long the session lasts (at most 24h)")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	f.args = fs.Args()
	if f.agent == "" || len(f.connections) == 0 || f.grant == "" || f.gateway == "" || f.image == "" || f.edgeImage == "" || f.probeImage == "" {
		return f, errUsage
	}
	return f, nil
}

// gatewayAddr is the address the edge dials for the gateway: the given one,
// or host.docker.internal on the URL's port for a gateway on this host's
// loopback; empty when the URL's own host is reachable.
func gatewayAddr(gateway, given string) (string, error) {
	u, err := url.Parse(gateway)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("--gateway must be the gateway's public URL")
	}
	if given != "" {
		return given, nil
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if ip, err := netip.ParseAddr(u.Hostname()); (err == nil && ip.IsLoopback()) || u.Hostname() == "localhost" {
		return net.JoinHostPort("host.docker.internal", port), nil
	}
	return "", nil
}

func sandboxRun(ctx context.Context, a *app, args []string) error {
	f, err := parseSandboxRun(a, args)
	if err != nil {
		return err
	}
	gwAddr, err := gatewayAddr(f.gateway, f.gatewayAddr)
	if err != nil {
		return err
	}
	images := [3]string{}
	for i, ref := range []string{f.image, f.edgeImage, f.probeImage} {
		if images[i], err = docker.ImageDigest(ref); err != nil {
			return err
		}
	}
	dc := docker.New(docker.CLI{})
	engine, err := dc.Engine(ctx)
	if err != nil {
		return err
	}
	if err := engine.Check(); err != nil {
		return err
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	conn := s.connect()
	sb, identity, runs := pantherclawv1connect.NewSandboxServiceClient(conn), pantherclawv1connect.NewIdentityServiceClient(conn),
		pantherclawv1connect.NewRunServiceClient(conn)
	digest, err := sandbox.ConfigDigest(f.gateway, f.connections, images, engine.Runtime())
	if err != nil {
		return err
	}
	// The probe key signs the sandbox run's report from inside its probe
	// container; the host key never leaves this process and signs the
	// control run's report and the canary's (HR-215).
	_, probeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	ev := engine.Evidence(engine.Runtime())
	started, err := sb.StartSession(ctx, &pantherclawv1.SandboxServiceStartSessionRequest{
		AgentId: f.agent, ConnectionIds: f.connections, ConfigDigest: digest, ProbePublicKey: probeKey.Public().(ed25519.PublicKey),
		HostPublicKey: hostKey.Public().(ed25519.PublicKey),
		Images:        &pantherclawv1.SandboxImages{Agent: images[0], Edge: images[1], Probe: images[2]},
		Engine:        &pantherclawv1.SandboxEngine{Version: ev.Version, ApiVersion: ev.APIVersion, Runtime: ev.Runtime, Desktop: ev.Desktop},
		Ttl:           durationpb.New(f.ttl),
	})
	if err != nil {
		return err
	}
	session := started.GetSession().GetId()
	_, _ = fmt.Fprintf(a.stderr, "sandbox session %s opened (expires %s)\n", session, started.GetSession().GetExpireTime().AsTime().Format(time.RFC3339))
	defer func() {
		if _, err := sb.EndSession(context.WithoutCancel(ctx), &pantherclawv1.SandboxServiceEndSessionRequest{SessionId: session}); err != nil {
			_, _ = fmt.Fprintf(a.stderr, "pclaw sandbox run: ending the session: %v\n", err)
		}
	}()

	dir, err := os.MkdirTemp("", "pclaw-sandbox-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	kf, inst, err := enrollSandboxInstance(ctx, a, s.server, started.GetEnrollmentToken(), identity, dir)
	if err != nil {
		return err
	}
	run, err := runs.StartRun(ctx, &pantherclawv1.StartRunRequest{AgentId: f.agent, InstanceId: &inst, GrantId: &f.grant, TaskRef: "sandbox " + session})
	if err != nil {
		return err
	}
	renewCtx, stopRenew := context.WithCancel(ctx)
	defer stopRenew()
	tokenFile, err := renewSandboxToken(renewCtx, a, kf, dir)
	if err != nil {
		return err
	}

	cn := canary.New(pclog.Discard())
	canaryCtx, stopCanary := context.WithCancel(ctx)
	defer stopCanary()
	ports, err := cn.Listen(canaryCtx, f.canaryListen, canary.Ports{})
	if err != nil {
		return err
	}
	mapped := resolveHosts(ctx, started.GetAgentHosts())
	gwPort, _ := strconv.Atoi(gwAddr[strings.LastIndex(gwAddr, ":")+1:])
	box, err := sandbox.Start(ctx, dc, engine, sandbox.Options{
		Session: session, EdgeImage: f.edgeImage, ProbeImage: f.probeImage, AgentImage: images[0],
		GatewayURL: f.gateway, GatewayAddr: gwAddr, Hosts: started.GetAgentHosts(), Connections: f.connections, MappedAddrs: mapped,
		Run: run.GetRun().GetId(), KeyFile: kf, TokenFile: tokenFile, ProbeKey: probeKey, HostKey: hostKey, Canary: cn, CanaryPorts: ports,
		HostPorts: []int{gwPort}, Dir: dir,
	})
	defer func() {
		if err := box.Close(context.WithoutCancel(ctx)); err != nil {
			_, _ = fmt.Fprintf(a.stderr, "pclaw sandbox run: removing the sandbox: %v\n", err)
		}
	}()
	if err != nil {
		return err
	}
	if err := box.PrepareAgent(ctx, sandbox.Agent{Image: f.image, Args: f.args, Workspace: f.workspace}); err != nil {
		return err
	}
	if f.workspace != "" {
		_, _ = fmt.Fprintf(a.stderr, "copied %s in: its repository without hooks, config or credentials (objects and refs only); "+
			"everything else under it, .env files included, is within the agent's reach\n", f.workspace)
	}
	n := started.GetNonces()
	evidence, err := box.Probe(ctx, sandbox.Nonces{Sandbox: n.GetSandbox(), Control: n.GetControl(), Canary: n.GetCanary()})
	if err != nil {
		return err
	}
	runID := run.GetRun().GetId()
	for _, r := range []struct{ kind, compact string }{{"sandbox", evidence.Sandbox}, {"control", evidence.Control}} {
		if _, err := sb.SubmitProbeReport(ctx, &pantherclawv1.SubmitProbeReportRequest{SessionId: session, Report: r.compact, RunId: runID}); err != nil {
			return fmt.Errorf("the %s report: %w", r.kind, err)
		}
	}
	closed, err := sb.SubmitCanaryReport(ctx, &pantherclawv1.SubmitCanaryReportRequest{SessionId: session, Report: evidence.Canary})
	if err != nil {
		return fmt.Errorf("the canary report: %w", err)
	}
	printClosures(a.stdout, closed.GetClosures())
	// The agent starts once the probes have run: it never shares the
	// sandbox network with the probe container.
	if err := box.StartAgent(ctx); err != nil {
		return err
	}
	if err := dc.Follow(ctx, box.Agent, a.stdout); err != nil {
		return err
	}
	code, err := dc.Wait(ctx, box.Agent)
	if err != nil {
		return err
	}
	if err := reportRoutes(ctx, sb, box, session, a.stderr); err != nil {
		return err
	}
	if f.out != "" {
		changes, err := box.CopyOut(ctx, f.workspace, f.out)
		if err != nil {
			return err
		}
		printChanges(a.stdout, f.out, changes)
	}
	if code != 0 {
		return fmt.Errorf("the agent exited with code %d", code)
	}
	return nil
}

// enrollSandboxInstance creates the sandbox instance's key in dir (only the
// edge mounts it), enrolls it with the session's enrollment token and
// admits it as the launching person, who sees the fingerprint (HR-094).
func enrollSandboxInstance(ctx context.Context, a *app, server, token string, identity pantherclawv1connect.IdentityServiceClient, dir string,
) (string, string, error) {
	kf, key, err := workloadclient.NewKeyFile()
	if err != nil {
		return "", "", err
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	jwk, err := json.Marshal(jws.PublicJWK(pub, ""))
	if err != nil {
		return "", "", err
	}
	wc, err := a.workloadClient(server, kf)
	if err != nil {
		return "", "", err
	}
	res, err := wc.Enroll(ctx, &pantherclawv1.EnrollRequest{EnrollmentToken: token, PublicJwk: string(jwk)})
	if err != nil {
		return "", "", fmt.Errorf("enrolling the sandbox instance: %w", err)
	}
	kf.Identifier, kf.Server = res.GetIdentifier(), server
	if res.GetState() != pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED {
		_, _ = fmt.Fprintf(a.stderr, "admitting sandbox instance %s, fingerprint %s\n", res.GetInstanceId(), res.GetFingerprint())
		if _, err := identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{Id: res.GetInstanceId(), Fingerprint: res.GetFingerprint()}); err != nil {
			return "", "", fmt.Errorf("admitting the sandbox instance (a person who owns the agent and holds agent.admit): %w", err)
		}
	}
	path := filepath.Join(dir, "workload.json")
	b, err := json.Marshal(kf)
	if err != nil {
		return "", "", err
	}
	// Read by the edge's uid through a read-only mount; dir is private.
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // G306: see above
		return "", "", err
	}
	return path, res.GetInstanceId(), nil
}

// renewSandboxToken keeps a valid workload token for the sandbox instance
// in dir/token/token, renewed here, outside the sandbox: the edge dials
// only the gateway and reads the file for every request.
func renewSandboxToken(ctx context.Context, a *app, keyFile, dir string) (string, error) {
	kf, err := workloadclient.ReadKeyFile(keyFile)
	if err != nil {
		return "", err
	}
	wc, err := a.workloadClient(kf.Server, kf)
	if err != nil {
		return "", err
	}
	tokens := filepath.Join(dir, "token")
	if err := os.Mkdir(tokens, 0o755); err != nil { //nolint:gosec // G301: read by the edge's uid; dir is private
		return "", err
	}
	path := filepath.Join(tokens, "token")
	tr := &tokenRenewal{a: a, wc: wc, identifier: kf.Identifier, name: "pclaw sandbox run"}
	r := tr.renewer(func(iss workloadclient.Issued) error {
		err := workloadclient.WriteTokenFile(path, iss.Token)
		if err == nil {
			err = os.Chmod(path, 0o644) //nolint:gosec // G302: read by the edge's uid; dir is private
		}
		return err
	})
	if err := r.Renew(ctx); err != nil {
		return "", fmt.Errorf("workload token: %w", err)
	}
	go func() { _ = r.Run(ctx) }()
	return path, nil
}

// resolveHosts resolves the agent hosts on this host: the probes try their
// real addresses, and no other third party (design decision 8).
func resolveHosts(ctx context.Context, hosts map[string]string) []string {
	var out []string
	for h := range hosts {
		addrs, err := net.DefaultResolver.LookupHost(ctx, h)
		if err != nil {
			continue // a host that does not resolve here is no direct route anyway
		}
		out = append(out, addrs...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// printClosures prints the coverage outcome of the probe run.
func printClosures(w io.Writer, closures []*pantherclawv1.SandboxClosure) {
	for _, c := range closures {
		if c.GetPassed() {
			_, _ = fmt.Fprintf(w, "connection %s: sandbox closure PASSED (closure %s), evidence for ENFORCED until %s\n",
				c.GetConnectionId(), c.GetClosureId(), c.GetExpireTime().AsTime().Format(time.RFC3339))
			continue
		}
		_, _ = fmt.Fprintf(w, "connection %s: sandbox closure FAILED (closure %s): %s\n", c.GetConnectionId(), c.GetClosureId(),
			strings.Join(c.GetFailed(), ", "))
	}
}

// reportRoutes sends the server the routes the edge saw the agent take
// before the session ends: the destinations it refused and the
// credentials it stripped (HR-214).
func reportRoutes(ctx context.Context, sb pantherclawv1connect.SandboxServiceClient, box *sandbox.Sandbox, session string, w io.Writer) error {
	routes, err := box.Routes(ctx)
	if err != nil || len(routes) == 0 {
		return err
	}
	req := &pantherclawv1.ReportRoutesRequest{SessionId: session}
	for _, r := range routes {
		kind := pantherclawv1.SandboxRouteKind_SANDBOX_ROUTE_KIND_DIRECT_API
		if r.Kind == sandbox.RouteCredential {
			kind = pantherclawv1.SandboxRouteKind_SANDBOX_ROUTE_KIND_CREDENTIAL
		}
		req.Routes = append(req.Routes, &pantherclawv1.SandboxRoute{Kind: kind, Locator: r.Locator})
	}
	res, err := sb.ReportRoutes(ctx, req)
	if err != nil {
		return fmt.Errorf("reporting the routes the edge saw: %w", err)
	}
	_, _ = fmt.Fprintf(w, "the edge refused or stripped %d routes of the agent (%d new to coverage)\n", len(routes), res.GetNewRoutes())
	return nil
}

// printChanges says what the agent changed and where the patch is, and
// lists the dotfiles, editor and task files among the changes for review
// before anything runs (founder decision 2026-10-11).
func printChanges(w io.Writer, out string, changes []workspace.Change) {
	if len(changes) == 0 {
		_, _ = fmt.Fprintln(w, "the agent changed nothing in the workspace")
		return
	}
	var flagged, binary []string
	for _, c := range changes {
		_, _ = fmt.Fprintf(w, "  %-8s %q\n", c.Kind, c.Path)
		if c.Flagged {
			flagged = append(flagged, strconv.Quote(c.Path))
		}
		if c.Binary && c.Kind != workspace.Deleted {
			binary = append(binary, strconv.Quote(c.Path))
		}
	}
	_, _ = fmt.Fprintf(w, "%d changes: apply %s to your repository with git apply\n", len(changes), filepath.Join(out, sandbox.PatchFile))
	if len(binary) > 0 {
		_, _ = fmt.Fprintf(w, "binary files are not in the patch; their new content is under %s: %s\n",
			filepath.Join(out, sandbox.BinaryDir), strings.Join(binary, ", "))
	}
	if len(flagged) > 0 {
		_, _ = fmt.Fprintf(w, "review before running anything, these dotfiles, editor or task files changed: %s\n", strings.Join(flagged, ", "))
	}
}
