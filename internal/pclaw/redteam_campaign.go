// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/redteam/campaign"
	"github.com/katocxl/pantherclaw/internal/redteam/relay"
	"github.com/katocxl/pantherclaw/internal/sandbox"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// `pclaw redteam campaign run` (G0 M25 D305-D310, D313; HR-607..HR-615)
// runs the library's attack campaigns against a range twin of an agent: its
// image, pinned by digest, in the containment sandbox, on simulated
// connections. For each campaign it plants the campaign's content in a
// workspace of its own and runs the agent once. The agent's model calls go
// through the edge and the gateway's model face to a relay this process
// starts, which holds the model key in memory and nowhere else (HR-607). The
// server derives every outcome from its own records when the campaign
// finishes (HR-608..HR-610); this command only prints them.
//
// Exit codes: 0 when no attempt was ALLOWED or RUN_TOO_LARGE, 1 when one was, 2 usage or
// infrastructure.

func init() {
	commands["redteam campaign run"] = command{
		usage: "redteam campaign run --agent RANGE_AGENT_ID --connection ID... --relay-connection ID --grant ID --gateway URL --image REF@sha256:… " +
			"--model-host HOST --model-key-file FILE [--model-key-header NAME] [--campaigns DIR] [--only RT-14x,…] [--fixture NAME=VALUE]… " +
			"[--scripted] [--workspace DIR] [--edge-image REF] [--probe-image REF] [--gateway-addr HOST:PORT] [--gateway-peer IP] " +
			"[--ttl DURATION] [-- COMMAND ARGS...]",
		run: redteamCampaignRun,
	}
}

// campaignSandbox runs one campaign's sandbox; a test replaces it.
var campaignSandbox = runSandbox

// modelKeyEnv are the variables the agent finds a model key in: the
// placeholder, never the key (HR-607).
var modelKeyEnv = []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}

// maxModelKey bounds the key file.
const maxModelKey = 8 << 10

type campaignFlags struct {
	sandbox                                    sandboxRunFlags
	relayConn, modelHost, keyFile, keyHeader   string
	dir, only, gatewayPeer, modelCA, modelDial string
	fixtures                                   list
	scripted                                   bool
}

func parseCampaignRun(a *app, args []string) (campaignFlags, error) {
	var f campaignFlags
	fs := flag.NewFlagSet("redteam campaign run", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	edge, _ := a.env("PANTHERCLAW_SANDBOX_EDGE_IMAGE")
	probe, _ := a.env("PANTHERCLAW_SANDBOX_PROBE_IMAGE")
	s := &f.sandbox
	fs.StringVar(&s.agent, "agent", "", "the range agent: the twin of the agent under test")
	fs.Var(&s.connections, "connection", "a simulated connection the sandbox maps (repeat)")
	fs.StringVar(&s.grant, "grant", "", "the range agent's grant")
	fs.StringVar(&s.gateway, "gateway", "", "the local gateway's public URL (a remote gateway is refused)")
	fs.StringVar(&s.gatewayAddr, "gateway-addr", "", "host:port the edge dials for the gateway")
	fs.StringVar(&s.image, "image", "", "the agent's image, pinned by digest")
	fs.StringVar(&s.edgeImage, "edge-image", edge, "the edge image (PANTHERCLAW_SANDBOX_EDGE_IMAGE)")
	fs.StringVar(&s.probeImage, "probe-image", probe, "the probe image (PANTHERCLAW_SANDBOX_PROBE_IMAGE)")
	fs.StringVar(&s.workspace, "workspace", "", "a directory copied into each campaign's workspace before its plants")
	fs.StringVar(&s.canaryListen, "canary-listen", "127.0.0.1", "where the canary listens on this host")
	fs.DurationVar(&s.ttl, "ttl", 2*time.Hour, "how long each sandbox session lasts (at most 24h)")
	fs.StringVar(&f.relayConn, "relay-connection", "", "the simulated model relay connection; the relay listens at its base URL")
	fs.StringVar(&f.modelHost, "model-host", "", "the one model host the agent may reach, as a DNS name")
	fs.StringVar(&f.keyFile, "model-key-file", "", "a file holding the model key, read once and kept in this process only")
	fs.StringVar(&f.keyHeader, "model-key-header", "x-api-key", "the header the relay puts the key in (authorization sends Bearer)")
	fs.StringVar(&f.dir, "campaigns", "redteam/campaigns", "the directory of RT-14x-*.yaml campaign files")
	fs.StringVar(&f.only, "only", "", "only these campaigns, comma separated")
	fs.Var(&f.fixtures, "fixture", "fill ${NAME} in the campaigns: NAME=VALUE (repeat)")
	fs.BoolVar(&f.scripted, "scripted", false, "the agent is the scripted stand-in: write each campaign's script into its workspace")
	fs.StringVar(&f.gatewayPeer, "gateway-peer", "", "the gateway's address as the relay sees it (default: this host's loopback)")
	fs.StringVar(&f.modelCA, "model-ca", "", "hidden, tests only: PEM roots for a local test provider instead of the system's")
	fs.StringVar(&f.modelDial, "model-dial", "", "hidden, tests only: host:port of a local test provider")
	fs.Usage = func() { hiddenDefaults(fs, "model-ca", "model-dial") }
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	s.args = fs.Args()
	if s.agent == "" || len(s.connections) == 0 || s.grant == "" || s.gateway == "" || s.image == "" || s.edgeImage == "" || s.probeImage == "" ||
		f.relayConn == "" || f.modelHost == "" || f.keyFile == "" {
		return f, errUsage
	}
	return f, nil
}

// hiddenDefaults prints a flag set's flags except the hidden ones (G0 M25
// D523: the test provider's flags stay out of the help).
func hiddenDefaults(fs *flag.FlagSet, hidden ...string) {
	_, _ = fmt.Fprintf(fs.Output(), "Usage of %s:\n", fs.Name())
	fs.VisitAll(func(fl *flag.Flag) {
		if slices.Contains(hidden, fl.Name) {
			return
		}
		_, _ = fmt.Fprintf(fs.Output(), "  -%s\n    \t%s\n", fl.Name, fl.Usage)
	})
}

// localGateway refuses a gateway that is not on this host or its private
// network: the relay serves the local gateway only (D308).
func localGateway(gateway string) error {
	u, err := url.Parse(gateway)
	if err != nil || u.Hostname() == "" {
		return errors.New("--gateway must be the gateway's URL")
	}
	if u.Hostname() == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || (!ip.Unmap().IsLoopback() && !ip.Unmap().IsPrivate()) {
		return errors.New("a remote gateway is refused: the model relay serves a gateway on this host or its private network, named by IP address")
	}
	return nil
}

// errKeyInWorkspace refuses a key file the sandbox would copy to the agent.
var errKeyInWorkspace = errors.New("--model-key-file is inside --workspace, which the sandbox copies to the agent")

// readModelKey reads the key file once. It must not be inside a workspace
// the sandbox copies, which would hand the key to the agent: not by its
// path, not through a symbolic link on either side, and not as a hard link
// anywhere in the workspace tree (D525 M3).
func readModelKey(path, workspace string) ([]byte, error) {
	fh, err := os.Open(path) //nolint:gosec // G304: the operator's key file
	if err != nil {
		return nil, errors.New("--model-key-file: cannot open the file")
	}
	defer func() { _ = fh.Close() }()
	if workspace != "" {
		if err := keyOutsideWorkspace(fh, path, workspace); err != nil {
			return nil, err
		}
	}
	raw, err := io.ReadAll(io.LimitReader(fh, maxModelKey+1))
	if err != nil || len(raw) > maxModelKey {
		clear(raw)
		return nil, fmt.Errorf("--model-key-file: unreadable or larger than %d bytes", maxModelKey)
	}
	key := bytes.Clone(bytes.TrimSpace(raw))
	clear(raw)
	if len(key) == 0 || bytes.ContainsAny(key, "\r\n") {
		clear(key)
		return nil, errors.New("--model-key-file: one key on one line")
	}
	return key, nil
}

// keyOutsideWorkspace checks the open key file against the workspace: its
// path and its resolved path are outside both the workspace's path and its
// resolved path, and no regular file in the workspace tree is the same file.
func keyOutsideWorkspace(fh *os.File, path, workspace string) error {
	keyInfo, err := fh.Stat()
	if err != nil {
		return errors.New("--model-key-file: cannot stat the file")
	}
	keys, err1 := absAndReal(path)
	wss, err2 := absAndReal(workspace)
	if err1 != nil || err2 != nil {
		return errors.New("--model-key-file or --workspace: cannot resolve the path")
	}
	for _, ws := range wss {
		for _, k := range keys {
			if rel, err := filepath.Rel(ws, k); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return errKeyInWorkspace
			}
		}
	}
	// A hard link to the key anywhere in the copied tree (the copy follows
	// no symbolic link, so neither does this scan).
	found := errors.New("found")
	err = filepath.WalkDir(wss[1], func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if os.SameFile(fi, keyInfo) {
			return found
		}
		return nil
	})
	switch {
	case errors.Is(err, found):
		return errKeyInWorkspace
	case err != nil:
		return fmt.Errorf("--workspace: cannot scan the tree: %w", err)
	}
	return nil
}

// absAndReal is a path made absolute, and with its symbolic links resolved.
func absAndReal(p string) ([2]string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return [2]string{}, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return [2]string{}, err
	}
	return [2]string{abs, resolved}, nil
}

// copyWorkspace copies src's directories and regular files into dst. It
// follows no symbolic link: a link, or any other file that is not regular,
// is skipped and counted (D525 M3).
func copyWorkspace(dst, src string) (skipped int, err error) {
	root, err := filepath.EvalSymlinks(src)
	if err != nil {
		return 0, err
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755) //nolint:gosec // G301: copied into the sandbox, read by the agent's uid
		case !d.Type().IsRegular():
			skipped++
			return nil
		}
		return copyRegular(target, p)
	})
	return skipped, err
}

func copyRegular(dst, src string) error {
	in, err := os.Open(src) //nolint:gosec // G304: the operator's workspace
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302: read by the agent's uid
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func parseFixtures(l list) (campaign.Fixtures, error) {
	fx := campaign.Fixtures{}
	for _, v := range l {
		if !fixtureRe.MatchString(v) || strings.HasPrefix(v, campaign.CanaryPrefix) {
			return nil, fmt.Errorf("--fixture %q: NAME=VALUE", v)
		}
		k, val, _ := strings.Cut(v, "=")
		fx[k] = val
	}
	return fx, nil
}

func redteamCampaignRun(ctx context.Context, a *app, args []string) error {
	f, err := parseCampaignRun(a, args)
	if err != nil {
		return err
	}
	if err := localGateway(f.sandbox.gateway); err != nil {
		return failExit("%v", err)
	}
	fx, err := parseFixtures(f.fixtures)
	if err != nil {
		return failExit("%v", err)
	}
	set, err := campaign.LoadDir(f.dir)
	if err != nil {
		return failExit("%v", err)
	}
	if f.only != "" {
		want := strings.Split(f.only, ",")
		set = slices.DeleteFunc(set, func(l campaign.Loaded) bool { return !slices.Contains(want, l.File.ID) })
	}
	if len(set) == 0 {
		return failExit("no campaigns in %s", f.dir)
	}
	image, err := docker.ImageDigest(f.sandbox.image)
	if err != nil {
		return failExit("%v", err)
	}
	var roots *x509.CertPool
	if f.modelCA != "" {
		pem, err := os.ReadFile(f.modelCA)
		if err != nil {
			return failExit("--model-ca: %v", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return failExit("--model-ca: no certificate")
		}
	}
	var peer netip.Addr
	if f.gatewayPeer != "" {
		if peer, err = netip.ParseAddr(f.gatewayPeer); err != nil {
			return failExit("--gateway-peer must be an IP address")
		}
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	conn := s.connect()
	ranges, conns := pantherclawv1connect.NewRangeServiceClient(conn), pantherclawv1connect.NewConnectionServiceClient(conn)
	rc, err := conns.GetConnection(ctx, &pantherclawv1.GetConnectionRequest{Id: f.relayConn})
	if err != nil {
		return failExit("the relay connection: %s", describe(err))
	}
	c := rc.GetConnection()
	if !c.GetModelRelay() || !c.GetSimulated() {
		return failExit("connection %s is not a simulated model relay", f.relayConn)
	}
	listen, err := relayListen(c.GetBaseUrl())
	if err != nil {
		return failExit("the relay connection's base URL: %v", err)
	}

	// The key is read last, once every check that needs no key passed, and
	// handed to the relay, which owns it from here (HR-607).
	key, err := readModelKey(f.keyFile, f.sandbox.workspace)
	if err != nil {
		return failExit("%v", err)
	}
	rl, err := relay.New(ctx, relay.Options{
		Listen: listen, Gateway: peer, ModelHost: f.modelHost, Key: key, KeyHeader: f.keyHeader, Roots: roots, DialAddr: f.modelDial,
		Log: pclog.Discard(),
	})
	clear(key)
	if err != nil {
		return failExit("%v", err)
	}
	defer func() { _ = rl.Close(context.WithoutCancel(ctx)) }()
	_, _ = fmt.Fprintf(a.stderr, "model relay for %s listening on %s; the key stays in this process\n", f.modelHost, rl.Addr())

	decls := make([]*pantherclawv1.CampaignDecl, 0, len(set))
	for _, l := range set {
		decls = append(decls, &pantherclawv1.CampaignDecl{Id: l.File.ID, Digest: l.Digest})
	}
	started, err := ranges.StartCampaign(ctx, &pantherclawv1.StartCampaignRequest{
		RangeAgentId: f.sandbox.agent, Campaigns: decls, RunnerVersion: runnerVersion(), ImageDigest: image,
		ModelHost: f.modelHost, RelayConnectionId: f.relayConn, Scripted: f.scripted,
	})
	if err != nil {
		return failExit("starting the campaign: %s", describe(err))
	}
	id := started.GetCampaignId()
	_, _ = fmt.Fprintf(a.stderr, "campaign %s started: %d campaigns against image %s\n", id, len(set), image)

	openStep := func(ctx context.Context, scenario string) error {
		_, err := ranges.StartCampaignStep(ctx, &pantherclawv1.StartCampaignStepRequest{CampaignId: id, ScenarioId: scenario})
		return err
	}
	reports, runErr := runCampaigns(ctx, a, f, set, fx, c.GetName(), openStep)
	// The campaign finishes whatever happened: a run left out only widens
	// the gap (HR-609).
	fin, err := ranges.FinishCampaign(context.WithoutCancel(ctx), &pantherclawv1.FinishCampaignRequest{CampaignId: id, Runs: reports})
	if err != nil {
		return failExit("finishing campaign %s: %s", id, describe(err))
	}
	st := rl.Stats()
	_, _ = fmt.Fprintf(a.stderr, "the relay carried %d model requests (%d bytes out, %d back)\n", st.Requests, st.BytesToModel, st.BytesFromModel)
	allowed, tooLarge := printCampaign(a.stdout, fin)
	if runErr != nil {
		return failExit("%v (campaign %s finished with the runs it had)", runErr, id)
	}
	if allowed {
		return &exitError{code: 1, msg: "pclaw: an attempt was ALLOWED: the boundary did not hold"}
	}
	if tooLarge {
		// The agent under test can push its own step past the server's
		// bounds, so this gap is a failure, not a pass (D543 R-M2).
		return &exitError{code: 1, msg: "pclaw: an attempt was RUN_TOO_LARGE: the step passed the server's bounds and was not derived"}
	}
	return nil
}

// relayListen is where the relay listens: its connection's base URL, an IP
// literal with a port.
func relayListen(base string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || u.Port() == "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("must be http://IP:PORT")
	}
	return u.Host, nil
}

// runCampaigns opens each campaign's step and runs its sandbox, and returns
// the runs it saw (the server checks them against its own binding). It
// stops at an infrastructure failure, returning what it has.
func runCampaigns(ctx context.Context, a *app, f campaignFlags, set []campaign.Loaded, fx campaign.Fixtures, relayName string,
	openStep func(context.Context, string) error,
) ([]*pantherclawv1.CampaignRunReport, error) {
	placeholder := "pc-placeholder-" + rand.Text()
	var reports []*pantherclawv1.CampaignRunReport
	for _, l := range set {
		// The server binds every run of the twin from now on to this step
		// (D525 M1).
		if err := openStep(ctx, l.File.ID); err != nil {
			return reports, fmt.Errorf("%s: opening the step: %s", l.File.ID, describe(err))
		}
		dir, err := os.MkdirTemp("", "pclaw-campaign-")
		if err != nil {
			return reports, err
		}
		res, err := runOneCampaign(ctx, a, f, l, fx, relayName, placeholder, dir)
		_ = os.RemoveAll(dir)
		if res.Run != "" {
			reports = append(reports, &pantherclawv1.CampaignRunReport{ScenarioId: l.File.ID, RunId: res.Run, Routes: campaignRoutes(res.Routes)})
		}
		var agentExit *agentExitError
		switch {
		case errors.As(err, &agentExit):
			// An agent under attack may well fail: the run still counts.
			_, _ = fmt.Fprintf(a.stderr, "%s: %v\n", l.File.ID, err)
		case err != nil:
			return reports, fmt.Errorf("%s: %w", l.File.ID, err)
		}
	}
	return reports, nil
}

// agentExitError is an agent's non-zero exit, which is no infrastructure
// failure.
type agentExitError struct{ code int }

func (e *agentExitError) Error() string { return fmt.Sprintf("the agent exited with code %d", e.code) }

func runOneCampaign(ctx context.Context, a *app, f campaignFlags, l campaign.Loaded, fx campaign.Fixtures, relayName, placeholder, dir string,
) (sandboxResult, error) {
	if f.sandbox.workspace != "" {
		skipped, err := copyWorkspace(dir, f.sandbox.workspace)
		if err != nil {
			return sandboxResult{}, fmt.Errorf("copying the workspace: %w", err)
		}
		if skipped > 0 {
			_, _ = fmt.Fprintf(a.stderr, "workspace: skipped %d symbolic links and other files that are not regular files\n", skipped)
		}
	}
	if err := l.File.Workspace(dir, fx.With(campaign.Canaries()), f.modelHost, f.scripted); err != nil {
		return sandboxResult{}, err
	}
	sf := f.sandbox
	sf.workspace, sf.out = dir, ""
	env := []string{"PC_CAMPAIGN=" + l.File.ID, "PC_CAMPAIGN_TASK=" + l.File.Task}
	for _, v := range modelKeyEnv {
		env = append(env, v+"="+placeholder)
	}
	_, _ = fmt.Fprintf(a.stderr, "%s: %s\n", l.File.ID, l.File.Title)
	return campaignSandbox(ctx, a, sf, sandboxExtra{modelHost: f.modelHost, modelConnection: relayName, placeholder: placeholder, env: env})
}

// campaignRoutes are the edge's routes as a run report carries them.
func campaignRoutes(routes []sandbox.Route) []*pantherclawv1.CampaignRoute {
	var out []*pantherclawv1.CampaignRoute
	for _, r := range routes {
		if len(out) == 64 {
			break
		}
		if r.Kind != sandbox.RouteDirectAPI && r.Kind != sandbox.RouteCredential {
			continue
		}
		out = append(out, &pantherclawv1.CampaignRoute{Kind: r.Kind, Locator: r.Locator})
	}
	return out
}

// printCampaign prints the server's outcomes and statement, and reports
// whether an attempt was ALLOWED, and whether one was too large to derive
// (RUN_TOO_LARGE), which an agent under test can force (D543 R-M2).
func printCampaign(w io.Writer, fin *pantherclawv1.FinishCampaignResponse) (allowed, tooLarge bool) {
	c := fin.GetCampaign()
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CAMPAIGN\tATTEMPT\tBOUNDARY\tEXPECTED\tOUTCOME\tBASIS\tREASON")

	for _, s := range fin.GetSteps() {
		outcome := strings.TrimPrefix(s.GetOutcome().String(), "CAMPAIGN_OUTCOME_")
		allowed = allowed || outcome == "ALLOWED"
		tooLarge = tooLarge || s.GetReason() == "RUN_TOO_LARGE"
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.GetScenarioId(), s.GetStepId(), s.GetBoundary(), s.GetExpected(), outcome,
			strings.TrimPrefix(s.GetBasis().String(), "CAMPAIGN_BASIS_"), s.GetReason()+s.GetRouteLocator())
	}
	_ = tw.Flush()
	n := c.GetCounts()
	_, _ = fmt.Fprintf(w, "held %d, denied %d, not routed (reported) %d, allowed %d, not exercised %d\n",
		n.GetHeld(), n.GetDenied(), n.GetNotRoutedReported(), n.GetAllowed(), n.GetNotExercised())
	_, _ = fmt.Fprintln(w, c.GetStatement())
	return allowed, tooLarge
}
