// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/relay"
)

// Kind is a connector connection's kind.
const Kind = "mcp_container"

// User runs every connector: a non-root uid of its own, distinct from the
// sandbox's roles (HR-085).
const User = "65520:65520"

// Placeholder is the value a credential placeholder gets: the credential
// is placed on the connector's mediated egress, never in its container
// (G0 M9 design decision 18).
const Placeholder = "pantherclaw-placeholder"

// Timings.
var (
	// SyncEvery is how often the supervisor matches its connectors to the
	// configuration.
	SyncEvery = 2 * time.Second
	// RetryAfter is how long a connector that failed to start waits.
	RetryAfter  = 30 * time.Second
	stopTimeout = 30 * time.Second
)

// Reporter tells the server a connector run's state (GatewayService.
// ReportConnectorState).
type Reporter func(ctx context.Context, r *pb.ReportConnectorStateRequest) error

// ErrNotRunning reports a connector the gateway is not running (yet).
var ErrNotRunning = errors.New("connectors: the connector is not running")

// Config is the gateway's connectors section (G0 M9 track C).
type Config struct {
	// Enabled lets the gateway run connector connections. Off by default:
	// a connector connection is then never started, and calls to it fail
	// unsent (HR-084).
	Enabled bool `json:"enabled" env:"PC_GW_CONNECTORS_ENABLED"`
	// EdgeImage is the edge's image (by digest, or a local id) in front of
	// a connector with an egress connection (G0 M9 design decision 6).
	EdgeImage string `json:"edge_image" env:"PC_GW_CONNECTORS_EDGE_IMAGE"`
	// EgressListen is where the gateway's egress listener listens, and
	// EgressAddr the host:port a connector's edge dials for it (for
	// example host.docker.internal:8095 on Docker Desktop). Only requests
	// carrying a running connector's binding token are taken.
	EgressListen string `json:"egress_listen" env:"PC_GW_CONNECTORS_EGRESS_LISTEN"`
	EgressAddr   string `json:"egress_addr" env:"PC_GW_CONNECTORS_EGRESS_ADDR"`
}

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Supervisor starts, replaces and stops the gateway's connector containers
// to match its configuration, through the Docker CLI with fixed arguments
// (HR-216). Each runs hardened (internal/sandbox/docker), as its own uid,
// on an internal network of its own with no route out, with no mount, no
// host environment and no credential.
type Supervisor struct {
	c      *docker.Client
	cfg    Config
	engine docker.Engine
	conf   Configuration
	log    *slog.Logger
	report Reporter
	send   Egress

	mu      sync.Mutex
	running map[string]*instance
	failed  map[string]time.Time
	// failures counts a connector's consecutive failed starts and exits,
	// which its next start waits for (backoff).
	failures map[string]int
}

type instance struct {
	id         string
	connection string
	// binding is the edge's token; egress the egress connection; dir the
	// edge's private directory.
	binding, egress, dir string
	revision             int32
	started              time.Time
	// renew is when the edge's CA needs renewing: the connector is then
	// replaced between calls (zero without an edge).
	renew         time.Time
	name, network string
	// relay is the edge's path to the egress listener on a native Linux
	// engine (HR-228).
	relay  *relay.Relay
	client *upstream.Client
	stdio  *Stdio
	stop   context.CancelFunc
	done   chan struct{}
	// pipes are the gateway's ends of the connector's input and output,
	// closed when it stops.
	pipes []*os.File
	// calls holds the one call the connector runs (Fly to land); flight
	// is that call, set while it is in flight.
	calls  chan struct{}
	flight *flight
}

// New returns a supervisor on this host's engine, which must pass the
// sandbox's engine check (Docker 28 or later, Linux, seccomp, runc;
// HR-218). The gateway must run as a host process, not inside a container.
func New(ctx context.Context, c *docker.Client, cfg Config, conf Configuration, log *slog.Logger) (*Supervisor, error) {
	if inContainer() {
		return nil, errors.New("connectors: the gateway runs inside a container; connectors need a host process")
	}
	e, err := c.Engine(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.Check(); err != nil {
		return nil, err
	}
	if log == nil {
		log = pclog.Discard()
	}
	return &Supervisor{
		c: c, cfg: cfg, engine: e, conf: conf, log: log, running: map[string]*instance{}, failed: map[string]time.Time{}, failures: map[string]int{},
	}, nil
}

// Client implements dispatch.Connectors: the running connector of this
// revision, while it can take a call.
func (s *Supervisor) Client(connection string, revision int32) (*upstream.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.running[connection]
	if !ok || in.revision != revision || !in.stdio.Usable() {
		return nil, ErrNotRunning
	}
	select {
	case <-in.done:
		return nil, ErrNotRunning
	default:
		return in.client, nil
	}
}

// Run keeps the connectors matched to the configuration until ctx ends,
// then stops them all.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.cfg.EgressListen != "" {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.EgressListen)
		if err != nil {
			return fmt.Errorf("connectors: egress listener: %w", err)
		}
		srv := &http.Server{
			Handler: s.egressHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
			MaxHeaderBytes: 16 << 10,
		}
		go func() { _ = srv.Serve(ln) }()
		defer func() { _ = srv.Close() }()
	}
	t := time.NewTicker(SyncEvery)
	defer t.Stop()
	for {
		s.Sync(ctx)
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stopTimeout)
			defer cancel()
			s.mu.Lock()
			ids := slices.Collect(maps.Keys(s.running))
			s.mu.Unlock()
			for _, id := range ids {
				s.stop(sctx, id)
			}
			return nil
		case <-t.C:
		}
	}
}

// Sync starts the active connector connections that are not running,
// replaces those whose revision changed, whose container stopped or whose
// last exchange was abandoned (it may still be working on it), and stops
// those no longer configured. A connector that keeps failing to start or
// exiting waits longer each time (backoff).
func (s *Supervisor) Sync(ctx context.Context) {
	want := map[string]*control.Connection{}
	if cfg := s.conf.Current(); cfg != nil {
		for id, c := range cfg.ByID {
			if c.GetKind() == Kind && c.GetState() == "ACTIVE" && c.GetConnector() != nil {
				want[id] = c
			}
		}
	}
	s.mu.Lock()
	var stale []string
	crashed := map[string]time.Duration{}
	for id, in := range s.running {
		c, ok := want[id]
		exited := !in.stdio.Usable()
		select {
		case <-in.done:
			exited = true
		default:
		}
		// An edge whose CA nears its end is replaced between calls: the
		// call slot is taken and kept until the connector stops.
		renew := false
		if !exited && !in.renew.IsZero() && time.Now().After(in.renew) {
			select {
			case in.calls <- struct{}{}:
				renew = true
			default:
			}
		}
		if exited {
			crashed[id] = time.Since(in.started)
		}
		if exited || !ok || renew || c.GetRevision() != in.revision {
			stale = append(stale, id)
		}
	}
	s.mu.Unlock()
	for _, id := range stale {
		s.stop(ctx, id)
	}
	s.mu.Lock()
	for id, ran := range crashed {
		if ran >= resetAfter {
			s.failures[id] = 0
		}
		s.failures[id]++
		s.failed[id] = time.Now()
	}
	s.mu.Unlock()
	for id, c := range want {
		s.mu.Lock()
		_, running := s.running[id]
		last, failed := s.failed[id]
		n := s.failures[id]
		s.mu.Unlock()
		if running || (failed && time.Since(last) < backoff(n)) {
			continue
		}
		if err := s.start(ctx, c); err != nil {
			s.log.WarnContext(ctx, "gateway.connector_failed", slog.String("connection", id), pclog.Err(err))
			s.mu.Lock()
			s.failures[id]++
			s.failed[id] = time.Now()
			s.mu.Unlock()
		}
	}
}

// resetAfter is how long a connector runs before its earlier failures no
// longer count.
const resetAfter = time.Minute

// backoff is how long a connector waits after its nth consecutive failure:
// at once the first time (a call that timed out leaves it broken, and the
// next call should not wait), then doubling from RetryAfter/8 up to five
// minutes.
func backoff(n int) time.Duration {
	if n <= 1 {
		return 0
	}
	d := RetryAfter / 8
	for i := 2; i < n && d < 5*time.Minute; i++ {
		d *= 2
	}
	return min(d, 5*time.Minute)
}

// inContainer reports whether the gateway itself runs in a container
// (Docker, Podman, Kubernetes): connectors need a host process (HR-216).
func inContainer() bool {
	for _, f := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	_, k8s := os.LookupEnv("KUBERNETES_SERVICE_HOST")
	return k8s
}

// start creates the connector's network and container and attaches to its
// standard input and output.
func (s *Supervisor) start(ctx context.Context, c *control.Connection) error {
	id, spec := c.GetId(), c.GetConnector()
	short := strings.ReplaceAll(id, "-", "")
	short = short[max(0, len(short)-16):]
	labels := map[string]string{docker.LabelSession: id}
	net := "pc-cnet-" + short
	name := "pc-conn-" + short
	// Each run has its own id; the server records its states (00094).
	run, rev := ids.NewV7().String(), spec.GetRevision()
	fail := func(class string, err error) error {
		s.tell(ctx, run, id, rev, name, pb.ConnectorState_CONNECTOR_STATE_FAILED, class)
		return err
	}
	s.tell(ctx, run, id, rev, name, pb.ConnectorState_CONNECTOR_STATE_STARTING, "")
	_ = s.c.RemoveLabelled(ctx, id) // what a crashed gateway may have left
	if strings.Contains(spec.GetImage(), "@") {
		if err := s.c.Pull(ctx, spec.GetImage()); err != nil {
			return fail("image_pull", err)
		}
	}
	if _, err := s.c.CreateNetwork(ctx, docker.Network{Name: net, Internal: true, Labels: labels}); err != nil {
		return fail("network", err)
	}
	var med mediated
	egressID := spec.GetEgressConnectionId()
	if egressID != "" {
		var egressConn *control.Connection
		if cfg := s.conf.Current(); cfg != nil {
			egressConn = cfg.ByID[egressID]
		}
		if egressConn == nil {
			_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
			return fail("egress", errors.New("connectors: the egress connection is not served by this gateway"))
		}
		var err error
		if med, err = s.startEdge(ctx, id, short, egressConn, net, labels); err != nil {
			_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
			med.cleanup()
			return fail("edge", err)
		}
	}
	env := make([]string, 0, len(spec.GetEnvironment())+len(spec.GetCredentialPlaceholders()))
	for _, k := range slices.Sorted(maps.Keys(spec.GetEnvironment())) {
		env = append(env, k+"="+spec.GetEnvironment()[k])
	}
	for _, k := range spec.GetCredentialPlaceholders() {
		env = append(env, k+"="+Placeholder)
	}
	l := spec.GetLimits()
	if _, err := s.c.CreateContainer(ctx, docker.Container{
		Name: name, Image: spec.GetImage(), User: User, Args: spec.GetCommand(), Networks: []string{net}, Env: append(env, med.env...),
		Mounts: med.mounts, BindRoot: med.dir,
		Runtime: s.engine.Runtime(), Labels: labels, Interactive: true,
		Limits: docker.Limits{PIDs: int(l.GetPids()), MemoryMiB: int(l.GetMemoryMib()), MilliCPUs: int(l.GetMilliCpus())},
	}); err != nil {
		_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
		med.cleanup()
		return fail("container", err)
	}
	// Operating-system pipes go to docker as they are: with an in-process
	// pipe, docker's exit would wait for a copy of the input that only
	// ends with the next write, and a connector killed from outside would
	// go unseen.
	inR, inW, err := os.Pipe()
	if err != nil {
		_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
		med.cleanup()
		return fail("pipe", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_, _ = inR.Close(), inW.Close()
		_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
		med.cleanup()
		return fail("pipe", err)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		code, err := s.c.Attach(runCtx, name, inR, outW)
		// The connector's output ends and its input fails from here.
		_, _ = outW.Close(), inR.Close()
		s.log.InfoContext(runCtx, "gateway.connector_stopped", slog.String("connection", id), slog.Int("exit_code", code), pclog.Err(err))
		state, class := pb.ConnectorState_CONNECTOR_STATE_STOPPED, ""
		if runCtx.Err() == nil {
			state, class = pb.ConnectorState_CONNECTOR_STATE_FAILED, "exited"
		}
		s.tell(runCtx, run, id, rev, name, state, class)
	}()
	stdio := NewStdio(inW, outR, int64(c.GetMaxResponseBytes()))
	s.mu.Lock()
	s.running[id] = &instance{
		id: run, revision: c.GetRevision(), started: time.Now(), renew: med.renew, name: name, network: net, stdio: stdio, stop: cancel, done: done,
		connection: id, binding: med.binding, egress: egressID, dir: med.dir, relay: med.relay, calls: make(chan struct{}, 1),
		client: upstream.New("http://connector.invalid/"+id, stdio), pipes: []*os.File{inW, outR},
	}
	delete(s.failed, id)
	s.mu.Unlock()
	s.tell(ctx, run, id, rev, name, pb.ConnectorState_CONNECTOR_STATE_RUNNING, "")
	s.log.InfoContext(ctx, "gateway.connector_started", slog.String("connection", id), slog.String("image", spec.GetImage()))
	return nil
}

// stop stops a connector and removes its container and network.
func (s *Supervisor) stop(ctx context.Context, id string) {
	s.mu.Lock()
	in, ok := s.running[id]
	delete(s.running, id)
	s.mu.Unlock()
	if !ok {
		return
	}
	in.stdio.Close()
	in.stop()
	if err := s.c.RemoveLabelled(context.WithoutCancel(ctx), id); err != nil {
		s.log.WarnContext(ctx, "gateway.connector_not_removed", slog.String("connection", id), pclog.Err(err))
	}
	if in.relay != nil {
		_ = in.relay.Close()
	}
	if in.dir != "" {
		_ = os.RemoveAll(in.dir)
	}
	select {
	case <-in.done:
	case <-time.After(stopTimeout):
	}
	for _, f := range in.pipes {
		_ = f.Close()
	}
}

// WithReporter reports every run's state through r.
func (s *Supervisor) WithReporter(r Reporter) *Supervisor {
	s.report = r
	return s
}

// tell reports a run's state; a failed report is logged, never fatal.
func (s *Supervisor) tell(ctx context.Context, run, connection string, revision int32, name string, state pb.ConnectorState, class string) {
	if s.report == nil {
		return
	}
	ev := s.engine.Evidence(s.engine.Runtime())
	if err := s.report(context.WithoutCancel(ctx), &pb.ReportConnectorStateRequest{
		InstanceId: run, ConnectionId: connection, SpecRevision: revision, State: state, ContainerName: name,
		EngineVersion: ev.Version, ApiVersion: ev.APIVersion, Runtime: ev.Runtime, ErrorClass: class,
	}); err != nil {
		s.log.WarnContext(ctx, "gateway.connector_report_failed", slog.String("connection", connection), pclog.Err(err))
	}
}
