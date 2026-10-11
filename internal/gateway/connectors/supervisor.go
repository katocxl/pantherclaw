// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
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
	engine docker.Engine
	conf   Configuration
	log    *slog.Logger
	report Reporter

	mu      sync.Mutex
	running map[string]*instance
	failed  map[string]time.Time
}

type instance struct {
	id            string
	revision      int32
	name, network string
	client        *upstream.Client
	stdio         *Stdio
	stdin         *io.PipeWriter
	stop          context.CancelFunc
	done          chan struct{}
}

// New returns a supervisor on this host's engine, which must pass the
// sandbox's engine check (Docker 28 or later, Linux, seccomp, runc;
// HR-218). The gateway must run as a host process, not inside a container.
func New(ctx context.Context, c *docker.Client, conf Configuration, log *slog.Logger) (*Supervisor, error) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
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
	return &Supervisor{c: c, engine: e, conf: conf, log: log, running: map[string]*instance{}, failed: map[string]time.Time{}}, nil
}

// Client implements dispatch.Connectors.
func (s *Supervisor) Client(connection string) (*upstream.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.running[connection]
	if !ok {
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
// replaces those whose revision changed or whose container stopped, and
// stops those no longer configured.
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
	for id, in := range s.running {
		c, ok := want[id]
		select {
		case <-in.done:
			ok = false
		default:
		}
		if !ok || c.GetRevision() != in.revision {
			stale = append(stale, id)
		}
	}
	s.mu.Unlock()
	for _, id := range stale {
		s.stop(ctx, id)
	}
	for id, c := range want {
		s.mu.Lock()
		_, running := s.running[id]
		last, failed := s.failed[id]
		s.mu.Unlock()
		if running || (failed && time.Since(last) < RetryAfter) {
			continue
		}
		if err := s.start(ctx, c); err != nil {
			s.log.WarnContext(ctx, "gateway.connector_failed", slog.String("connection", id), pclog.Err(err))
			s.mu.Lock()
			s.failed[id] = time.Now()
			s.mu.Unlock()
		}
	}
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
	env := make([]string, 0, len(spec.GetEnvironment())+len(spec.GetCredentialPlaceholders()))
	for _, k := range slices.Sorted(maps.Keys(spec.GetEnvironment())) {
		env = append(env, k+"="+spec.GetEnvironment()[k])
	}
	for _, k := range spec.GetCredentialPlaceholders() {
		env = append(env, k+"="+Placeholder)
	}
	l := spec.GetLimits()
	if _, err := s.c.CreateContainer(ctx, docker.Container{
		Name: name, Image: spec.GetImage(), User: User, Args: spec.GetCommand(), Networks: []string{net}, Env: env,
		Runtime: s.engine.Runtime(), Labels: labels, Interactive: true,
		Limits: docker.Limits{PIDs: int(l.GetPids()), MemoryMiB: int(l.GetMemoryMib()), MilliCPUs: int(l.GetMilliCpus())},
	}); err != nil {
		_ = s.c.RemoveLabelled(context.WithoutCancel(ctx), id)
		return fail("container", err)
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		code, err := s.c.Attach(runCtx, name, inR, outW)
		outW.CloseWithError(errors.Join(ErrExited, err))
		_ = inR.Close()
		s.log.InfoContext(runCtx, "gateway.connector_stopped", slog.String("connection", id), slog.Int("exit_code", code), pclog.Err(err))
		state, class := pb.ConnectorState_CONNECTOR_STATE_STOPPED, ""
		if runCtx.Err() == nil {
			state, class = pb.ConnectorState_CONNECTOR_STATE_FAILED, "exited"
		}
		s.tell(runCtx, run, id, rev, name, state, class)
	}()
	stdio := NewStdio(inW, outR)
	s.mu.Lock()
	s.running[id] = &instance{
		id: run, revision: c.GetRevision(), name: name, network: net, stdio: stdio, stdin: inW, stop: cancel, done: done,
		client: upstream.New("http://connector.invalid/"+id, stdio),
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
	in.stop()
	_ = in.stdin.Close() // os/exec waits for stdin's copy until the pipe closes
	if err := s.c.RemoveLabelled(context.WithoutCancel(ctx), id); err != nil {
		s.log.WarnContext(ctx, "gateway.connector_not_removed", slog.String("connection", id), pclog.Err(err))
	}
	select {
	case <-in.done:
	case <-time.After(stopTimeout):
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
