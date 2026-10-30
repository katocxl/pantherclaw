// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package agent is the host agent of a shared hosting host (G0 M19 D203,
// ADR-0041): cmd/pantherclaw-host. Over its own host certificate (no org,
// purpose "hosting", HR-500) it fetches the hosted gateways placed on its
// host, runs one isolated container per org through the Docker CLI with
// fixed arguments (internal/hosting/profile, HR-501), hands each its
// single-use enrollment token through the org's private tmpfs directory
// only (HR-502), routes agents to it by server name without terminating
// TLS (internal/hosting/sni), and stops a deprovisioned one only after the
// server revoked it (HR-503).
package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/hosting/sni"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// Engine is what the agent asks of the Docker CLI (docker.Client).
type Engine interface {
	CreateNetwork(ctx context.Context, n docker.Network) (docker.NetworkInfo, error)
	RemoveNetwork(ctx context.Context, name string) error
	CreateContainer(ctx context.Context, c docker.Container) (docker.ContainerInfo, error)
	InspectContainer(ctx context.Context, name string) (docker.ContainerInfo, error)
	Start(ctx context.Context, name string) error
	RemoveContainer(ctx context.Context, name string) error
}

// Agent reconciles a host's hosted gateways.
type Agent struct {
	Control pantherclawv1connect.HostingAgentServiceClient
	Engine  Engine
	// Volumes removes a hosted gateway's state volume on deprovision.
	Volumes func(ctx context.Context, name string) error
	Private *Private
	Router  *sni.Router
	// Images maps a gateway version to its image, pinned by digest; the
	// first version listed is the default (operator configuration).
	Images  map[string]string
	Default string
	Runtime string
	Version string
	Log     *slog.Logger
	// Health checks a running process; default: a TCP connect to its port.
	Health func(ctx context.Context, addr string) error
	// RollTimeout bounds the wait for an upgraded process to answer;
	// default DefaultRollTimeout.
	RollTimeout time.Duration
	// held maps a version whose upgrade failed here to when it may be tried
	// again (rollout.go).
	held map[string]time.Time
}

// Interval is how often the agent reconciles.
const Interval = 10 * time.Second

// Run reconciles every Interval until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		if err := a.Reconcile(ctx); err != nil && ctx.Err() == nil {
			a.Log.WarnContext(ctx, "hosting.reconcile_failed", pclog.Err(err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// Reconcile brings the host to its assignments once.
func (a *Agent) Reconcile(ctx context.Context) error {
	res, err := a.Control.ListAssignments(ctx, &pb.ListAssignmentsRequest{AgentVersion: a.Version})
	if err != nil {
		return err
	}
	routes := map[string]string{}
	var errs []error
	for _, as := range res.GetAssignments() {
		addr, err := a.reconcileOne(ctx, as)
		if err != nil {
			errs = append(errs, err)
			a.Log.WarnContext(ctx, "hosting.assignment_failed", slog.String("hosted_gateway", as.GetId()), pclog.Err(err))
		}
		if addr != "" {
			routes[as.GetSlug()] = addr
		}
	}
	a.Router.Set(routes)
	if err := a.roll(ctx, res.GetAssignments(), routes); err != nil {
		errs = append(errs, err)
		a.Log.WarnContext(ctx, "hosting.upgrade_failed", pclog.Err(err))
	}
	return errors.Join(errs...)
}

func (a *Agent) image(version string) (string, string) {
	if img, ok := a.imageOf(version); ok {
		return img, version
	}
	return a.Images[a.Default], a.Default
}

func (a *Agent) spec(hosted ids.UUID, l *pb.HostedGatewayLimits, image string) profile.Spec {
	return profile.Spec{
		Hosted: hosted, Image: image, Root: a.Private.Dir(hosted), Runtime: a.Runtime,
		Limits: profile.Limits{MilliCPUs: int(l.GetMilliCpus()), MemoryMiB: int(l.GetMemoryMib()), PIDs: int(l.GetPids())},
	}
}

// reconcileOne acts on one assignment and returns its route, if it serves.
func (a *Agent) reconcileOne(ctx context.Context, as *pb.HostingAssignment) (string, error) {
	hosted, err := ids.ParseUUID(as.GetId())
	if err != nil {
		return "", err
	}
	names := profile.NamesOf(hosted)
	switch as.GetState() {
	case pb.HostedGatewayState_HOSTED_GATEWAY_STATE_DEPROVISIONING:
		// The server revoked the gateway before it got here (HR-503).
		return "", a.stop(ctx, as, hosted)
	case pb.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED:
		return "", a.start(ctx, as, hosted)
	case pb.HostedGatewayState_HOSTED_GATEWAY_STATE_ENROLLED, pb.HostedGatewayState_HOSTED_GATEWAY_STATE_RUNNING:
		info, err := a.Engine.InspectContainer(ctx, names.Container)
		if err != nil || !info.State.Running {
			// Gone or stopped: start it again; it keeps its identity in
			// its volume, so it needs no token.
			_ = a.Engine.RemoveContainer(ctx, names.Container)
			img, _ := a.image(as.GetVersion())
			if err := a.run(ctx, hosted, a.spec(hosted, as.GetLimits(), img)); err != nil {
				return "", err
			}
			return "", nil
		}
		addr := net.JoinHostPort(info.Address(names.Network), strconv.Itoa(profile.Port))
		healthy := info.Address(names.Network) != "" && a.health(ctx, addr) == nil
		if healthy {
			// Enrolled: the token is spent; it leaves the tmpfs too.
			if err := a.Private.RemoveToken(hosted); err != nil {
				return "", err
			}
		}
		_, version := a.image(as.GetVersion())
		if _, err := a.Control.ReportHostedGateway(ctx, &pb.ReportHostedGatewayRequest{
			OrgId: as.GetOrgId(), Id: as.GetId(), Healthy: healthy, Version: version,
		}); err != nil {
			return "", err
		}
		if !healthy {
			return "", nil
		}
		return addr, nil
	}
	return "", nil
}

func (a *Agent) health(ctx context.Context, addr string) error {
	if a.Health != nil {
		return a.Health(ctx, addr)
	}
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

// start provisions a placed hosted gateway: its private directory with its
// configuration, the token pulled once and written there, its network and
// its container.
func (a *Agent) start(ctx context.Context, as *pb.HostingAssignment, hosted ids.UUID) error {
	tok, err := a.Control.PullEnrollmentToken(ctx, &pb.PullEnrollmentTokenRequest{OrgId: as.GetOrgId(), Id: as.GetId()})
	if err != nil {
		if connect.CodeOf(err) == connect.CodeFailedPrecondition {
			return nil // already pulled; the next list shows it ENROLLED
		}
		return err
	}
	if _, err := a.Private.Prepare(hosted, tok.GetGatewayApiUrl(), tok.GetCaSha256()); err != nil {
		return err
	}
	if err := a.Private.WriteToken(hosted, pclog.NewSecret(tok.GetToken())); err != nil {
		return err
	}
	img, _ := a.image(as.GetTargetVersion())
	return a.run(ctx, hosted, a.spec(hosted, as.GetLimits(), img))
}

// run creates the org's network and container and starts it.
func (a *Agent) run(ctx context.Context, hosted ids.UUID, s profile.Spec) error {
	c, err := s.Container()
	if err != nil {
		return err
	}
	n := s.Network()
	if _, err := a.Engine.CreateNetwork(ctx, n); err != nil && !alreadyExists(err) {
		return err
	}
	if _, err := a.Engine.CreateContainer(ctx, c); err != nil {
		return err
	}
	return a.Engine.Start(ctx, c.Name)
}

// stop removes a deprovisioned hosted gateway's container, network, volume
// and private directory, then reports it gone.
func (a *Agent) stop(ctx context.Context, as *pb.HostingAssignment, hosted ids.UUID) error {
	names := profile.NamesOf(hosted)
	if err := a.Engine.RemoveContainer(ctx, names.Container); err != nil && !notFound(err) {
		return err
	}
	if err := a.Engine.RemoveNetwork(ctx, names.Network); err != nil && !notFound(err) {
		return err
	}
	if a.Volumes != nil {
		if err := a.Volumes(ctx, names.Volume); err != nil && !notFound(err) {
			return err
		}
	}
	if err := a.Private.Remove(hosted); err != nil {
		return err
	}
	_, err := a.Control.ReportStopped(ctx, &pb.ReportStoppedRequest{OrgId: as.GetOrgId(), Id: as.GetId()})
	return err
}

func alreadyExists(err error) bool {
	var e *docker.Error
	return errors.As(err, &e) && containsFold(e.Stderr, "already exists")
}

func notFound(err error) bool {
	var e *docker.Error
	return errors.As(err, &e) && (containsFold(e.Stderr, "no such") || containsFold(e.Stderr, "not found"))
}

func containsFold(s, sub string) bool { return strings.Contains(strings.ToLower(s), sub) }
