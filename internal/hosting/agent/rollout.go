// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Upgrades (G0 M19 item 18, ADR-0041). The server sets a hosted gateway's
// target from its org's fleet policy; the agent rolls one org at a time.
// The reconcile loop is single-threaded and waits for each upgrade, so a
// second org starts only after the first answers its health check, and
// only while every other process on the host is serving.
const (
	// DefaultRollTimeout is how long an upgraded process has to answer.
	DefaultRollTimeout = 2 * time.Minute
	// RollHold is how long a version that failed here is left alone. While
	// it lasts no org on this host rolls to it.
	RollHold = time.Hour
	// rollPoll is how often the agent checks an upgraded process.
	rollPoll = 2 * time.Second
)

var errUpgradeUnhealthy = errors.New("hosting agent: the upgraded process did not answer")

// imageOf finds a version's image, with or without the leading v: the
// server reports fleet versions as vMAJOR.MINOR.PATCH.
func (a *Agent) imageOf(version string) (string, bool) {
	if version == "" {
		return "", false
	}
	for _, v := range []string{version, strings.TrimPrefix(version, "v"), "v" + version} {
		if img, ok := a.Images[v]; ok {
			return img, true
		}
	}
	return "", false
}

// roll upgrades at most one RUNNING process toward its target. routes are
// the routes just set; roll updates them, since a new container may get a
// new address.
func (a *Agent) roll(ctx context.Context, assignments []*pb.HostingAssignment, routes map[string]string) error {
	var next *pb.HostingAssignment
	for _, as := range assignments {
		if as.GetState() != pb.HostedGatewayState_HOSTED_GATEWAY_STATE_RUNNING {
			continue
		}
		if routes[as.GetSlug()] == "" {
			return nil // something on this host is not serving: wait
		}
		if next == nil && a.due(as) {
			next = as
		}
	}
	if next == nil {
		return nil
	}
	return a.upgrade(ctx, next, routes)
}

// due reports whether as should move to its target now. A target this host
// has no image for waits until the operator lists one.
func (a *Agent) due(as *pb.HostingAssignment) bool {
	target := as.GetTargetVersion()
	if target == "" || target == as.GetVersion() {
		return false
	}
	if until, ok := a.held[target]; ok {
		if time.Now().Before(until) {
			return false
		}
		delete(a.held, target)
	}
	_, ok := a.imageOf(target)
	return ok
}

// upgrade replaces one process with the target image, keeping its volume
// (and so its identity) and its network. A process that does not answer in
// time is replaced by the version it ran, and the target is held.
func (a *Agent) upgrade(ctx context.Context, as *pb.HostingAssignment, routes map[string]string) error {
	hosted, err := ids.ParseUUID(as.GetId())
	if err != nil {
		return err
	}
	target := as.GetTargetVersion()
	img, _ := a.imageOf(target)
	a.Log.InfoContext(ctx, "hosting.upgrade_started", slog.String("hosted_gateway", as.GetId()),
		slog.String("from", as.GetVersion()), slog.String("to", target))
	addr, err := a.replace(ctx, as, hosted, img)
	if err == nil {
		routes[as.GetSlug()] = addr
		a.Router.Set(routes)
		_, err := a.Control.ReportHostedGateway(ctx, &pb.ReportHostedGatewayRequest{
			OrgId: as.GetOrgId(), Id: as.GetId(), Healthy: true, Version: target,
		})
		return err
	}
	if a.held == nil {
		a.held = map[string]time.Time{}
	}
	a.held[target] = time.Now().Add(RollHold)
	delete(routes, as.GetSlug())
	a.Router.Set(routes)
	failed := fmt.Errorf("upgrade of %s to %s: %w", as.GetId(), target, err)
	old, version := a.image(as.GetVersion())
	addr, err = a.replace(ctx, as, hosted, old)
	if err != nil {
		// The next reconcile starts it again.
		return errors.Join(failed, fmt.Errorf("rollback: %w", err))
	}
	routes[as.GetSlug()] = addr
	a.Router.Set(routes)
	_, err = a.Control.ReportHostedGateway(ctx, &pb.ReportHostedGatewayRequest{
		OrgId: as.GetOrgId(), Id: as.GetId(), Healthy: true, Version: version,
	})
	return errors.Join(failed, err)
}

// replace swaps a hosted gateway's container for one running img and waits
// until it answers, returning its address.
func (a *Agent) replace(ctx context.Context, as *pb.HostingAssignment, hosted ids.UUID, img string) (string, error) {
	names := profile.NamesOf(hosted)
	if err := a.Engine.RemoveContainer(ctx, names.Container); err != nil && !notFound(err) {
		return "", err
	}
	if err := a.run(ctx, a.spec(hosted, as.GetLimits(), img)); err != nil {
		return "", err
	}
	timeout := a.RollTimeout
	if timeout == 0 {
		timeout = DefaultRollTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		info, err := a.Engine.InspectContainer(ctx, names.Container)
		if ip := info.Address(names.Network); err == nil && info.State.Running && ip != "" {
			addr := net.JoinHostPort(ip, strconv.Itoa(profile.Port))
			if a.health(ctx, addr) == nil {
				return addr, nil
			}
		}
		if !time.Now().Before(deadline) {
			return "", errUpgradeUnhealthy
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(min(rollPoll, timeout)):
		}
	}
}
