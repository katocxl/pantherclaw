// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

const newImg = "ghcr.io/katocxl/pantherclaw-gateway@sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// rolling returns an agent with two RUNNING orgs on version 1.0.0, each
// with the target v1.1.0, and their containers serving.
func rolling(t *testing.T) (*Agent, *control, *engine, [2]string) {
	t.Helper()
	a, c, e, _ := newAgent(t)
	a.Images["1.1.0"] = newImg
	a.RollTimeout = time.Millisecond
	var names [2]string
	for i, slug := range []string{"acme", "bravo"} {
		as, hosted := assignment(pb.HostedGatewayState_HOSTED_GATEWAY_STATE_RUNNING)
		as.Slug, as.Version = slug, "1.0.0"
		c.assignments = append(c.assignments, as)
		names[i] = profile.NamesOf(hosted).Container
	}
	for range 2 { // the first starts the containers, the second routes them
		if err := a.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, as := range c.assignments {
		as.TargetVersion = "v1.1.0"
	}
	c.reports = nil
	return a, c, e, names
}

// lastVersion returns the last version reported for as.
func lastVersion(c *control, as *pb.HostingAssignment) string {
	v := ""
	for _, r := range c.reports {
		if r.GetId() == as.GetId() {
			v = r.GetVersion()
		}
	}
	return v
}

// TestUpgradesRollOneOrgAtATime: one reconcile moves one org to the target
// image and reports the new version; the next org moves only on a later
// reconcile, and an org at its target stays.
//
// Covers: PN-010.4
func TestUpgradesRollOneOrgAtATime(t *testing.T) {
	a, c, e, names := rolling(t)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.containers[names[0]].Image != newImg || e.containers[names[1]].Image != img {
		t.Fatalf("images %q %q", e.containers[names[0]].Image, e.containers[names[1]].Image)
	}
	if got := lastVersion(c, c.assignments[0]); got != "v1.1.0" {
		t.Fatalf("reported %q", got)
	}
	if got := a.Router.Slug("acme.gw.example.test"); got != "acme" {
		t.Fatalf("slug %q after the upgrade", got)
	}
	c.assignments[0].Version = "v1.1.0" // the server's record of the report
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.containers[names[1]].Image != newImg {
		t.Fatal("the second org did not follow")
	}
	c.assignments[1].Version = "v1.1.0"
	before := len(*e.order)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*e.order) != before {
		t.Fatalf("a finished roll-out touched containers: %v", (*e.order)[before:])
	}
}

// TestAFailedUpgradeRollsBackAndStopsTheRollOut: a process that does not
// answer goes back to the version it ran, the version it failed on is held
// so no other org on the host rolls to it, and a version with no image
// here is left alone.
//
// Covers: PN-010.4
func TestAFailedUpgradeRollsBackAndStopsTheRollOut(t *testing.T) {
	a, c, e, names := rolling(t)
	a.Health = func(context.Context, string) error {
		if e.containers[names[0]].Image == newImg {
			return errors.New("no answer")
		}
		return nil
	}
	if err := a.Reconcile(context.Background()); !errors.Is(err, errUpgradeUnhealthy) {
		t.Fatalf("reconcile: %v", err)
	}
	if e.containers[names[0]].Image != img || !e.running[names[0]] {
		t.Fatalf("not rolled back: %q", e.containers[names[0]].Image)
	}
	if got := lastVersion(c, c.assignments[0]); got != "1.0.0" {
		t.Fatalf("reported %q", got)
	}
	if got := a.Router.Slug("acme.gw.example.test"); got != "acme" {
		t.Fatalf("slug %q after the rollback", got)
	}
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.containers[names[1]].Image != img {
		t.Fatal("another org rolled to a version that failed")
	}
	a.held = nil
	c.assignments[0].TargetVersion, c.assignments[1].TargetVersion = "v9.9.9", "v9.9.9"
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.containers[names[0]].Image != img {
		t.Fatal("rolled to a version with no image")
	}
}

// TestNoUpgradeWhileAProcessIsDown: a process that is not serving stops
// the roll-out on its host until it is back.
//
// Covers: PN-010.4
func TestNoUpgradeWhileAProcessIsDown(t *testing.T) {
	a, _, e, names := rolling(t)
	a.Health = func(context.Context, string) error { return errors.New("down") }
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.containers[names[0]].Image != img || e.containers[names[1]].Image != img {
		t.Fatal("rolled while a process was down")
	}
}

// TestAProcessNoAssignmentNamesIsRemoved: the record of a deleted org is
// gone, so its container, network, volume and directory go with no report,
// and an assigned process stays. A failed listing removes nothing (D228).
//
// Covers: PN-010.4
func TestAProcessNoAssignmentNamesIsRemoved(t *testing.T) {
	a, c, e, _ := newAgent(t)
	as, hosted := assignment(pb.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED)
	c.assignments = append(c.assignments, as)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	gone := ids.NewV7()
	names := profile.NamesOf(gone)
	e.containers[names.Container] = docker.Container{Name: names.Container}
	e.running[names.Container] = true
	var volumes []string
	a.Volumes = func(_ context.Context, name string) error {
		volumes = append(volumes, name)
		return nil
	}
	a.Running = func(context.Context) ([]ids.UUID, error) { return nil, errors.New("no engine") }
	if err := a.Reconcile(context.Background()); err == nil || e.containers[names.Container].Name == "" {
		t.Fatalf("a failed listing: %v, %d containers", err, len(e.containers))
	}
	a.Running = func(context.Context) ([]ids.UUID, error) { return []ids.UUID{hosted, gone}, nil }
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.containers[names.Container]; ok || len(volumes) != 1 || volumes[0] != names.Volume {
		t.Fatalf("still there: %v, volumes %v", e.containers, volumes)
	}
	if _, ok := e.containers[profile.NamesOf(hosted).Container]; !ok {
		t.Fatal("removed an assigned process")
	}
}

// TestAnUnfinishedRemovalFinishesOnTheNextSweep: the private directory goes
// last, so a removal stopped after the container or after the network
// leaves the directory, and the next sweep finishes it from that alone. An
// assigned gateway's directory and anything else in the root stay, and a
// failed listing removes nothing (D231).
//
// Covers: PN-010.4
func TestAnUnfinishedRemovalFinishesOnTheNextSweep(t *testing.T) {
	a, c, e, _ := newAgent(t)
	as, hosted := assignment(pb.HostedGatewayState_HOSTED_GATEWAY_STATE_PROVISIONED)
	c.assignments = append(c.assignments, as)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var volumes []string
	var volumeErr error
	a.Volumes = func(_ context.Context, name string) error {
		if err := volumeErr; err != nil {
			volumeErr = nil
			return err
		}
		volumes = append(volumes, name)
		return nil
	}
	a.Running = func(context.Context) ([]ids.UUID, error) { return nil, nil }
	failed := errors.New("engine busy")
	for name, stop := range map[string]func(){
		"after the container": func() { e.networkErr = failed },
		"after the network":   func() { volumeErr = failed },
	} {
		t.Run(name, func(t *testing.T) {
			e.networks, volumes = nil, nil
			gone := ids.NewV7()
			names := profile.NamesOf(gone)
			if _, err := a.Private.Prepare(gone, "https://gw-api.example.test:8443", "sha256:aa"); err != nil {
				t.Fatal(err)
			}
			a.Running = func(context.Context) ([]ids.UUID, error) { return []ids.UUID{gone}, nil }
			stop()
			if err := a.Reconcile(context.Background()); !errors.Is(err, failed) {
				t.Fatalf("stopped removal: %v", err)
			}
			if _, err := os.Stat(a.Private.Dir(gone)); err != nil {
				t.Fatalf("the directory went before the rest: %v", err)
			}
			a.Running = func(context.Context) ([]ids.UUID, error) { return nil, nil } // the container is gone
			if err := a.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(a.Private.Dir(gone)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the directory stayed: %v", err)
			}
			if !slices.Contains(e.networks, names.Network) || !slices.Contains(volumes, names.Volume) {
				t.Fatalf("networks %v, volumes %v", e.networks, volumes)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(a.Private.Dir(hosted), filepath.Base(profile.ConfigFile))); err != nil {
		t.Fatalf("an assigned gateway's directory: %v", err)
	}
	gone := ids.NewV7()
	foreign := []string{"lost+found", "pc-hgc-notahex", "PC-HGC-" + profile.NamesOf(gone).Container[len("pc-hgc-"):], strings.ToUpper(profile.NamesOf(gone).Container)}
	for _, name := range foreign {
		if err := os.MkdirAll(filepath.Join(a.Private.Root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.networks = nil
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.networks) != 0 {
		t.Fatalf("removed for a foreign name: %v", e.networks)
	}
	for _, name := range foreign {
		if _, err := os.Stat(filepath.Join(a.Private.Root, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	names := profile.NamesOf(gone)
	e.containers[names.Container] = docker.Container{Name: names.Container}
	a.Running = func(context.Context) ([]ids.UUID, error) { return []ids.UUID{gone}, nil }
	a.Private = &Private{Root: filepath.Join(a.Private.Root, "missing")}
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("a failed directory listing was not reported")
	}
	if _, ok := e.containers[names.Container]; !ok {
		t.Fatal("a failed directory listing removed a container")
	}
}
