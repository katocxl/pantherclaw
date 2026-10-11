// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package docker_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
)

const selfcheck = "github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest/testdata/selfcheck"

func TestHR218_ThisEngineRunsTheSandboxAndIsRecorded(t *testing.T) {
	c, e := dockertest.Client(t)
	net := dockertest.Network(t, c, true)
	info := dockertest.Container(t, c, docker.Container{
		Name: docker.NewName("test"), Image: docker.BaseImage, User: "65532:65532", Args: []string{"/nothing"},
		Networks: []string{net.Name}, Runtime: e.Runtime(),
	})
	ev := e.Evidence(info.Runtime())
	if ev.Version == "" || ev.APIVersion == "" || ev.Runtime != e.Runtime() {
		t.Fatalf("evidence %+v", ev)
	}
	t.Logf("engine evidence: %+v (gVisor installed: %v)", ev, e.GVisor())
}

// TestHR122_AnIsolatedContainerHasNoRouteOut runs a hardened container on
// an internal network in isolated gateway mode and checks, from inside, the
// basics B3's probes later check in full: non-root, read-only root, noexec
// /tmp, and no route to the internet, metadata, the host or the bridge.
func TestHR122_AnIsolatedContainerHasNoRouteOut(t *testing.T) {
	c, e := dockertest.Client(t)
	bin := dockertest.BuildLinux(t, e, selfcheck)
	net := dockertest.Network(t, c, true)
	prefix, err := netip.ParsePrefix(net.Subnet())
	if err != nil {
		t.Fatalf("subnet %q: %v", net.Subnet(), err)
	}
	bridge := prefix.Addr().Next().String()
	targets := []string{"192.0.2.1:443", "198.51.100.1:53", "169.254.169.254:80", "host.docker.internal:80", "172.17.0.1:2375", bridge + ":53", bridge + ":2375"}
	name := docker.NewName("test")
	dockertest.Container(t, c, docker.Container{
		Name: name, Image: docker.BaseImage, User: "65532:65532", Args: append([]string{"/pc/selfcheck"}, targets...),
		Networks: []string{net.Name}, Runtime: e.Runtime(), Mounts: []docker.Mount{{Kind: docker.Bind, Source: bin, Target: "/pc/selfcheck"}},
		Limits: docker.Limits{PIDs: 32, MemoryMiB: 64, MilliCPUs: 500},
	})
	if err := c.Start(t.Context(), name); err != nil {
		t.Fatal(err)
	}
	if code, err := c.Wait(t.Context(), name); err != nil || code != 0 {
		t.Fatalf("selfcheck exited %d, %v", code, err)
	}
	out, err := c.Logs(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	want := []string{"uid 65532", "root-write denied", "tmp-write allowed", "tmp-exec denied"}
	for _, a := range targets {
		want = append(want, "dial "+a+" denied")
	}
	for _, w := range want {
		if !strings.Contains(got, w+"\n") {
			t.Errorf("selfcheck lacks %q:\n%s", w, got)
		}
	}
}

// TestHR218_GVisorIsUsedWhenInstalled: runsc, when the engine lists it and
// is not Docker Desktop, is the runtime every container gets.
func TestHR218_GVisorIsUsedWhenInstalled(t *testing.T) {
	c, e := dockertest.Client(t)
	if e.Runtime() != docker.RuntimeRunsc {
		t.Skipf("no runsc to use in %s (desktop: %v, listed: %v)", e.Platform, e.Desktop, e.GVisor())
	}
	net := dockertest.Network(t, c, true)
	info := dockertest.Container(t, c, docker.Container{
		Name: docker.NewName("test"), Image: docker.BaseImage, User: "65532:65532", Args: []string{"/nothing"},
		Networks: []string{net.Name}, Runtime: e.Runtime(),
	})
	if got := e.Evidence(info.Runtime()).Runtime; got != docker.RuntimeRunsc {
		t.Fatalf("runtime %q", got)
	}
}
