// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package profile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

const image = "ghcr.io/katocxl/pantherclaw-gateway@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// recorder captures the first docker command and fails it, so nothing is
// inspected: the test reads the arguments only.
type recorder struct{ calls [][]string }

func (r *recorder) Run(_ context.Context, args ...string) ([]byte, error) {
	r.calls = append(r.calls, args)
	return nil, errors.New("not an engine")
}

func spec(t *testing.T) Spec {
	t.Helper()
	parent := t.TempDir()
	if p, err := filepath.EvalSymlinks(parent); err == nil {
		parent = p
	}
	root := filepath.Join(parent, "org")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return Spec{Hosted: ids.NewV7(), Image: image, Root: root, Runtime: docker.RuntimeRunc}
}

func createArgs(t *testing.T, s Spec) []string {
	t.Helper()
	c, err := s.Container()
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	_, _ = docker.New(r).CreateContainer(context.Background(), c)
	if len(r.calls) == 0 || r.calls[0][0] != "create" {
		t.Fatalf("no create command: %v", r.calls)
	}
	return r.calls[0]
}

func flagValues(args []string, flag string) []string {
	var out []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			out = append(out, args[i+1])
		}
	}
	return out
}

// TestHR501_TheContainerIsIsolated: the hosted gateway's container runs as
// a non-root uid of its own, with a read-only root, every capability
// dropped, no new privileges, private namespaces, cgroup limits, its own
// network only, and no Docker socket, host network or published port.
//
// Covers: PN-010.4
func TestHR501_TheContainerIsIsolated(t *testing.T) {
	s := spec(t)
	args := createArgs(t, s)
	for _, want := range []string{"--read-only", "--init"} {
		if !slices.Contains(args, want) {
			t.Errorf("missing %s", want)
		}
	}
	checks := map[string]string{
		"--cap-drop": "ALL", "--ipc": "private", "--cgroupns": "private", "--runtime": docker.RuntimeRunc,
		"--pids-limit": "128", "--memory": "256m", "--cpus": "0.500", "--network": NamesOf(s.Hosted).Network,
	}
	for flag, want := range checks {
		if got := flagValues(args, flag); !slices.Equal(got, []string{want}) {
			t.Errorf("%s = %v, want [%s]", flag, got, want)
		}
	}
	if got := flagValues(args, "--security-opt"); !slices.Contains(got, "no-new-privileges=true") {
		t.Errorf("security options %v", got)
	}
	user := flagValues(args, "--user")
	if len(user) != 1 || strings.HasPrefix(user[0], "0:") || UID(s.Hosted) < docker.MinID {
		t.Errorf("user %v", user)
	}
	for _, a := range args {
		l := strings.ToLower(a)
		if strings.Contains(l, "docker.sock") || a == "--privileged" || a == "host" || strings.HasPrefix(a, "--publish") || a == "-p" || strings.HasPrefix(a, "--cap-add") {
			t.Errorf("forbidden argument %q", a)
		}
	}
	mounts := flagValues(args, "--mount")
	if len(mounts) != 2 {
		t.Fatalf("mounts %v", mounts)
	}
	for _, m := range mounts {
		if strings.HasPrefix(m, "type=bind") && !strings.HasSuffix(m, ",readonly") {
			t.Errorf("a bind mount is writable: %s", m)
		}
	}
}

// TestHR501_LimitsAreClampedAndOrgsGetTheirOwnUID: limits a record asks
// for never pass the ceilings, missing ones take the defaults, and two
// orgs get different uids, networks and volumes.
//
// Covers: PN-010.4
func TestHR501_LimitsAreClampedAndOrgsGetTheirOwnUID(t *testing.T) {
	s := spec(t)
	s.Limits = Limits{MilliCPUs: 64000, MemoryMiB: 1 << 20, PIDs: -1}
	c, err := s.Container()
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.MilliCPUs != Ceilings.MilliCPUs || c.Limits.MemoryMiB != Ceilings.MemoryMiB || c.Limits.PIDs != DefaultLimits.PIDs {
		t.Errorf("limits %+v", c.Limits)
	}
	other := spec(t)
	a, b := NamesOf(s.Hosted), NamesOf(other.Hosted)
	if a.Network == b.Network || a.Volume == b.Volume || a.Container == b.Container {
		t.Error("two orgs share an engine object")
	}
	if UID(s.Hosted) == UID(other.Hosted) {
		t.Error("two orgs share a uid")
	}
}

// TestHR501_ProfileRefusesUnpinnedImagesAndRuntimes: an image not pinned
// by digest, a relative private directory or an unnamed runtime is
// refused before anything runs.
//
// Covers: PN-010.4
func TestHR501_ProfileRefusesUnpinnedImagesAndRuntimes(t *testing.T) {
	for name, mut := range map[string]func(*Spec){
		"tag":      func(s *Spec) { s.Image = "ghcr.io/katocxl/pantherclaw-gateway:latest" },
		"relative": func(s *Spec) { s.Root = "org" },
		"runtime":  func(s *Spec) { s.Runtime = "" },
		"no id":    func(s *Spec) { s.Hosted = ids.UUID{} },
	} {
		s := spec(t)
		mut(&s)
		if _, err := s.Container(); !errors.Is(err, ErrProfile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR502_TheTokenIsNeverInTheEnvironment: the container's environment
// and arguments carry no enrollment token; the gateway reads it from the
// read-only mount of the host's private tmpfs directory.
//
// Covers: PN-010.4
func TestHR502_TheTokenIsNeverInTheEnvironment(t *testing.T) {
	s := spec(t)
	c, err := s.Container()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Env {
		if strings.Contains(strings.ToLower(e), "token") || strings.Contains(e, "pcg_") {
			t.Errorf("environment carries %q", e)
		}
	}
	if !slices.Contains(c.Args, TokenFile) || !strings.HasPrefix(TokenFile, EnrollDir+"/") {
		t.Errorf("args %v", c.Args)
	}
	var bind docker.Mount
	for _, m := range c.Mounts {
		if m.Kind == docker.Bind {
			bind = m
		}
	}
	if bind.Source != s.Root || bind.Target != EnrollDir || !bind.ReadOnly {
		t.Errorf("token mount %+v", bind)
	}
}
