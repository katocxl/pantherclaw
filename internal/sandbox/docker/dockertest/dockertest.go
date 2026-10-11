// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package dockertest gives the Docker-gated tests (build tag sandbox, run by
// `task test:sandbox`) a checked engine, and networks and containers that
// are removed when the test ends. The engine is shared with other sessions:
// every name is fresh (docker.NewName) and nothing else is touched.
package dockertest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
)

// RequireEnv runs the Docker tests: unset, they skip; "1", an unreachable or
// unsuitable engine fails them.
const RequireEnv = "PC_TEST_SANDBOX"

// cleanupTimeout bounds each removal at the end of a test.
const cleanupTimeout = 30 * time.Second

// Client returns a client of the local engine, which passed Engine.Check
// (HR-218), with the base image pulled.
func Client(t testing.TB) (*docker.Client, docker.Engine) {
	t.Helper()
	if os.Getenv(RequireEnv) != "1" {
		t.Skip(RequireEnv + " is not 1")
	}
	c := docker.New(docker.CLI{})
	e, err := c.Engine(t.Context())
	if err != nil {
		t.Fatalf("docker engine: %v", err)
	}
	if err := e.Check(); err != nil {
		t.Fatal(err)
	}
	if err := c.Pull(t.Context(), docker.BaseImage); err != nil {
		t.Fatal(err)
	}
	return c, e
}

// Network creates a network that is removed when the test ends; its name
// is fresh.
func Network(t testing.TB, c *docker.Client, internal bool) docker.NetworkInfo {
	t.Helper()
	n := docker.Network{Name: docker.NewName("test"), Internal: internal, Labels: map[string]string{"org.pantherclaw.test": t.Name()}}
	info, err := c.CreateNetwork(t.Context(), n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := c.RemoveNetwork(ctx, n.Name); err != nil {
			t.Errorf("remove network %s: %v", n.Name, err)
		}
	})
	return info
}

// Container creates ct and removes it when the test ends. Remove it before
// its networks: cleanups run last first, so create networks first.
func Container(t testing.TB, c *docker.Client, ct docker.Container) docker.ContainerInfo {
	t.Helper()
	info, err := c.CreateContainer(t.Context(), ct)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := c.RemoveContainer(ctx, ct.Name); err != nil {
			t.Errorf("remove container %s: %v", ct.Name, err)
		}
	})
	return info
}

// BuildLinux builds the package pkg (an import path in this module) as a
// static Linux binary for the engine's architecture and returns its path.
// Containers get it as a read-only bind mount, with its directory as
// their bind root.
func BuildLinux(t testing.TB, e docker.Engine, pkg string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", out, pkg) //nolint:gosec // G204: test helper, fixed program
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+e.Arch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return out
}

// Image builds the image of a repository Dockerfile (for example
// deploy/sandbox/edge.Dockerfile) around a static Linux build of pkg, as
// task sandbox:images does, and removes it when the test ends. The test's
// name is a label, so that concurrent test packages never share an image.
func Image(t testing.TB, c *docker.Client, e docker.Engine, pkg, dockerfile string) string {
	t.Helper()
	bin := BuildLinux(t, e, pkg)
	// The probe image copies an empty workspace directory from its context.
	if err := os.Mkdir(filepath.Join(filepath.Dir(bin), "workspace"), 0o750); err != nil {
		t.Fatal(err)
	}
	id, err := c.BuildImage(t.Context(), filepath.Join(repoRoot(t), filepath.FromSlash(dockerfile)), filepath.Dir(bin),
		map[string]string{"org.pantherclaw.test": t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := c.RemoveImage(ctx, id); err != nil {
			t.Errorf("remove image %s: %v", id, err)
		}
	})
	return id
}

// repoRoot is the directory of the module's go.mod above the test's.
func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}
