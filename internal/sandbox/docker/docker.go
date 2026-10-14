// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package docker drives the Docker CLI for the containment sandbox and the
// connector runtime (G0 M9 decisions 1, 5 and 8). The package builds every
// argument itself and runs the docker executable without a shell; no
// container ever gets the Docker socket, the host network or the host
// environment (HR-216). Before anything runs, Engine.Check refuses an
// engine older than 28, and every network and container is inspected after
// creation and removed again unless the engine applied what was asked: the
// isolation self-check (HR-218).
package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// BaseImage is the image the sandbox's own containers (edge, probes) run:
// distroless static, non-root, pinned by digest. Their binaries are built
// for Linux and bind-mounted read-only; the image has no shell.
const BaseImage = "gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"

// Output limits: docker's answers are small JSON documents; a container's
// logs are capped by the caller's protocol (probe results).
const (
	maxOutput = 4 << 20
	maxStderr = 1 << 10
)

// Runner runs the Docker CLI with an argument vector and returns its
// standard output. CLI is the real one; tests use a fake.
type Runner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}

// CLI runs the docker executable found in PATH, directly, never through a
// shell. The CLI keeps the calling process's environment, which it needs
// for its context and configuration; containers never inherit it: every
// variable a container gets is a NAME=VALUE argument (HR-216).
type CLI struct{}

// Run runs one docker command.
func (CLI) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: a fixed program; this package builds and validates every argument (HR-216)
	var out, errOut capped
	out.max, errOut.max = maxOutput, maxStderr
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	if err == nil && out.over {
		err = errors.New("output too large")
	}
	if err != nil {
		e := &Error{Command: command(args), Stderr: strings.TrimSpace(errOut.String()), Err: err}
		if x, ok := errors.AsType[*exec.ExitError](err); ok {
			e.ExitCode = x.ExitCode()
		}
		return nil, e
	}
	return out.Bytes(), nil
}

// Error is a docker command that failed: its subcommand, exit code and the
// start of its standard error.
type Error struct {
	Command  string
	ExitCode int
	Stderr   string
	Err      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("docker %s: %v: %s", e.Command, e.Err, e.Stderr)
}

func (e *Error) Unwrap() error { return e.Err }

// command names a docker invocation by its subcommand words, never its
// values.
func command(args []string) string {
	var w []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(w) == 2 {
			break
		}
		w = append(w, a)
	}
	return strings.Join(w, " ")
}

// capped keeps the first max bytes written and remembers whether more came.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); len(p) > room {
		c.over = true
		c.Buffer.Write(p[:max(room, 0)])
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

// Client creates, checks and removes the sandbox's networks and containers.
type Client struct {
	r Runner
}

// New returns a client over r (CLI{} for the real engine).
func New(r Runner) *Client {
	return &Client{r: r}
}

// ErrInvalid reports a network or container description the package
// refuses to pass to docker: nothing ran.
var ErrInvalid = errors.New("docker: refused")

var (
	nameRE  = regexp.MustCompile(`^pc-[a-z0-9][a-z0-9-]{0,40}$`)
	labelRE = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9-]+)+$`)
)

// NewName returns a fresh name for a network, container or volume: "pc-",
// the kind and 16 random hex digits, so that sessions sharing one engine
// never collide.
func NewName(kind string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "pc-" + kind + "-" + hex.EncodeToString(b[:])
}

func checkName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: name %q", ErrInvalid, name)
	}
	return nil
}

// labelArgs renders labels as --label arguments in a stable order.
func labelArgs(labels map[string]string) ([]string, error) {
	var args []string
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		v := labels[k]
		if !labelRE.MatchString(k) || len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") {
			return nil, fmt.Errorf("%w: label %q", ErrInvalid, k)
		}
		args = append(args, "--label", k+"="+v)
	}
	return args, nil
}
