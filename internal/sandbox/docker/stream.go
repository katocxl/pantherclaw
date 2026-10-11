// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
)

// Streamer runs a docker command with its standard input and output
// streamed: a workspace in and out, the agent's output.
type Streamer interface {
	Stream(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error
}

// Stream runs one docker command, streaming stdin and stdout.
func (CLI) Stream(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // G204: a fixed program; this package builds and validates every argument (HR-216)
	var errOut capped
	errOut.max = maxStderr
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, &errOut
	if err := cmd.Run(); err != nil {
		e := &Error{Command: command(args), Stderr: strings.TrimSpace(errOut.String()), Err: err}
		if x, ok := errors.AsType[*exec.ExitError](err); ok {
			e.ExitCode = x.ExitCode()
		}
		return e
	}
	return nil
}

// ErrNoStreams reports a runner that cannot stream.
var ErrNoStreams = errors.New("docker: the runner cannot stream")

func (c *Client) streamer() (Streamer, error) {
	s, ok := c.r.(Streamer)
	if !ok {
		return nil, ErrNoStreams
	}
	return s, nil
}

// CreateVolume creates a named volume, for a workspace.
func (c *Client) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	if err := checkName(name); err != nil {
		return err
	}
	l, err := labelArgs(labels)
	if err != nil {
		return err
	}
	_, err = c.r.Run(ctx, append(append([]string{"volume", "create"}, l...), name)...)
	return err
}

// RemoveVolume removes a named volume the sandbox created.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	_, err := c.r.Run(ctx, "volume", "rm", "--force", name)
	return err
}

// Attach starts a created container with its standard input and output
// attached, waits for it and returns its exit code.
func (c *Client) Attach(ctx context.Context, name string, stdin io.Reader, stdout io.Writer) (int, error) {
	if err := checkName(name); err != nil {
		return 0, err
	}
	s, err := c.streamer()
	if err != nil {
		return 0, err
	}
	args := []string{"start", "--attach", name}
	if stdin != nil {
		args = []string{"start", "--attach", "--interactive", name}
	}
	// docker start exits with the container's code, or its own: the
	// container's state says which.
	serr := s.Stream(ctx, stdin, stdout, args...)
	info, err := c.InspectContainer(context.WithoutCancel(ctx), name)
	if err == nil && info.State.Status == "exited" {
		return info.State.ExitCode, nil
	}
	return 0, errors.Join(serr, err)
}

// Follow streams a container's standard output to w until it stops.
func (c *Client) Follow(ctx context.Context, name string, w io.Writer) error {
	if err := checkName(name); err != nil {
		return err
	}
	s, err := c.streamer()
	if err != nil {
		return err
	}
	return s.Stream(ctx, nil, w, "logs", "--follow", name)
}
