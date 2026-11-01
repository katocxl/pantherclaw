// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
)

// InspectOptions describe one inspection of a stdio MCP server (G0 M24 D214,
// HR-584).
type InspectOptions struct {
	// Session labels what the inspection creates.
	Session string
	// EdgeImage is the sandbox's edge image; Image is the server's, pinned by
	// digest, and Args follow it.
	EdgeImage, Image string
	Args             []string
	// Dir is a private directory for the files the containers mount.
	Dir string
}

// Inspection is what an inspection saw from outside the server.
type Inspection struct {
	// Attempts are the destinations the server asked the proxy for, each
	// refused. What it tried past the proxy the network dropped, unrecorded.
	Attempts []Route
}

// Inspect runs a server with nothing: no credential, no workspace, no route
// out. Its network is internal and the edge sits on that network alone, with
// no uplink and no gateway, and refuses everything it is asked for. talk
// speaks to the server's stdio. It runs on the machine of whoever started it:
// nothing on the server or a hosted gateway calls it. Everything it creates
// is removed, also on failure.
func Inspect(ctx context.Context, c *docker.Client, e docker.Engine, o InspectOptions,
	talk func(ctx context.Context, in io.Writer, out io.Reader) error,
) (_ Inspection, err error) {
	if err := e.Check(); err != nil {
		return Inspection{}, err
	}
	if o.Session == "" || o.Dir == "" || o.EdgeImage == "" || o.Image == "" {
		return Inspection{}, errors.New("sandbox: an inspection needs a session, a directory and both images")
	}
	dir, err := filepath.EvalSymlinks(o.Dir)
	if err != nil {
		return Inspection{}, fmt.Errorf("sandbox: %w", err)
	}
	session, id := strings.ToLower(o.Session), short(o.Session)
	s := &Sandbox{
		c: c, engine: e, runtime: e.Runtime(), labels: map[string]string{docker.LabelSession: session},
		o:        Options{Session: o.Session, Dir: dir, EdgeImage: o.EdgeImage},
		Internal: "pc-sbx-" + id, Edge: "pc-edge-" + id, Agent: "pc-agent-" + id,
	}
	defer func() { err = errors.Join(err, s.Close(ctx)) }()
	if err := s.startInspectEdge(ctx); err != nil {
		return Inspection{}, err
	}
	info, err := s.container(ctx, s.inspectContainer(o))
	if err != nil {
		return Inspection{}, err
	}
	for _, check := range agentChecks(info, dir) {
		if !check.OK {
			return Inspection{}, fmt.Errorf("sandbox: the inspected container failed %s", check.ID)
		}
	}
	if err := s.attach(ctx, talk); err != nil {
		return Inspection{}, err
	}
	log, err := s.c.Logs(ctx, s.Edge)
	if err != nil {
		return Inspection{}, err
	}
	return Inspection{Attempts: edgeRoutes(log, "")}, nil
}

// startInspectEdge creates the network and an edge that has only it.
func (s *Sandbox) startInspectEdge(ctx context.Context) error {
	internal, err := s.c.CreateNetwork(ctx, docker.Network{Name: s.Internal, Internal: true, Labels: s.labels})
	if err != nil {
		return err
	}
	s.networks = append(s.networks, s.Internal)
	path, err := s.writeJSON("edge.json", edge.Config{
		Format: edge.ConfigFormat, Mode: edge.ModeInspect, Session: s.o.Session, Listen: ":" + edgePort, Subnet: internal.Subnet(),
	})
	if err != nil {
		return err
	}
	if _, err := s.container(ctx, s.inspectEdge(path)); err != nil {
		return err
	}
	if err := s.c.Start(ctx, s.Edge); err != nil {
		return err
	}
	if _, err := s.waitReady(ctx); err != nil {
		return err
	}
	s.EdgeAddr = s.Edge + ":" + edgePort
	return nil
}

// inspectEdge is the edge's container: on the internal network alone, with
// its configuration and no key, token or binding.
func (s *Sandbox) inspectEdge(config string) docker.Container {
	return docker.Container{
		Name: s.Edge, Image: s.o.EdgeImage, User: EdgeUser, Args: []string{"--config", configPath}, Networks: []string{s.Internal},
		Mounts: []docker.Mount{{Kind: docker.Bind, Source: config, Target: configPath}},
		Limits: docker.Limits{PIDs: 128, MemoryMiB: 256, MilliCPUs: 1000},
	}
}

// inspectContainer is the inspected server's container: the internal network,
// the edge as its proxy, and nothing else. Its environment names the proxy
// and no more: no credential, nothing from the host (HR-584).
func (s *Sandbox) inspectContainer(o InspectOptions) docker.Container {
	proxy := "http://" + s.EdgeAddr
	return docker.Container{
		Name: s.Agent, Image: o.Image, User: AgentUser, Args: o.Args, Networks: []string{s.Internal}, Interactive: true,
		Env:    []string{"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy, "HTTP_PROXY=" + proxy, "http_proxy=" + proxy, "NO_PROXY=", "no_proxy=", "HOME=/tmp"},
		Limits: docker.Limits{PIDs: 128, MemoryMiB: 512, MilliCPUs: 1000},
	}
}

// attach runs talk over the server's stdio and stops the server, which also
// ends a server that ignores the end of its input.
func (s *Sandbox) attach(ctx context.Context, talk func(ctx context.Context, in io.Writer, out io.Reader) error) error {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		_, err := s.c.Attach(ctx, s.Agent, inR, outW)
		_ = outW.Close()
		_ = inR.Close()
		done <- err
	}()
	err := talk(ctx, inW, outR)
	_ = inW.Close()
	_ = outR.Close()
	rmErr := s.c.RemoveContainer(context.WithoutCancel(ctx), s.Agent)
	<-done // a server that was stopped reports that; talk says what it heard
	return errors.Join(err, rmErr)
}
