// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
	"github.com/katocxl/pantherclaw/internal/sandbox/probe"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sandbox/workspace"
)

// AgentUser runs the agent and owns its workspace: a non-root uid of its
// own (G0 M9 design decision 8). The probe image's /workspace has this
// owner, which a new workspace volume takes when it is first mounted.
const AgentUser = "65533:65533"

// Agent is the agent a sandbox runs.
type Agent struct {
	// Image is pinned by digest.
	Image string
	Args  []string
	// Env are extra NAME=VALUE entries; nothing comes from the host.
	Env []string
	// Workspace is the host directory copied in; empty for none.
	Workspace string
}

// caEnv points the usual TLS clients at the session CA, the only root the
// agent needs: every route out is the edge (HR-213).
var caEnv = []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"}

// PrepareAgent copies the workspace into a new volume and creates the
// agent's container, hardened like the others, on the internal network
// only, with the edge as its proxy and the session CA mounted read-only.
// It holds no credential or key (HR-213). Start it with the Docker
// client's Start, or Attach.
func (s *Sandbox) PrepareAgent(ctx context.Context, a Agent) error {
	if digestOf(a.Image) != s.o.AgentImage {
		return errors.New("sandbox: the agent image is not the session's")
	}
	s.Workspace = "pc-ws-" + short(s.o.Session)
	if err := s.c.CreateVolume(ctx, s.Workspace, s.labels); err != nil {
		return err
	}
	if err := s.workspace(ctx, "in", a.Workspace, ""); err != nil {
		return err
	}
	proxy := "http://" + s.EdgeAddr
	env := []string{"HTTPS_PROXY=" + proxy, "https_proxy=" + proxy, "HTTP_PROXY=" + proxy, "http_proxy=" + proxy, "NO_PROXY=", "no_proxy=", "HOME=/tmp"}
	for _, v := range caEnv {
		env = append(env, v+"="+caPath)
	}
	s.Agent = "pc-agent-" + short(s.o.Session)
	info, err := s.container(ctx, docker.Container{
		Name: s.Agent, Image: a.Image, User: AgentUser, Args: a.Args, Networks: []string{s.Internal},
		Env: append(env, a.Env...), WorkDir: probe.Workspace,
		Mounts: []docker.Mount{
			{Kind: docker.Bind, Source: s.CAFile, Target: caPath},
			{Kind: docker.Volume, Source: s.Workspace, Target: probe.Workspace},
		},
	})
	if err != nil {
		return err
	}
	s.base.Config.Checks = append(s.base.Config.Checks, agentChecks(info, s.o.Dir)...)
	return nil
}

// agentChecks are pclaw's configuration checks of the agent's container as
// the engine made it, which the closure of the host route needs: no mount
// names the engine's socket, and every bind is a file of the session's
// private directory (the session CA certificate), never another host path.
func agentChecks(info docker.ContainerInfo, dir string) []report.Check {
	sock := report.Check{ID: "agent_no_docker_socket", OK: true}
	bind := report.Check{ID: "agent_no_host_bind", OK: true}
	for _, m := range info.HostConfig.Mounts {
		if s := strings.ToLower(m.Source + " " + m.Target); strings.Contains(s, "docker.sock") || strings.Contains(s, "docker_engine") {
			sock.OK, sock.Detail = false, m.Target
		}
		if m.Type != "bind" {
			continue
		}
		rel, err := filepath.Rel(dir, m.Source)
		fi, serr := os.Stat(m.Source)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) || serr != nil || !fi.Mode().IsRegular() {
			bind.OK, bind.Detail = false, m.Target
		}
	}
	return []report.Check{sock, bind}
}

// CopyOut copies the workspace volume into dir, which must not exist yet
// or be empty.
func (s *Sandbox) CopyOut(ctx context.Context, dir string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("sandbox: %s is not empty", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return s.workspace(ctx, "out", "", dir)
}

// workspace runs the probe image's workspace mode as the agent's uid with
// only the volume mounted: in streams a tar of host (an empty one without
// a workspace, which still gives the volume its owner), out unpacks the
// volume into outDir.
func (s *Sandbox) workspace(ctx context.Context, dir, host, outDir string) error {
	name := "pc-ws" + dir + "-" + short(s.o.Session)
	if _, err := s.container(ctx, docker.Container{
		Name: name, Image: s.o.ProbeImage, User: AgentUser, Args: []string{"workspace", dir}, Networks: []string{s.Internal},
		Mounts: []docker.Mount{{Kind: docker.Volume, Source: s.Workspace, Target: probe.Workspace}}, Interactive: dir == "in",
		Limits: docker.Limits{PIDs: 64, MemoryMiB: 256, MilliCPUs: 1000},
	}); err != nil {
		return err
	}
	defer func() { _ = s.c.RemoveContainer(context.WithoutCancel(ctx), name) }()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var code int
	var err error
	if dir == "in" {
		go func() {
			var perr error
			if host != "" {
				perr = workspace.Pack(host, pw)
			} else {
				perr = tar.NewWriter(pw).Close()
			}
			pw.CloseWithError(perr)
			done <- perr
		}()
		code, err = s.c.Attach(ctx, name, pr, io.Discard)
		_ = pr.Close()
	} else {
		go func() {
			uerr := workspace.Unpack(pr, outDir)
			_, _ = io.Copy(io.Discard, pr) // unblock the writer after an error
			done <- uerr
		}()
		code, err = s.c.Attach(ctx, name, nil, pw)
		_ = pw.Close()
	}
	if werr := <-done; werr != nil {
		return werr
	}
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("sandbox: copying the workspace %s exited %d", dir, code)
	}
	return nil
}
