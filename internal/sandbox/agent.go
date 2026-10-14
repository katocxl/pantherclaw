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
	if _, err := s.workspace(ctx, "in", a.Workspace, ""); err != nil {
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

// What CopyOut writes: the patch, the list of changes, and the new content
// of changed binary files, which git applies only by SHA-1 ids.
const (
	PatchFile    = "changes.patch"
	ManifestFile = "changes.txt"
	BinaryDir    = "binary"
)

// CopyOut brings the agent's work back as a patch, never as a tree or a
// .git (founder decision 2026-10-11): the volume's files come back without
// any .git into a private directory and are compared with orig, the
// directory that was copied in (empty for none). dir, which must not exist
// yet or be empty, gets changes.patch, which the developer applies to
// their own repository with git apply, changes.txt, and under binary/ the
// new content of changed binary files, none of them executable. Nothing
// of the agent's is run, and no .git or tree is written back. It returns
// what changed.
func (s *Sandbox) CopyOut(ctx context.Context, orig, dir string) ([]workspace.Change, error) {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("sandbox: %s is not empty", dir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp, err := os.MkdirTemp(s.o.Dir, "out-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	exec, err := s.workspace(ctx, "out", "", tmp)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, PatchFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the directory the launcher named
	if err != nil {
		return nil, err
	}
	changes, err := workspace.Diff(orig, tmp, exec, f)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	for _, c := range changes {
		if c.Binary && c.Kind != workspace.Deleted {
			if err := copyFile(filepath.Join(tmp, filepath.FromSlash(c.Path)), filepath.Join(dir, BinaryDir, filepath.FromSlash(c.Path))); err != nil {
				return nil, err
			}
		}
	}
	m, err := os.OpenFile(filepath.Join(dir, ManifestFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the directory the launcher named
	if err != nil {
		return nil, err
	}
	err = workspace.WriteManifest(m, changes)
	if cerr := m.Close(); err == nil {
		err = cerr
	}
	return changes, err
}

// copyFile copies a file to a new, non-executable dst.
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	in, err := os.Open(src) //nolint:gosec // G304: a file of the private copy-out directory
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644) //nolint:gosec // G302,G304: a new file under the launcher's directory
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// workspace runs the probe image's workspace mode as the agent's uid with
// only the volume mounted: in streams a tar of host, its repository
// cleaned (an empty tar without a workspace, which still gives the volume
// its owner); out unpacks the volume's files, never a .git, into outDir
// and returns the executable ones.
func (s *Sandbox) workspace(ctx context.Context, dir, host, outDir string) (workspace.Executables, error) {
	name := "pc-ws" + dir + "-" + short(s.o.Session)
	if _, err := s.container(ctx, docker.Container{
		Name: name, Image: s.o.ProbeImage, User: AgentUser, Args: []string{"workspace", dir}, Networks: []string{s.Internal},
		Mounts: []docker.Mount{{Kind: docker.Volume, Source: s.Workspace, Target: probe.Workspace}}, Interactive: dir == "in",
		Limits: docker.Limits{PIDs: 64, MemoryMiB: 256, MilliCPUs: 1000},
	}); err != nil {
		return nil, err
	}
	defer func() { _ = s.c.RemoveContainer(context.WithoutCancel(ctx), name) }()
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var exec workspace.Executables
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
			var uerr error
			exec, uerr = workspace.UnpackFiles(pr, outDir)
			_, _ = io.Copy(io.Discard, pr) // unblock the writer after an error
			done <- uerr
		}()
		code, err = s.c.Attach(ctx, name, nil, pw)
		_ = pw.Close()
	}
	if werr := <-done; werr != nil {
		return nil, werr
	}
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("sandbox: copying the workspace %s exited %d", dir, code)
	}
	return exec, nil
}
