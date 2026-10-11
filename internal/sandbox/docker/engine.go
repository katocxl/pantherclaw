// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
)

// MinEngineMajor is the oldest Docker engine the sandbox and the connector
// runtime run on: internal networks in isolated gateway mode need 28
// (HR-122, HR-218).
const MinEngineMajor = 28

// Runtimes the sandbox records (HR-218): runc by default, runsc (gVisor)
// when it is installed and asked for.
const (
	RuntimeRunc  = "runc"
	RuntimeRunsc = "runsc"
)

// ErrEngine reports an engine the sandbox refuses to run on.
var ErrEngine = errors.New("docker: the engine cannot run a sandbox")

// Engine is what the sandbox reads about the Docker engine before it
// creates anything.
type Engine struct {
	Version    string
	APIVersion string
	OS         string
	Arch       string
	Kernel     string
	// Platform names the distribution, for example "Docker Desktop 4.94.0".
	Platform string
	// Runtimes are the registered runtimes by name, and DefaultRuntime the
	// one a container gets without --runtime.
	Runtimes       []string
	DefaultRuntime string
	gvisor         bool
	seccomp        bool
}

// Engine reads the engine's version, runtimes and security options.
func (c *Client) Engine(ctx context.Context) (Engine, error) {
	out, err := c.r.Run(ctx, "version", "--format", "{{json .Server}}")
	if err != nil {
		return Engine{}, err
	}
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
		OS         string `json:"Os"`
		Arch       string `json:"Arch"`
		Kernel     string `json:"KernelVersion"`
		Platform   struct {
			Name string `json:"Name"`
		} `json:"Platform"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return Engine{}, fmt.Errorf("%w: unreadable version: %w", ErrEngine, err)
	}
	out, err = c.r.Run(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return Engine{}, err
	}
	var info struct {
		Runtimes map[string]struct {
			Path string `json:"path"`
		} `json:"Runtimes"`
		DefaultRuntime  string   `json:"DefaultRuntime"`
		SecurityOptions []string `json:"SecurityOptions"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return Engine{}, fmt.Errorf("%w: unreadable info: %w", ErrEngine, err)
	}
	e := Engine{
		Version: v.Version, APIVersion: v.APIVersion, OS: v.OS, Arch: v.Arch, Kernel: v.Kernel,
		Platform: v.Platform.Name, Runtimes: slices.Sorted(maps.Keys(info.Runtimes)), DefaultRuntime: info.DefaultRuntime,
	}
	for name, r := range info.Runtimes {
		if name == RuntimeRunsc || path.Base(strings.ReplaceAll(r.Path, `\`, "/")) == RuntimeRunsc {
			e.gvisor = true
		}
	}
	for _, o := range info.SecurityOptions {
		if strings.HasPrefix(o, "name=seccomp") {
			e.seccomp = true
		}
	}
	return e, nil
}

// Check refuses an engine the sandbox cannot isolate with (HR-218): older
// than MinEngineMajor, not running Linux containers, or without seccomp.
func (e Engine) Check() error {
	major, err := strconv.Atoi(strings.TrimPrefix(strings.SplitN(e.Version, ".", 2)[0], "v"))
	switch {
	case err != nil:
		return fmt.Errorf("%w: unreadable engine version %q", ErrEngine, e.Version)
	case major < MinEngineMajor:
		return fmt.Errorf("%w: Docker %s is older than %d, which isolated internal networks need (HR-122)", ErrEngine, e.Version, MinEngineMajor)
	case e.OS != "linux":
		return fmt.Errorf("%w: the engine runs %q containers, not linux", ErrEngine, e.OS)
	case !e.seccomp:
		return fmt.Errorf("%w: seccomp is off in the engine (HR-085)", ErrEngine)
	}
	return nil
}

// GVisor reports whether a runsc runtime is registered. Docker Desktop has
// none; gVisor is recorded when used but never required (G0 M9 decision 4).
func (e Engine) GVisor() bool { return e.gvisor }

// Runtime is the --runtime value for a container: "" (the engine's
// default) unless gVisor is asked for, which fails when it is missing.
func (e Engine) Runtime(gvisor bool) (string, error) {
	if !gvisor {
		return "", nil
	}
	if !e.gvisor {
		return "", fmt.Errorf("%w: gVisor (runsc) is not installed in this engine", ErrEngine)
	}
	return RuntimeRunsc, nil
}

// Evidence is the engine record a sandbox or connector run keeps (HR-218).
type Evidence struct {
	EngineVersion string `json:"engine_version"`
	APIVersion    string `json:"api_version"`
	Platform      string `json:"platform,omitempty"`
	// Runtime is the runtime the container actually got, from inspect.
	Runtime string `json:"runtime"`
}

// Evidence records the engine and the runtime a verified container runs
// under (ContainerInfo.Runtime).
func (e Engine) Evidence(runtime string) Evidence {
	return Evidence{EngineVersion: e.Version, APIVersion: e.APIVersion, Platform: e.Platform, Runtime: runtime}
}
