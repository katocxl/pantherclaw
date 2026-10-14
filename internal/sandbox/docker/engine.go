// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// MinEngineMajor is the oldest Docker engine the sandbox and the connector
// runtime run on: internal networks in isolated gateway mode need 28
// (HR-122, HR-218).
const MinEngineMajor = 28

// The only runtimes a container gets, named on every container so that an
// engine's default (nvidia, sysbox, kata…) never applies: runsc (gVisor)
// when the engine lists it and is not Docker Desktop, runc otherwise
// (HR-218, G0 M9 design decision 8).
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
	// Desktop: the engine is Docker Desktop's, where gVisor is skipped.
	Desktop bool
	// Runtimes are the registered runtimes by name.
	Runtimes []string
	seccomp  bool
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
		Runtimes        map[string]jsontext.Value `json:"Runtimes"`
		SecurityOptions []string                  `json:"SecurityOptions"`
		OperatingSystem string                    `json:"OperatingSystem"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return Engine{}, fmt.Errorf("%w: unreadable info: %w", ErrEngine, err)
	}
	e := Engine{
		Version: v.Version, APIVersion: v.APIVersion, OS: v.OS, Arch: v.Arch, Kernel: v.Kernel, Platform: v.Platform.Name,
		Desktop:  strings.Contains(v.Platform.Name, "Docker Desktop") || info.OperatingSystem == "Docker Desktop",
		Runtimes: slices.Sorted(maps.Keys(info.Runtimes)),
	}
	for _, o := range info.SecurityOptions {
		if strings.HasPrefix(o, "name=seccomp") {
			e.seccomp = true
		}
	}
	return e, nil
}

// Check refuses an engine the sandbox cannot isolate with (HR-218): older
// than MinEngineMajor, not running Linux containers, without seccomp, or
// without a runtime named runc.
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
	case !slices.Contains(e.Runtimes, RuntimeRunc):
		return fmt.Errorf("%w: the engine has no runtime named runc", ErrEngine)
	}
	return nil
}

// GVisor reports whether a runtime named runsc is registered.
func (e Engine) GVisor() bool { return slices.Contains(e.Runtimes, RuntimeRunsc) }

// Runtime is the runtime every container of a run gets: runsc when the
// engine lists it, unless it is Docker Desktop, where gVisor is detected and
// skipped; runc otherwise. gVisor is recorded when used, never required
// (G0 M9 decision 4).
func (e Engine) Runtime() string {
	if e.GVisor() && !e.Desktop {
		return RuntimeRunsc
	}
	return RuntimeRunc
}

// Evidence is the engine record a sandbox or connector run keeps (HR-218),
// in the shape of the probe report's "engine" (G0 M9 contracts).
type Evidence struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	// Runtime is runc or runsc: the runtime the container got, from
	// inspect, which VerifyContainer checked against the one asked for.
	Runtime string `json:"runtime"`
	Desktop bool   `json:"desktop"`
}

// Evidence records the engine and the runtime a verified container runs
// under (ContainerInfo.Runtime).
func (e Engine) Evidence(runtime string) Evidence {
	return Evidence{Version: e.Version, APIVersion: e.APIVersion, Runtime: runtime, Desktop: e.Desktop}
}
