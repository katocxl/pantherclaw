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
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Default resource limits for a container.
const (
	DefaultPIDs      = 256
	DefaultMemoryMiB = 1024
	DefaultMilliCPUs = 1000
)

// MountKind says what a mount is.
type MountKind int

const (
	// Bind mounts a host file or directory, always read-only: binaries
	// and the CA certificate.
	Bind MountKind = iota + 1
	// Volume mounts a named volume: a writable workspace (NTFS binds are
	// slow, and nothing writes to the host).
	Volume
)

// Mount is a file system a container gets besides its read-only root and
// /tmp.
type Mount struct {
	Kind     MountKind
	Source   string
	Target   string
	ReadOnly bool
}

// Limits caps a container's processes, memory and CPU.
type Limits struct {
	PIDs      int
	MemoryMiB int
	MilliCPUs int
}

// Container is a container for the sandbox or the connector runtime. The
// hardening is not optional: every container runs with a read-only root,
// a noexec /tmp, all capabilities dropped, no-new-privileges, Docker's
// default seccomp profile, private IPC and cgroup namespaces, no ICMP
// sockets, no IPv6 and no IP forwarding, so that a container on two
// networks (the edge) never routes for another (HR-085, HR-122).
type Container struct {
	Name string
	// Image is pinned by digest.
	Image string
	// User is "uid:gid", never root.
	User string
	// Args follow the image; distroless images have no entrypoint, so the
	// first is the program.
	Args []string
	// Networks are user-defined networks the sandbox created; at least one.
	Networks []string
	// Env is NAME=VALUE only: a bare NAME would copy the host's value.
	Env     []string
	Mounts  []Mount
	WorkDir string
	// Runtime is RuntimeRunc or RuntimeRunsc (Engine.Runtime): always
	// named, so that the engine's default never applies (HR-218).
	Runtime string
	// PingGID, when set, lets that group (the probe container's) open
	// unprivileged ICMP sockets, so that the probe can send echo requests
	// and show the network drops them; every other container gets none.
	// No capability is ever added: NET_RAW would not reach a non-root
	// process anyway, which Docker gives no ambient capabilities (G0 M9
	// design decision 5, as built).
	PingGID int
	Limits  Limits
	Labels  map[string]string
	// Interactive keeps standard input open (stdio MCP connectors).
	Interactive bool
}

var (
	// imageRE: a reference pinned by digest, or a local image id (images
	// built by task sandbox:images are referenced by their id).
	imageRE  = regexp.MustCompile(`^([a-z0-9][a-z0-9._/:-]*@)?sha256:[0-9a-f]{64}$`)
	userRE   = regexp.MustCompile(`^([0-9]{1,9}):([0-9]{1,9})$`)
	envRE    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}=`)
	targetRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

func (c Container) args() ([]string, error) {
	bad := func(what string) error { return fmt.Errorf("%w: container %s: %s", ErrInvalid, c.Name, what) }
	if err := checkName(c.Name); err != nil {
		return nil, err
	}
	if !imageRE.MatchString(c.Image) {
		return nil, bad("the image is not pinned by digest")
	}
	m := userRE.FindStringSubmatch(c.User)
	if m == nil || m[1] == "0" || m[2] == "0" {
		return nil, bad("the user is not a non-root uid:gid")
	}
	if c.PingGID != 0 && strconv.Itoa(c.PingGID) != m[2] {
		return nil, bad("the ping group is not the container's own")
	}
	if len(c.Networks) == 0 {
		return nil, bad("no network")
	}
	if c.Runtime != RuntimeRunc && c.Runtime != RuntimeRunsc {
		return nil, bad("runtime " + c.Runtime)
	}
	if c.WorkDir != "" && !targetRE.MatchString(c.WorkDir) {
		return nil, bad("work dir")
	}
	l := c.Limits
	if l.PIDs <= 0 {
		l.PIDs = DefaultPIDs
	}
	if l.MemoryMiB <= 0 {
		l.MemoryMiB = DefaultMemoryMiB
	}
	if l.MilliCPUs <= 0 {
		l.MilliCPUs = DefaultMilliCPUs
	}
	args := []string{
		"create", "--name", c.Name, "--pull", "never", "--restart", "no", "--init",
		"--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
		"--runtime", c.Runtime, "--user", c.User, "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true", "--security-opt", "seccomp=builtin",
		"--ipc", "private", "--cgroupns", "private",
		"--sysctl", "net.ipv4.ping_group_range=" + c.pingRange(), "--sysctl", "net.ipv6.conf.all.disable_ipv6=1", "--sysctl", "net.ipv4.ip_forward=0",
		"--pids-limit", strconv.Itoa(l.PIDs), "--memory", strconv.Itoa(l.MemoryMiB) + "m",
		"--cpus", strconv.FormatFloat(float64(l.MilliCPUs)/1000, 'f', 3, 64),
	}
	for _, n := range c.Networks {
		if err := checkName(n); err != nil {
			return nil, err
		}
		args = append(args, "--network", n)
	}
	for _, e := range c.Env {
		if !envRE.MatchString(e) || strings.ContainsAny(e, "\r\n\x00") {
			return nil, bad("env entries are NAME=VALUE")
		}
		args = append(args, "--env", e)
	}
	for _, m := range c.Mounts {
		a, err := m.arg()
		if err != nil {
			return nil, bad(err.Error())
		}
		args = append(args, "--mount", a)
	}
	if c.WorkDir != "" {
		args = append(args, "--workdir", c.WorkDir)
	}
	if c.Interactive {
		args = append(args, "--interactive")
	}
	labels, err := labelArgs(c.Labels)
	if err != nil {
		return nil, err
	}
	args = append(args, labels...)
	return append(append(args, c.Image), c.Args...), nil
}

// arg renders a mount for --mount, refusing the Docker socket and anything
// the CSV syntax could misread (HR-216).
func (m Mount) arg() (string, error) {
	if m.Source == "" || strings.ContainsAny(m.Source, ",\"\r\n\x00") || !targetRE.MatchString(m.Target) || path.Clean(m.Target) != m.Target {
		return "", errors.New("mount source or target")
	}
	for _, p := range []string{m.Source, m.Target} {
		if s := strings.ToLower(p); strings.Contains(s, "docker.sock") || strings.Contains(s, "docker_engine") {
			return "", errors.New("the Docker socket is never mounted")
		}
	}
	switch m.Kind {
	case Bind:
		return "type=bind,source=" + m.Source + ",target=" + m.Target + ",readonly", nil
	case Volume:
		if err := checkName(m.Source); err != nil {
			return "", errors.New("volume name")
		}
		a := "type=volume,source=" + m.Source + ",target=" + m.Target
		if m.ReadOnly {
			a += ",readonly"
		}
		return a, nil
	}
	return "", errors.New("mount kind")
}

// ContainerInfo is what the engine reports about a container.
type ContainerInfo struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		User  string `json:"User"`
		Image string `json:"Image"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode    string            `json:"NetworkMode"`
		Privileged     bool              `json:"Privileged"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		CapAdd         []string          `json:"CapAdd"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		IpcMode        string            `json:"IpcMode"`
		PidMode        string            `json:"PidMode"`
		UTSMode        string            `json:"UTSMode"`
		UsernsMode     string            `json:"UsernsMode"`
		CgroupnsMode   string            `json:"CgroupnsMode"`
		Binds          []string          `json:"Binds"`
		VolumesFrom    []string          `json:"VolumesFrom"`
		Devices        []jsontext.Value  `json:"Devices"`
		Sysctls        map[string]string `json:"Sysctls"`
		Tmpfs          map[string]string `json:"Tmpfs"`
		PidsLimit      int64             `json:"PidsLimit"`
		Memory         int64             `json:"Memory"`
		NanoCPUs       int64             `json:"NanoCpus"`
		Runtime        string            `json:"Runtime"`
		Init           bool              `json:"Init"`
		Mounts         []struct {
			Type     string `json:"Type"`
			Source   string `json:"Source"`
			Target   string `json:"Target"`
			ReadOnly bool   `json:"ReadOnly"`
		} `json:"Mounts"`
	} `json:"HostConfig"`
	// State is the container's run state, current when inspected.
	State struct {
		Status   string `json:"Status"`
		Running  bool   `json:"Running"`
		ExitCode int    `json:"ExitCode"`
	} `json:"State"`
	NetworkSettings struct {
		Networks map[string]jsontext.Value `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Runtime is the runtime the container got, for its evidence (HR-218).
func (i ContainerInfo) Runtime() string { return i.HostConfig.Runtime }

// CreateContainer creates c without starting it and checks what the engine
// made of it (HR-218); a container that fails the check is removed again.
func (c *Client) CreateContainer(ctx context.Context, ct Container) (ContainerInfo, error) {
	args, err := ct.args()
	if err != nil {
		return ContainerInfo{}, err
	}
	if _, err := c.r.Run(ctx, args...); err != nil {
		return ContainerInfo{}, err
	}
	info, err := c.InspectContainer(ctx, ct.Name)
	if err == nil {
		err = VerifyContainer(ct, info)
	}
	if err != nil {
		return ContainerInfo{}, errors.Join(err, c.RemoveContainer(context.WithoutCancel(ctx), ct.Name))
	}
	return info, nil
}

// InspectContainer reads a container.
func (c *Client) InspectContainer(ctx context.Context, name string) (ContainerInfo, error) {
	if err := checkName(name); err != nil {
		return ContainerInfo{}, err
	}
	out, err := c.r.Run(ctx, "container", "inspect", "--format", "{{json .}}", name)
	if err != nil {
		return ContainerInfo{}, err
	}
	var info ContainerInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return ContainerInfo{}, fmt.Errorf("docker: unreadable container %s: %w", name, err)
	}
	return info, nil
}

// VerifyContainer compares what the engine reports with the hardening
// every container must have (HR-085, HR-216, HR-218).
func VerifyContainer(ct Container, info ContainerInfo) error {
	h := info.HostConfig
	fail := func(what string) error { return fmt.Errorf("%w: container %s: %s", ErrIsolation, ct.Name, what) }
	sec := map[string]bool{}
	for _, o := range h.SecurityOpt {
		sec[o] = true
	}
	switch {
	case strings.TrimPrefix(info.Name, "/") != ct.Name || info.Config.Image != ct.Image:
		return fail("another container answered")
	case h.Privileged || len(h.CapAdd) > 0 || !slices.Equal(h.CapDrop, []string{"ALL"}) || len(h.Devices) > 0:
		return fail("privileges")
	case !h.ReadonlyRootfs:
		return fail("the root file system is writable")
	case !sec["no-new-privileges=true"] || !sec["seccomp=builtin"]:
		return fail("security options")
	case info.Config.User != ct.User:
		return fail("user")
	case h.IpcMode != "private" || h.CgroupnsMode != "private" || h.PidMode != "" || h.UTSMode != "" || h.UsernsMode != "":
		return fail("namespaces")
	case !slices.Equal(slices.Sorted(maps.Keys(info.NetworkSettings.Networks)), slices.Sorted(slices.Values(ct.Networks))):
		return fail("networks")
	case h.NetworkMode == "host" || strings.HasPrefix(h.NetworkMode, "container:"):
		return fail("network mode " + h.NetworkMode)
	case h.Sysctls["net.ipv4.ping_group_range"] != ct.pingRange() || h.Sysctls["net.ipv6.conf.all.disable_ipv6"] != "1" || h.Sysctls["net.ipv4.ip_forward"] != "0":
		return fail("sysctls")
	case h.PidsLimit <= 0 || h.Memory <= 0 || h.NanoCPUs <= 0 || !h.Init:
		return fail("limits")
	case h.Runtime != ct.Runtime:
		return fail("runtime " + h.Runtime)
	case len(h.Binds) > 0 || len(h.VolumesFrom) > 0 || len(h.Mounts) != len(ct.Mounts) || len(h.Tmpfs) != 1 || h.Tmpfs["/tmp"] == "":
		return fail("mounts")
	}
	for _, m := range h.Mounts {
		if strings.Contains(strings.ToLower(m.Source), "docker.sock") || (m.Type == "bind" && !m.ReadOnly) {
			return fail("mount " + m.Target)
		}
	}
	return nil
}

// RemoveContainer removes a container the sandbox created, with its
// anonymous volumes.
func (c *Client) RemoveContainer(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	_, err := c.r.Run(ctx, "rm", "--force", "--volumes", name)
	return err
}

// Start starts a created container.
func (c *Client) Start(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	_, err := c.r.Run(ctx, "start", name)
	return err
}

// Wait waits for a container to stop and returns its exit code.
func (c *Client) Wait(ctx context.Context, name string) (int, error) {
	if err := checkName(name); err != nil {
		return 0, err
	}
	out, err := c.r.Run(ctx, "wait", name)
	if err != nil {
		return 0, err
	}
	code, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, fmt.Errorf("docker wait %s: %q", name, out)
	}
	return code, nil
}

// Logs returns a stopped container's standard output (its standard error
// is not returned).
func (c *Client) Logs(ctx context.Context, name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	return c.r.Run(ctx, "logs", name)
}

// Pull fetches an image by its digest.
func (c *Client) Pull(ctx context.Context, image string) error {
	if !imageRE.MatchString(image) {
		return fmt.Errorf("%w: image %q is not pinned by digest", ErrInvalid, image)
	}
	_, err := c.r.Run(ctx, "pull", "--quiet", image)
	return err
}

// pingRange is the container's ping_group_range: no group, or PingGID's.
func (c Container) pingRange() string {
	if c.PingGID > 0 {
		g := strconv.Itoa(c.PingGID)
		return g + " " + g
	}
	return "1 0"
}
