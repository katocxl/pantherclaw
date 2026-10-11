// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package docker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

const testImage = "gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"

// fake answers docker commands by their first two words and records every
// call.
type fake struct {
	out   map[string]string
	calls [][]string
}

func (f *fake) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if out, ok := f.out[command(args)]; ok {
		return []byte(out), nil
	}
	return nil, &Error{Command: command(args), ExitCode: 1, Err: errors.New("exit status 1")}
}

func (f *fake) called(cmd string) bool {
	return slices.ContainsFunc(f.calls, func(a []string) bool { return command(a) == cmd })
}

func engineFake(version, info string) *fake {
	return &fake{out: map[string]string{
		"version": `{"Version":"` + version + `","ApiVersion":"1.56","Os":"linux","Arch":"amd64","KernelVersion":"6.6.87.2","Platform":{"Name":"Docker Desktop 4.94.0"}}`,
		"info":    info,
	}}
}

const desktopInfo = `{"Runtimes":{"io.containerd.runc.v2":{"path":"runc"},"nvidia":{"path":"nvidia-container-runtime"},"runc":{"path":"runc"}},` +
	`"DefaultRuntime":"runc","SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]}`

func TestHR218_RefusesAnEngineOlderThan28(t *testing.T) {
	for _, tc := range []struct {
		version string
		ok      bool
	}{{"29.8.2", true}, {"28.0.0", true}, {"28.0.0-rc.1", true}, {"27.5.1", false}, {"26.1.4", false}, {"", false}, {"dev", false}} {
		e, err := New(engineFake(tc.version, desktopInfo)).Engine(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Check(); (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrEngine)) {
			t.Errorf("Docker %q: Check() = %v, want ok=%v", tc.version, err, tc.ok)
		}
	}
}

func TestHR218_RefusesAnEngineWithoutSeccompLinuxOrRunc(t *testing.T) {
	for name, info := range map[string]string{
		"no seccomp": `{"Runtimes":{"runc":{"path":"runc"}},"SecurityOptions":["name=cgroupns"]}`,
		"no runc":    `{"Runtimes":{"nvidia":{"path":"nvidia-container-runtime"}},"SecurityOptions":["name=seccomp,profile=builtin"]}`,
	} {
		e, err := New(engineFake("29.8.2", info)).Engine(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.Check(); !errors.Is(err, ErrEngine) {
			t.Errorf("%s: Check() = %v", name, err)
		}
	}
	e, _ := New(engineFake("29.8.2", desktopInfo)).Engine(t.Context())
	e.OS = "windows"
	if err := e.Check(); !errors.Is(err, ErrEngine) {
		t.Fatalf("windows containers: Check() = %v", err)
	}
}

// TestHR218_TheRuntimeIsRuncOrRunscAndRecorded: a container always names
// its runtime, so that an engine's default (here nvidia) never applies;
// runsc is used when listed, except on Docker Desktop, where it is skipped.
func TestHR218_TheRuntimeIsRuncOrRunscAndRecorded(t *testing.T) {
	e, err := New(engineFake("29.8.2", desktopInfo)).Engine(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !e.Desktop || e.GVisor() || e.Runtime() != RuntimeRunc {
		t.Fatalf("Docker Desktop: desktop=%v gVisor=%v runtime=%q", e.Desktop, e.GVisor(), e.Runtime())
	}
	if got := e.Evidence(RuntimeRunc); got != (Evidence{Version: "29.8.2", APIVersion: "1.56", Runtime: "runc", Desktop: true}) {
		t.Fatalf("evidence %+v", got)
	}
	gvisor := `{"Runtimes":{"runsc":{"path":"/usr/local/bin/runsc"},"runc":{"path":"runc"}},"DefaultRuntime":"runc","SecurityOptions":["name=seccomp,profile=builtin"],"OperatingSystem":"Ubuntu 24.04"}`
	f := engineFake("29.8.2", gvisor)
	f.out["version"] = strings.Replace(f.out["version"], "Docker Desktop 4.94.0", "Docker Engine - Community", 1)
	if e, _ = New(f).Engine(t.Context()); e.Desktop || !e.GVisor() || e.Runtime() != RuntimeRunsc {
		t.Fatalf("Linux with runsc: desktop=%v gVisor=%v runtime=%q", e.Desktop, e.GVisor(), e.Runtime())
	}
	if e, _ = New(engineFake("29.8.2", gvisor)).Engine(t.Context()); !e.GVisor() || e.Runtime() != RuntimeRunc {
		t.Fatalf("Docker Desktop with runsc: runtime=%q", e.Runtime())
	}
}

func TestHR122_SandboxNetworksAreInternalIsolatedWithoutIPv6(t *testing.T) {
	args, err := Network{Name: "pc-sbx-1", Internal: true, Labels: map[string]string{"org.pantherclaw.session": "s1"}}.args()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"network create --driver bridge --ipv6=false --internal",
		"--opt com.docker.network.bridge.gateway_mode_ipv4=isolated",
		"--opt com.docker.network.bridge.gateway_mode_ipv6=isolated",
		"--label org.pantherclaw.session=s1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("args %q lack %q", got, want)
		}
	}
	if args[len(args)-1] != "pc-sbx-1" {
		t.Errorf("the name is not last: %q", args)
	}
	up, _ := Network{Name: "pc-up-1"}.args()
	if j := strings.Join(up, " "); strings.Contains(j, "--internal") || !strings.Contains(j, "--ipv6=false") {
		t.Errorf("uplink args %q", j)
	}
}

func TestHR218_ANetworkTheEngineDidNotIsolateIsRemoved(t *testing.T) {
	n := Network{Name: "pc-sbx-1", Internal: true}
	ok := `{"Name":"pc-sbx-1","Driver":"bridge","Internal":true,"EnableIPv6":false,"Options":{"com.docker.network.bridge.gateway_mode_ipv4":"isolated","com.docker.network.bridge.gateway_mode_ipv6":"isolated"},"IPAM":{"Config":[{"Subnet":"172.19.0.0/16"}]}}`
	f := &fake{out: map[string]string{"network create": "id\n", "network inspect": ok}}
	info, err := New(f).CreateNetwork(t.Context(), n)
	if err != nil || info.Subnet() != "172.19.0.0/16" {
		t.Fatalf("isolated network: %+v, %v", info, err)
	}
	for name, inspected := range map[string]string{
		"not internal":    strings.Replace(ok, `"Internal":true`, `"Internal":false`, 1),
		"IPv6 on":         strings.Replace(ok, `"EnableIPv6":false`, `"EnableIPv6":true`, 1),
		"nat gateway":     strings.Replace(ok, `gateway_mode_ipv4":"isolated"`, `gateway_mode_ipv4":"nat"`, 1),
		"options ignored": strings.Replace(ok, `"com.docker.network.bridge.gateway_mode_ipv6":"isolated"`, `"x":"y"`, 1),
		"another network": strings.Replace(ok, `"pc-sbx-1"`, `"pc-sbx-2"`, 1),
	} {
		f := &fake{out: map[string]string{"network create": "id\n", "network inspect": inspected, "network rm": ""}}
		if _, err := New(f).CreateNetwork(t.Context(), n); !errors.Is(err, ErrIsolation) {
			t.Errorf("%s: CreateNetwork() = %v, want ErrIsolation", name, err)
		}
		if !f.called("network rm") {
			t.Errorf("%s: the network was not removed", name)
		}
	}
}

func agent() Container {
	return Container{
		Name: "pc-agent-1", Image: testImage, User: "65532:65532", Args: []string{"/pc/agent", "--flag"}, Runtime: RuntimeRunc,
		Networks: []string{"pc-sbx-1"}, Env: []string{"HTTPS_PROXY=http://pc-edge-1:3128"},
		Mounts: []Mount{
			{Kind: Bind, Source: `C:\Users\dev\bin\agent`, Target: "/pc/agent"},
			{Kind: Volume, Source: "pc-ws-1", Target: "/workspace"},
		},
		Labels: map[string]string{"org.pantherclaw.session": "s1"},
	}
}

func TestHR085_EveryContainerGetsTheHardeningFlags(t *testing.T) {
	args, err := agent().args()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	for _, want := range []string{
		"create --name pc-agent-1 --pull never --restart no --init",
		"--read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m",
		"--runtime runc --user 65532:65532 --cap-drop ALL",
		"--security-opt no-new-privileges=true --security-opt seccomp=builtin",
		"--ipc private --cgroupns private",
		"--sysctl net.ipv4.ping_group_range=1 0 --sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv4.ip_forward=0",
		"--pids-limit 256 --memory 1024m --cpus 1.000",
		"--network pc-sbx-1",
		`--mount type=bind,source=C:\Users\dev\bin\agent,target=/pc/agent,readonly`,
		"--mount type=volume,source=pc-ws-1,target=/workspace",
		"--env HTTPS_PROXY=http://pc-edge-1:3128",
		testImage + " /pc/agent --flag",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("args lack %q:\n%s", want, got)
		}
	}
	for _, never := range []string{"--privileged", "--network host", "--cap-add", "unconfined", "--env-file", "-v"} {
		if slices.Contains(args, never) || strings.Contains(got, never+" ") {
			t.Errorf("args contain %q", never)
		}
	}
}

func TestHR216_RefusesTheDockerSocketHostEnvironmentAndRoot(t *testing.T) {
	for name, mutate := range map[string]func(*Container){
		"docker.sock bind": func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{Kind: Bind, Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"})
		},
		"windows engine pipe": func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{Kind: Bind, Source: `\\.\pipe\docker_engine`, Target: "/pc/sock"})
		},
		"socket as target": func(c *Container) {
			c.Mounts = append(c.Mounts, Mount{Kind: Bind, Source: "/tmp/x", Target: "/run/docker.sock"})
		},
		"host env by name":       func(c *Container) { c.Env = append(c.Env, "GITHUB_TOKEN") },
		"env with newline":       func(c *Container) { c.Env = append(c.Env, "A=b\nc") },
		"root user":              func(c *Container) { c.User = "0:0" },
		"root group":             func(c *Container) { c.User = "1000:0" },
		"user name":              func(c *Container) { c.User = "nobody" },
		"host network":           func(c *Container) { c.Networks = []string{"host"} },
		"no network":             func(c *Container) { c.Networks = nil },
		"tag only":               func(c *Container) { c.Image = "gcr.io/distroless/static-debian12:nonroot" },
		"unknown runtime":        func(c *Container) { c.Runtime = "nvidia" },
		"engine default runtime": func(c *Container) { c.Runtime = "" },
		"comma in source":        func(c *Container) { c.Mounts[0].Source = "/x,target=/etc" },
		"relative target":        func(c *Container) { c.Mounts[0].Target = "pc/agent" },
		"unclean target":         func(c *Container) { c.Mounts[0].Target = "/pc/../etc" },
		"volume not ours":        func(c *Container) { c.Mounts[1].Source = "pantherclaw-pg" },
		"name not ours":          func(c *Container) { c.Name = "postgres" },
		"label with a newline":   func(c *Container) { c.Labels["org.pantherclaw.x"] = "a\nb" },
		"label key not reversed": func(c *Container) { c.Labels["session"] = "x" },
	} {
		c := agent()
		mutate(&c)
		f := &fake{}
		if _, err := New(f).CreateContainer(t.Context(), c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: CreateContainer() = %v, want ErrInvalid", name, err)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: docker ran: %q", name, f.calls)
		}
	}
}

const hardenedInspect = `{"Id":"abc","Name":"/pc-agent-1","Config":{"User":"65532:65532","Image":"` + testImage + `"},` +
	`"HostConfig":{"NetworkMode":"pc-sbx-1","Privileged":false,"ReadonlyRootfs":true,"CapAdd":null,"CapDrop":["ALL"],` +
	`"SecurityOpt":["no-new-privileges=true","seccomp=builtin"],"IpcMode":"private","PidMode":"","UTSMode":"","UsernsMode":"","CgroupnsMode":"private",` +
	`"Binds":null,"VolumesFrom":null,"Devices":[],"Sysctls":{"net.ipv4.ping_group_range":"1 0","net.ipv6.conf.all.disable_ipv6":"1","net.ipv4.ip_forward":"0"},` +
	`"Tmpfs":{"/tmp":"rw,noexec,nosuid,nodev,size=64m"},"PidsLimit":256,"Memory":1073741824,"NanoCpus":1000000000,"Runtime":"runc","Init":true,` +
	`"Mounts":[{"Type":"bind","Source":"C:\\Users\\dev\\bin\\agent","Target":"/pc/agent","ReadOnly":true},{"Type":"volume","Source":"pc-ws-1","Target":"/workspace"}]},` +
	`"NetworkSettings":{"Networks":{"pc-sbx-1":{}}}}`

func TestHR218_AContainerTheEngineDidNotHardenIsRemoved(t *testing.T) {
	f := &fake{out: map[string]string{"create": "abc\n", "container inspect": hardenedInspect}}
	info, err := New(f).CreateContainer(t.Context(), agent())
	if err != nil || info.Runtime() != RuntimeRunc {
		t.Fatalf("hardened container: runtime %q, %v", info.Runtime(), err)
	}
	for name, inspected := range map[string]string{
		"privileged":        strings.Replace(hardenedInspect, `"Privileged":false`, `"Privileged":true`, 1),
		"cap added":         strings.Replace(hardenedInspect, `"CapAdd":null`, `"CapAdd":["NET_RAW"]`, 1),
		"writable root":     strings.Replace(hardenedInspect, `"ReadonlyRootfs":true`, `"ReadonlyRootfs":false`, 1),
		"seccomp dropped":   strings.Replace(hardenedInspect, `,"seccomp=builtin"`, ``, 1),
		"root user":         strings.Replace(hardenedInspect, `"User":"65532:65532"`, `"User":""`, 1),
		"host pid":          strings.Replace(hardenedInspect, `"PidMode":""`, `"PidMode":"host"`, 1),
		"host ipc":          strings.Replace(hardenedInspect, `"IpcMode":"private"`, `"IpcMode":"host"`, 1),
		"second network":    strings.Replace(hardenedInspect, `{"pc-sbx-1":{}}`, `{"pc-sbx-1":{},"bridge":{}}`, 1),
		"ping allowed":      strings.Replace(hardenedInspect, `"1 0"`, `"0 2147483647"`, 1),
		"forwarding":        strings.Replace(hardenedInspect, `ip_forward":"0"`, `ip_forward":"1"`, 1),
		"no pids limit":     strings.Replace(hardenedInspect, `"PidsLimit":256`, `"PidsLimit":0`, 1),
		"bind added":        strings.Replace(hardenedInspect, `"Binds":null`, `"Binds":["/var/run/docker.sock:/var/run/docker.sock"]`, 1),
		"writable bind":     strings.Replace(hardenedInspect, `"ReadOnly":true`, `"ReadOnly":false`, 1),
		"tmpfs added":       strings.Replace(hardenedInspect, `"Tmpfs":{`, `"Tmpfs":{"/run":"rw",`, 1),
		"device":            strings.Replace(hardenedInspect, `"Devices":[]`, `"Devices":[{"PathOnHost":"/dev/kvm"}]`, 1),
		"another image":     strings.Replace(hardenedInspect, `"Image":"gcr.io`, `"Image":"docker.io`, 1),
		"another container": strings.Replace(hardenedInspect, `"/pc-agent-1"`, `"/pc-agent-2"`, 1),
	} {
		f := &fake{out: map[string]string{"create": "abc\n", "container inspect": inspected, "rm": ""}}
		if _, err := New(f).CreateContainer(t.Context(), agent()); !errors.Is(err, ErrIsolation) {
			t.Errorf("%s: CreateContainer() = %v, want ErrIsolation", name, err)
		}
		if !f.called("rm") {
			t.Errorf("%s: the container was not removed", name)
		}
	}
}

func TestNewNameIsUniqueAndAccepted(t *testing.T) {
	a, b := NewName("sbx"), NewName("sbx")
	if a == b || checkName(a) != nil {
		t.Fatalf("NewName: %q, %q", a, b)
	}
}

func TestErrorNamesTheSubcommandNotItsValues(t *testing.T) {
	if got := command([]string{"network", "create", "--label", "secret=x", "pc-1"}); got != "network create" {
		t.Fatalf("command = %q", got)
	}
	if got := command([]string{"create", "--name", "pc-1"}); got != "create" {
		t.Fatalf("command = %q", got)
	}
}

// TestHR085_OnlyTheProbeGetsNETRAWBack: NET_RAW is the one capability a
// container may get back, only when asked, and the self-check holds the
// engine to exactly that.
func TestHR085_OnlyTheProbeGetsNETRAWBack(t *testing.T) {
	plain, _ := agent().args()
	if slices.Contains(plain, "--cap-add") {
		t.Fatalf("a capability was added: %q", plain)
	}
	p := agent()
	p.NetRaw = true
	args, _ := p.args()
	if !strings.Contains(strings.Join(args, " "), "--cap-drop ALL") || !strings.Contains(strings.Join(args, " "), "--cap-add NET_RAW") {
		t.Fatalf("probe args %q", args)
	}
	withRaw := strings.Replace(hardenedInspect, `"CapAdd":null`, `"CapAdd":["CAP_NET_RAW"]`, 1)
	if err := verifyJSON(t, p, withRaw); err != nil {
		t.Fatalf("probe with NET_RAW: %v", err)
	}
	if err := verifyJSON(t, p, hardenedInspect); !errors.Is(err, ErrIsolation) {
		t.Fatalf("probe without NET_RAW: %v", err)
	}
	if err := verifyJSON(t, agent(), withRaw); !errors.Is(err, ErrIsolation) {
		t.Fatalf("agent with NET_RAW: %v", err)
	}
	p.Runtime = RuntimeRunsc
	if err := verifyJSON(t, p, withRaw); !errors.Is(err, ErrIsolation) {
		t.Fatalf("runsc asked, runc got: %v", err)
	}
}

func verifyJSON(t *testing.T, c Container, inspected string) error {
	t.Helper()
	f := &fake{out: map[string]string{"container inspect": inspected}}
	info, err := New(f).InspectContainer(t.Context(), c.Name)
	if err != nil {
		t.Fatal(err)
	}
	return VerifyContainer(c, info)
}

// TestHR216_CleanupTouchesOnlyTheSessionsLabel: removal lists by the exact
// session label and removes only what the engine listed.
func TestHR216_CleanupTouchesOnlyTheSessionsLabel(t *testing.T) {
	f := &fake{out: map[string]string{
		"ps": "0123456789ab\n", "rm": "", "network ls": "abcdef0123456789\n", "network rm": "", "volume ls": "pc-ws-1\n", "volume rm": "",
	}}
	if err := New(f).RemoveLabelled(t.Context(), "3f2a9c"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range f.calls {
		got = append(got, strings.Join(c, " "))
	}
	want := []string{
		"ps --all --quiet --no-trunc --filter label=org.pantherclaw.sandbox.session=3f2a9c", "rm --force --volumes 0123456789ab",
		"network ls --quiet --no-trunc --filter label=org.pantherclaw.sandbox.session=3f2a9c", "network rm abcdef0123456789",
		"volume ls --quiet --filter label=org.pantherclaw.sandbox.session=3f2a9c", "volume rm --force pc-ws-1",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("calls:\n%s", strings.Join(got, "\n"))
	}
	for _, bad := range []string{"", "x,label=other", "A", "s1 --all"} {
		if err := New(&fake{}).RemoveLabelled(t.Context(), bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	f = &fake{out: map[string]string{"ps": "--all\n", "network ls": "", "volume ls": ""}}
	if err := New(f).RemoveLabelled(t.Context(), "3f2a9c"); err == nil || f.called("rm") {
		t.Fatal("an unexpected listing reached rm")
	}
}
