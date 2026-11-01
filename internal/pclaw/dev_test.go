// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeDev replaces the node and the simulators for one test.
type fakeDev struct {
	upArgs, downArgs, statusArgs []string
	started, stopped             []string
	live                         map[string]bool
	statusErr                    error
	identity                     func(pid int) (string, error)
}

// fakeStart is the start time the fake records for a process.
func fakeStart(pid int) string { return "started-" + strconv.Itoa(pid) }

func installFakeDev(t *testing.T) *fakeDev {
	t.Helper()
	f := &fakeDev{live: map[string]bool{}, identity: func(pid int) (string, error) { return fakeStart(pid), nil }}
	up, down, status, start, stop, ls, bin, id := devNodeUp, devNodeDown, devNodeStatus, devStartSim, devStopSim, devListening, devSimBinary, devProcessIdentity
	t.Cleanup(func() {
		devNodeUp, devNodeDown, devNodeStatus, devStartSim, devStopSim, devListening, devSimBinary, devProcessIdentity = up, down, status, start, stop, ls, bin, id
	})
	devNodeUp = func(_ context.Context, _ *app, args []string) error {
		f.upArgs = args
		return saveNodeState(args[slices.Index(args, "--dir")+1], nodeState{Deployment: nodeDeploymentDev, APIPort: 8080, GatewayPort: 8090, Org: "org-1", OIDC: &nodeOIDC{ClientID: "client"}})
	}
	devNodeDown = func(_ context.Context, _ *app, args []string) error { f.downArgs = args; return nil }
	devNodeStatus = func(_ context.Context, _ *app, args []string) error { f.statusArgs = args; return f.statusErr }
	devStartSim = func(_ context.Context, _, _ string, s devSim) (devRunning, error) {
		f.started = append(f.started, s.Name)
		f.live[s.Addr] = true
		pid := 100 + len(f.started)
		return devRunning{Name: s.Name, Addr: s.Addr, PID: pid, Started: fakeStart(pid)}, nil
	}
	devStopSim = func(pid int) error { f.stopped = append(f.stopped, string(rune(pid))); return nil }
	devListening = func(addr string) bool { return f.live[addr] }
	devSimBinary = func() (string, error) { return "pantherclaw-sim", nil }
	devProcessIdentity = func(_ context.Context, pid int) (string, error) { return f.identity(pid) }
	return f
}

func devRun(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"dev"}, args...), &out, &errb, func(string) (string, bool) { return "", false }, Options{})
	return code, out.String(), errb.String()
}

// TestD125_DevUpIsANodeWithItsSimulators: up runs nodeUp with --dev in its
// own directory, starts every simulator once, and a second up keeps them.
//
// Covers: F859
func TestD125_DevUpIsANodeWithItsSimulators(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	code, out, stderr := devRun(t, "up", "--dir", dir, "--port", "18080")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !slices.Contains(f.upArgs, "--dev") || !slices.Contains(f.upArgs, dir) || !slices.Contains(f.upArgs, "18080") {
		t.Errorf("node args: %v", f.upArgs)
	}
	if len(f.started) != len(devSims) {
		t.Errorf("started %v", f.started)
	}
	if !strings.Contains(out, "SIMULATED") {
		t.Errorf("output: %s", out)
	}
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("second up")
	}
	if len(f.started) != len(devSims) {
		t.Errorf("second up restarted: %v", f.started)
	}
}

// TestD125_DevIsLoopbackOnly: every simulator, and the ports the node
// publishes, are on loopback.
func TestD125_DevIsLoopbackOnly(t *testing.T) {
	for _, s := range devSims {
		if !loopback(s.Addr) {
			t.Errorf("simulator %s on %s", s.Name, s.Addr)
		}
	}
	for addr, want := range map[string]bool{"127.0.0.1:1": true, "[::1]:1": true, "0.0.0.0:1": false, "10.0.0.1:1": false, "localhost:1": false, "": false} {
		if loopback(addr) != want {
			t.Errorf("loopback(%q)", addr)
		}
	}
	y, err := nodeComposeYAML(nodeComposeData{Project: "p", ServerImage: "s", GatewayImage: "g", PostgresImage: "pg", APIPort: 8080, GatewayPort: 8090})
	if err != nil {
		t.Fatal(err)
	}
	published := regexp.MustCompile(`(?m)^\s+- "?([0-9.]*:?[0-9]+:[0-9]+)"?\s*$`).FindAllStringSubmatch(string(y), -1)
	if len(published) == 0 {
		t.Fatal("no published ports found")
	}
	for _, m := range published {
		if !strings.HasPrefix(m[1], "127.0.0.1:") {
			t.Errorf("published beyond loopback: %s", m[1])
		}
	}
}

// TestD125_APortInUseIsNeverTakenForOurs: a port something else holds
// stops up and nothing is killed.
func TestD125_APortInUseIsNeverTakenForOurs(t *testing.T) {
	f := installFakeDev(t)
	f.live[devSims[0].Addr] = true
	code, _, stderr := devRun(t, "up", "--dir", t.TempDir())
	if code == 0 || !strings.Contains(stderr, "already in use") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(f.started) != 0 || len(f.stopped) != 0 {
		t.Errorf("started %v, stopped %v", f.started, f.stopped)
	}
}

// TestD125_DevDownStopsOnlyWhatIsItsOwn: a recorded simulator whose port
// is gone is not killed, since its id may be another process's by now.
func TestD125_DevDownStopsOnlyWhatIsItsOwn(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("up")
	}
	delete(f.live, devSims[0].Addr)
	if code, _, stderr := devRun(t, "down", "--dir", dir); code != 0 {
		t.Fatalf("down: %s", stderr)
	}
	if len(f.stopped) != len(devSims)-1 {
		t.Errorf("stopped %d", len(f.stopped))
	}
	if !slices.Contains(f.downArgs, dir) {
		t.Errorf("node down: %v", f.downArgs)
	}
	st, err := loadDevState(dir)
	if err != nil || len(st.Sims) != 0 {
		t.Errorf("state: %+v %v", st, err)
	}
}

// TestD134_DevDownLeavesAProcessItCannotProveItsOwn: an id in use after a
// reboot, an identity that cannot be read and a state file from before
// identities all stop nothing, and each is reported.
func TestD134_DevDownLeavesAProcessItCannotProveItsOwn(t *testing.T) {
	for name, tamper := range map[string]func(*fakeDev, string){
		"another process has the id": func(f *fakeDev, _ string) {
			f.identity = func(int) (string, error) { return "a later process", nil }
		},
		"identity unreadable": func(f *fakeDev, _ string) {
			f.identity = func(int) (string, error) { return "", errors.New("no such process") }
		},
		"no identity saved": func(_ *fakeDev, dir string) {
			st, err := loadDevState(dir)
			if err != nil {
				t.Fatal(err)
			}
			for i := range st.Sims {
				st.Sims[i].Started = ""
			}
			if err := saveDevState(dir, st); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := installFakeDev(t)
			dir := t.TempDir()
			if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
				t.Fatal("up")
			}
			tamper(f, dir)
			code, _, stderr := devRun(t, "down", "--dir", dir)
			if code != 0 {
				t.Fatalf("down: %s", stderr)
			}
			if len(f.stopped) != 0 {
				t.Errorf("stopped %d processes it could not prove its own", len(f.stopped))
			}
			if !strings.Contains(stderr, "left "+devSims[0].Addr+" running") {
				t.Errorf("not reported: %s", stderr)
			}
			if !slices.Contains(f.downArgs, dir) {
				t.Errorf("the node stayed up: %v", f.downArgs)
			}
		})
	}
}

// TestD143_DevDownKeepsWhatItLeftRunning: a process left running stays on
// record, marked unproved, until it is gone.
func TestD143_DevDownKeepsWhatItLeftRunning(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("up")
	}
	s := devSims[0]
	f.identity = func(pid int) (string, error) {
		if pid == 101 { // the first simulator started
			return "a later process", nil
		}
		return fakeStart(pid), nil
	}
	if code, _, stderr := devRun(t, "down", "--dir", dir); code != 0 {
		t.Fatalf("down: %s", stderr)
	}
	st, err := loadDevState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Sims) != 1 || st.Sims[0].Name != s.Name || !st.Sims[0].Unproved {
		t.Fatalf("state: %+v", st)
	}
	delete(f.live, s.Addr)
	if code, _, stderr := devRun(t, "down", "--dir", dir); code != 0 {
		t.Fatalf("second down: %s", stderr)
	}
	if st, err := loadDevState(dir); err != nil || len(st.Sims) != 0 {
		t.Errorf("state after it went: %+v %v", st, err)
	}
}

// TestD143_AForeignListenerIsNeverTakenForOurs: up, status and env read a
// listener as dev down does: a recorded id that proves nothing, or no
// record at all, is another process's port.
func TestD143_AForeignListenerIsNeverTakenForOurs(t *testing.T) {
	foreign := func(int) (string, error) { return "a later process", nil }
	for name, tamper := range map[string]func(*fakeDev){
		"recorded, another process has the id": func(f *fakeDev) { f.identity = foreign },
		"recorded, identity unreadable": func(f *fakeDev) {
			f.identity = func(int) (string, error) { return "", errors.New("no such process") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := installFakeDev(t)
			dir := t.TempDir()
			if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
				t.Fatal("up")
			}
			tamper(f)
			started := len(f.started)
			if code, _, stderr := devRun(t, "up", "--dir", dir); code == 0 || !strings.Contains(stderr, "in use by another process") {
				t.Errorf("up: exit %d: %s", code, stderr)
			}
			if len(f.started) != started || len(f.stopped) != 0 {
				t.Errorf("up started %v, stopped %v", f.started, f.stopped)
			}
			if _, out, _ := devRun(t, "status", "--dir", dir); !strings.Contains(out, "payments: in use by another process") {
				t.Errorf("status:\n%s", out)
			}
			code, out, stderr := devRun(t, "env", "--dir", dir)
			if code != 0 {
				t.Fatalf("env: %s", stderr)
			}
			if strings.Contains(out, "PANTHERCLAW_SIM_") || !strings.Contains(stderr, "left out PANTHERCLAW_SIM_PAYMENTS") {
				t.Errorf("env points at another process:\n%s\n%s", out, stderr)
			}
			if !strings.Contains(out, "PANTHERCLAW_SERVER=") {
				t.Errorf("env lost the node's settings:\n%s", out)
			}
		})
	}
}

// TestD143_AListenerWithNoRecordIsForeign: env still names a port nothing
// holds, and leaves out one that pclaw did not start.
func TestD143_AListenerWithNoRecordIsForeign(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("up")
	}
	if err := saveDevState(dir, devState{}); err != nil {
		t.Fatal(err)
	}
	delete(f.live, devSims[1].Addr)
	_, out, _ := devRun(t, "env", "--dir", dir)
	if strings.Contains(out, "PANTHERCLAW_SIM_PAYMENTS=") || !strings.Contains(out, "PANTHERCLAW_SIM_MCP=") {
		t.Errorf("env:\n%s", out)
	}
}

// TestD146_TheStartTimeComesFromProcStat: field 22 of a sample stat file,
// on any system, whatever the program's name holds.
func TestD146_TheStartTimeComesFromProcStat(t *testing.T) {
	const tail = " S 1 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 987654 12345 67 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
	dir := t.TempDir()
	sample := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(dir, "stat")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, program := range map[string]string{
		"plain":       "(pantherclaw-sim)",
		"spaces":      "(a b c)",
		"parentheses": "(a) (b) S 1)",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readProcStart(sample(t, "4242 "+program+tail))
			if err != nil || got != "987654" {
				t.Errorf("got %q, %v", got, err)
			}
		})
	}
	for name, content := range map[string]string{
		"no name":     "4242 pantherclaw S 1",
		"too short":   "4242 (x) S 1 2 3\n",
		"not a count": strings.Replace("4242 (x)"+tail, "987654", "soon", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := readProcStart(sample(t, content)); err == nil {
				t.Errorf("read %q", got)
			}
		})
	}
	if got, err := readProcStart(filepath.Join(dir, "gone")); err == nil {
		t.Errorf("read a missing file: %q", got)
	}
}

// TestD134_ProcessIdentityTellsProcessesApart: read twice it stays the same,
// and a process that has ended never reads as this one.
func TestD134_ProcessIdentityTellsProcessesApart(t *testing.T) {
	ctx := t.Context()
	own, err := processIdentity(ctx, os.Getpid())
	if err != nil || own == "" {
		t.Fatalf("identity %q: %v", own, err)
	}
	if again, err := processIdentity(ctx, os.Getpid()); err != nil || again != own {
		t.Fatalf("identity moved: %q then %q (%v)", own, again, err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if gone, err := processIdentity(ctx, child.Process.Pid); err == nil && gone == own {
		t.Errorf("an ended process reads as this one: %q", gone)
	}
}

// TestD125_DevEnvPrintsNoSecret: settings only, however many secrets the
// node directory holds.
func TestD125_DevEnvPrintsNoSecret(t *testing.T) {
	installFakeDev(t)
	dir := t.TempDir()
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("up")
	}
	if err := os.MkdirAll(filepath.Join(dir, nodeSecretsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	const secret = "hunter2-node-secret"
	for _, n := range nodePasswordFiles {
		if err := os.WriteFile(filepath.Join(dir, nodeSecretsDir, n), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, stderr := devRun(t, "env", "--dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{"PANTHERCLAW_SERVER=http://localhost:8080", "PANTHERCLAW_GATEWAY=http://localhost:8090", "PANTHERCLAW_ORG=org-1", "PANTHERCLAW_SIM_PAYMENTS=http://127.0.0.1:9090"} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret) || regexp.MustCompile(`(?i)secret|password|token|\bkey\b`).MatchString(out) {
		t.Errorf("a secret, or a setting named like one:\n%s", out)
	}
}

// TestD125_DevAnswersForDevelopmentNodesOnly: a production node's directory
// is refused, with nothing touched.
func TestD125_DevAnswersForDevelopmentNodesOnly(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	if err := saveNodeState(dir, nodeState{Deployment: nodeDeploymentProd}); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"env", "status", "down"} {
		if code, _, stderr := devRun(t, cmd, "--dir", dir); code == 0 || !strings.Contains(stderr, "not a development one") {
			t.Errorf("%s: exit %d: %s", cmd, code, stderr)
		}
	}
	if f.downArgs != nil || f.statusArgs != nil {
		t.Error("touched a production node")
	}
	if code, _, _ := devRun(t, "env", "--dir", t.TempDir()); code == 0 {
		t.Error("env with no node")
	}
}

// TestD125_DevStatusShowsSimulatorsEvenWhenTheNodeIsNotReady.
func TestD125_DevStatusShowsSimulatorsEvenWhenTheNodeIsNotReady(t *testing.T) {
	f := installFakeDev(t)
	dir := t.TempDir()
	if code, _, _ := devRun(t, "up", "--dir", dir); code != 0 {
		t.Fatal("up")
	}
	delete(f.live, devSims[1].Addr)
	f.statusErr = errors.New("not ready")
	code, out, _ := devRun(t, "status", "--dir", dir)
	if code == 0 {
		t.Error("status passed with a node that is not ready")
	}
	if !strings.Contains(out, "payments: running") || !strings.Contains(out, "mcp: not running") {
		t.Errorf("status:\n%s", out)
	}
}

// TestD125_ASimulatorIsNotGivenPantherClawSettings: it talks to no server.
func TestD125_ASimulatorIsNotGivenPantherClawSettings(t *testing.T) {
	got := simEnv([]string{"PATH=/bin", "PANTHERCLAW_API_KEY=pck_x", "pantherclaw_server=x", "HOME=/h"})
	if !slices.Equal(got, []string{"PATH=/bin", "HOME=/h"}) {
		t.Errorf("env: %v", got)
	}
}

// TestD125_ListeningSeesAnOpenPort: the check the start and stop rest on,
// against a real socket.
func TestD125_ListeningSeesAnOpenPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	if !listening(l.Addr().String()) {
		t.Error("an open port does not count as listening")
	}
	addr := l.Addr().String()
	_ = l.Close()
	if listening(addr) {
		t.Error("a closed port counts as listening")
	}
}

// TestD125_NoSimulatorBinaryStopsBeforeTheNode: a missing simulator is
// told at once, not after a node has started.
func TestD125_NoSimulatorBinaryStopsBeforeTheNode(t *testing.T) {
	f := installFakeDev(t)
	devSimBinary = func() (string, error) { return "", errors.New("pclaw dev needs pantherclaw-sim") }
	code, _, stderr := devRun(t, "up", "--dir", t.TempDir())
	if code == 0 || !strings.Contains(stderr, "needs pantherclaw-sim") || f.upArgs != nil {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
