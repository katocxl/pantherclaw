// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// pclaw dev up|down|status|env (G0 M23 D125): a development node, kept
// apart from any other in ~/.pantherclaw/dev, with the simulated targets
// beside it. Everything listens on loopback only. The simulators are
// host processes (pantherclaw-sim, shipped with pclaw); dev.json says which
// are ours. pclaw dev env prints connection settings and never a secret.

func init() {
	commands["dev up"] = command{usage: "dev up [--org-name N] [--port P] [--gateway-port P] [--dir D]", run: devUp}
	commands["dev down"] = command{usage: "dev down [--dir D]", run: devDown}
	commands["dev status"] = command{usage: "dev status [--dir D]", run: devStatus}
	commands["dev env"] = command{usage: "dev env [--dir D]", run: devEnv}
}

const (
	devStateFile = "dev.json"
	// devSimReady bounds the wait for one simulator's port.
	devSimReady = 10 * time.Second
)

// devSim is one simulator pclaw dev runs. Those that need a key file
// (github, aws) stay out: they are started by hand with that file.
type devSim struct {
	Name string
	Addr string
}

// devSims are the simulators, on their usual ports (docs/BUILD_GUIDE.md).
var devSims = []devSim{
	{"payments", "127.0.0.1:9090"},
	{"mcp", "127.0.0.1:9091"},
	{"stripe", "127.0.0.1:9093"},
	{"slack", "127.0.0.1:9095"},
	{"jira", "127.0.0.1:9096"},
	{"gitlab", "127.0.0.1:9097"},
	{"teams", "127.0.0.1:9098"},
}

// devRunning is a simulator this pclaw started. Started is the process's
// start time as the system reports it (processIdentity): after a reboot the
// same id can be someone else's, so the id alone proves nothing. Unproved
// says dev down left it running for want of that proof (D143).
type devRunning struct {
	Name     string `json:"name"`
	Addr     string `json:"addr"`
	PID      int    `json:"pid"`
	Started  string `json:"started"`
	Unproved bool   `json:"unproved,omitempty"`
}

// ours reports whether r's process is provably the one pclaw started.
func (r devRunning) ours(ctx context.Context) bool {
	id, err := devProcessIdentity(ctx, r.PID)
	return err == nil && r.Started != "" && id == r.Started
}

// What holds a simulator's port. Every dev command reads it the same way
// (D143): a listener is ours only when its process is proved ours.
const (
	devSimStopped = "not running"
	devSimRunning = "running"
	devSimForeign = "in use by another process"
)

// devSimState says what holds s's port.
func devSimState(ctx context.Context, st devState, s devSim) string {
	if !devListening(s.Addr) {
		return devSimStopped
	}
	i := slices.IndexFunc(st.Sims, func(r devRunning) bool { return r.Name == s.Name && r.Addr == s.Addr })
	if i >= 0 && st.Sims[i].ours(ctx) {
		return devSimRunning
	}
	return devSimForeign
}

type devState struct {
	Sims []devRunning `json:"sims"`
}

// The seams tests replace.
var (
	devNodeUp          = nodeUp
	devNodeDown        = nodeDown
	devNodeStatus      = nodeStatus
	devStartSim        = startDevSim
	devStopSim         = stopDevSim
	devListening       = listening
	devSimBinary       = findSimBinary
	devProcessIdentity = processIdentity
)

// devDir resolves the directory: --dir, else ~/.pantherclaw/dev.
func devDir(dirFlag string) (string, error) {
	if dirFlag != "" {
		return filepath.Abs(dirFlag)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("pclaw: no home directory: %w", err)
	}
	return filepath.Join(home, ".pantherclaw", "dev"), nil
}

// devFlags parses a dev command's flags.
func devFlags(a *app, name string, args []string, extra func(*flag.FlagSet)) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	dirFlag := fs.String("dir", "", "development node directory (default ~/.pantherclaw/dev)")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", err
		}
		return "", errUsage
	}
	if fs.NArg() != 0 {
		return "", errUsage
	}
	return devDir(*dirFlag)
}

func devUp(ctx context.Context, a *app, args []string) error {
	var org string
	var port, gatewayPort int
	dir, err := devFlags(a, "dev up", args, func(fs *flag.FlagSet) {
		fs.StringVar(&org, "org-name", "", "name of the organization the first run creates")
		fs.IntVar(&port, "port", 0, "API port on 127.0.0.1")
		fs.IntVar(&gatewayPort, "gateway-port", 0, "gateway port on 127.0.0.1")
	})
	if err != nil {
		return err
	}
	bin, err := devSimBinary()
	if err != nil {
		return err
	}
	up := []string{"--dev", "--dir", dir}
	if org != "" {
		up = append(up, "--org-name", org)
	}
	if port != 0 {
		up = append(up, "--port", strconv.Itoa(port))
	}
	if gatewayPort != 0 {
		up = append(up, "--gateway-port", strconv.Itoa(gatewayPort))
	}
	if err := devNodeUp(ctx, a, up); err != nil {
		return err
	}
	st, err := loadDevState(dir)
	if err != nil {
		return err
	}
	for _, s := range devSims {
		switch devSimState(ctx, st, s) {
		case devSimRunning:
			continue
		case devSimForeign:
			return fmt.Errorf("pclaw: %s is already in use by another process, so simulator %s cannot start; stop what holds it, then run pclaw dev up again", s.Addr, s.Name)
		}
		st.Sims = slices.DeleteFunc(st.Sims, func(r devRunning) bool { return r.Name == s.Name })
		if !loopback(s.Addr) {
			return fmt.Errorf("pclaw: simulator %s is not on loopback: %s", s.Name, s.Addr)
		}
		running, err := devStartSim(ctx, bin, dir, s)
		if err != nil {
			return err
		}
		st.Sims = append(st.Sims, running)
		if err := saveDevState(dir, st); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(a.stdout, "Simulators (SIMULATED, loopback only): %s\nSettings: pclaw dev env · pclaw dev status · pclaw dev down\n", simNames(st))
	return nil
}

func devDown(ctx context.Context, a *app, args []string) error {
	dir, err := devFlags(a, "dev down", args, nil)
	if err != nil {
		return err
	}
	if node, ok, err := loadNodeState(dir); err != nil {
		return err
	} else if ok && node.Deployment != nodeDeploymentDev {
		return fmt.Errorf("pclaw: the node in %s is a %s deployment, not a development one", dir, node.Deployment)
	}
	st, err := loadDevState(dir)
	if err != nil {
		return err
	}
	var failed []string
	var kept []devRunning // what still runs stays on record (D143)
	for _, r := range st.Sims {
		// Nothing listening means it is gone, and the id may be another
		// process's by now.
		if !devListening(r.Addr) {
			continue
		}
		// Something listens, but only the start time says it is what we
		// started (D134). Unproved, it is left running and said so.
		if !r.ours(ctx) {
			_, _ = fmt.Fprintf(a.stderr, "pclaw: left %s running: process %d is not provably the simulator pclaw started; if it is, stop it yourself\n", r.Addr, r.PID)
			r.Unproved = true
			kept = append(kept, r)
			continue
		}
		if err := devStopSim(r.PID); err != nil {
			failed = append(failed, fmt.Sprintf("%s (process %d): %v", r.Name, r.PID, err))
			kept = append(kept, r)
		}
	}
	st.Sims = kept
	if err := saveDevState(dir, st); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(failed) > 0 {
		return errors.New("pclaw: could not stop: " + strings.Join(failed, "; "))
	}
	return devNodeDown(ctx, a, []string{"--dir", dir})
}

func devStatus(ctx context.Context, a *app, args []string) error {
	dir, err := devFlags(a, "dev status", args, nil)
	if err != nil {
		return err
	}
	if err := requireDevNode(dir); err != nil {
		return err
	}
	st, err := loadDevState(dir)
	if err != nil {
		return err
	}
	// The simulators are shown even when the node is not ready.
	statusErr := devNodeStatus(ctx, a, []string{"--dir", dir})
	_, _ = fmt.Fprintln(a.stdout, "\nsimulators:")
	for _, s := range devSims {
		_, _ = fmt.Fprintf(a.stdout, "  %s: %s, http://%s\n", s.Name, devSimState(ctx, st, s), s.Addr)
	}
	return statusErr
}

// devEnv prints connection settings: addresses and the organization id,
// which are no secret. The node's secrets are never read here. A port some
// other process holds is left out, so nothing is pointed at that process.
func devEnv(ctx context.Context, a *app, args []string) error {
	dir, err := devFlags(a, "dev env", args, nil)
	if err != nil {
		return err
	}
	if err := requireDevNode(dir); err != nil {
		return err
	}
	st, _, err := loadNodeState(dir)
	if err != nil {
		return err
	}
	sims, err := loadDevState(dir)
	if err != nil {
		return err
	}
	lines := []string{
		"PANTHERCLAW_SERVER=" + nodePublicURL(st),
		"PANTHERCLAW_GATEWAY=http://localhost:" + strconv.Itoa(st.GatewayPort),
		"PANTHERCLAW_ORG=" + st.Org,
	}
	for _, s := range devSims {
		name := "PANTHERCLAW_SIM_" + strings.ToUpper(s.Name)
		if devSimState(ctx, sims, s) == devSimForeign {
			_, _ = fmt.Fprintf(a.stderr, "pclaw: left out %s: %s is in use by another process\n", name, s.Addr)
			continue
		}
		lines = append(lines, name+"=http://"+s.Addr)
	}
	_, err = fmt.Fprintln(a.stdout, strings.Join(lines, "\n"))
	return err
}

// requireDevNode refuses a directory with no node, or a node that is not a
// development one: pclaw dev answers for its own only.
func requireDevNode(dir string) error {
	st, ok, err := loadNodeState(dir)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("pclaw: no development node in %s (run pclaw dev up first)", dir)
	}
	if st.Deployment != nodeDeploymentDev {
		return fmt.Errorf("pclaw: the node in %s is a %s deployment, not a development one", dir, st.Deployment)
	}
	return nil
}

func loadDevState(dir string) (devState, error) {
	var st devState
	b, err := os.ReadFile(filepath.Join(dir, devStateFile)) //nolint:gosec // G304: the node directory pclaw manages
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("pclaw: %s: %w", filepath.Join(dir, devStateFile), err)
	}
	return st, nil
}

func saveDevState(dir string, st devState) error {
	b, err := json.Marshal(st, json.Deterministic(true))
	if err != nil {
		return err
	}
	return writeNodeFile(filepath.Join(dir, devStateFile), append(indentJSON(b), '\n'), 0o600)
}

func simNames(st devState) string {
	names := make([]string, 0, len(st.Sims))
	for _, r := range st.Sims {
		names = append(names, r.Name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// loopback reports whether addr is a loopback host and a port.
func loopback(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	return err == nil && ap.Addr().IsLoopback()
}

// listening reports whether something accepts connections on addr.
func listening(addr string) bool {
	c, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// findSimBinary finds pantherclaw-sim beside pclaw, as a release ships it,
// else on PATH.
func findSimBinary() (string, error) {
	name := "pantherclaw-sim"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), name)
		if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", errors.New("pclaw dev needs pantherclaw-sim beside pclaw or on PATH (a release ships it; from a checkout: go build ./cmd/pantherclaw-sim)")
}

// pantherclawEnv matches what a simulator must not inherit: it talks to no
// server, so it has no use for a key.
var pantherclawEnv = regexp.MustCompile(`(?i)^PANTHERCLAW_`)

func simEnv(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), pantherclawEnv.MatchString)
}

// startDevSim starts one simulator, detached so that it outlives pclaw,
// and waits for its port. Its log is sim-<name>.log in dir.
func startDevSim(ctx context.Context, bin, dir string, s devSim) (devRunning, error) {
	log, err := os.OpenFile(filepath.Join(dir, "sim-"+s.Name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the node directory pclaw manages
	if err != nil {
		return devRunning{}, err
	}
	defer func() { _ = log.Close() }()
	cmd := exec.Command(bin, s.Name, "--addr", s.Addr) //nolint:gosec,noctx // G204: pclaw's own simulator; it must outlive this command's context
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.Env = dir, log, log, simEnv(os.Environ())
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return devRunning{}, fmt.Errorf("pclaw: start simulator %s: %w", s.Name, err)
	}
	pid := cmd.Process.Pid
	// Read while the process is still ours to wait for, so the id cannot
	// have been reused yet. Without it, dev down could never stop this one.
	started, err := devProcessIdentity(ctx, pid)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Process.Release()
		return devRunning{}, fmt.Errorf("pclaw: identify simulator %s: %w", s.Name, err)
	}
	_ = cmd.Process.Release()
	deadline := time.Now().Add(devSimReady)
	for !devListening(s.Addr) {
		if time.Now().After(deadline) {
			_ = devStopSim(pid)
			return devRunning{}, fmt.Errorf("pclaw: simulator %s did not listen on %s within %s; see %s", s.Name, s.Addr, devSimReady, log.Name())
		}
		select {
		case <-ctx.Done():
			_ = devStopSim(pid)
			return devRunning{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return devRunning{Name: s.Name, Addr: s.Addr, PID: pid, Started: started}, nil
}

// procStartField is the place of starttime in /proc/<pid>/stat, counted
// from 1 (proc(5)).
const procStartField = 22

// readProcStart reads a process's start time from a Linux /proc/<pid>/stat
// file, in clock ticks since boot. The second field is the program's name
// in parentheses, which can itself hold spaces and parentheses, so fields
// are counted from the last closing one (D146).
func readProcStart(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: a /proc path pclaw builds from a number
	if err != nil {
		return "", err
	}
	i := bytes.LastIndexByte(b, ')')
	if i < 0 {
		return "", fmt.Errorf("%s: no program name", path)
	}
	fields := strings.Fields(string(b[i+1:]))
	const first = 3 // the field right after the name
	if len(fields) <= procStartField-first {
		return "", fmt.Errorf("%s: %d fields after the program name", path, len(fields))
	}
	start := fields[procStartField-first]
	if _, err := strconv.ParseUint(start, 10, 64); err != nil {
		return "", fmt.Errorf("%s: start time %q", path, start)
	}
	return start, nil
}

func stopDevSim(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
