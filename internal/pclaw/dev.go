// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
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

// devRunning is a simulator this pclaw started.
type devRunning struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
	PID  int    `json:"pid"`
}

type devState struct {
	Sims []devRunning `json:"sims"`
}

// The seams tests replace.
var (
	devNodeUp     = nodeUp
	devNodeDown   = nodeDown
	devNodeStatus = nodeStatus
	devStartSim   = startDevSim
	devStopSim    = stopDevSim
	devListening  = listening
	devSimBinary  = findSimBinary
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
		if slices.ContainsFunc(st.Sims, func(r devRunning) bool { return r.Name == s.Name && devListening(r.Addr) }) {
			continue
		}
		st.Sims = slices.DeleteFunc(st.Sims, func(r devRunning) bool { return r.Name == s.Name })
		if !loopback(s.Addr) {
			return fmt.Errorf("pclaw: simulator %s is not on loopback: %s", s.Name, s.Addr)
		}
		if devListening(s.Addr) {
			return fmt.Errorf("pclaw: %s is already in use, so simulator %s cannot start; stop what holds it, then run pclaw dev up again", s.Addr, s.Name)
		}
		pid, err := devStartSim(ctx, bin, dir, s)
		if err != nil {
			return err
		}
		st.Sims = append(st.Sims, devRunning{Name: s.Name, Addr: s.Addr, PID: pid})
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
	for _, r := range st.Sims {
		// Nothing listening means it is gone, and the id may be another
		// process's by now.
		if !devListening(r.Addr) {
			continue
		}
		if err := devStopSim(r.PID); err != nil {
			failed = append(failed, fmt.Sprintf("%s (process %d): %v", r.Name, r.PID, err))
		}
	}
	st.Sims = nil
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
		state := "not running"
		if i := slices.IndexFunc(st.Sims, func(r devRunning) bool { return r.Name == s.Name }); i >= 0 && devListening(st.Sims[i].Addr) {
			state = "running"
		}
		_, _ = fmt.Fprintf(a.stdout, "  %s: %s, http://%s\n", s.Name, state, s.Addr)
	}
	return statusErr
}

// devEnv prints connection settings: addresses and the organization id,
// which are no secret. The node's secrets are never read here.
func devEnv(_ context.Context, a *app, args []string) error {
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
	lines := []string{
		"PANTHERCLAW_SERVER=" + nodePublicURL(st),
		"PANTHERCLAW_GATEWAY=http://localhost:" + strconv.Itoa(st.GatewayPort),
		"PANTHERCLAW_ORG=" + st.Org,
	}
	for _, s := range devSims {
		lines = append(lines, "PANTHERCLAW_SIM_"+strings.ToUpper(s.Name)+"=http://"+s.Addr)
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
	c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
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
func startDevSim(ctx context.Context, bin, dir string, s devSim) (int, error) {
	log, err := os.OpenFile(filepath.Join(dir, "sim-"+s.Name+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: the node directory pclaw manages
	if err != nil {
		return 0, err
	}
	defer func() { _ = log.Close() }()
	cmd := exec.Command(bin, s.Name, "--addr", s.Addr) //nolint:gosec,noctx // G204: pclaw's own simulator; it must outlive this command's context
	cmd.Dir, cmd.Stdout, cmd.Stderr, cmd.Env = dir, log, log, simEnv(os.Environ())
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("pclaw: start simulator %s: %w", s.Name, err)
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()
	deadline := time.Now().Add(devSimReady)
	for !devListening(s.Addr) {
		if time.Now().After(deadline) {
			_ = devStopSim(pid)
			return 0, fmt.Errorf("pclaw: simulator %s did not listen on %s within %s; see %s", s.Name, s.Addr, devSimReady, log.Name())
		}
		select {
		case <-ctx.Done():
			_ = devStopSim(pid)
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return pid, nil
}

func stopDevSim(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
