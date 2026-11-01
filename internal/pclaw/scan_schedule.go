// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// scheduleName names the scheduled scan in each platform's scheduler.
const (
	scheduleName  = "PantherClawScan"
	scheduleLabel = "dev.pantherclaw.scan"
	scheduleUnit  = "pantherclaw-scan"
)

// Limits on --every.
const (
	minScheduleEvery = time.Hour
	maxScheduleEvery = 30 * 24 * time.Hour
)

var errScheduleEvery = errors.New("--every is a whole number of minutes from 1h to 720h")

// maxTaskCommand is the longest command schtasks /TR takes.
const maxTaskCommand = 261

// runScheduler runs a scheduler command; tests replace it.
var runScheduler = func(ctx context.Context, name string, args ...string) (string, error) {
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed tools, arguments built here
	return string(b), err
}

// scheduleSpec is what a schedule installs on one platform: files to write,
// and the commands to run for each action.
type scheduleSpec struct {
	files                  map[string]string
	install, remove, query [][]string
}

// scanSchedule is a scheduled scan's settings.
type scanSchedule struct {
	goos, exe, home string
	every           time.Duration
	allUsers        bool
	// env holds the settings the scan reads, by name. It never holds a key.
	env map[string]string
}

// scheduledEnv are the settings a scheduled scan takes from the environment
// it was installed in. PANTHERCLAW_API_KEY is left out on purpose: a key goes
// in a file, never in a scheduler's definition.
var scheduledEnv = []string{"PANTHERCLAW_API_KEY_FILE", "PANTHERCLAW_SERVER", "PANTHERCLAW_CONFIG_DIR"}

// taskQuote quotes v for a task's command: backslashes before the closing
// quote are doubled, or they would escape it (D282).
func taskQuote(v string) string {
	return `"` + v + strings.Repeat(`\`, len(v)-len(strings.TrimRight(v, `\`))) + `"`
}

// scheduledFlags are scheduledEnv as `pclaw scan` flags.
var scheduledFlags = []struct{ env, flag string }{
	{"PANTHERCLAW_API_KEY_FILE", "--key-file"}, {"PANTHERCLAW_SERVER", "--server"}, {"PANTHERCLAW_CONFIG_DIR", "--config-dir"},
}

// scanArgs are the scheduled command's arguments.
func (s scanSchedule) scanArgs() []string {
	args := []string{"scan", "--submit", "--device", "--no-env"}
	if s.allUsers {
		args = append(args, "--all-users")
	}
	return args
}

// spec builds the platform's definition (G0 M24 D237). A scan of all users
// is the machine's own job, so it runs as SYSTEM or root; otherwise it is the
// person's.
func (s scanSchedule) spec() (scheduleSpec, error) {
	switch s.goos {
	case "windows":
		return s.schtasks()
	case "darwin":
		return s.launchd(), nil
	case "linux":
		return s.systemd(), nil
	}
	return scheduleSpec{}, fmt.Errorf("pclaw: scheduling a scan on %s is not supported", s.goos)
}

func (s scanSchedule) schtasks() (scheduleSpec, error) {
	mins := int(s.every / time.Minute)
	sc, mo := "MINUTE", mins
	if mins%(24*60) == 0 {
		sc, mo = "DAILY", mins/(24*60)
	} else if mins >= 24*60 {
		return scheduleSpec{}, errors.New("on Windows, --every is under 24h or a whole number of days")
	}
	tr := `"` + s.exe + `" ` + strings.Join(s.scanArgs(), " ")
	// A task carries no environment, so its settings are flags (D248). The key
	// is never one of them: only the file that holds it.
	for _, f := range scheduledFlags {
		if v, ok := s.env[f.env]; ok {
			if strings.Contains(v, `"`) {
				return scheduleSpec{}, fmt.Errorf("%s holds a quotation mark", f.env)
			}
			tr += " " + f.flag + " " + taskQuote(v)
		}
	}
	if len(tr) > maxTaskCommand {
		return scheduleSpec{}, fmt.Errorf("the task's command is over %d characters: use shorter paths", maxTaskCommand)
	}
	create := []string{"schtasks", "/Create", "/F", "/TN", scheduleName, "/SC", sc, "/MO", strconv.Itoa(mo), "/TR", tr}
	if s.allUsers {
		create = append(create, "/RU", "SYSTEM", "/RL", "HIGHEST")
	}
	return scheduleSpec{
		install: [][]string{create},
		remove:  [][]string{{"schtasks", "/Delete", "/F", "/TN", scheduleName}},
		query:   [][]string{{"schtasks", "/Query", "/TN", scheduleName}},
	}, nil
}

func (s scanSchedule) launchd() scheduleSpec {
	dir := filepath.Join(s.home, "Library", "LaunchAgents")
	domain := "gui/" + strconv.Itoa(os.Getuid())
	if s.allUsers {
		dir, domain = "/Library/LaunchDaemons", "system"
	}
	path := dir + "/" + scheduleLabel + ".plist"
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0"><dict>` + "\n")
	b.WriteString("<key>Label</key><string>" + scheduleLabel + "</string>\n<key>ProgramArguments</key><array>")
	for _, a := range append([]string{s.exe}, s.scanArgs()...) {
		b.WriteString("<string>" + xmlText(a) + "</string>")
	}
	b.WriteString("</array>\n<key>StartInterval</key><integer>" + strconv.Itoa(int(s.every/time.Second)) + "</integer>\n")
	if len(s.env) > 0 {
		b.WriteString("<key>EnvironmentVariables</key><dict>")
		for _, name := range scheduledEnv {
			if v, ok := s.env[name]; ok {
				b.WriteString("<key>" + name + "</key><string>" + xmlText(v) + "</string>")
			}
		}
		b.WriteString("</dict>\n")
	}
	b.WriteString("</dict></plist>\n")
	return scheduleSpec{
		files:   map[string]string{path: b.String()},
		install: [][]string{{"launchctl", "bootstrap", domain, path}},
		remove:  [][]string{{"launchctl", "bootout", domain + "/" + scheduleLabel}},
		query:   [][]string{{"launchctl", "print", domain + "/" + scheduleLabel}},
	}
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s)) // a strings.Builder never fails
	return b.String()
}

func (s scanSchedule) systemd() scheduleSpec {
	dir, ctl := filepath.ToSlash(filepath.Join(s.home, ".config", "systemd", "user")), []string{"systemctl", "--user"}
	if s.allUsers {
		dir, ctl = "/etc/systemd/system", []string{"systemctl"}
	}
	var unit strings.Builder
	unit.WriteString("[Unit]\nDescription=PantherClaw scan\n\n[Service]\nType=oneshot\n")
	for _, name := range scheduledEnv {
		if v, ok := s.env[name]; ok {
			unit.WriteString("Environment=" + strconv.Quote(name+"="+v) + "\n")
		}
	}
	unit.WriteString("ExecStart=" + strconv.Quote(s.exe) + " " + strings.Join(s.scanArgs(), " ") + "\n")
	timer := fmt.Sprintf("[Unit]\nDescription=PantherClaw scan\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec=%ds\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
		int(s.every/time.Second))
	cmd := func(args ...string) []string { return append(append([]string{}, ctl...), args...) }
	return scheduleSpec{
		files: map[string]string{dir + "/" + scheduleUnit + ".service": unit.String(), dir + "/" + scheduleUnit + ".timer": timer},
		install: [][]string{
			cmd("daemon-reload"),
			cmd("enable", "--now", scheduleUnit+".timer"),
		},
		remove: [][]string{cmd("disable", "--now", scheduleUnit+".timer")},
		query:  [][]string{cmd("list-timers", scheduleUnit+".timer", "--all")},
	}
}

// checkEvery refuses an interval a scheduler cannot hold.
func checkEvery(d time.Duration) error {
	if d < minScheduleEvery || d > maxScheduleEvery || d%time.Minute != 0 {
		return errScheduleEvery
	}
	return nil
}

// scanScheduleCmd is `pclaw scan schedule install|remove|status` (G0 M24
// D237): a periodic `pclaw scan --submit --device`.
func scanScheduleCmd(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("scan schedule", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	every := fs.Duration("every", 24*time.Hour, "how often to scan, from 1h to 720h")
	allUsers := fs.Bool("all-users", false, "scan every home directory, as root or SYSTEM")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (action != "install" && action != "remove" && action != "status") {
		return errUsage
	}
	if err := checkEvery(*every); err != nil {
		return err
	}
	if *allUsers && action != "status" && !privileged() {
		return errAllUsersPrivilege
	}
	if *allUsers && action == "install" && !binaryProtected() {
		return errBinaryWritable
	}
	exe, err := resolvedExecutable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil && !*allUsers {
		return err
	}
	s := scanSchedule{goos: runtime.GOOS, exe: exe, home: home, every: *every, allUsers: *allUsers, env: map[string]string{}}
	for _, name := range scheduledEnv {
		if v, ok := a.env(name); ok && v != "" {
			if strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("%s holds a line break", name)
			}
			s.env[name] = v
		}
	}
	spec, err := s.spec()
	if err != nil {
		return err
	}
	return applySchedule(ctx, a, action, spec)
}

func applySchedule(ctx context.Context, a *app, action string, spec scheduleSpec) error {
	run := func(cmds [][]string) (string, error) {
		var out strings.Builder
		for _, c := range cmds {
			o, err := runScheduler(ctx, c[0], c[1:]...)
			out.WriteString(o)
			if err != nil {
				return out.String(), fmt.Errorf("%s: %w: %s", c[0], err, strings.TrimSpace(o))
			}
		}
		return out.String(), nil
	}
	switch action {
	case "install":
		for path, content := range spec.files {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: a scheduler's directory
				return err
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // G306: schedulers read it; it holds no key
				return err
			}
		}
		if _, err := run(spec.install); err != nil {
			return err
		}
		_, err := fmt.Fprintln(a.stdout, "scheduled: pclaw scan --submit --device")
		return err
	case "remove":
		if _, err := run(spec.remove); err != nil {
			return err
		}
		for path := range spec.files {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		_, err := fmt.Fprintln(a.stdout, "schedule removed")
		return err
	}
	out, err := run(spec.query)
	if err != nil {
		_, werr := fmt.Fprintln(a.stdout, "not scheduled")
		return werr
	}
	_, err = fmt.Fprint(a.stdout, out)
	return err
}
