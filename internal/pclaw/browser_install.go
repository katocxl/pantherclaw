// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// `pclaw browser install-host` installs the native messaging host for the
// managed extension (G0 M33 D979, HR-753): the host's configuration file
// (0600), a wrapper that starts `pclaw browser host` with it, and the host
// manifest, registered for Chrome and Chromium for the current user (or,
// with --system, for the machine). The manifest lets only the named
// extension ids start the host.

func init() {
	commands["browser install-host"] = command{
		usage: "browser install-host --gateway URL --connection NAME --key-file FILE --extension-id ID [--extension-id ID ...] [--run ID] [--browser chrome|chromium|all] [--system]",
		run:   browserInstallHost,
	}
}

// browserHostManifest is Chrome's native messaging host manifest.
type browserHostManifest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Path           string   `json:"path"`
	Type           string   `json:"type"`
	AllowedOrigins []string `json:"allowed_origins"`
}

// browserInstallDir is where the configuration and the wrapper go.
func browserInstallDir(a *app, system bool) (string, error) {
	if !system {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "PantherClaw", "browser"), nil
	}
	switch runtime.GOOS {
	case "windows":
		pd, _ := a.env("ProgramData")
		if pd == "" {
			return "", errors.New("ProgramData is not set")
		}
		return filepath.Join(pd, "PantherClaw", "browser"), nil
	case "darwin":
		return "/Library/Application Support/PantherClaw/browser", nil
	default:
		return "/etc/pantherclaw/browser", nil
	}
}

func browserInstallHost(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("browser install-host", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	gateway := fs.String("gateway", "", "the gateway's public URL")
	conn := fs.String("connection", "", "the kind-local connection the extension's calls use")
	keyFile := fs.String("key-file", "", "the enrolled desktop workload key file")
	run := fs.String("run", "", "the run (default: the key file's)")
	browser := fs.String("browser", "all", "chrome, chromium or all")
	system := fs.Bool("system", false, "install for every user of the machine")
	var extIDs list
	fs.Var(&extIDs, "extension-id", "an extension id allowed to start the host (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *conn == "" || *keyFile == "" || len(extIDs) == 0 {
		return errUsage
	}
	if _, err := checkServer(*gateway); err != nil {
		return errors.New("--gateway must be a base URL using https (http only for localhost)")
	}
	if *run != "" {
		if _, err := ids.ParseUUID(*run); err != nil {
			return errors.New("--run must be a run id")
		}
	}
	var browsers []string
	switch *browser {
	case "chrome", "chromium":
		browsers = []string{*browser}
	case "all":
		browsers = []string{"chrome", "chromium"}
	default:
		return errors.New("--browser must be chrome, chromium or all")
	}
	origins := make([]string, 0, len(extIDs))
	for _, id := range extIDs {
		if !extensionIDPattern.MatchString(id) {
			return fmt.Errorf("--extension-id %q is not a Chrome extension id", id)
		}
		origins = append(origins, "chrome-extension://"+id+"/")
	}
	key, err := filepath.Abs(*keyFile)
	if err != nil {
		return err
	}
	if _, err := os.Stat(key); err != nil {
		return fmt.Errorf("--key-file: %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.Abs(exe); err != nil {
		return err
	}
	dir, err := browserInstallDir(a, *system)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: the manifest and wrapper must be readable by the browser
		return err
	}
	cfgPath := filepath.Join(dir, "host-config.json")
	for _, p := range []string{exe, cfgPath} {
		if strings.ContainsAny(p, "\"\r\n%$`") {
			return fmt.Errorf("the path %q cannot be quoted in the host wrapper", p)
		}
	}
	cfg, err := json.Marshal(browserHostConfig{
		Gateway: *gateway, Connection: *conn, KeyFile: key, Run: *run, ExtensionIDs: extIDs,
	}, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	if err := writeFileMode(cfgPath, cfg, 0o600); err != nil {
		return err
	}
	var wrapper string
	if runtime.GOOS == "windows" {
		wrapper = filepath.Join(dir, "pantherclaw-browser-host.bat")
		err = writeFileMode(wrapper, []byte(`@"`+exe+`" browser host --config "`+cfgPath+`" %*`+"\r\n"), 0o644)
	} else {
		wrapper = filepath.Join(dir, "pantherclaw-browser-host.sh")
		err = writeFileMode(wrapper, []byte("#!/bin/sh\nexec \""+exe+"\" browser host --config \""+cfgPath+"\" \"$@\"\n"), 0o755)
	}
	if err != nil {
		return err
	}
	manifest, err := json.Marshal(browserHostManifest{
		Name: browserHostName, Description: "PantherClaw native messaging host", Path: wrapper, Type: "stdio", AllowedOrigins: origins,
	}, json.Deterministic(true), jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	written, err := registerBrowserHostFn(dir, browsers, *system, manifest)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(a.stdout, "configuration: "+cfgPath)
	_, _ = fmt.Fprintln(a.stdout, "wrapper: "+wrapper)
	for _, w := range written {
		_, _ = fmt.Fprintln(a.stdout, "manifest: "+w)
	}
	return nil
}

// registerBrowserHostFn registers the manifest; a variable so tests do not
// write the machine's registry or browser directories.
var registerBrowserHostFn = registerBrowserHost

// writeFileMode writes a file and sets its mode (WriteFile keeps the mode
// of a file that already exists).
func writeFileMode(path string, b []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, b, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
