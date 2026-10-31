// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/scan"
)

// maxAPIKeyFile bounds a key file; a key is far shorter.
const maxAPIKeyFile = 4 << 10

var errAllUsersPrivilege = errors.New("--all-users reads other people's home directories, so it runs as root or SYSTEM")

// Seams for tests: the platform's answers.
var (
	machineID       = platformMachineID
	privileged      = platformPrivileged
	machineSaltDir  = platformMachineDir
	binaryProtected = checkBinaryProtected
)

// deviceScope is this machine's scan scope (G0 M24 D234): `device:` and the
// first 16 hex digits of SHA-256 over the machine id and a local salt, so the
// id means nothing off this machine.
func deviceScope(env Env) (string, error) {
	id, err := machineID()
	if err != nil {
		return "", fmt.Errorf("pclaw: reading the machine id: %w", err)
	}
	salt, err := deviceSalt(env)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("pantherclaw device scope v1\x00"))
	h.Write(salt)
	h.Write([]byte{0})
	h.Write([]byte(id))
	return "device:" + hex.EncodeToString(h.Sum(nil))[:16], nil
}

// deviceSalt reads the local salt, creating it on first use. It lives in a
// machine-wide directory when it can, so a run as SYSTEM or root and a
// person's run give one device id (D251), and in the pclaw configuration
// directory otherwise. It says nothing without the machine id, so everyone on
// the machine may read it.
func deviceSalt(env Env) ([]byte, error) {
	if dir := machineSaltDir(); dir != "" {
		if salt, err := readSalt(filepath.Join(dir, "device-salt"), 0o755, 0o644); err == nil {
			return salt, nil
		}
	}
	creds, err := credsPath(env)
	if err != nil {
		return nil, err
	}
	return readSalt(filepath.Join(filepath.Dir(creds), "device-salt"), 0o700, 0o600)
}

// readSalt reads the salt at path, or creates it. Two first runs agree: the
// one that loses the race reads the other's.
func readSalt(path string, dirMode, fileMode os.FileMode) ([]byte, error) {
	for range 2 {
		b, err := os.ReadFile(path) //nolint:gosec // G304: a directory of pclaw's own
		if err == nil {
			salt, err := hex.DecodeString(strings.TrimSpace(string(b)))
			if err != nil || len(salt) != 32 {
				return nil, fmt.Errorf("pclaw: %s is not a device salt", path)
			}
			return salt, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		salt := make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // G304: as above
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		_, err = f.WriteString(hex.EncodeToString(salt) + "\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return salt, err
	}
	return nil, fmt.Errorf("pclaw: %s keeps changing", path)
}

// homeSkips are profile directories no person owns.
var homeSkips = []string{"Public", "Default", "Default User", "All Users", "Shared", "defaultuser0", "lost+found"}

// userHomes lists the home directories under roots: real directories only,
// so a link in a parent directory cannot point the scan elsewhere.
func userHomes(roots []string) []string {
	var out []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && !slices.Contains(homeSkips, e.Name()) {
				out = append(out, filepath.Join(root, e.Name()))
			}
		}
	}
	return out
}

// homeRoots are where this platform keeps home directories. The second
// result is a home outside them (root's).
func homeRoots() ([]string, []string) {
	switch runtime.GOOS {
	case "windows":
		drive := os.Getenv("SystemDrive")
		if drive == "" {
			drive = "C:"
		}
		return []string{drive + `\Users`}, nil
	case "darwin":
		return []string{"/Users"}, []string{"/var/root"}
	default:
		return []string{"/home"}, []string{"/root"}
	}
}

// userConfigDirOf is os.UserConfigDir for another person's home.
func userConfigDirOf(goos, home string) string {
	switch goos {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support")
	default:
		return filepath.Join(home, ".config")
	}
}

// scanAllUsers runs the same metadata scan over each home directory (D235).
// The scan stays inside each home and follows no link: its owner controls
// what is there, and this runs as root or SYSTEM. Each person's own
// environment is not read.
func scanAllUsers(host string, paths, homes []string) []scan.Finding {
	out := scan.Run(scan.Options{Host: host, Paths: paths})
	for _, home := range homes {
		out = append(out, scan.Run(scan.Options{Host: host, Home: home, ConfigDir: userConfigDirOf(runtime.GOOS, home), Contained: true})...)
	}
	return out
}

// useAPIKeyFile makes PANTHERCLAW_API_KEY_FILE the API key of this run, for a
// scheduled scan that must not hold a key in its environment (D235). A key in
// PANTHERCLAW_API_KEY wins.
func (a *app) useAPIKeyFile() error {
	if key, ok := a.env("PANTHERCLAW_API_KEY"); ok && key != "" {
		return nil
	}
	path, ok := a.env("PANTHERCLAW_API_KEY_FILE")
	if !ok || path == "" {
		return nil
	}
	f, err := os.Open(path) //nolint:gosec // G304: a path the operator set
	if err != nil {
		return fmt.Errorf("PANTHERCLAW_API_KEY_FILE: %w", err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, maxAPIKeyFile+1)
	n, _ := f.Read(buf)
	key := strings.TrimSpace(string(buf[:n]))
	if key == "" || n > maxAPIKeyFile || !apiKeyShape.MatchString(key) {
		return errors.New("PANTHERCLAW_API_KEY_FILE: the file does not hold one API key")
	}
	env := a.env
	a.env = func(name string) (string, bool) {
		if name == "PANTHERCLAW_API_KEY" {
			return key, true
		}
		return env(name)
	}
	return nil
}

// apiKeyShape is one printable word, so a key file cannot carry a header
// break into a request.
var apiKeyShape = regexp.MustCompile(`^[\x21-\x7e]+$`)
