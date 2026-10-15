// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command squawk runs the pinned squawk migration linter (ADR-0003,
// BUILD_GUIDE §3.3) over the migrations added after the baseline.
//
// squawk is a Rust binary, so it cannot be pinned through a go.mod like the
// other tools. This command downloads the release asset for the host from
// GitHub, refuses it unless its SHA-256 matches the digest pinned below
// (DEPENDENCY_POLICY §2), caches it in the user cache directory and checks the
// digest again on every run before it writes the binary it runs.
//
// Only the "-- +goose Up" section of each migration is linted: the Down
// section is the rollback and drops what Up created by design. The lines of
// the Down section are blanked so reported line numbers stay right.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
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

// version is the newest squawk release outside the 7-day cooldown when it was
// pinned (2.67.0, 2026-10-04).
const version = "2.67.0"

// assets maps GOOS/GOARCH to the release asset and its SHA-256.
var assets = map[string]struct{ name, sha256 string }{
	"linux/amd64":   {"squawk-linux-x64", "03efe0e666b63bf33e2493693ee0aa9dbed07cbdcd20f7a8292245c1da9d790a"},
	"linux/arm64":   {"squawk-linux-arm64", "25c4f95f81bcdbb0a0dc909820c22eb657a12381558b7275bd69f98f253b9b64"},
	"darwin/amd64":  {"squawk-darwin-x64", "19a0753349e728e3191aba9dd593c80b18635415997d6f095b9115db2af282c7"},
	"darwin/arm64":  {"squawk-darwin-arm64", "7b980008d258c61bd065cac6f00b6f9c6fddcd23eca22493ba87a6d1992d4c3e"},
	"windows/amd64": {"squawk-windows-x64.exe", "d6004a875a29c4d9b251f926eecd8c353e7d6444aeb19f99c64adfcf981963c4"},
}

// baseline is the last migration merged before squawk was added. Merged
// migrations are never edited, so findings in them could not be fixed; every
// later migration is linted.
const baseline = 98

var migrationName = regexp.MustCompile(`^(\d{5})_[a-z0-9_]+\.sql$`)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("squawk", flag.ContinueOnError)
	fl.SetOutput(stderr)
	root := fl.String("root", ".", "repository root")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	files, err := migrations(filepath.Join(*root, "migrations"))
	if err != nil {
		fmt.Fprintln(stderr, "squawk:", err)
		return 2
	}
	b, name, err := binary()
	if err != nil {
		fmt.Fprintln(stderr, "squawk:", err)
		return 2
	}
	bin, cleanup, err := exe(b, name)
	if err != nil {
		fmt.Fprintln(stderr, "squawk:", err)
		return 2
	}
	defer cleanup()
	config := filepath.Join(*root, ".squawk.toml")
	failed := 0
	for _, name := range files {
		src, err := os.ReadFile(filepath.Join(*root, "migrations", name)) //nolint:gosec // G304: a migration file the repository lists
		if err != nil {
			fmt.Fprintln(stderr, "squawk:", err)
			return 2
		}
		cmd := exec.CommandContext(context.Background(), bin, "--config", config, "--reporter", "gcc", "--stdin-filepath", "migrations/"+name) //nolint:gosec // G204: the verified squawk binary
		cmd.Stdin = bytes.NewReader(upSection(src))
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				fmt.Fprintln(stderr, "squawk:", err)
				return 2
			}
			failed++
		}
	}
	if failed > 0 {
		fmt.Fprintf(stderr, "squawk: %d of %d migrations after %05d have findings\n", failed, len(files), baseline)
		return 1
	}
	fmt.Fprintf(stdout, "squawk %s: %d migrations after %05d are clean\n", version, len(files), baseline)
	return 0
}

// migrations lists the migration files numbered after the baseline, in order.
func migrations(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if n, _ := strconv.Atoi(m[1]); n > baseline {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}

// upSection blanks every line from "-- +goose Down" on, keeping the line count.
func upSection(src []byte) []byte {
	lines := strings.SplitAfter(string(src), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "-- +goose Down") {
			for j := i; j < len(lines); j++ {
				if strings.HasSuffix(lines[j], "\n") {
					lines[j] = "\n"
				} else {
					lines[j] = ""
				}
			}
			break
		}
	}
	return []byte(strings.Join(lines, ""))
}

// binary returns the verified squawk binary, downloading it once. The
// cache only saves the download: what runs is written from these checked
// bytes into a private directory (exe), so a cached file changed after the
// check is never executed.
func binary() ([]byte, string, error) {
	a, ok := assets[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return nil, "", fmt.Errorf("no pinned squawk %s for %s/%s", version, runtime.GOOS, runtime.GOARCH)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return nil, "", err
	}
	dir := filepath.Join(cache, "pantherclaw-tools", "squawk-"+version)
	path := filepath.Join(dir, a.name)
	if b, err := os.ReadFile(path); err == nil && digest(b) == a.sha256 { //nolint:gosec // G304: the cached download, checked here
		return b, a.name, nil
	}
	url := "https://github.com/sbdchd/squawk/releases/download/v" + version + "/" + a.name
	b, err := download(url)
	if err != nil {
		return nil, "", err
	}
	if got := digest(b); got != a.sha256 {
		return nil, "", fmt.Errorf("%s: sha256 %s, want %s", url, got, a.sha256)
	}
	// Caching is best effort: a failure only means downloading again.
	if os.MkdirAll(dir, 0o750) == nil {
		if tmp, err := os.CreateTemp(dir, a.name+".*"); err == nil {
			_, werr := tmp.Write(b)
			if errors.Join(werr, tmp.Close()) != nil || os.Rename(tmp.Name(), path) != nil {
				_ = os.Remove(tmp.Name())
			}
		}
	}
	return b, a.name, nil
}

// exe writes the verified binary into a new private directory and returns
// its path and a function that removes the directory.
func exe(b []byte, name string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "pantherclaw-squawk-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o700); err != nil { //nolint:gosec // G306: the binary must be executable; the directory is private (0700)
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func download(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// The release asset redirects to GitHub's object store; the digest is checked after.
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
