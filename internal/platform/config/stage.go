// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MaxStagedBytes caps each file `secrets stage` copies (G0 M13 D42).
const MaxStagedBytes = 1 << 20

// StageSecrets copies every file of from into to, each written 0400 and
// owned by the running user, for ReadSecretFile (G0 M13 D42). A Kubernetes
// Secret volume shows its keys group-readable (fsGroup) or owned by root,
// which ReadSecretFile refuses; the Helm chart mounts each key into from
// with subPath (a regular file) and runs this as an init container into an
// in-memory emptyDir. Only regular files are copied: a symbolic link, a
// directory, a device or any other entry fails the whole command, as does a
// file over MaxStagedBytes or an empty from. Existing files in to are
// replaced. It returns the names it staged.
func StageSecrets(from, to string) ([]string, error) {
	if from == "" || to == "" {
		return nil, errors.New("config: stage: --from and --to are required")
	}
	if fi, err := os.Stat(to); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("config: stage: %s is not a directory", to)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return nil, fmt.Errorf("config: stage: %w", err)
	}
	type file struct {
		name string
		b    []byte
	}
	var files []file
	for _, e := range entries {
		p := filepath.Join(from, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, fmt.Errorf("config: stage: %w", err)
		}
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("config: stage: %s is not a regular file (%s); mount each secret key with subPath", p, fi.Mode().Type())
		}
		if fi.Size() > MaxStagedBytes {
			return nil, fmt.Errorf("config: stage: %s exceeds %d bytes", p, MaxStagedBytes)
		}
		b, err := readRegular(p)
		if err != nil {
			return nil, err
		}
		files = append(files, file{e.Name(), b})
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("config: stage: %s has no files", from)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		if err := writeStaged(filepath.Join(to, f.name), f.b); err != nil {
			return nil, err
		}
		names = append(names, f.name)
	}
	return names, nil
}

// readRegular reads p, refusing a file swapped for something else between
// the check and the open or grown past the cap.
func readRegular(p string) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // G304: the operator's secret mounts
	if err != nil {
		return nil, fmt.Errorf("config: stage: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("config: stage: %s is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxStagedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("config: stage: read %s: %w", p, err)
	}
	if len(b) > MaxStagedBytes {
		return nil, fmt.Errorf("config: stage: %s exceeds %d bytes", p, MaxStagedBytes)
	}
	return b, nil
}

// writeStaged writes b to path as 0400, replacing any earlier copy (an
// init container that runs again in the same pod).
func writeStaged(path string, b []byte) error {
	tmp := path + ".staging"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's staging directory
	if err != nil {
		return fmt.Errorf("config: stage: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return fmt.Errorf("config: stage: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: stage: %w", err)
	}
	if err := os.Chmod(tmp, 0o400); err != nil {
		return fmt.Errorf("config: stage: %w", err)
	}
	// An earlier copy is 0400: rename replaces it on Unix; remove it first
	// for Windows.
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: stage: %w", err)
	}
	return nil
}

// StageSecretsCommand is `secrets stage --from DIR --to DIR`, shared by
// pantherclaw-server and pantherclaw-gateway.
func StageSecretsCommand(prog string, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "stage" {
		_, _ = fmt.Fprintf(stderr, "usage: %s secrets stage --from DIR --to DIR\n", prog)
		return flag.ErrHelp
	}
	fs := flag.NewFlagSet("secrets stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	from := fs.String("from", "", "directory of secret files (each a regular file, for example a Kubernetes Secret key mounted with subPath)")
	to := fs.String("to", "", "existing directory to write them to, each 0400 (an in-memory emptyDir)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *from == "" || *to == "" {
		fs.Usage()
		return flag.ErrHelp
	}
	names, err := StageSecrets(*from, *to)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "staged %d secret files into %s: %s\n", len(names), *to, strings.Join(names, ", "))
	return nil
}
