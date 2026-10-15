// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pack holds the built-in detection pack (G0 M10 D11, D12, HR-241).
// The pack ships inside the release-signed binary: builtin/*.yaml plus
// manifest.json, which lists each file's SHA-256 and the pack version. Load
// checks every file against the manifest and the manifest against the
// generated PackDigest constant; on any mismatch detections stay off and
// the caller raises an owned failure. "Signed" therefore means
// release-signed and digest-checked; there is no separate detection root.
package pack

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

//go:embed builtin/*.yaml builtin/manifest.json
var builtin embed.FS

// ErrIntegrity reports a pack whose files do not match its manifest or
// whose manifest does not match PackDigest.
var ErrIntegrity = errors.New("detection: built-in pack integrity check failed")

// Manifest lists the pack's version and the SHA-256 of each rule file.
type Manifest struct {
	Version string            `json:"version"`
	Files   map[string]string `json:"files"`
}

// Pack is the loaded, verified built-in pack.
type Pack struct {
	Version string
	Rules   []*engine.Compiled
}

// Load verifies and compiles the embedded pack.
func Load(env *celenv.Env) (*Pack, error) {
	return load(builtin, PackDigest, env)
}

func load(fsys fs.FS, want string, env *celenv.Env) (*Pack, error) {
	raw, err := fs.ReadFile(fsys, "builtin/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("%w: manifest digest differs from the built-in constant", ErrIntegrity)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrIntegrity, err)
	}
	names, err := fs.Glob(fsys, "builtin/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
	}
	listed := slices.Sorted(maps.Keys(m.Files))
	got := make([]string, len(names))
	for i, n := range names {
		got[i] = path.Base(n)
	}
	if !slices.Equal(listed, got) {
		return nil, fmt.Errorf("%w: files %v, manifest lists %v", ErrIntegrity, got, listed)
	}
	p := &Pack{Version: m.Version}
	seen := map[string]bool{}
	for _, n := range got {
		b, err := fs.ReadFile(fsys, "builtin/"+n)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIntegrity, err)
		}
		d := rules.Digest(b)
		if d != m.Files[n] {
			return nil, fmt.Errorf("%w: %s differs from the manifest", ErrIntegrity, n)
		}
		r, err := rules.Parse(b)
		if err != nil {
			return nil, err
		}
		if !r.Builtin() || seen[r.ID] || strings.ReplaceAll(strings.TrimPrefix(r.ID, "pc."), ".", "_")+".yaml" != n {
			return nil, fmt.Errorf("%w: %s holds rule %q", ErrIntegrity, n, r.ID)
		}
		seen[r.ID] = true
		c, err := engine.Compile(env, r, d, m.Version)
		if err != nil {
			return nil, err
		}
		p.Rules = append(p.Rules, c)
	}
	return p, nil
}

// BuildManifest computes the manifest of the rule files in dir (for the
// generator test).
func BuildManifest(fsys fs.FS, version string) ([]byte, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	m := Manifest{Version: version, Files: map[string]string{}}
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		m.Files[n] = rules.Digest(b)
	}
	out, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(out)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}
