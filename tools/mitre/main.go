// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Command mitre regenerates PantherClaw's pinned MITRE catalogs (G0 M28
// D711, D711a): internal/threatmap/catalog/attack-enterprise.json from
// MITRE ATT&CK Enterprise (STIX 2.1, attack-stix-data) and
// internal/threatmap/catalog/atlas.json from MITRE ATLAS (atlas-data, format
// v6).
//
// The sources are pinned in tools/mitre/pins.json (version, URL, SHA-256).
// The command downloads each pinned URL over HTTPS, refuses it unless its
// SHA-256 matches the pin, and writes only ids, names, tactics, parents,
// platforms, the deprecated and revoked flags and URLs: never descriptions,
// detections, mitigations, procedure examples or case studies. It fails
// without writing anything on any source it does not understand.
//
// It never runs in CI or `task check`: `task mitre:update` runs it after a
// reviewed edit of pins.json.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Format is the generated catalog's format id (D711).
const Format = "pantherclaw.mitre-catalog/v1"

// Framework ids, as internal/threatmap/catalog names them (D710).
const (
	frameworkATTACK = "attack-enterprise"
	frameworkATLAS  = "atlas"
)

// Notices carried at the top of each generated file (D711a): the
// copyright line and the licence the data comes under.
const (
	noticeATTACK = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. Licence: MITRE ATT&CK Terms of Use (see NOTICE)."
	noticeATLAS  = "Copyright 2021-2026 MITRE. Licence: Apache License, Version 2.0 (see NOTICE)."
)

// maxDownload bounds one source file.
const maxDownload = 64 << 20

// Pin is one pinned source.
type Pin struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Pins is tools/mitre/pins.json.
type Pins struct {
	ATTACK Pin `json:"attack"`
	ATLAS  Pin `json:"atlas"`
}

// Tactic is one generated tactic.
type Tactic struct {
	ID        string `json:"id"`
	ShortName string `json:"short_name"`
	Name      string `json:"name"`
	Order     int    `json:"order"`
	URL       string `json:"url"`
}

// Technique is one generated technique or sub-technique.
type Technique struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics"`
	Parent     string   `json:"parent"`
	Platforms  []string `json:"platforms"`
	Deprecated bool     `json:"deprecated"`
	Revoked    bool     `json:"revoked"`
	URL        string   `json:"url"`
}

// Catalog is one generated file.
type Catalog struct {
	Format       string      `json:"format"`
	Framework    string      `json:"framework"`
	Version      string      `json:"version"`
	SourceURL    string      `json:"source_url"`
	SourceSHA256 string      `json:"source_sha256"`
	Notice       string      `json:"notice"`
	Tactics      []Tactic    `json:"tactics"`
	Techniques   []Technique `json:"techniques"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("mitre", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", "..", "repository root")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := update(*root, download); err != nil {
		fmt.Fprintln(stderr, "mitre:", err)
		return 1
	}
	return 0
}

// update reads the pins, fetches and checks both sources, builds both
// catalogs and only then writes them.
func update(root string, fetch func(string) ([]byte, error)) error {
	raw, err := os.ReadFile(filepath.Join(root, "tools", "mitre", "pins.json")) //nolint:gosec // G304: the pins file under the -root the developer gave
	if err != nil {
		return err
	}
	var pins Pins
	if err := json.Unmarshal(raw, &pins, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("pins.json: %w", err)
	}
	attackSrc, err := fetchPinned(pins.ATTACK, fetch)
	if err != nil {
		return err
	}
	atlasSrc, err := fetchPinned(pins.ATLAS, fetch)
	if err != nil {
		return err
	}
	attack, err := buildATTACK(attackSrc, pins.ATTACK)
	if err != nil {
		return fmt.Errorf("ATT&CK %s: %w", pins.ATTACK.Version, err)
	}
	atlas, err := buildATLAS(atlasSrc, pins.ATLAS)
	if err != nil {
		return fmt.Errorf("ATLAS %s: %w", pins.ATLAS.Version, err)
	}
	dir := filepath.Join(root, "internal", "threatmap", "catalog")
	outs := []struct {
		name string
		c    *Catalog
		b    []byte
	}{{name: "attack-enterprise.json", c: attack}, {name: "atlas.json", c: atlas}}
	for i := range outs {
		if outs[i].b, err = encode(outs[i].c); err != nil {
			return fmt.Errorf("%s: %w", outs[i].name, err)
		}
	}
	for _, o := range outs {
		if err := os.WriteFile(filepath.Join(dir, o.name), o.b, 0o644); err != nil { //nolint:gosec // G306: a checked-in source file
			return err
		}
	}
	return nil
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// fetchPinned downloads a pinned source and refuses it unless its SHA-256
// is the pin's.
func fetchPinned(p Pin, fetch func(string) ([]byte, error)) ([]byte, error) {
	if p.Version == "" || !strings.HasPrefix(p.URL, "https://") || !sha256RE.MatchString(p.SHA256) {
		return nil, fmt.Errorf("pins.json: a pin needs a version, an https URL and a sha256 (%q)", p.URL)
	}
	b, err := fetch(p.URL)
	if err != nil {
		return nil, err
	}
	if got := digest(b); got != p.SHA256 {
		return nil, fmt.Errorf("%s: sha256 %s, want %s", p.URL, got, p.SHA256)
	}
	return b, nil
}

// encode writes a catalog sorted by id, 2-space JSON, LF, with a trailing
// newline (D711).
func encode(c *Catalog) ([]byte, error) {
	slices.SortFunc(c.Tactics, func(a, b Tactic) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(c.Techniques, func(a, b Technique) int { return strings.Compare(a.ID, b.ID) })
	b, err := json.Marshal(c, jsontext.WithIndent("  "), json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func download(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDownload {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxDownload)
	}
	return b, nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var errShape = errors.New("unexpected source shape")

func shape(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errShape, fmt.Sprintf(format, a...))
}

// nonNil keeps empty lists as [] in the output.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
