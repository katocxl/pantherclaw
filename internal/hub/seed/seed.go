// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package seed reads the Hub's source tree (G0 M23 D110, F848):
// items/<kind>/<slug>/item.yaml, each with a tests/ directory the checks read
// and no published item carries. Load turns every item.yaml into the exact
// bytes of its published item and the entry the index lists for it.
//
// task hub:check runs the real validators over what Load returns (D112): see
// check_test.go here.
package seed

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/hub/domain"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// source is an item.yaml as authored: an item, without its spec, and what the
// index says about it.
type source struct {
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Kind    domain.Kind    `json:"kind"`
	Title   string         `json:"title"`
	Summary string         `json:"summary"`
	Body    jsontext.Value `json:"body"`
}

// Item is one source item.
type Item struct {
	// Dir is its directory, relative to the Hub root.
	Dir string
	// Entry is what the index lists for it, with the digest and size of Raw.
	Entry domain.Entry
	// Raw is the exact bytes of its published items/<sha256>.json.
	Raw []byte
	// Item is Raw decoded.
	Item domain.Item
	// Tests are the files of its tests/ directory, by base name. They are
	// never published.
	Tests map[string][]byte
}

// Load reads every item of the Hub source tree rooted at fsys, sorted by
// name. An item that does not meet the format, sits in another kind's
// directory, has no tests or repeats a name is an error.
func Load(fsys fs.FS) ([]Item, error) {
	var out []Item
	for _, kind := range domain.Kinds() {
		dir := path.Join("items", string(kind))
		slugs, err := fs.ReadDir(fsys, dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		for _, s := range slugs {
			if !s.IsDir() {
				return nil, fmt.Errorf("%s/%s: an item is a directory", dir, s.Name())
			}
			it, err := loadItem(fsys, path.Join(dir, s.Name()), kind)
			if err != nil {
				return nil, err
			}
			out = append(out, it)
		}
	}
	kinds, err := fs.ReadDir(fsys, "items")
	if err != nil {
		return nil, err
	}
	for _, k := range kinds {
		if !domain.Kind(k.Name()).Valid() {
			return nil, fmt.Errorf("items/%s: not a kind", k.Name())
		}
	}
	slices.SortFunc(out, func(a, b Item) int { return strings.Compare(a.Entry.Name, b.Entry.Name) })
	for i := 1; i < len(out); i++ {
		if out[i].Entry.Name == out[i-1].Entry.Name {
			return nil, fmt.Errorf("%s and %s are both %s", out[i-1].Dir, out[i].Dir, out[i].Entry.Name)
		}
	}
	return out, nil
}

func loadItem(fsys fs.FS, dir string, kind domain.Kind) (Item, error) {
	raw, err := fs.ReadFile(fsys, path.Join(dir, "item.yaml"))
	if err != nil {
		return Item{}, err
	}
	doc, err := rtdomain.ToJSON(raw)
	if err != nil {
		return Item{}, fmt.Errorf("%s: %w", dir, err)
	}
	var src source
	if err := json.Unmarshal(doc, &src, json.RejectUnknownMembers(true)); err != nil {
		return Item{}, fmt.Errorf("%s: %w", dir, err)
	}
	if src.Kind != kind {
		return Item{}, fmt.Errorf("%s: kind %q is in another kind's directory", dir, src.Kind)
	}
	published, err := json.Marshal(domain.Item{Spec: domain.ItemSpec, Name: src.Name, Version: src.Version, Kind: src.Kind, Body: src.Body}, json.Deterministic(true))
	if err != nil {
		return Item{}, fmt.Errorf("%s: %w", dir, err)
	}
	it, err := domain.DecodeItem(published)
	if err != nil {
		return Item{}, fmt.Errorf("%s: %w", dir, err)
	}
	sum := sha256.Sum256(published)
	out := Item{
		Dir: dir, Raw: published, Item: it, Tests: map[string][]byte{},
		Entry: domain.Entry{
			Name: src.Name, Version: src.Version, Kind: src.Kind, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(published)),
			Title: src.Title, Summary: src.Summary,
		},
	}
	tests, err := fs.ReadDir(fsys, path.Join(dir, "tests"))
	if err != nil {
		return Item{}, fmt.Errorf("%s: an item has tests: %w", dir, err)
	}
	for _, t := range tests {
		if t.IsDir() {
			return Item{}, fmt.Errorf("%s/tests/%s: tests are files", dir, t.Name())
		}
		if out.Tests[t.Name()], err = fs.ReadFile(fsys, path.Join(dir, "tests", t.Name())); err != nil {
			return Item{}, err
		}
	}
	if len(out.Tests) == 0 {
		return Item{}, fmt.Errorf("%s: an item has tests", dir)
	}
	return out, nil
}
