// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/agentconfig"
	"github.com/katocxl/pantherclaw/internal/gateway/outbound"
)

// DigestTooLarge is the digest of a configuration file larger than
// MaxFileSize, which is not read.
const DigestTooLarge = "too_large"

// maxConfigFilesPerTree bounds the files listed under one protected tree
// (a skills or rules directory).
const maxConfigFilesPerTree = 500

// agentConfigFindings reports each agent configuration and memory file of
// agentconfig's table by its digest (G0 M30 D941): client, scope, class,
// SHA-256 of the bytes and size, never the contents. A file of at most
// MaxFileSize is also read for the outbound credential formats; a hit is an
// env_secret finding naming the format, never the value (D942).
func agentConfigFindings(o Options) []Finding {
	var out []Finding
	var seen []os.FileInfo
	for _, r := range rootDirs(o) {
		for _, e := range agentconfig.OfRoot(r.root) {
			if dir, tree := e.Tree(); tree {
				for _, p := range o.treeFiles(filepath.Join(r.dir, filepath.FromSlash(dir))) {
					out = append(out, o.configFile(e, p, &seen)...)
				}
				continue
			}
			out = append(out, o.configFile(e, filepath.Join(r.dir, filepath.FromSlash(e.Glob)), &seen)...)
		}
	}
	return out
}

// configFile reports one protected file, once even when two locations name
// it.
func (o Options) configFile(e agentconfig.Entry, path string, seen *[]os.FileInfo) []Finding {
	if !o.allowed(path) {
		return nil
	}
	stat := os.Stat
	if o.Contained {
		stat = os.Lstat // The same no-link rule as o.reader (D287).
	}
	info, err := stat(path)
	if err != nil || !info.Mode().IsRegular() || slices.ContainsFunc(*seen, func(s os.FileInfo) bool { return os.SameFile(s, info) }) {
		return nil
	}
	*seen = append(*seen, info)
	attrs := map[string]string{
		"client": e.Client, "scope": string(e.Scope), "path_class": string(e.Class), "path": clip(path), "host": clip(o.Host),
	}
	var b []byte
	if info.Size() > MaxFileSize {
		attrs["digest"], attrs["size"] = DigestTooLarge, strconv.FormatInt(info.Size(), 10)
	} else {
		if b = o.reader()(path); b == nil {
			return nil
		}
		sum := sha256.Sum256(b)
		attrs["digest"], attrs["size"] = hex.EncodeToString(sum[:]), strconv.Itoa(len(b))
	}
	out := []Finding{{Kind: KindAgentConfig, Key: key(KindAgentConfig, o.Host, path), Attributes: attrs}}
	if b == nil {
		return out
	}
	for _, kind := range outbound.Formats(string(b)) {
		f := secretFinding(o.Host, path, kind, kind, "")
		f.Attributes["source"], f.Attributes["path_class"] = "config_file", string(e.Class)
		out = append(out, f)
	}
	return out
}

// treeFiles lists the regular files below dir, at most MaxDepth deep and
// maxConfigFilesPerTree of them, following no link.
func (o Options) treeFiles(dir string) []string {
	if !o.allowed(dir) {
		return nil
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil //nolint:nilerr // unreadable entries are skipped
		case d.IsDir():
			rel, _ := filepath.Rel(dir, path)
			if rel != "." && strings.Count(rel, string(filepath.Separator)) >= MaxDepth {
				return filepath.SkipDir
			}
			return nil
		case !d.Type().IsRegular():
			return nil
		}
		if out = append(out, path); len(out) >= maxConfigFilesPerTree {
			return filepath.SkipAll
		}
		return nil
	})
	return out
}
