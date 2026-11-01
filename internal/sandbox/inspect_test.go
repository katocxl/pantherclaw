// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func inspectRig() (*Sandbox, InspectOptions) {
	o := InspectOptions{Session: "s", EdgeImage: "edge@sha256:x", Image: "server@sha256:y", Args: []string{"--stdio"}, Dir: "/d"}
	return &Sandbox{
		o: Options{Session: "s", EdgeImage: o.EdgeImage, Dir: o.Dir}, Internal: "pc-sbx", Edge: "pc-edge", Agent: "pc-agent", EdgeAddr: "pc-edge:3128",
	}, o
}

// TestHR584_InspectedServerHasNothing: the server gets the internal network, a
// proxy that refuses, and nothing else: no mount, no credential, no value from
// the host, and the edge has no way out either.
// Covers: F871
func TestHR584_InspectedServerHasNothing(t *testing.T) {
	t.Setenv("PANTHERCLAW_API_KEY", "must-not-travel")
	s, o := inspectRig()
	c := s.inspectContainer(o)
	if len(c.Mounts) != 0 || c.WorkDir != "" || !slices.Equal(c.Networks, []string{s.Internal}) || c.Image != o.Image || !slices.Equal(c.Args, o.Args) || !c.Interactive {
		t.Fatalf("%+v", c)
	}
	allowed := regexp.MustCompile(`^(HTTPS?_PROXY|https?_proxy)=http://pc-edge:3128$|^(NO_PROXY|no_proxy)=$|^HOME=/tmp$`)
	for _, e := range c.Env {
		if !allowed.MatchString(e) {
			t.Errorf("env %q", e)
		}
	}
	e := s.inspectEdge("/d/s-edge.json")
	if !slices.Equal(e.Networks, []string{s.Internal}) || len(e.Mounts) != 1 || e.Mounts[0].Target != configPath || len(e.Env) != 0 {
		t.Fatalf("%+v", e)
	}
	if c.User != AgentUser {
		t.Errorf("user %q", c.User)
	}
}

// TestHR584_NothingElseRunsAnInspection: the sandbox package is imported by
// pclaw alone, so nothing on the server or a hosted gateway can reach Inspect.
// Covers: F871
func TestHR584_NothingElseRunsAnInspection(t *testing.T) {
	root := filepath.Join("..", "..")
	const self = "github.com/katocxl/pantherclaw/internal/sandbox"
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			p := filepath.ToSlash(path)
			if d.IsDir() {
				if strings.HasSuffix(p, "/internal/pclaw") || strings.HasSuffix(p, "/internal/sandbox") || strings.HasSuffix(p, "/cmd/pclaw") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				if v, _ := strconv.Unquote(imp.Path.Value); v == self {
					t.Errorf("%s imports the sandbox", p)
				}
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}
