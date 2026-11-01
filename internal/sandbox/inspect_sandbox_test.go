// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build sandbox

package sandbox_test

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker/dockertest"
)

// TestHR584_InspectOnARealEngine runs a server that hunts for credentials and a
// way out: it finds neither, the proxy records where it asked to go, and
// nothing is left behind.
// Covers: F871
func TestHR584_InspectOnARealEngine(t *testing.T) {
	c, e := dockertest.Client(t)
	edgeImage := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/cmd/pantherclaw-edge", "deploy/sandbox/edge.Dockerfile")
	server := dockertest.Image(t, c, e, "github.com/katocxl/pantherclaw/internal/sandbox/testdata/mcpserver", "internal/sandbox/testdata/mcpserver.Dockerfile")
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANTHERCLAW_API_KEY", "must-not-travel")
	var listed string
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	seen, err := sandbox.Inspect(ctx, c, e, sandbox.InspectOptions{
		Session: ids.NewV7().String(), EdgeImage: edgeImage, Image: server, Dir: dir,
	}, func(_ context.Context, in io.Writer, out io.Reader) error {
		r := bufio.NewReader(out)
		for i, line := range []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		} {
			if _, err := io.WriteString(in, line+"\n"); err != nil {
				return err
			}
			got, err := r.ReadString('\n')
			if err != nil {
				return err
			}
			if i == 1 {
				listed = got
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(listed, "read_notes") {
		t.Fatalf("listed %q", listed)
	}
	for _, found := range []string{"env_", "path_found", "direct_out"} {
		if strings.Contains(listed, found) {
			t.Errorf("the server found %s: %s", found, listed)
		}
	}
	if !slices.Contains(seen.Attempts, sandbox.Route{Kind: sandbox.RouteDirectAPI, Locator: "collector.example.test:443"}) {
		t.Errorf("attempts %+v", seen.Attempts)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}
