// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/sandbox/workspace"
)

func TestSandboxRunNeedsItsFlags(t *testing.T) {
	a := &app{stderr: io.Discard, env: func(string) (string, bool) { return "", false }}
	full := []string{
		"--agent", "a", "--connection", "c1", "--connection", "c2", "--grant", "g", "--gateway", "http://127.0.0.1:8090",
		"--image", "x@sha256:" + strings.Repeat("a", 64), "--edge-image", "sha256:" + strings.Repeat("b", 64),
		"--probe-image", "sha256:" + strings.Repeat("c", 64), "--", "curl", "https://api.github.com",
	}
	f, err := parseSandboxRun(a, full)
	if err != nil || len(f.connections) != 2 || strings.Join(f.args, " ") != "curl https://api.github.com" {
		t.Fatalf("flags %+v, %v", f, err)
	}
	single := slices.Concat(full[:4], full[6:16])
	for i := 0; i < len(single); i += 2 {
		args := append(append([]string{}, single[:i]...), single[i+2:]...)
		if _, err := parseSandboxRun(a, args); !errors.Is(err, errUsage) {
			t.Errorf("without %s: %v", single[i], err)
		}
	}
	env := &app{stderr: io.Discard, env: func(k string) (string, bool) {
		return map[string]string{"PANTHERCLAW_SANDBOX_EDGE_IMAGE": "e", "PANTHERCLAW_SANDBOX_PROBE_IMAGE": "p"}[k], true
	}}
	f, _ = parseSandboxRun(env, full[:10])
	if f.edgeImage != "e" || f.probeImage != "p" {
		t.Fatalf("images from the environment: %+v", f)
	}
}

func TestTheEdgeDialsTheHostForALoopbackGateway(t *testing.T) {
	for gw, want := range map[string]string{
		"http://127.0.0.1:8090":       "host.docker.internal:8090",
		"http://localhost:8090":       "host.docker.internal:8090",
		"https://[::1]":               "host.docker.internal:443",
		"https://gw.example.com:8443": "",
	} {
		if got, err := gatewayAddr(gw, ""); err != nil || got != want {
			t.Errorf("%s: %q, %v", gw, got, err)
		}
	}
	if got, _ := gatewayAddr("http://127.0.0.1:8090", "gw:1"); got != "gw:1" {
		t.Errorf("given address: %q", got)
	}
	if _, err := gatewayAddr("ftp://x", ""); err == nil {
		t.Error("an ftp gateway was accepted")
	}
}

func TestTheCoverageOutcomeIsPrinted(t *testing.T) {
	var buf bytes.Buffer
	exp := timestamppb.New(time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC))
	printClosures(&buf, []*pantherclawv1.SandboxClosure{
		{ConnectionId: "c1", ClosureId: "x1", Passed: true, ExpireTime: exp},
		{ConnectionId: "c2", ClosureId: "x2", Failed: []string{"edge_unmapped_refused", "external_canary"}},
	})
	got := buf.String()
	if !strings.Contains(got, "c1: sandbox closure PASSED (closure x1), evidence for ENFORCED until 2026-10-12T09:00:00Z") ||
		!strings.Contains(got, "c2: sandbox closure FAILED (closure x2): edge_unmapped_refused, external_canary") {
		t.Fatalf("printed:\n%s", got)
	}
}

// TestTheChangesAreListedWithTheFilesToReview: the run lists what the
// agent changed, where the patch is, which binary files are beside it, and
// the dotfiles and task files to review before running anything.
func TestTheChangesAreListedWithTheFilesToReview(t *testing.T) {
	var buf bytes.Buffer
	printChanges(&buf, "out", []workspace.Change{
		{Path: "main.go", Kind: workspace.Modified},
		{Path: ".envrc", Kind: workspace.Added, Flagged: true},
		{Path: "logo.png", Kind: workspace.Added, Binary: true},
	})
	got := buf.String()
	for _, want := range []string{
		"3 changes: apply " + filepath.Join("out", "changes.patch"), "under " + filepath.Join("out", "binary") + `: "logo.png"`,
		`these dotfiles, editor or task files changed: ".envrc"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("printed lacks %q:\n%s", want, got)
		}
	}
	buf.Reset()
	printChanges(&buf, "out", nil)
	if !strings.Contains(buf.String(), "changed nothing") {
		t.Errorf("no changes: %q", buf.String())
	}
}

// TestTheSandboxCommandsNeedTheirSession: sandbox get and end need the
// session; list takes none.
func TestTheSandboxCommandsNeedTheirSession(t *testing.T) {
	a := &app{stderr: io.Discard}
	for _, name := range []string{"sandbox get", "sandbox end"} {
		if err := commands[name].run(t.Context(), a, nil); !errors.Is(err, errUsage) {
			t.Errorf("%s without a session: %v", name, err)
		}
	}
	if _, ok := commands["sandbox list"]; !ok {
		t.Error("no sandbox list")
	}
}
