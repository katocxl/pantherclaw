// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/admincli"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/pclaw"
)

const (
	m23Rule  = "pc.detect.shell-merge-attempt"
	m23Other = "pc.detect.first-production-deploy"
)

// hubKit is the development Hub key and the sites built with it.
type hubKit struct {
	t   *testing.T
	key string
	pub string
}

func newHubKit(t *testing.T) *hubKit {
	t.Helper()
	dir := t.TempDir()
	var out, errb bytes.Buffer
	if code := admincli.Run([]string{"keygen", "--purpose", "hub-dev", "--out-dir", dir}, &out, &errb, time.Now); code != 0 {
		t.Fatalf("keygen: %d %s", code, errb.String())
	}
	return &hubKit{t: t, key: filepath.Join(dir, "hub-dev.key"), pub: filepath.Join(dir, "hub-dev.pub.json")}
}

// build runs pclaw-admin hub build over the seed content.
func (h *hubKit) build(version int) string {
	h.t.Helper()
	dir := filepath.Join(h.t.TempDir(), "site")
	var out, errb bytes.Buffer
	if code := admincli.Run([]string{"hub", "build", "--dir", "../../hub", "--out", dir, "--key", h.key,
		"--version", strconv.Itoa(version), "--expires-days", "30"}, &out, &errb, time.Now); code != 0 {
		h.t.Fatalf("hub build: %d %s", code, errb.String())
	}
	return dir
}

// TestE2E_M23_HubAndCI is M23's exit journey (G0 M23 D108): a Hub built with
// the development key installs to a draft on a real server; a tampered item
// and a rolled-back index are refused by pclaw and by the server on its own.
//
// Covers: F841, F844, F845, F846, F847
func TestE2E_M23_HubAndCI(t *testing.T) {
	kit := newHubKit(t)
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", billing: true, people: &p, hubKey: kit.pub})
	activePlan(t, s.pool, s.org)
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	admin := people.user(t, "m23-admin", "m23-admin@example.test")
	admin.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	id := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'm23-admin'")
	if code, o, e := admin.pclaw(t, "role", "bind", "--role", "security_admin", "--user", id); code != 0 {
		t.Fatalf("role bind: %d %s %s", code, o, e)
	}
	admin.login(t, org, "")
	hub := func(args ...string) (int, string, string) {
		t.Helper()
		var o, e bytes.Buffer
		code := pclaw.Run(context.Background(), append([]string{"hub"}, args...), &o, &e, admin.env("PANTHERCLAW_HUB_DEV_KEY", kit.pub), pclaw.Options{})
		return code, o.String(), e.String()
	}
	rc := pantherclawv1connect.NewHubServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, admin)},
	}, s.apiURL)))
	count := func(sql string) int {
		t.Helper()
		n, err := strconv.Atoi(s.row(t, sql))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	items, err := seed.Load(os.DirFS("../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string][]byte{}
	for _, it := range items {
		raw[it.Entry.Name] = it.Raw
	}
	sha := map[string]string{}
	for _, it := range items {
		sha[it.Entry.Name] = it.Entry.SHA256
	}
	v2 := kit.build(2)
	doc2, err := os.ReadFile(filepath.Join(v2, "index.jws"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("an install ends as a draft and changes nothing else", func(t *testing.T) {
		if code, o, e := hub("search", "shell", "--source", v2); code != 0 || !strings.Contains(o, m23Rule) {
			t.Fatalf("search: %d %s %s", code, o, e)
		}
		if code, o, e := hub("install", m23Rule, "--source", v2); code != 0 || !strings.Contains(o, "HUB_INSTALL_STATUS_INSTALLED") {
			t.Fatalf("install: %d %s %s", code, o, e)
		}
		if n := count("SELECT count(*)::text FROM pc.custom_detection_rules WHERE state = 'DRAFT'"); n != 1 {
			t.Fatalf("draft rules: %d", n)
		}
		if n := count("SELECT count(*)::text FROM pc.custom_detection_rules WHERE state <> 'DRAFT'"); n != 0 {
			t.Fatalf("rules past draft: %d", n)
		}
		res, err := rc.InstallHubItem(context.Background(), &pantherclawv1.InstallHubItemRequest{IndexJws: string(doc2), Item: raw[m23Rule]})
		if err != nil || !res.GetAlreadyInstalled() {
			t.Fatalf("again: %v %v", res, err)
		}
		if n := count("SELECT count(*)::text FROM pc.custom_detection_rules"); n != 1 {
			t.Fatalf("rules after reinstalling: %d", n)
		}
	})

	t.Run("a tampered item is refused", func(t *testing.T) {
		bad := bytes.Replace(raw[m23Other], []byte("title"), []byte("TITLE"), 1)
		if err := os.WriteFile(filepath.Join(v2, "items", sha[m23Other]+".json"), bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, e := hub("install", m23Other, "--source", v2); code == 0 || !strings.Contains(e, "HUB_DIGEST") {
			t.Fatalf("pclaw: %d %s", code, e)
		}
		_, err := rc.InstallHubItem(context.Background(), &pantherclawv1.InstallHubItemRequest{IndexJws: string(doc2), Item: bad})
		if err == nil || !strings.Contains(err.Error(), "HUB_DIGEST") {
			t.Fatalf("server: %v", err)
		}
	})

	t.Run("a rolled-back index is refused", func(t *testing.T) {
		v1 := kit.build(1)
		if code, _, e := hub("install", m23Other, "--source", v1); code == 0 || !strings.Contains(e, "HUB_ROLLBACK") {
			t.Fatalf("pclaw: %d %s", code, e)
		}
		doc1, err := os.ReadFile(filepath.Join(v1, "index.jws"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = rc.InstallHubItem(context.Background(), &pantherclawv1.InstallHubItemRequest{IndexJws: string(doc1), Item: raw[m23Other]})
		if err == nil || !strings.Contains(err.Error(), "HUB_ROLLBACK") {
			t.Fatalf("server: %v", err)
		}
		if n := count("SELECT count(*)::text FROM pc.hub_installs"); n != 1 {
			t.Fatalf("installs: %d", n)
		}
	})

	t.Run("a range scenario stays on this machine", func(t *testing.T) {
		dir := t.TempDir()
		v3 := kit.build(3)
		if code, o, e := hub("install", "pc.range.merge-without-a-reviewer", "--scenario-dir", dir, "--source", v3); code != 0 {
			t.Fatalf("install: %d %s %s", code, o, e)
		}
		files, err := filepath.Glob(filepath.Join(dir, "CX-*.yaml"))
		if err != nil || len(files) != 1 {
			t.Fatalf("scenarios: %v %v", files, err)
		}
		if n := count("SELECT count(*)::text FROM pc.hub_installs"); n != 1 {
			t.Fatalf("installs: %d", n)
		}
	})
}
