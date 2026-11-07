// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/agents/app"
)

// TestHR711_AChangedDigestWritesConfigChanged: the first sighting of an
// agent configuration file and a rescan with the same digest write no
// agent.config_changed; a rescan with another digest writes exactly one,
// with the old and new digests and nothing of the contents, and no
// agent.discovery_changed (G0 M30 D941).
func TestHR711_AChangedDigestWritesConfigChanged(t *testing.T) {
	w := newWorld(t)
	key := sha256.Sum256([]byte("agent_config CLAUDE.md"))
	oldDigest, newDigest := strings.Repeat("1", 64), strings.Repeat("2", 64)
	submit := func(digest string) {
		t.Helper()
		f := app.ScanFinding{Kind: "agent_config", Key: key, Attributes: map[string]string{
			"client": "claude_code", "scope": "project", "path_class": "memory", "digest": digest, "size": "42",
		}}
		if _, err := w.inv.SubmitScan(w.teamOwner(), "laptop", []app.ScanFinding{f}, app.ScanMode{}); err != nil {
			t.Fatal(err)
		}
	}
	changes := func() int {
		return w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.config_changed'`, w.org)
	}
	submit(oldDigest)
	submit(oldDigest)
	if n := changes(); n != 0 {
		t.Fatalf("first sighting and same digest wrote %d config_changed", n)
	}
	submit(newDigest)
	if n := changes(); n != 1 {
		t.Fatalf("changed digest wrote %d config_changed", n)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.config_changed'
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,old_digest}' = $2
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,new_digest}' = $3
		AND convert_from(body, 'UTF8')::jsonb #>> '{details,path_class}' = 'memory'`, w.org, oldDigest, newDigest); n != 1 {
		t.Fatal("config_changed does not carry the old and new digests")
	}
	if n := w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.agent.discovery_changed'`, w.org); n != 0 {
		t.Fatalf("a digest change wrote %d discovery_changed", n)
	}
	submit(newDigest)
	if n := changes(); n != 1 {
		t.Fatalf("the same new digest wrote another config_changed: %d", n)
	}
}
