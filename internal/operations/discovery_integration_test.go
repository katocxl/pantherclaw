// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package operations_test

import (
	"crypto/sha256"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// vanished records a scan discovery of agent that people were told
// vanished.
func (f *fx) vanished(agent ids.UUID) ids.UUID {
	id := ids.NewV7()
	key := sha256.Sum256([]byte(id.String()))
	f.exec(`INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, state, observed)
		VALUES ($1, $2, $3, 'scan', $4, 'CLAIMED', '{"kind":"mcp_server"}')`, f.org, id, agent, key[:])
	f.exec("UPDATE pc.discoveries SET missed_scans = 3, vanish_notified_at = now() WHERE org_id = $1 AND id = $2", f.org, id)
	return id
}

// changed records a material change of agent's discovery, ago before now.
func (f *fx) changed(agent ids.UUID, ago string) ids.UUID {
	id := ids.NewV7()
	f.exec(`INSERT INTO pc.agent_changes (org_id, id, agent_id, kind, actor, details, created_at)
		VALUES ($1, $2, $3, 'agent.discovery_changed', 'system', '{"kind":"mcp_server"}', now() - $4::interval)`,
		f.org, id, agent, ago)
	return id
}

// TestDiscoveryChangesQueueWithinTheViewersScope (D114, D116): vanished and
// changed discoveries queue as DISCOVERY_CHANGE items, read with
// agent.read: the org-wide viewer sees both agents', a team viewer only
// its own team's; a change older than the week is not queued.
// Covers: PN-001.3
func TestDiscoveryChangesQueueWithinTheViewersScope(t *testing.T) {
	f := newFx(t)
	goneA, goneB := f.vanished(f.agentA), f.vanished(f.agentB)
	changedA, changedB := f.changed(f.agentA, "1 hour"), f.changed(f.agentB, "1 hour")
	stale := f.changed(f.agentA, "8 days")
	item := func(id ids.UUID) string { return string(operations.KindDiscoveryChange) + ":" + id.String() }

	q, err := f.s.GetWorkQueue(f.orgWide())
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(q)
	for _, want := range []ids.UUID{goneA, goneB, changedA, changedB} {
		if !slices.Contains(got, item(want)) {
			t.Errorf("org-wide queue %v lacks %s", got, item(want))
		}
	}
	if slices.Contains(got, item(stale)) {
		t.Errorf("a change older than the week is queued: %v", got)
	}
	if q.Counts[operations.KindDiscoveryChange] != 4 {
		t.Errorf("counts %v", q.Counts)
	}
	for _, it := range q.Items {
		if it.Kind == operations.KindDiscoveryChange && (it.State != "VANISHED" && it.State != "CHANGED") {
			t.Errorf("item %+v", it)
		}
	}

	q, err = f.s.GetWorkQueue(f.teamOf(f.teamA))
	if err != nil {
		t.Fatal(err)
	}
	got = kinds(q)
	if !slices.Contains(got, item(goneA)) || !slices.Contains(got, item(changedA)) {
		t.Errorf("team A queue %v lacks its own agent's items", got)
	}
	if slices.Contains(got, item(goneB)) || slices.Contains(got, item(changedB)) {
		t.Errorf("team A queue %v shows team B's agent's items", got)
	}
	if q.Counts[operations.KindDiscoveryChange] != 2 {
		t.Errorf("team A counts %v", q.Counts)
	}
}
