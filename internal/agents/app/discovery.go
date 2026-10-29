// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"maps"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Notifier queues a notification in the caller's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// orgScanReads are the scan sources an org-scan finding kind needs read in
// full before its absence counts as a miss: the repositories are listed to
// find workflows and MCP configuration (HR-459).
var orgScanReads = map[string][]string{
	"github_workflow":   {"repositories", "workflows"},
	"github_mcp_config": {"repositories", "mcp_configs"},
	"github_app":        {"org_installations"},
}

// orgScanBlocks are the notes of a report that make a kind's listing
// partial: findings it could not submit or the server dropped, an App it
// could not use (every kind), and repositories it could not read (the kinds
// read from repositories).
var orgScanBlocks = map[string][]string{
	"github_workflow":   {"findings", "organization", "contents"},
	"github_mcp_config": {"findings", "organization", "contents"},
	"github_app":        {"findings", "organization"},
}

// missedKinds are the finding kinds a finished org scan read in full: only
// for those does a discovery it did not see count a miss (D114, HR-459).
func missedKinds(scanned []string, notScanned map[string]string) []string {
	var out []string
	for _, kind := range slices.Sorted(maps.Keys(orgScanReads)) {
		ok := true
		for _, s := range orgScanReads[kind] {
			if _, partial := notScanned[s]; partial || !slices.Contains(scanned, s) {
				ok = false
			}
		}
		for _, n := range orgScanBlocks[kind] {
			if _, partial := notScanned[n]; partial {
				ok = false
			}
		}
		if ok {
			out = append(out, kind)
		}
	}
	return out
}

// OrgScanFinished counts the misses of a finished org scan, in its
// transaction (PN-001.3, D114). Only a DONE run counts, and only for the
// kinds it read in full; each github_scan discovery of the connection that
// the run did not see misses once. A discovery that reaches
// domain.VanishAfterMisses is recorded and announced once, to its agent's
// owners or, unclaimed, to the org admins, with a work-queue item. Its
// state and its agent's state and authority do not change (G3, HR-458).
func OrgScanFinished(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify Notifier, gateway, connection, run ids.UUID,
	state string, scanned []string, notScanned map[string]string,
) error {
	if state != "DONE" {
		return nil
	}
	kinds := missedKinds(scanned, notScanned)
	if len(kinds) == 0 {
		return nil
	}
	org := tx.OrgID()
	missed, err := q.MissOrgScanDiscoveries(ctx, dbq.MissOrgScanDiscoveriesParams{
		OrgID: org, ConnectionID: connection.String(), Run: run, Kinds: kinds,
	})
	if err != nil {
		return err
	}
	ledger := evdomain.Actor{Type: "gateway", ID: gateway.String()}
	for _, d := range missed {
		if d.MissedScans < domain.VanishAfterMisses || d.VanishNotifiedAt != nil {
			continue
		}
		v := vanished{id: d.ID, agent: d.AgentID, kind: observedKind(d.Observed), misses: d.MissedScans, source: "github_scan"}
		if err := v.notice(ctx, tx, q, notify, ledger, map[string]string{"scan": run.String(), "connection": connection.String()}); err != nil {
			return err
		}
	}
	return nil
}

// vanished is a discovery that just reached the vanish threshold.
type vanished struct {
	id, agent    ids.UUID
	kind, source string
	misses       int32
}

// notice records and announces v once: a lost race (another scan noticed
// it first) does nothing.
func (v vanished) notice(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify Notifier, ledger evdomain.Actor,
	more map[string]string,
) error {
	org := tx.OrgID()
	if n, err := q.MarkDiscoveryVanished(ctx, org, v.id); err != nil || n != 1 {
		return err
	}
	details := map[string]string{
		"discovery_id": v.id.String(), "source": v.source, "kind": v.kind, "missed_scans": strconv.Itoa(int(v.misses)),
	}
	for k, val := range more {
		details[k] = val
	}
	if err := RecordChange(ctx, q, org, v.agent, domain.Change{Kind: domain.ChangeDiscoveryVanished, Actor: domain.System, Details: details}); err != nil {
		return err
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: string(domain.ChangeDiscoveryVanished), Actor: ledger, Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: v.agent.String()}, Details: details,
	}); err != nil {
		return err
	}
	if notify == nil {
		return nil
	}
	people, err := noticeRecipients(ctx, q, org, v.agent)
	if err != nil {
		return err
	}
	_, err = notify.Enqueue(ctx, tx, napp.Message{
		Org: org, Type: "agent.discovery_vanished", Personal: people, DedupeKey: "discovery_vanished:" + v.id.String() + ":" + details["scan"],
		Params: map[string]string{
			"agent": v.agent.String(), "kind": v.kind, "discovery": v.id.String(), "scans": strconv.Itoa(int(v.misses)),
		},
	})
	return err
}

// noticeRecipients are who hears about a discovery's change (D116): the
// claimed agent's owner and backup owner, else the org admins.
func noticeRecipients(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID) ([]ids.UUID, error) {
	owners, err := q.DiscoveryNoticeOwners(ctx, org, agent)
	if err != nil || len(owners) > 0 {
		return owners, err
	}
	return q.DiscoveryNoticeAdmins(ctx, org)
}

// observedKind is a discovery's finding kind, as the server recorded it,
// or "unknown".
func observedKind(observed []byte) string {
	var o map[string]string
	if json.Unmarshal(observed, &o) != nil || (!githubKinds[o["kind"]] && !localKinds[o["kind"]]) {
		return "unknown"
	}
	return o["kind"]
}
