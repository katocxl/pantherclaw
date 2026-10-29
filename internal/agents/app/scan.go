// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxOpenScanDiscoveries is the cap on open discoveries per org, the same
// as for gateway discoveries (HR-148): the org scans' (github_scan) and
// all others' each have their own, so neither fills the other's room.
const MaxOpenScanDiscoveries = 200

// ScanFinding is one finding of a local `pclaw scan` (PN-001.1). Its
// attributes are UNTRUSTED observations.
type ScanFinding struct {
	Kind       string
	Key        [32]byte
	Attributes map[string]string
}

// ScanResult counts what a submission did.
type ScanResult struct {
	Created, Counted, Dropped int
	// Reopened counts the created that reopened a dismissed finding.
	Reopened int
	// Missed counts the discoveries of the scope a complete CI-mode scan
	// did not see (D115).
	Missed int
}

// ScanMode is how a local scan was run (G0 M17 D115). With a Scope it is a
// CI-mode scan: its findings are ci_scan discoveries of that scope. Complete
// says it read the whole scope and the submission carries every finding of
// it, so a discovery of the scope it lacks counts a miss (HR-459).
type ScanMode struct {
	Scope    string
	Complete bool
}

// MaxScopeLen bounds a CI-mode scan's scope.
const MaxScopeLen = 256

// MaxCompleteFindings is the most findings a complete scan has: it is one
// submission (D130).
const MaxCompleteFindings = 200

var (
	// ErrScopeRequired refuses a complete scan without a scope.
	ErrScopeRequired = pcerr.New(pcerr.InvalidArgument, "SCAN_SCOPE", "a complete scan names its scope (--scope)")
	// ErrScope refuses a scope that is not plain text of 1 to 256 characters.
	ErrScope = pcerr.New(pcerr.InvalidArgument, "SCAN_SCOPE", "a scope is 1 to 256 characters of plain text")
	// ErrCompleteTooLarge refuses a complete scan of more findings than one
	// submission carries (D130).
	ErrCompleteTooLarge = pcerr.New(pcerr.InvalidArgument, "SCAN_TOO_LARGE",
		"complete scans are limited to 200 findings per scope; narrow --scope")
)

func (m ScanMode) check(findings int) error {
	if m.Complete && m.Scope == "" {
		return ErrScopeRequired
	}
	if m.Scope != "" && (utf8.RuneCountInString(m.Scope) > MaxScopeLen || !plainScope(m.Scope)) {
		return ErrScope
	}
	if m.Complete && findings > MaxCompleteFindings {
		return ErrCompleteTooLarge
	}
	return nil
}

// plainScope reports whether s is one trimmed line of text with no control or
// format (bidi) characters: a scope is shown to people as untrusted text.
func plainScope(s string) bool {
	if s == "" || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

// scopedKey is a CI-mode finding's key within its scope, so the same
// finding in two scopes is two discoveries, each missed on its own.
func scopedKey(scope string, key [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("pantherclaw ci_scan key v1\x00"))
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write(key[:])
	return [32]byte(h.Sum(nil))
}

// scanName is a readable name for a discovered agent; nothing binds to it
// (F034).
func scanName(f ScanFinding) string {
	var s string
	switch f.Kind {
	case "mcp_server":
		s = "MCP server " + f.Attributes["name"]
		if c := f.Attributes["client"]; c != "" {
			s += " (" + c + ")"
		}
	case "github_mcp_config":
		s = "MCP configuration " + f.Attributes["repo"] + " " + f.Attributes["path"]
	case "github_workflow":
		s = "GitHub workflow " + f.Attributes["repo"] + " " + f.Attributes["path"]
	case "github_app":
		s = "GitHub App " + f.Attributes["app_slug"]
	default:
		s = "agent project " + filepath.Base(f.Attributes["path"])
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// SubmitScan records scan findings as DISCOVERED agents, each with a
// discovery and an ADMISSION entry (F015); a finding submitted before is
// only counted. The caller needs agent.manage somewhere in the org. At
// most MaxOpenScanDiscoveries discoveries are open per org; past that,
// findings are dropped and counted. Submitting grants nothing.
func (inv *Inventory) SubmitScan(ctx context.Context, host string, findings []ScanFinding, mode ScanMode) (ScanResult, error) {
	for _, f := range findings {
		if !localKinds[f.Kind] {
			return ScanResult{}, ErrScanKind
		}
	}
	if err := mode.check(len(findings)); err != nil {
		return ScanResult{}, err
	}
	source := "scan"
	if mode.Scope != "" {
		source = "ci_scan"
	}
	var res ScanResult
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if !c.CanAnywhere(td.PermAgentManage) {
			return td.ErrPermissionDenied(td.PermAgentManage)
		}
		if err := q.LockDiscoveries(ctx, c.Org.String()); err != nil {
			return err
		}
		open, err := q.CountOpenDiscoveriesOfSource(ctx, c.Org, source)
		if err != nil {
			return err
		}
		by := actor(c)
		w := discoverer{by: c.Principal.String(), actor: by, ledger: c.Actor(), source: source, notify: inv.notify}
		if mode.Scope != "" {
			// A CI-mode scan: its submission is its run, which misses are counted
			// against (D115).
			run := ids.NewV7()
			w.run, w.scope = &run, &mode.Scope
		}
		for _, f := range findings {
			if mode.Scope != "" {
				f.Key = scopedKey(mode.Scope, f.Key)
			}
			observed := maps.Clone(f.Attributes)
			if observed == nil {
				observed = map[string]string{}
			}
			observed["kind"], observed["submitted_by"] = f.Kind, string(by)
			if host != "" {
				observed["host"] = host
			}
			if mode.Scope != "" {
				observed["scope"] = mode.Scope
			}
			obs, err := json.Marshal(observed)
			if err != nil {
				return err
			}
			// A finding dismissed for what it could do then reopens when that
			// changes, as an org scan's does (#336 review); otherwise it is
			// counted again.
			var reopen ids.UUID
			prior, err := q.GetScanDiscovery(ctx, c.Org, source, f.Key[:])
			switch {
			case db.IsNoRows(err):
			case err != nil:
				return err
			case prior.State == "DISMISSED" && riskChanged(f.Kind, prior.Observed, observed):
				reopen = prior.ID
			default:
				if err := touch(ctx, tx, q, c.Org, w, f, obs, observed, prior); err != nil {
					return err
				}
				res.Counted++
				continue
			}
			if open >= MaxOpenScanDiscoveries {
				res.Dropped++
				continue
			}
			if err := insertFinding(ctx, tx, q, c.Org, w, f, obs, observed, reopen); err != nil {
				return err
			}
			open++
			res.Created++
			if !reopen.IsZero() {
				res.Reopened++
				if err := record(ctx, tx, c, "agents.discovery_reopened", prior.AgentID, map[string]string{
					"discovery": reopen.String(), "kind": f.Kind, "source": source,
				}); err != nil {
					return err
				}
			}
		}
		// A complete CI-mode scan counts what it missed in its scope; one that
		// dropped findings did not record all it saw, so it counts nothing
		// (HR-459).
		if mode.Complete && res.Dropped == 0 {
			n, err := scopeMissed(ctx, tx, q, inv.notify, c.Actor(), mode.Scope, *w.run)
			if err != nil {
				return err
			}
			res.Missed = n
		}
		details := map[string]string{
			"created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted), "dropped": strconv.Itoa(res.Dropped),
			"reopened": strconv.Itoa(res.Reopened),
		}
		if mode.Scope != "" {
			details["complete"], details["missed"] = strconv.FormatBool(mode.Complete), strconv.Itoa(res.Missed)
			details["scan"] = w.run.String()
		}
		return record(ctx, tx, c, "agents.scan_submitted", ids.UUID{}, details)
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

// discoverer is who submitted a finding: a person or service account
// (local scan) or a gateway (organization scan), and the source it records.
type discoverer struct {
	by     string
	actor  domain.Actor
	ledger evdomain.Actor
	source string
	// trusted are more trusted facts for the admission entry (the scan and
	// gateway of an organization scan).
	trusted map[string]string
	// run is the scan that saw the finding, which misses are counted
	// against (D114); scope is a CI-mode scan's scope (D115).
	run   *ids.UUID
	scope *string
	// notify announces a material change of an open or claimed discovery
	// (D116); nil records it without a notice.
	notify Notifier
}

// touch records that a known finding was seen again: it is counted, its
// misses reset, and a discovery people were told had vanished records its
// reappearance, without a notice (D114).
func touch(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, w discoverer, f ScanFinding, obs []byte,
	observed map[string]string, prior dbq.GetScanDiscoveryRow,
) error {
	if _, err := q.TouchScanDiscovery(ctx, dbq.TouchScanDiscoveryParams{
		Observed: obs, LastScanRun: w.run, OrgID: org, ScanKey: f.Key[:], Source: w.source,
	}); err != nil {
		return err
	}
	// What its route may do changed while it was open or claimed: recorded
	// and announced, the agent unchanged (D116, HR-460).
	if (prior.State == "OPEN" || prior.State == "CLAIMED") && riskChanged(f.Kind, prior.Observed, observed) {
		if err := w.changed(ctx, tx, q, org, f.Kind, prior, observed); err != nil {
			return err
		}
	}
	if prior.VanishNotifiedAt == nil {
		return nil
	}
	details := map[string]string{"discovery_id": prior.ID.String(), "source": w.source, "kind": f.Kind}
	if w.run != nil {
		details["scan"] = w.run.String()
	}
	if err := RecordChange(ctx, q, org, prior.AgentID, domain.Change{Kind: domain.ChangeDiscoveryReappeared, Actor: w.actor, Details: details}); err != nil {
		return err
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: string(domain.ChangeDiscoveryReappeared), Actor: w.ledger, Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: prior.AgentID.String()}, Details: details,
	})
	return err
}

// insertFinding records a new finding as a DISCOVERED agent with its
// discovery, an ADMISSION entry and a history entry. With reopen, the
// finding was dismissed: that discovery reopens for the new agent instead.
func insertFinding(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, w discoverer, f ScanFinding, obs []byte,
	observed map[string]string, reopen ids.UUID,
) error {
	a, err := q.InsertDiscoveredAgent(ctx, dbq.InsertDiscoveredAgentParams{
		OrgID: org, ID: ids.NewV7(), Name: scanName(f), CreatedBy: w.by,
	})
	if err != nil {
		return err
	}
	d := dbq.PcDiscovery{ID: reopen}
	if reopen.IsZero() {
		if d, err = q.InsertScanDiscovery(ctx, dbq.InsertScanDiscoveryParams{
			OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Source: w.source, ScanKey: f.Key[:], Observed: obs,
			LastScanRun: w.run, ScanScope: w.scope,
		}); err != nil {
			return err
		}
	} else if n, err := q.ReopenScanDiscovery(ctx, dbq.ReopenScanDiscoveryParams{
		AgentID: a.ID, Observed: obs, LastScanRun: w.run, OrgID: org, ID: reopen,
	}); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("agents: discovery %s was not dismissed", reopen)
	}
	trusted := maps.Clone(w.trusted)
	if trusted == nil {
		trusted = map[string]string{}
	}
	trusted["source"], trusted["discovery_id"], trusted["submitted_by"] = w.source, d.ID.String(), w.by
	ev, err := json.Marshal(map[string]map[string]string{"trusted": trusted, "untrusted": observed})
	if err != nil {
		return err
	}
	if _, err := q.InsertAgentAdmissionEntry(ctx, dbq.InsertAgentAdmissionEntryParams{
		OrgID: org, ID: ids.NewV7(), AgentID: a.ID, Evidence: ev,
	}); err != nil {
		return err
	}
	details := map[string]string{"discovery_id": d.ID.String(), "source": w.source}
	if !reopen.IsZero() {
		details["reopened"] = "true"
	}
	if err := RecordChange(ctx, q, org, a.ID, domain.Change{Kind: domain.ChangeDiscovered, Actor: w.actor, Details: details}); err != nil {
		return err
	}
	// The discovery is also an audit record, so it reaches the evidence feed
	// in chain order (G0 M11 part 2 D18a: the agent.discovered trigger).
	_, err = audit.Record(ctx, tx, audit.Event{
		Name: string(domain.ChangeDiscovered), Actor: w.ledger, Outcome: audit.Success,
		Object: &audit.Object{Type: "agent", ID: a.ID.String()}, Details: details,
	})
	return err
}

// Kinds of findings: a local `pclaw scan` reports MCP servers and agent
// projects; a gateway's organization scan reports GitHub Apps, workflows
// and committed MCP configuration (G0 M8, HR-209).
var (
	localKinds  = map[string]bool{"mcp_server": true, "agent_project": true}
	githubKinds = map[string]bool{"github_app": true, "github_workflow": true, "github_mcp_config": true}
	// ErrScanKind refuses a finding of the other kind of scan.
	ErrScanKind = pcerr.New(pcerr.InvalidArgument, "SCAN_KIND",
		"a local scan reports mcp_server and agent_project findings; github_* findings come only from a gateway's organization scan")
)
