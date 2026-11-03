// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"maps"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	saas "github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// SaaS discovery records what people built in SaaS tenants (N6, G0 M26 D407)
// as discoveries of the vendor's source, through the same writers as every
// scan. Each agent lands DISCOVERED, observe-only and external: it has no key
// path, and a claim sets its owner and nothing else (HR-639).

var (
	// ErrSaaSKey refuses a finding whose key is not its record's: the server
	// derives it from the source, the tenant and the record's id, so nobody
	// picks which discovery a finding lands on.
	ErrSaaSKey = pcerr.New(pcerr.InvalidArgument, "SAAS_FINDING", "a finding's key, tenant and id must be its record's own")
	// ErrSaaSReport refuses a report that names what its source does not read,
	// or says it both read and did not read one thing.
	ErrSaaSReport = pcerr.New(pcerr.InvalidArgument, "SAAS_REPORT", "a report accounts for its source's reads, each read or not read")
	// ErrExternalClaim refuses the ordinary claim of an external agent: it
	// would make the agent usable, and an external one never is.
	ErrExternalClaim = pcerr.New(pcerr.FailedPrecondition, "AGENT_EXTERNAL",
		"an external agent is never claimed: set its owner (SetSaasAgentOwner); it stays observe-only")
	// ErrNotExternal refuses SetSaasAgentOwner on any other agent.
	ErrNotExternal = pcerr.New(pcerr.FailedPrecondition, "AGENT_NOT_EXTERNAL", "only an external agent takes an owner this way")
)

// SaaSReport is a report a server records: from an import, or a gateway's
// finished scan.
type SaaSReport struct {
	Source, Tenant string
	Findings       []ScanFinding
	Scanned        []string
	NotScanned     map[string]string
	Counts         map[string]int64
}

// SaaSResult is what an import did.
type SaaSResult struct {
	ScanResult
	Run ids.UUID
}

// checkSaaSFindings keeps what each finding's kind names, and refuses one
// that is not of the source or not its own record's.
func checkSaaSFindings(source, tenant string, findings []ScanFinding) (int, error) {
	kind, dropped := saas.KindOf(source), 0
	for i := range findings {
		f := &findings[i]
		id := f.Attributes["agent_id"]
		if f.Kind != kind || f.Attributes["tenant"] != tenant || id == "" || f.Key != saas.Key(source, tenant, id) {
			return 0, ErrSaaSKey
		}
		kept, n := saas.Clean(f.Kind, f.Attributes)
		f.Attributes = kept
		dropped += n
	}
	return dropped, nil
}

// NormalizeSaaSReport closes a report over its source's reads: a name outside
// them or the notes is refused, nothing is both read and not read, a value is
// made plain, and a read the report leaves out is recorded as not reported
// (HR-637).
func NormalizeSaaSReport(source string, scanned []string, notScanned map[string]string) ([]string, map[string]string, error) {
	reads := saas.Reads(source)
	if reads == nil {
		return nil, nil, ErrSaaSReport
	}
	out := make(map[string]string, len(notScanned))
	for k, v := range notScanned {
		if !slices.Contains(reads, k) && !slices.Contains(saas.Notes, k) {
			return nil, nil, ErrSaaSReport
		}
		out[k] = saas.Text(v)
		if out[k] == "" {
			out[k] = "not read"
		}
	}
	kept := make([]string, 0, len(scanned))
	for _, s := range scanned {
		if _, both := out[s]; both || !slices.Contains(reads, s) {
			return nil, nil, ErrSaaSReport
		}
		kept = append(kept, s)
	}
	slices.Sort(kept)
	kept = slices.Compact(kept)
	for _, s := range reads {
		if _, unread := out[s]; !unread && !slices.Contains(kept, s) {
			out[s] = "not reported"
		}
	}
	return kept, out, nil
}

// recordSaaS records findings under w, reopening a dismissed one whose
// material attributes changed, and returns what it did. A material attribute
// a report did not finish reading keeps what was recorded: an unread read is
// no change (HR-637).
func recordSaaS(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, w discoverer, source string,
	findings []ScanFinding, notScanned map[string]string,
) (ScanResult, error) {
	var res ScanResult
	if err := q.LockDiscoveries(ctx, org.String()); err != nil {
		return res, err
	}
	open, err := q.CountOpenDiscoveriesOfSource(ctx, org, source)
	if err != nil {
		return res, err
	}
	for _, f := range findings {
		unread := notScanned
		if read := f.Attributes[saas.AttrUnread]; read != "" {
			unread = map[string]string{read: "not read"}
		}
		delete(f.Attributes, saas.AttrUnread)
		observed := maps.Clone(f.Attributes)
		observed["kind"], observed["submitted_by"], observed["scan_run"] = f.Kind, w.by, w.run.String()
		var reopen ids.UUID
		prior, err := q.GetScanDiscovery(ctx, org, source, f.Key[:])
		found := err == nil
		if err != nil && !db.IsNoRows(err) {
			return res, err
		}
		if found {
			keepUnread(f.Kind, prior.Observed, observed, unread)
		}
		obs, err := json.Marshal(observed)
		if err != nil {
			return res, err
		}
		if found && (prior.State != "DISMISSED" || !riskChanged(f.Kind, prior.Observed, observed)) {
			if err := touch(ctx, tx, q, org, w, f, obs, observed, prior); err != nil {
				return res, err
			}
			res.Counted++
			continue
		}
		if found {
			reopen = prior.ID // dismissed for what it could do then: people judge it again
		}
		if open >= MaxOpenScanDiscoveries {
			res.Dropped++
			continue
		}
		if err := insertFinding(ctx, tx, q, org, w, f, obs, observed, reopen); err != nil {
			return res, err
		}
		open++
		res.Created++
		if !reopen.IsZero() {
			res.Reopened++
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "agents.discovery_reopened", Actor: w.ledger, Outcome: audit.Success,
				Object:  &audit.Object{Type: "discovery", ID: reopen.String()},
				Details: map[string]string{"scan": w.run.String(), "kind": f.Kind, "previous_agent": prior.AgentID.String()},
			}); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// keepUnread puts back into observed what recorded says of the material
// attributes notScanned leaves unread.
func keepUnread(kind string, recorded []byte, observed, notScanned map[string]string) {
	var before map[string]string
	if json.Unmarshal(recorded, &before) != nil {
		return
	}
	for _, k := range saas.MaterialKeys(kind) {
		if !saas.KeepsPrior(k, notScanned) {
			continue
		}
		if v, ok := before[k]; ok {
			observed[k] = v
		} else {
			delete(observed, k)
		}
	}
}

// SaaSReportComplete reports whether a finished report read all its source
// reads and left no note: only such a run can say something is gone.
func SaaSReportComplete(source string, scanned []string, notScanned map[string]string) bool {
	if len(notScanned) > 0 {
		return false
	}
	for _, s := range saas.Reads(source) {
		if !slices.Contains(scanned, s) {
			return false
		}
	}
	return true
}

// saasMissed counts the misses of a complete run of a tenant (D114): each
// discovery of it the run did not see misses once, and one that reaches
// domain.VanishAfterMisses is announced once. Neither its state nor its
// agent's changes (HR-458).
func saasMissed(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify Notifier, ledger evdomain.Actor,
	source, tenant string, run ids.UUID,
) (int, error) {
	missed, err := q.MissSaasDiscoveries(ctx, dbq.MissSaasDiscoveriesParams{OrgID: tx.OrgID(), Source: source, Tenant: tenant, Run: run})
	if err != nil {
		return 0, err
	}
	for _, d := range missed {
		if d.MissedScans < domain.VanishAfterMisses || d.VanishNotifiedAt != nil {
			continue
		}
		v := vanished{id: d.ID, agent: d.AgentID, kind: observedKind(d.Observed), misses: d.MissedScans, source: source}
		if err := v.notice(ctx, tx, q, notify, ledger, map[string]string{"scan": run.String(), "tenant": tenant}); err != nil {
			return 0, err
		}
	}
	return len(missed), nil
}

// SaaSScanFinished counts the misses of a gateway's finished scan, in its
// transaction.
func SaaSScanFinished(ctx context.Context, tx db.TenantTx, q *dbq.Queries, notify Notifier, gateway ids.UUID, source, tenant string,
	run ids.UUID, state string, scanned []string, notScanned map[string]string,
) error {
	if state != "DONE" || !SaaSReportComplete(source, scanned, notScanned) {
		return nil
	}
	_, err := saasMissed(ctx, tx, q, notify, evdomain.Actor{Type: "gateway", ID: gateway.String()}, source, tenant, run)
	return err
}

// ImportSaaS records a parsed recording as one finished run. The caller needs
// agent.manage at the org; a scanner key reaches device scans only (HR-589).
// A run over the cap on open discoveries reports what it dropped as not
// scanned, so it counts no misses.
func (inv *Inventory) ImportSaaS(ctx context.Context, r SaaSReport) (SaaSResult, error) {
	dropped, err := checkSaaSFindings(r.Source, r.Tenant, r.Findings)
	if err != nil {
		return SaaSResult{}, err
	}
	scanned, notScanned, err := NormalizeSaaSReport(r.Source, r.Scanned, r.NotScanned)
	if err != nil {
		return SaaSResult{}, err
	}
	if !saas.CountsOK(r.Counts) {
		return SaaSResult{}, ErrSaaSReport
	}
	out := SaaSResult{Run: ids.NewV7()}
	err = inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermAgentManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		by := c.Principal.String()
		if err := q.InsertSaasRun(ctx, dbq.InsertSaasRunParams{
			OrgID: c.Org, ID: out.Run, Source: r.Source, Origin: "import", Tenant: r.Tenant, StartedBy: by,
		}); err != nil {
			return err
		}
		w := discoverer{
			by: by, actor: actor(c), ledger: c.Actor(), source: r.Source, run: &out.Run, notify: inv.notify, external: true,
			trusted: map[string]string{"scan": out.Run.String(), "tenant": r.Tenant},
		}
		res, err := recordSaaS(ctx, tx, q, c.Org, w, r.Source, r.Findings, notScanned)
		if err != nil {
			return err
		}
		res.DroppedAttributes = dropped
		if res.Dropped > 0 {
			notScanned[saas.NoteFindings] = strconv.Itoa(res.Dropped) + " findings dropped: the org's open findings of this source are at their cap"
		}
		if SaaSReportComplete(r.Source, scanned, notScanned) {
			if res.Missed, err = saasMissed(ctx, tx, q, inv.notify, c.Actor(), r.Source, r.Tenant, out.Run); err != nil {
				return err
			}
		}
		out.ScanResult = res
		if err := FinishSaaSRun(ctx, q, c.Org, out.Run, "DONE", r.Counts, scanned, notScanned); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.saas_import_submitted", ids.UUID{}, map[string]string{
			"scan": out.Run.String(), "source": r.Source, "created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted),
			"dropped": strconv.Itoa(res.Dropped), "reopened": strconv.Itoa(res.Reopened), "missed": strconv.Itoa(res.Missed),
			"not_scanned": strconv.Itoa(len(notScanned)),
		})
	})
	if err != nil {
		return SaaSResult{}, err
	}
	return out, nil
}

// FinishSaaSRun ends a run with its summary.
func FinishSaaSRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, run ids.UUID, state string, counts map[string]int64,
	scanned []string, notScanned map[string]string,
) error {
	if counts == nil {
		counts = map[string]int64{}
	}
	c, err := json.Marshal(counts, json.Deterministic(true))
	if err != nil {
		return err
	}
	n, err := json.Marshal(notScanned, json.Deterministic(true))
	if err != nil {
		return err
	}
	return q.FinishSaasRun(ctx, dbq.FinishSaasRunParams{State: state, Counts: c, Scanned: scanned, NotScanned: n, OrgID: org, ID: run})
}

// SubmitSaaSScan records a gateway's SaaS scan findings. Only the gateway
// holding the run's saas_scan lease submits, while it holds it; the org and
// the gateway come from its certificate, and lease is the lease's secret.
func (inv *Inventory) SubmitSaaSScan(ctx context.Context, org ids.OrgID, gateway, scan ids.UUID, lease []byte, findings []ScanFinding) (ScanResult, error) {
	var res ScanResult
	err := inv.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		hash := sha256.Sum256(lease)
		run, err := q.GatewaySaasRun(ctx, dbq.GatewaySaasRunParams{OrgID: org, ID: scan, GatewayID: gateway, LeaseHash: hash[:]})
		if db.IsNoRows(err) {
			return ErrNoScanLease
		} else if err != nil {
			return err
		}
		dropped, err := checkSaaSFindings(run.Source, run.Tenant, findings)
		if err != nil {
			return err
		}
		ledger := evdomain.Actor{Type: "gateway", ID: gateway.String()}
		w := discoverer{
			by: "gateway:" + gateway.String(), actor: domain.System, ledger: ledger, source: run.Source, run: &scan, notify: inv.notify,
			external: true, trusted: map[string]string{"gateway": gateway.String(), "scan": scan.String(), "tenant": run.Tenant},
		}
		if res, err = recordSaaS(ctx, tx, q, org, w, run.Source, findings, nil); err != nil {
			return err
		}
		res.DroppedAttributes = dropped
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "agents.saas_scan_submitted", Actor: ledger, Outcome: audit.Success,
			Details: map[string]string{
				"scan": scan.String(), "source": run.Source, "created": strconv.Itoa(res.Created), "counted": strconv.Itoa(res.Counted),
				"dropped": strconv.Itoa(res.Dropped), "reopened": strconv.Itoa(res.Reopened),
			},
		})
		return err
	})
	if err != nil {
		return ScanResult{}, err
	}
	return res, nil
}

// SetExternalOwner names an external agent's owner (D407, HR-639): the only
// claim such an agent takes. It sets the owner and nothing else. The agent
// stays DISCOVERED, so it holds no key, token or grant; its discovery leaves
// the open queue and its admission entry closes. Naming another owner later
// is how its owner changes: a transfer needs a claimed agent. The caller needs
// agent.manage at the org, which is where an unplaced agent lives.
func (inv *Inventory) SetExternalOwner(ctx context.Context, id, owner, backup ids.UUID, reason string) (Agent, error) {
	if err := domain.ValidateReason(reason); err != nil {
		return Agent{}, invalid(err)
	}
	if owner.IsZero() || owner == backup {
		return Agent{}, ErrOwner
	}
	var out Agent
	err := inOrg(ctx, inv.pool, func(ctx context.Context, c tenancy.Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := load(ctx, c, q, id, td.PermAgentManage, true)
		if err != nil {
			return err
		}
		if !r.External {
			return ErrNotExternal
		}
		if domain.State(r.State) != domain.StateDiscovered {
			return ErrState
		}
		if err := checkOwners(ctx, q, c.Org, owner, backup); err != nil {
			return err
		}
		set, err := q.SetExternalOwner(ctx, dbq.SetExternalOwnerParams{
			OrgID: c.Org, ID: id, OwnerUserID: &owner, BackupOwnerUserID: optUUID(backup),
		})
		if db.IsNoRows(err) {
			return ErrLostRace
		} else if err != nil {
			return err
		}
		if err := q.SetAgentDiscoveryState(ctx, "CLAIMED", c.Org, id); err != nil {
			return err
		}
		if _, err := q.CloseOpenAgentEntries(ctx, dbq.CloseOpenAgentEntriesParams{
			OrgID: c.Org, AgentID: id, State: "APPROVED", DecidedBy: ptr(string(actor(c))), Reason: reason, SubjectType: ptr("agent"),
		}); err != nil {
			return err
		}
		out = agentView(set)
		details := map[string]string{"owner_user_id": owner.String()}
		if err := RecordChange(ctx, q, c.Org, id, domain.Change{Kind: domain.ChangeExternalOwnerSet, Actor: actor(c), Reason: reason, Details: details}); err != nil {
			return err
		}
		return record(ctx, tx, c, "agents.external_owner_set", id, details)
	})
	return out, err
}
