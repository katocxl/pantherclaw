// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package packbuild builds evidence packs (G0 M7 design decision 15,
// HR-196, F525–F532) in the worker. A pack is built from its creator's
// permissions at the moment the job runs: the job loads the person's role
// bindings, reads every transaction of the scope through the evidence
// explorer as that person (evidence.read where each transaction's agent
// lives), and counts what it had to leave out as a gap. It then adds what
// the creator asked for and may read: the versions the decisions applied,
// the approvals that held them, containment and restoration events, and
// verify bundles with the latest checkpoint, inclusion proofs and anchor;
// signs the manifest with the evidence_packs key (and co-signs it with
// ML-DSA-65 when evidence.mldsa_cosign is on); and stores the ZIP for 7
// days. Nothing here writes evidence or reaches a target.
package packbuild

import (
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// Limits of one pack.
const (
	// MaxTransactions bounds the transactions of a scope; beyond it the
	// pack holds the first ones and says so (a gap).
	MaxTransactions = 5000
	maxEvents       = 1000
	pageRows        = 200
	// containmentMargin widens the window of a scope given by its
	// transactions, so the events that led to them are included.
	containmentMargin = 24 * time.Hour
)

// Failure codes: evidence_packs.error_code.
const (
	CodeCreatorUnavailable = "CREATOR_UNAVAILABLE"
	CodeTooLarge           = "PACK_TOO_LARGE"
	CodeNoSigner           = "NO_SIGNER"
	CodeBuildFailed        = "BUILD_FAILED"
)

// retentionAt is the retention of every category in effect at at (F530,
// design decision 9): the revision the org set ("policy <category> rN"), or
// the default when the system recorded it or nothing was recorded yet.
func retentionAt(revs []retention.Revision, at time.Time) []pack.Retention {
	cats := retention.Categories()
	out := make([]pack.Retention, 0, len(cats))
	for _, c := range cats {
		b, _ := retention.BoundsOf(c)
		r := pack.Retention{Category: string(c), Days: b.Default, Source: "default"}
		if cur, ok := retention.Current(revs, c, at); ok {
			r.Days = cur.Days
			if cur.SetBy != nil {
				r.Source = "policy " + cur.Label()
			}
		}
		out = append(out, r)
	}
	return out
}

// Ledger kinds of org-level containment and restoration events (F529).
var orgEventKinds = []string{
	"audit.connection.quarantined", "audit.connection.restored", "audit.connection.retired",
	"audit.security.kill_switch_engaged", "audit.security.kill_switch_restored",
}

// CaptureSource reads the payload captures of transactions for a pack
// (capture.PackSource). Without one, a pack that asks for captures records
// the gap "not_captured".
type CaptureSource interface {
	// Captures returns the opened captures of txn as pack files under
	// captures/<txn>/, each after an audited read (HR-199) by the caller
	// in ctx, the pack's creator, naming pack packID.
	Captures(ctx context.Context, org ids.OrgID, packID, txn ids.UUID) ([]pack.File, error)
}

// Service builds packs.
type Service struct {
	Pool      *db.Pool
	Keys      *keys.Registry
	LogOrigin string
	// Cosign adds the ML-DSA-65 co-signature (evidence.mldsa_cosign).
	Cosign   bool
	Explorer *txapp.Explorer
	// Bundles exports the verify bundles (the creator's caller decides
	// what they hold).
	Bundles  *evapp.Service
	Captures CaptureSource
	// Executions reads automation executions for packs of scope
	// automation_execution (G0 M11 part 2 D30); nil fails them.
	Executions Executions
	Clock      clock.Clock
	Log        *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return pclog.Discard()
	}
	return s.Log
}

// row is a pack being built.
type row struct {
	id        ids.UUID
	createdBy ids.UUID
	scope     pack.Scope
	include   pack.Include
	created   time.Time
	// retention are the org's retention revisions (migration 00072).
	retention []retention.Revision
	// automation is set for a governed automation's pack (G0 M11 part 2
	// D85): created by its execution identity, holding only the evidence
	// of agents (nil: all of the org's).
	automation *ids.UUID
	agents     []ids.UUID
}

var errCreator = errors.New("packbuild: the creator is not an active person of the org")

// Build builds pack id of org. A pack already built (or failed) is left
// alone; a failure that will not change on a retry marks it FAILED.
func (s *Service) Build(ctx context.Context, org ids.OrgID, id ids.UUID) error {
	var r *row
	var bindings []td.Binding
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := q.GetEvidencePack(ctx, org, id)
		if err != nil {
			return err
		}
		if p.State != "BUILDING" {
			return nil
		}
		r = &row{id: p.ID, createdBy: p.CreatedBy, created: p.CreatedAt}
		if err := json.Unmarshal(p.Scope, &r.scope, json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("packbuild: stored scope: %w", err)
		}
		if err := json.Unmarshal(p.Include, &r.include, json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("packbuild: stored include: %w", err)
		}
		auto, err := q.EvidencePackAutomation(ctx, org, id)
		if err != nil {
			return err
		}
		r.automation, r.agents = auto.AutomationID, auto.AutomationAgents
		if err := creatorActive(ctx, q, org, r); err != nil {
			return err
		}
		revs, err := q.ListRetentionRevisions(ctx, org)
		if err != nil {
			return err
		}
		r.retention = retention.RevisionsOf(revs)
		if r.automation != nil {
			return nil
		}
		bindings, err = tenancy.Bindings(ctx, q, org, td.PrincipalRef{Kind: td.KindUser, ID: p.CreatedBy})
		return err
	}, db.ReadOnly())
	switch {
	case errors.Is(err, errCreator):
		return s.fail(ctx, org, id, CodeCreatorUnavailable)
	case err != nil:
		return err
	case r == nil:
		return nil
	}
	caller := tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: r.createdBy}, Bindings: bindings,
	}}
	if r.automation != nil {
		caller = automationCaller(org, r.createdBy)
	}
	// The pack is made now: its manifest's time, and the start of its 7
	// days (the database checks expires_at = ready_at + 7 days).
	ready := s.now().UTC().Truncate(time.Second)
	b := &builder{s: s, org: org, r: r, c: caller, ctx: tenancy.WithCaller(ctx, caller), agentPaths: map[ids.UUID]td.Path{}, now: ready}
	if r.scope.Kind == pack.ScopeRange {
		// A range pack always holds receipts: `pclaw verify` checks them (HR-224).
		r.include.Receipts = true
		if b.rangeData, err = b.loadRange(); errors.Is(err, errRange) {
			return s.fail(ctx, org, id, CodeRangeUnavailable)
		} else if err != nil {
			return err
		}
	}
	if r.scope.Kind == pack.ScopeAutomationExecution {
		if b.execData, err = b.loadExecution(); errors.Is(err, errExecution) {
			return s.fail(ctx, org, id, CodeExecutionUnavailable)
		} else if err != nil {
			return err
		}
	}
	content, manifest, items, err := b.build()
	switch {
	case errors.Is(err, pack.ErrTooLarge):
		return s.fail(ctx, org, id, CodeTooLarge)
	case errors.Is(err, errNoSigner):
		return s.fail(ctx, org, id, CodeNoSigner)
	case err != nil:
		return err
	}
	msum, csum := sha256.Sum256([]byte(manifest)), sha256.Sum256(content)
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).MarkEvidencePackReady(ctx, dbq.MarkEvidencePackReadyParams{
			OrgID: org, ID: id, Manifest: &manifest, ManifestSha256: msum[:], Content: content, ContentSha256: csum[:],
			ContentSize: pgtype.Int8{Int64: int64(len(content)), Valid: true}, Items: ptr(int32(items)), ReadyAt: &ready, //nolint:gosec // G115: ≤ MaxFiles
		})
		if err == nil && n != 1 {
			return db.ErrLostRace
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("packbuild: store pack: %w", err)
	}
	s.log().InfoContext(ctx, "evidence.pack_ready", slog.String("org", org.String()), slog.String("pack", id.String()),
		slog.Int("items", items), slog.Int("bytes", len(content)))
	return nil
}

func ptr[T any](v T) *T { return &v }

// fail marks the pack FAILED with code (once).
func (s *Service) fail(ctx context.Context, org ids.OrgID, id ids.UUID, code string) error {
	s.log().WarnContext(ctx, "evidence.pack_failed", slog.String("org", org.String()), slog.String("pack", id.String()),
		slog.String("code", code))
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := dbq.New(tx).MarkEvidencePackFailed(ctx, code, org, id)
		return err
	})
}

var errNoSigner = errors.New("packbuild: no active evidence_packs key")

// builder builds one pack as its creator.
type builder struct {
	s          *Service
	org        ids.OrgID
	r          *row
	c          tenancy.Caller
	ctx        context.Context //nolint:containedctx // one build: the creator's caller context
	now        time.Time
	m          pack.Manifest
	files      []pack.File
	agentPaths map[ids.UUID]td.Path
	// What the readable transactions involve.
	txns        []txapp.Evidence
	agents      map[ids.UUID]bool
	connections map[ids.UUID]bool
	first, last time.Time
	// rangeData is the range of a pack of scope range.
	rangeData *rangeData
	// execData is the execution of a pack of scope automation_execution.
	execData *execData
}

func (b *builder) gap(subject, reason, format string, args ...any) {
	b.m.Gaps = append(b.m.Gaps, pack.Gap{Subject: subject, Reason: reason, Detail: fmt.Sprintf(format, args...)})
}

func (b *builder) add(path, kind string, v any) error {
	data, err := pack.Canonical(v)
	if err != nil {
		return err
	}
	b.files = append(b.files, pack.File{Path: path, Kind: kind, Data: data})
	return nil
}

func (b *builder) build() ([]byte, string, int, error) {
	r := b.r
	now := b.now
	b.m = pack.Manifest{
		Format: pack.Format, Pack: r.id.String(), Org: b.org.String(), Origin: b.s.LogOrigin + "/org/" + b.org.String(),
		Exporter: pack.Exporter{Type: string(td.KindUser), ID: r.createdBy.String()},
		Created:  now.UTC().Format(time.RFC3339), Expires: now.Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Scope: r.scope, Include: r.include, Transactions: []pack.TransactionState{}, EffectStates: map[string]int{},
		Retention: retentionAt(r.retention, now), Gaps: []pack.Gap{}, Statement: r.scope.ExpectedStatement(),
		Filters: []string{fmt.Sprintf("evidence.read where each transaction's agent lives, as person %s held it at %s",
			r.createdBy, now.UTC().Format(time.RFC3339))},
	}
	b.agents, b.connections = map[ids.UUID]bool{}, map[ids.UUID]bool{}
	if err := b.transactions(); err != nil {
		return nil, "", 0, err
	}
	if b.rangeData != nil {
		if err := b.assurance(); err != nil {
			return nil, "", 0, err
		}
	}
	if b.execData != nil {
		if err := b.automation(); err != nil {
			return nil, "", 0, err
		}
	}
	if r.include.Versions {
		if err := b.versions(); err != nil {
			return nil, "", 0, err
		}
		if err := b.coverage(); err != nil {
			return nil, "", 0, err
		}
	}
	if r.include.Approvals {
		b.m.Filters = append(b.m.Filters, "approval.read where each transaction's agent lives")
		if err := b.approvals(); err != nil {
			return nil, "", 0, err
		}
	}
	if r.include.Containment {
		b.m.Filters = append(b.m.Filters, "containment.read at org scope for connection and kill-switch events")
		if err := b.containment(); err != nil {
			return nil, "", 0, err
		}
	}
	if b.rangeData != nil && r.include.Receipts {
		if err := b.probeProofs(); err != nil {
			return nil, "", 0, err
		}
	}
	if err := b.proofs(); err != nil {
		return nil, "", 0, err
	}
	if err := b.captures(); err != nil {
		return nil, "", 0, err
	}
	b.redactions()
	slices.SortFunc(b.files, func(x, y pack.File) int { return strings.Compare(x.Path, y.Path) })
	for _, f := range b.files {
		b.m.Items = append(b.m.Items, pack.ItemOf(f))
	}
	payload, err := pack.Canonical(b.m)
	if err != nil {
		return nil, "", 0, err
	}
	signer, err := b.s.Keys.Signer(keys.PurposeEvidencePacks)
	if err != nil {
		return nil, "", 0, errNoSigner
	}
	manifest, err := signer.Sign(pack.JWSType, payload)
	if err != nil {
		return nil, "", 0, err
	}
	var cosign []byte
	if b.s.Cosign {
		if cosign, err = b.cosign(manifest); err != nil {
			return nil, "", 0, err
		}
	}
	content, err := pack.Write(b.files, manifest, cosign, b.r.created)
	if err != nil {
		return nil, "", 0, err
	}
	return content, manifest, len(b.files), nil
}

// cosign signs the manifest's signing input with the checkpoints_pq key.
func (b *builder) cosign(manifest string) ([]byte, error) {
	ks := b.s.Keys.AltKeys(keys.PurposeCheckpointsPQ)
	if len(ks) == 0 || ks[0].State != keys.StateActive {
		return nil, errNoSigner
	}
	priv, ok := ks[0].Private.Reveal().(*mldsa.PrivateKey)
	if !ok {
		return nil, errNoSigner
	}
	signed, err := pack.ParseJWS(manifest)
	if err != nil {
		return nil, err
	}
	sig, err := priv.Sign(nil, signed.SigningInput, &mldsa.Options{Context: pack.CosignContext})
	if err != nil {
		return nil, fmt.Errorf("packbuild: co-sign: %w", err)
	}
	return pack.Canonical(pack.Cosign{Algorithm: "ML-DSA-65", Kid: ks[0].KID, Signature: sig})
}

// scopeIDs lists the transactions of the scope, in id order, and whether
// the scope named them.
func (b *builder) scopeIDs() ([]ids.UUID, bool, error) {
	sc := b.r.scope
	if sc.Kind == pack.ScopeRange {
		return b.rangeData.transactions(), true, nil
	}
	if sc.Kind == pack.ScopeAutomationExecution {
		return b.execData.transactions, true, nil
	}
	if sc.Kind == pack.ScopeTransactions {
		out := make([]ids.UUID, 0, len(sc.Transactions))
		for _, s := range sc.Transactions {
			id, err := ids.ParseUUID(s)
			if err != nil {
				return nil, true, fmt.Errorf("packbuild: stored scope: %w", err)
			}
			out = append(out, id)
		}
		slices.SortFunc(out, func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
		return slices.Compact(out), true, nil
	}
	// Every transaction of the scope is listed; each is then read as the
	// creator, and what they may not read is recorded as a gap.
	p := dbq.ListTransactionsParams{
		OrgID: b.org, AllAgents: true, VisibleAgents: []string{}, Decisions: []string{}, ExecutionStates: []string{},
		EffectStates: []string{}, PageLimit: pageRows,
	}
	var err error
	if sc.Run != "" {
		run, err := ids.ParseUUID(sc.Run)
		if err != nil {
			return nil, false, err
		}
		p.RunID = &run
	}
	if sc.Agent != "" {
		agent, err := ids.ParseUUID(sc.Agent)
		if err != nil {
			return nil, false, err
		}
		p.AgentID = &agent
	}
	if p.StartTime, err = timeOf(sc.From); err != nil {
		return nil, false, err
	}
	if p.EndTime, err = timeOf(sc.To); err != nil {
		return nil, false, err
	}
	var out []ids.UUID
	err = b.s.Pool.InTenantTx(b.ctx, b.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for {
			rows, err := q.ListTransactions(ctx, p)
			if err != nil {
				return err
			}
			for _, row := range rows {
				out = append(out, row.ID)
			}
			if len(rows) < pageRows || len(out) > MaxTransactions {
				return nil
			}
			p.Before = rows[len(rows)-1].ID
		}
	}, db.ReadOnly(), db.RepeatableRead())
	slices.SortFunc(out, func(x, y ids.UUID) int { return strings.Compare(x.String(), y.String()) })
	return out, false, err
}

func timeOf(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // unset
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil, fmt.Errorf("packbuild: stored scope time: %w", err)
	}
	return &t, nil
}

// transactions reads every transaction of the scope as the creator.
func (b *builder) transactions() error {
	all, named, err := b.scopeIDs()
	if err != nil {
		return err
	}
	if len(all) > MaxTransactions {
		b.gap("transactions", pack.GapLimit, "the scope has more than %d transactions: the pack holds the first %d by id; "+
			"narrow the scope for the rest", MaxTransactions, MaxTransactions)
		all = all[:MaxTransactions]
	}
	outside := 0
	for _, id := range all {
		ev, err := b.s.Explorer.TransactionEvidence(b.ctx, id)
		switch {
		case errors.Is(err, txapp.ErrTransactionNotFound):
			if named {
				b.gap("transaction "+id.String(), pack.GapNotFound, "no such transaction in the org")
			}
			continue
		case pcerr.CodeOf(err) == pcerr.PermissionDenied:
			outside++
			if named {
				b.gap("transaction "+id.String(), pack.GapOutsidePermission, "you do not hold evidence.read where its agent lives")
			}
			continue
		case err != nil:
			return err
		case !b.r.declared(ev.Transaction.Agent):
			// An automation's pack holds only its declared agents (D85).
			outside++
			if named {
				b.gap("transaction "+id.String(), pack.GapOutsidePermission, "its agent is outside the automation's declared scope")
			}
			continue
		}
		if err := b.transaction(ev); err != nil {
			return err
		}
	}
	if outside > 0 && !named {
		b.gap("transactions", pack.GapOutsidePermission,
			"%d transactions of the scope are outside your evidence.read: they are not in this pack", outside)
	}
	return nil
}

// creatorActive checks that the pack's creator may still build it: an
// active person of the org, or for an automation's pack its active
// execution identity of an automation that is not retired.
func creatorActive(ctx context.Context, q *dbq.Queries, org ids.OrgID, r *row) error {
	if r.automation == nil {
		state, err := q.PackCreatorState(ctx, org, r.createdBy)
		if db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return errCreator
		}
		return err
	}
	s, err := q.AutomationPackCreatorState(ctx, org, r.createdBy, *r.automation)
	if db.IsNoRows(err) || (err == nil && (s.AccountState != "ACTIVE" || s.AutomationState == "RETIRED")) {
		return errCreator
	}
	return err
}

// automationCaller is who builds an automation's pack (D85): its execution
// identity, reading evidence only. The automation holds no role binding of
// its own (HR-270); the pack's declared agents (row.agents) bound what it
// holds, and the people who confirmed the version held evidence.read and
// evidence.export there.
func automationCaller(org ids.OrgID, account ids.UUID) tenancy.Caller {
	return tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: account},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		Scopes:   []td.Permission{td.PermEvidenceRead},
	}}
}

// declared reports whether an agent's evidence may be in the pack: always
// for a person's pack (their evidence.read decides), and for an
// automation's only within the agents it declared.
func (r *row) declared(agent ids.UUID) bool {
	return r.automation == nil || r.agents == nil || slices.Contains(r.agents, agent)
}
