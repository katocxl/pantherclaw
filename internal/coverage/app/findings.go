// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// KindOverreach is the finding kind of credential overreach (F048).
const KindOverreach = "credential_overreach"

// ErrDismissal reports a dismissal without a written reason.
var ErrDismissal = pcerr.New(pcerr.InvalidArgument, "INVALID_DISMISSAL", "a dismissal needs a written reason of 10 to 1,000 characters")

// declaredScopes reads the credential scopes the package's operations
// declare (dispatch.credential_scope, G0 M8): those of the operations
// allowed says are granted, and those of the operations executed. A
// package without them declares nothing.
func declaredScopes(raw []byte, allowed func(string) bool, executed map[string]bool) (declared, used domain.Permissions, err error) {
	doc, err := manifest.ToJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	var p struct {
		Definitions []struct {
			Operation string `json:"operation"`
			Dispatch  *struct {
				CredentialScope map[string]string `json:"credential_scope"`
			} `json:"dispatch"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(doc, &p); err != nil {
		return nil, nil, err
	}
	declared, used = domain.Permissions{}, domain.Permissions{}
	for _, d := range p.Definitions {
		if d.Dispatch == nil {
			continue
		}
		scope := domain.Permissions{}
		for k, v := range d.Dispatch.CredentialScope {
			scope = scope.Merge(domain.ParsePermissions(k + ":" + v))
		}
		if allowed(d.Operation) {
			declared = declared.Merge(scope)
		}
		if executed[d.Operation] {
			used = used.Merge(scope)
		}
	}
	return declared, used, nil
}

// granted reports which operations the org's active grants allow.
func granted(ctx context.Context, q *dbq.Queries, org ids.OrgID) (func(string) bool, error) {
	rows, err := q.CoverageGrantBoundsOfOrg(ctx, org)
	if err != nil {
		return nil, err
	}
	var bounds []gdomain.Bounds
	for _, raw := range rows {
		var b gdomain.Bounds
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		bounds = append(bounds, b)
	}
	return func(op string) bool {
		return slices.ContainsFunc(bounds, func(b gdomain.Bounds) bool { return b.Operations == nil || b.Operations.Matches(op) })
	}, nil
}

// RefreshFindings compares, for one connection, the permissions its
// credential actually holds (the GitHub App installation behind it, as
// last read into connection_github) with what its package declares the
// operations the org's grants allow need, and records the excess as
// credential-overreach findings (F048, decision 9). The org scan's
// github_app findings are the org's other Apps: routes of their own, never
// this credential. Used lists the scopes of the operations executed
// through the connection in the last 30 days. A finding no longer found is
// resolved, a dismissed one too; a dismissed one stays dismissed while its
// excess is unchanged.
func (s *Service) RefreshFindings(ctx context.Context, tx db.TenantTx, connection ids.UUID) error {
	q := dbq.New(tx)
	b, err := q.CoverageBinding(ctx, tx.OrgID(), connection)
	if err != nil || b.PackageVersionID == nil {
		return err
	}
	raw, err := q.GetPackageVersionRaw(ctx, tx.OrgID(), *b.PackageVersionID)
	if err != nil {
		return err
	}
	allowed, err := granted(ctx, q, tx.OrgID())
	if err != nil {
		return err
	}
	ops, err := q.CoverageExecutedOperations(ctx, tx.OrgID(), &connection)
	if err != nil {
		return err
	}
	executed := map[string]bool{}
	for _, op := range ops {
		executed[op] = true
	}
	declared, used, err := declaredScopes(raw, allowed, executed)
	if err != nil {
		return err
	}
	keep := [][]byte{}
	// find records the excess of one credential's reach; source names the
	// credential in the fingerprint.
	find := func(source, subject string, held domain.Permissions) error {
		excess, severity := domain.Overreach(declared, held)
		if len(excess) == 0 {
			return nil
		}
		fp := sha256.Sum256([]byte(KindOverreach + "|" + connection.String() + "|" + source + "|" +
			strings.Join(slices.Sorted(slices.Values(excess)), ",")))
		if _, err := q.UpsertCoverageFinding(ctx, dbq.UpsertCoverageFindingParams{
			OrgID: tx.OrgID(), ID: ids.NewV7(), Kind: KindOverreach, ConnectionID: &connection, Subject: truncate(subject, 256),
			Declared: declared.List(), Held: held.List(), Used: used.List(), Excess: excess, Severity: severity,
			Fingerprint: fp[:],
		}); err != nil {
			return err
		}
		keep = append(keep, fp[:])
		return nil
	}
	// The installation behind the connection's own credential, as last
	// read (G0 M8 G3).
	switch inst, err := q.CoverageInstallationOfConnection(ctx, tx.OrgID(), connection); {
	case err == nil && inst.ReadAt == nil:
		// The gateway has not read the installation's permissions yet: its
		// reach is not observed, which is never "no overreach". The findings
		// stay as they are until it is read (G0 M8 follow-up; coordinator
		// decision D7).
		return nil
	case err == nil:
		id := strconv.FormatInt(inst.InstallationID, 10)
		if err := find("installation:"+id, "GitHub App installation "+id+" on "+inst.AccountLogin,
			domain.ParsePermissions(string(inst.Permissions))); err != nil {
			return err
		}
	case !db.IsNoRows(err):
		return err
	}
	// A dismissed finding no longer found ends its dismissal; it is audited
	// with the dismissal before the row forgets it.
	gone, err := q.DismissedCoverageFindingsGone(ctx, dbq.DismissedCoverageFindingsGoneParams{
		OrgID: tx.OrgID(), Kind: KindOverreach, ConnectionID: &connection, Keep: keep,
	})
	if err != nil {
		return err
	}
	for _, g := range gone {
		details := map[string]string{"kind": KindOverreach, "excess": truncate(strings.Join(g.Excess, ","), 512)}
		auditReason(details, deref(g.DismissReason))
		if g.DismissedBy != nil {
			details["dismissed_by"] = g.DismissedBy.String()
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "coverage.finding_resolved", Actor: Actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "coverage_finding", ID: g.ID.String()},
			Details: details,
		}); err != nil {
			return err
		}
	}
	_, err = q.ResolveCoverageFindings(ctx, dbq.ResolveCoverageFindingsParams{
		OrgID: tx.OrgID(), Kind: KindOverreach, ConnectionID: &connection, Keep: keep,
	})
	return err
}

// auditReason adds a written reason to audit details as reason_1, reason_2
// and so on, each at most 512 bytes and cut at a character boundary, so a
// reason of up to 1,000 characters is kept whole.
func auditReason(details map[string]string, reason string) map[string]string {
	for i := 1; reason != ""; i++ {
		part := truncate(reason, 512)
		details["reason_"+strconv.Itoa(i)] = part
		reason = reason[len(part):]
	}
	return details
}

// truncate cuts s to at most n bytes, at a character boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ListFindings lists the org's coverage findings newest first, optionally
// in one state; the caller holds coverage.read at org scope.
func (s *Service) ListFindings(ctx context.Context, state *string, connection *ids.UUID, size int32, token string) ([]dbq.PcCoverageFinding, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []dbq.PcCoverageFinding
	var next string
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		if err := r.c.Require(td.PermCoverageRead, td.OrgPath(r.c.Org)); err != nil {
			return err
		}
		rows, err := r.q.ListCoverageFindingsPage(ctx, dbq.ListCoverageFindingsPageParams{
			OrgID: r.c.Org, State: state, ConnectionID: connection, Before: cursor(p), MaxRows: p.Limit(),
		})
		out, next = page.Finish(p, rows, func(x dbq.PcCoverageFinding) ids.UUID { return x.ID })
		return err
	})
	return out, next, err
}

// AcknowledgeFinding acknowledges an open finding with a written reason,
// dismissing it; only a person holding coverage.manage at org scope does,
// since a dismissal hides exposure.
func (s *Service) AcknowledgeFinding(ctx context.Context, id ids.UUID, reason string) (dbq.PcCoverageFinding, error) {
	var out dbq.PcCoverageFinding
	reason = strings.TrimSpace(reason)
	if n := utf8.RuneCountInString(reason); n < 10 || n > 1000 {
		return out, ErrDismissal
	}
	c, err := manager(ctx)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).DismissCoverageFinding(ctx, dbq.DismissCoverageFindingParams{
			OrgID: c.Org, ID: id, DismissedBy: &c.Principal.ID, DismissReason: &reason,
		})
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "coverage.finding_dismissed", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "coverage_finding", ID: out.ID.String()},
			Details: auditReason(map[string]string{
				"kind": out.Kind, "severity": out.Severity, "excess": truncate(strings.Join(out.Excess, ","), 512),
			}, reason),
		})
		return err
	})
	return out, err
}
