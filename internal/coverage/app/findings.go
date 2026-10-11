// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"
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
// credentials actually hold (the GitHub App installations the org scan
// found for it) with what its package declares the operations the org's
// grants allow need, and records the excess as credential-overreach
// findings (F048, decision 9). Used lists the scopes of the operations
// executed through the connection in the last 30 days. A finding no longer
// found is resolved; a dismissed one stays dismissed until its excess
// changes, which makes it a new finding.
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
	reach, err := q.CoverageReachOfConnection(ctx, tx.OrgID(), connection.String())
	if err != nil {
		return err
	}
	keep := [][]byte{}
	for _, r := range reach {
		var observed map[string]string
		if json.Unmarshal(r.Observed, &observed) != nil {
			continue
		}
		held := domain.ParsePermissions(observed["permissions"])
		excess, severity := domain.Overreach(declared, held)
		if len(excess) == 0 {
			continue
		}
		subject := "GitHub App " + observed["app_slug"]
		if len(subject) > 256 {
			subject = subject[:256]
		}
		fp := sha256.Sum256([]byte(KindOverreach + "|" + connection.String() + "|" + r.ID.String() + "|" +
			strings.Join(slices.Sorted(slices.Values(excess)), ",")))
		if _, err := q.UpsertCoverageFinding(ctx, dbq.UpsertCoverageFindingParams{
			OrgID: tx.OrgID(), ID: ids.NewV7(), Kind: KindOverreach, ConnectionID: &connection, Subject: subject,
			Declared: declared.List(), Held: held.List(), Used: used.List(), Excess: excess, Severity: severity,
			Fingerprint: fp[:],
		}); err != nil {
			return err
		}
		keep = append(keep, fp[:])
	}
	_, err = q.ResolveCoverageFindings(ctx, dbq.ResolveCoverageFindingsParams{
		OrgID: tx.OrgID(), Kind: KindOverreach, ConnectionID: &connection, Keep: keep,
	})
	return err
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

// DismissFinding dismisses an open finding with a written reason; only a
// person holding coverage.manage at org scope does, since a dismissal
// hides exposure.
func (s *Service) DismissFinding(ctx context.Context, id ids.UUID, reason string) (dbq.PcCoverageFinding, error) {
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
			Object:  &audit.Object{Type: "coverage_finding", ID: out.ID.String()},
			Details: map[string]string{"kind": out.Kind, "severity": out.Severity, "excess": strings.Join(out.Excess, ",")},
		})
		return err
	})
	return out, err
}
