// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/detection/injection"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// ReasonUpstreamDrift is the recorded reason of a package version
// quarantined because an upstream MCP tool changed.
const ReasonUpstreamDrift = "upstream_drift"

// ErrDrift reports a drift report about a tool the connection's pinned
// package did not review with that digest, or one where nothing changed.
var ErrDrift = pcerr.New(pcerr.InvalidArgument, "DRIFT_NOT_REVIEWED",
	"the connection's pinned package reviewed no such upstream tool with that digest, or the tool did not change")

// ReportDrift records that a gateway found an upstream MCP server's tool no
// longer matching the definition its package was reviewed against (HR-081;
// G0 M6 design decision 14), and quarantines the org's pinned version of
// the connection's package. One transaction raises the epoch, so
// outstanding permits fail BeginDispatch; moves the version to QUARANTINED,
// so the Authority refuses every action pinned to it, through every
// connection; audits the change with the gateway as actor; and notifies
// org admins. A person reviews the package again to lift it.
//
// The report must be about a connection of kind mcp that the gateway
// serves (otherwise not found) and an upstream tool the pinned package
// reviewed with exactly expected (otherwise ErrDrift), so a gateway can
// quarantine only what its own connections use. It reports whether the
// version is quarantined; a retired version stays as it is. A report about a
// simulated connection is audited with simulated=true and changes nothing
// else (HR-222).
func (s *Service) ReportDrift(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, tool, expected, observed string) (bool, error) {
	return s.ReportDriftDescribed(ctx, org, gateway, id, tool, expected, observed, ObservedDescription{})
}

// ObservedDescription is the tool description a gateway observed with its
// drift report: the text (nil when the gateway sent none), whether the
// gateway cut it short, and the SHA-256 of the whole description.
// Transaction is the call whose own check observed the drift (zero from a
// periodic check): the drift's run is that transaction's, read from the
// server's own row of it through this connection, never from the gateway
// (HR-665). With no such row the report is processed without a run, never
// refused, so no quarantine is lost.
type ObservedDescription struct {
	Text        *string
	Truncated   bool
	Digest      string
	Transaction ids.UUID
}

// ReportDriftDescribed is ReportDrift with the tool description the
// gateway observed (G0 M10 D47). The description is scanned for
// instruction-like content: a hit writes connection.tool_description_flagged
// and opens the package version's TOOL_REVIEW entry (HR-244); a report
// without one (an older gateway) records the scan as not_scanned. Drift
// itself also opens the TOOL_REVIEW entry of the version it quarantines.
func (s *Service) ReportDriftDescribed(ctx context.Context, org ids.OrgID, gateway, id ids.UUID, tool, expected, observed string,
	description ObservedDescription,
) (bool, error) {
	scan, found := injection.ScanNotScanned, injection.Result{}
	if description.Text != nil {
		found = injection.Scan(*description.Text)
		switch {
		case found.Flagged:
			scan = injection.ScanFlagged
		case description.Truncated:
			scan = injection.ScanPartial
		default:
			scan = injection.ScanClean
		}
	}
	if observed == expected {
		return false, ErrDrift
	}
	c := actor{Org: org, By: "gateway:" + gateway.String(), Audit: evdomain.Actor{Type: "gateway", ID: gateway.String()}}
	if tool == ToolA2ACard {
		return s.reportCardDrift(ctx, c, gateway, id, expected, observed) // G0 M14 D86
	}
	quarantined := false
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		quarantined = false
		q := dbq.New(tx)
		conn, err := lock(ctx, q, org, id)
		if err != nil {
			return err
		}
		if conn.GatewayID != gateway || conn.Kind != KindMCP {
			return ErrNotFound
		}
		run, err := driftRun(ctx, q, org, conn.ID, description.Transaction)
		if err != nil {
			return err
		}
		pin, err := q.PinnedPackageRaw(ctx, org, conn.Package)
		if db.IsNoRows(err) {
			return ErrPackage
		} else if err != nil {
			return err
		}
		p, err := manifest.Decode(pin.Raw)
		if err != nil {
			return ErrPackage
		}
		if !reviewed(p.Definitions, tool, expected) {
			return ErrDrift
		}
		if conn.Simulated {
			// HR-222: a simulator's drift changes nothing real: no epoch, no
			// quarantine, no notification. The gateway still refuses locally.
			details := map[string]string{
				"simulated": "true", "upstream_tool": tool, "expected_digest": expected, "observed_digest": observed,
				"description_scan": scan,
			}
			if !run.IsZero() {
				details["run"] = run.String()
			}
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: auditkind.ConnectionDriftReported, Actor: c.Audit, Outcome: audit.Success,
				Object: &audit.Object{Type: "connection", ID: conn.ID.String()}, Details: details,
			})
			return err
		}
		v, err := q.GetPackageVersionState(ctx, org, conn.Package, pin.Version)
		if err != nil {
			return err
		}
		if found.Flagged {
			if err := injection.Record(ctx, tx, c.Audit, audit.Object{Type: "connection", ID: conn.ID.String()}, tool, "drift", found,
				map[string]string{
					"connection_id": conn.ID.String(), "package": conn.Package, "version": pin.Version,
					"full_description_digest": description.Digest,
				}); err != nil {
				return err
			}
			if _, err := pgwaitlist.OpenToolReview(ctx, tx, org, v.ID, conn.Package, pin.Version, c.Audit); err != nil {
				return err
			}
		}
		from := domain.State(v.State)
		switch from {
		case domain.StateQuarantined:
			quarantined = true
			return nil
		case domain.StateActive, domain.StateStale:
		case domain.StateUnclassified, domain.StateDraft, domain.StateReviewed, domain.StateRetired:
			return nil // not in use: nothing to stop
		}
		if err := bumpEpoch(ctx, q, org); err != nil {
			return err
		}
		if err := db.ExpectOneRow(q.TransitionPackageVersion(ctx, dbq.TransitionPackageVersionParams{
			ToState: string(domain.StateQuarantined), OrgID: org, ID: v.ID, FromState: string(from),
		})); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, DriftQuarantinedEvent(c.Audit, conn.ID, conn.Package, pin.Version, from, tool, expected, observed, scan, run)); err != nil {
			return err
		}
		// A person reviews the quarantined version again (PN-006.2, HR-244).
		if _, err := pgwaitlist.OpenToolReview(ctx, tx, org, v.ID, conn.Package, pin.Version, c.Audit); err != nil {
			return err
		}
		if s.notify != nil {
			if _, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: "security.package_quarantined", Params: map[string]string{
				"package": conn.Package, "version": pin.Version, "reason": ReasonUpstreamDrift,
			}}); err != nil {
				return err
			}
		}
		quarantined = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return quarantined, nil
}

// DriftQuarantinedEvent is the package.transitioned audit event of a package
// version quarantined because an upstream tool of the connection drifted
// from its reviewed definition (PN-006.2, F401). run is the run of the call
// whose own check found the drift, zero when none is known (a periodic
// check, or a transaction the server has no row of): only a known run is
// named (HR-665).
func DriftQuarantinedEvent(actor evdomain.Actor, connection ids.UUID, pkg, version string, from domain.State,
	tool, expected, observed, scan string, run ids.UUID,
) audit.Event {
	details := map[string]string{
		"from": string(from), "to": string(domain.StateQuarantined), "reason": ReasonUpstreamDrift,
		"connection_id": connection.String(), "upstream_tool": tool, "expected_digest": expected, "observed_digest": observed,
		"description_scan": scan,
	}
	if !run.IsZero() {
		details["run"] = run.String()
	}
	return audit.Event{
		Name: auditkind.PackageTransitioned, Actor: actor, Outcome: audit.Success,
		Object: &audit.Object{Type: "package_version", ID: trust.Key(pkg, version)}, Details: details,
	}
}

// driftRun is the run of the org's own transaction txn through connection,
// zero when txn is zero or names no such transaction (HR-665): a drift
// report is never refused for its transaction.
func driftRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, connection, txn ids.UUID) (ids.UUID, error) {
	if txn.IsZero() {
		return ids.UUID{}, nil
	}
	run, err := q.DriftTransactionRun(ctx, org, txn, &connection)
	if db.IsNoRows(err) {
		return ids.UUID{}, nil
	}
	return run, err
}

// reviewed reports whether a definition dispatches to the upstream tool
// with exactly the reviewed digest.
func reviewed(defs []domain.Definition, tool, digest string) bool {
	for _, d := range defs {
		if d.Dispatch != nil && d.Dispatch.MCP != nil && d.Dispatch.MCP.Tool == tool && d.Dispatch.MCP.UpstreamDigest == digest {
			return true
		}
	}
	return false
}
