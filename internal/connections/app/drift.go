// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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
	if observed == expected {
		return false, ErrDrift
	}
	c := actor{Org: org, By: "gateway:" + gateway.String(), Audit: evdomain.Actor{Type: "gateway", ID: gateway.String()}}
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
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "connection.drift_reported", Actor: c.Audit, Outcome: audit.Success,
				Object: &audit.Object{Type: "connection", ID: conn.ID.String()},
				Details: map[string]string{
					"simulated": "true", "upstream_tool": tool, "expected_digest": expected, "observed_digest": observed,
				},
			})
			return err
		}
		v, err := q.GetPackageVersionState(ctx, org, conn.Package, pin.Version)
		if err != nil {
			return err
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
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "package.transitioned", Actor: c.Audit, Outcome: audit.Success,
			Object: &audit.Object{Type: "package_version", ID: trust.Key(conn.Package, pin.Version)},
			Details: map[string]string{
				"from": string(from), "to": string(domain.StateQuarantined), "reason": ReasonUpstreamDrift,
				"connection_id": conn.ID.String(), "upstream_tool": tool, "expected_digest": expected, "observed_digest": observed,
			},
		}); err != nil {
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
