// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"
	"unicode"
	"unicode/utf8"

	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Route is a route a session's edge saw the agent take: a destination it
// refused (direct_api; host and port) or a credential it stripped
// (credential; its kind and a SHA-256 prefix, never the value).
type Route struct {
	Kind    string
	Locator string
}

// MaxRoutes bounds the routes of one report.
const MaxRoutes = 64

// ErrRoutes rejects a report of routes that is empty, too long, of another
// kind or with a locator that is not printable text of at most 512
// characters.
var ErrRoutes = pcerr.New(pcerr.InvalidArgument, "SANDBOX_ROUTES",
	"routes are 1 to 64 direct_api or credential routes, each with a printable locator of at most 512 characters")

// ReportRoutes records the routes the session's edge saw the agent take as
// observed routes (source probe) of the session's agent and every mapped
// connection, while the session is open (sandbox.run over the agent). They
// are untrusted observations that never grant anything (HR-148, G0 M9
// design decision 11); a first sighting makes coverage recompute the
// scope. It returns the number of first sightings.
func (s *Service) ReportRoutes(ctx context.Context, session ids.UUID, routes []Route) (int, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return 0, err
	}
	if len(routes) == 0 || len(routes) > MaxRoutes {
		return 0, ErrRoutes
	}
	for _, r := range routes {
		if !validRoute(r) {
			return 0, ErrRoutes
		}
	}
	n := 0
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sess, err := q.LockSandboxSession(ctx, c.Org, session)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := agentFor(ctx, c, q, sess.AgentID); err != nil {
			return err
		}
		if sess.State != "OPEN" || !s.now().Before(sess.ExpiresAt) {
			return ErrNotOpen
		}
		conns, err := q.SandboxSessionBindings(ctx, sess.OrgID, sess.ID)
		if err != nil {
			return err
		}
		for _, r := range routes {
			for _, conn := range conns {
				first, err := s.Coverage.RecordRoute(ctx, tx, covdomain.ObservedRoute{
					Agent: sess.AgentID, Connection: conn.ConnectionID, SandboxSession: sess.ID, Kind: covdomain.RouteKind(r.Kind),
					Locator: r.Locator,
				})
				if err != nil {
					return err
				}
				if first {
					n++
				}
			}
		}
		return record(ctx, tx, c, "sandbox.routes_reported", sess.ID, map[string]string{
			"agent_id": sess.AgentID.String(), "routes": strconv.Itoa(len(routes)), "new_routes": strconv.Itoa(n),
		})
	})
	return n, err
}

// validRoute: a direct_api or credential route whose locator is printable
// text of at most 512 characters.
func validRoute(r Route) bool {
	if r.Kind != string(covdomain.KindDirectAPI) && r.Kind != string(covdomain.KindCredential) {
		return false
	}
	if r.Locator == "" || !utf8.ValidString(r.Locator) || utf8.RuneCountInString(r.Locator) > 512 {
		return false
	}
	for _, ch := range r.Locator {
		if !unicode.IsPrint(ch) {
			return false
		}
	}
	return true
}
