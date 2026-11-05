// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/browsersites/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Page compare errors.
var (
	ErrCompareConnection = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_FOUND", "connection not found")
	ErrCompareHost       = pcerr.New(pcerr.InvalidArgument, "BROWSER_COMPARE_HOST_INVALID",
		"the host matches none of the org's browser sites marked for the compare")
)

// CompareThrottle is how long one (connection, host, path) is recorded once.
const CompareThrottle = time.Hour

// PageCompare is one cloaking compare mismatch a gateway reports (G0 M33
// D986): digests and sizes only, never page content (HR-750).
type PageCompare struct {
	Run, Transaction         ids.UUID
	Host                     string
	PathSHA256               string
	AgentStatus, PlainStatus int32
	AgentBytes, PlainBytes   int64
	SimilarityPermille       int32
}

// Compares records cloaking compare reports, throttled in memory to once
// per (connection, host, path) per hour. It only alerts: nothing it does
// changes a decision.
type Compares struct {
	Pool *db.Pool
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu   sync.Mutex
	seen map[compareKey]time.Time
}

type compareKey struct {
	conn       ids.UUID
	host, path string
}

func (c *Compares) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// claim reports whether k is due, and marks it recorded at t.
func (c *Compares) claim(k compareKey, t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[compareKey]time.Time{}
	}
	if last, ok := c.seen[k]; ok && t.Sub(last) < CompareThrottle {
		return false
	}
	for x, last := range c.seen {
		if t.Sub(last) >= CompareThrottle {
			delete(c.seen, x)
		}
	}
	c.seen[k] = t
	return true
}

func (c *Compares) release(k compareKey, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[k].Equal(t) {
		delete(c.seen, k)
	}
}

// ReportPageCompare records a mismatch as audit browser.cloaking_suspected,
// with the gateway as actor and the connection as object (HR-750). The
// connection must be one the gateway serves (otherwise not found) and the
// host must match one of the org's compare sites (otherwise invalid). It
// reports false when the same (connection, host, path) was recorded within
// the hour.
func (c *Compares) ReportPageCompare(ctx context.Context, org ids.OrgID, gateway, conn ids.UUID, in PageCompare) (bool, error) {
	k := compareKey{conn: conn, host: in.Host, path: in.PathSHA256}
	var (
		recorded bool
		at       time.Time
	)
	err := c.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetConnection(ctx, org, conn)
		if db.IsNoRows(err) {
			return ErrCompareConnection
		} else if err != nil {
			return err
		}
		if row.GatewayID != gateway {
			return ErrCompareConnection
		}
		sites, err := q.ListBrowserCompareSites(ctx, org)
		if err != nil {
			return err
		}
		list := make([]domain.Site, 0, len(sites))
		for _, s := range sites {
			list = append(list, domain.Site{Host: s.Host, IncludeSubdomains: s.IncludeSubdomains})
		}
		if !domain.Matches(in.Host, list) {
			return ErrCompareHost
		}
		at = c.now()
		if !c.claim(k, at) {
			return nil
		}
		recorded = true
		details := map[string]string{
			"host": in.Host, "path_sha256": in.PathSHA256,
			"agent_status": strconv.Itoa(int(in.AgentStatus)), "plain_status": strconv.Itoa(int(in.PlainStatus)),
			"agent_bytes": strconv.FormatInt(in.AgentBytes, 10), "plain_bytes": strconv.FormatInt(in.PlainBytes, 10),
			"similarity_permille": strconv.Itoa(int(in.SimilarityPermille)),
		}
		if !in.Run.IsZero() {
			details["run_id"] = in.Run.String()
		}
		if !in.Transaction.IsZero() {
			details["transaction_id"] = in.Transaction.String()
		}
		if row.Simulated {
			details["simulated"] = "true"
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.BrowserCloakingSuspected, Actor: evdomain.Actor{Type: "gateway", ID: gateway.String()},
			Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: conn.String()}, Details: details,
		})
		return err
	})
	if err != nil {
		if recorded {
			c.release(k, at)
		}
		return false, err
	}
	return recorded, nil
}
