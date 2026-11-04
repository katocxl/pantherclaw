// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ledgertest chains an org's ledger for tests that read the feed.
package ledgertest

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Settle is how long ChainSettled waits for other transactions to end.
const Settle = time.Minute

// ChainSettled chains org until every committed entry of org is linked, and
// returns how many it linked.
//
// One ledger.ChainAll is not enough before reading the feed. The chainer
// links only entries whose transaction id is below the snapshot's xmin, so
// that no entry can commit later below the chain's watermark. Any
// transaction still open anywhere on the database (another test package,
// a River client, a shuffled sibling test) holds xmin back, and ChainAll
// then links nothing although the entries have committed. A detection pass
// over that feed reads no events and looks drained. So this keeps chaining
// until no committed entry of org is left unlinked. That is the condition
// the feed needs, not a timeout; the wait ends as soon as the open
// transactions do, and Settle only bounds a stuck one.
func ChainSettled(t testing.TB, ctx context.Context, pool *db.Pool, org ids.OrgID) int {
	t.Helper()
	deadline := time.Now().Add(Settle)
	total := 0
	for {
		n, err := ledger.ChainAll(ctx, pool, org, 1000)
		total += n
		if err != nil {
			t.Fatal(err)
		}
		var left int
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries e WHERE e.org_id = $1
				AND NOT EXISTS (SELECT 1 FROM pc.ledger_chain c WHERE c.org_id = e.org_id AND c.entry_id = e.id)`, org).Scan(&left)
		}); err != nil {
			t.Fatal(err)
		}
		if left == 0 {
			return total
		}
		if time.Now().After(deadline) {
			t.Fatalf("ledgertest: %d committed entries of %s not chained within %s; a transaction stays open", left, org, Settle)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
