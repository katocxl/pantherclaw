// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/transactionsrpc"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// registerM7 mounts the M7 track A services people use: the transaction
// list, the evidence explorer and reconciliation. verification signs the
// effect receipts a person's resolution or a compensation appends; consoleURL is
// the console base for an explanation's links (empty: no console); kp opens
// the sealed inputs an explanation reads its material values from.
func registerM7(rs *connect.Server, pool *db.Pool, kp keys.KeyProvider, verification *txapp.Service, consoleURL string) {
	explorer := &txapp.Explorer{Pool: pool, Recordings: replayRecordings{replayEngine(pool, kp)}}
	pantherclawv1connect.RegisterTransactionServiceHandler(rs, transactionsrpc.New(explorer).WithConsoleURL(consoleURL))
	reconciler := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: pool}, Effects: verification}
	pantherclawv1connect.RegisterReconciliationServiceHandler(rs, transactionsrpc.NewReconciliations(explorer, reconciler))
}

// mountM7Pages adds the reconciliation page, the only place a person
// releases an unknown outcome, with a security key (G0 M7 design decision
// 3): it needs security keys, like the approval page. The release signs its
// effect receipt with verification's signer and tells org admins.
func mountM7Pages(web *webhttp.Handler, pool *db.Pool, verification *txapp.Service, m5 *m5Services) {
	if m5 == nil || m5.webauthn == nil {
		return
	}
	releases := &txapp.Releases{
		Store: &pgtransactions.Store{Pool: pool, Notify: m5.notifications}, Explorer: &txapp.Explorer{Pool: pool}, Effects: verification,
	}
	web.WithReconciliations(releases, m5.webauthn)
}

// newVerification builds the server side of verification (G0 M7 track A):
// leases, reports and the expiry of leases and windows. Effect receipts are
// signed with the receipts key, like decision and execution receipts; notify
// (M5 notifications) tells admins about effects without a receipt.
func newVerification(pool *db.Pool, reg *keys.Registry, notify pgtransactions.Notifier) (*txapp.Service, error) {
	receipts, err := reg.Signer(keys.PurposeReceipts)
	if err != nil {
		return nil, err
	}
	actionTokens, err := reg.Signer(keys.PurposeActionTokens)
	if err != nil {
		return nil, err
	}
	return &txapp.Service{Store: &pgtransactions.Store{Pool: pool, Notify: notify}, Receipts: receipts, ActionTokens: actionTokens}, nil
}
