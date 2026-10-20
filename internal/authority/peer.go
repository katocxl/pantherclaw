// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/a2a/a2astore"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// Peer delegation (G0 M14 D33, D77, D89; HR-324..326). A message to a peer
// agent enrolled in the same org, through an a2a connection that names it,
// is sent for the requester: at BeginDispatch, in its transaction, the
// Authority gives the peer a child run of the requester's run and a grant
// delegated from the requester's grant, bounded by the connection's peer
// scope. The requester's limits carry over (the delegated grant is within
// its parent and shares its ancestors' budgets), the principal is the
// requester's, and revoking the requester's grant or ending its run
// revokes and ends the peer's. A permit that never reaches BeginDispatch
// creates nothing. The child run's id travels only in the action token's
// pc_peer_run claim (D77); the peer's helper reads it and acts in that run.

// PeerRunTTL is the longest a peer's run lives; never past its parent.
const PeerRunTTL = 60 * time.Minute

// OperationPeerSend is the operation a peer message is.
const OperationPeerSend = "a2a.message.send"

// ErrPeerDelegation refuses the dispatch: the peer's run or grant could
// not be made within the requester's (nothing is sent).
var ErrPeerDelegation = pcerr.New(pcerr.FailedPrecondition, "DELEGATION_NOT_ALLOWED",
	"the requester's grant cannot be delegated to the peer agent")

// Peer delegates to peer agents. Grants is the grants service with its
// in-transaction store (DelegateTx).
type Peer struct {
	Grants *grantsapp.Service
}

// Delegate is the BeginDispatch hook (pgauthority.Store.Peer): for a peer
// message it returns the peer's child run and the interface URL the action
// token is addressed to; for any other dispatch nil.
func (p *Peer) Delegate(ctx context.Context, tx db.TenantTx, org ids.OrgID, d finalize.Dispatching) (*ids.UUID, string, error) {
	if d.Connection == nil || d.Operation != OperationPeerSend {
		return nil, "", nil
	}
	q := dbq.New(tx)
	conn := *d.Connection
	if _, err := q.GetA2AConnectionWriter(ctx, org, conn); db.IsNoRows(err) {
		return nil, "", nil // not an a2a connection
	} else if err != nil {
		return nil, "", err
	}
	pin, err := a2astore.Get(ctx, q, org, conn, a2astore.StateActive)
	if errors.Is(err, a2astore.ErrNotFound) {
		return nil, "", ErrPeerDelegation
	} else if err != nil {
		return nil, "", err
	}
	audience := pin.Config.GetInterface().GetUrl()
	peerAgent := pin.Config.GetPeerAgentId()
	if peerAgent == "" {
		// An external peer acts under its own authority (R-41): the message
		// carries no delegated run.
		return nil, "", nil
	}
	agent, err := ids.ParseUUID(peerAgent)
	if err != nil {
		return nil, "", ErrPeerDelegation
	}
	txn, err := q.TransactionRun(ctx, org, d.Transaction)
	if err != nil {
		return nil, "", err
	}
	// The requester's run row is locked first: one peer run per key, and
	// its state cannot change under the delegation.
	parent, err := q.LockRun(ctx, org, txn)
	if err != nil {
		return nil, "", err
	}
	if parent.EffectiveState != "ACTIVE" || parent.PcRun.InstanceID == nil || parent.PcRun.GrantID == nil {
		return nil, "", ErrPeerDelegation
	}
	if got, ok, err := a2astore.GetPeerRun(ctx, q, org, txn, conn, ""); err != nil {
		return nil, "", err
	} else if ok {
		return &got.Run, audience, nil
	}
	instance := *parent.PcRun.InstanceID
	child, err := runsapp.StartChildRunTx(ctx, tx, runsapp.ChildInput{
		Caller:      pap.Instance{Org: org, Agent: parent.PcRun.AgentID, Instance: instance},
		ParentRunID: txn, AgentID: agent, TaskRef: "a2a peer of run " + txn.String(), TTL: PeerRunTTL,
	})
	if err != nil {
		return nil, "", pcerr.Wrap(err, pcerr.FailedPrecondition, "DELEGATION_NOT_ALLOWED", "the peer agent's run cannot be started")
	}
	bounds, err := gdomain.DecodeBounds(pin.Config.GetPeerScope().GetBounds())
	if err != nil {
		return nil, "", ErrPeerDelegation
	}
	// The peer may do what both the requester's grant and the connection's
	// peer scope allow (HR-324): a wider scope narrows to the grant.
	if gs, ok := p.Grants.Store.(interface {
		GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id gdomain.GrantID) (gdomain.Grant, bool, error)
	}); ok {
		pg, err := gdomain.ParseGrantID(parent.PcRun.GrantID.String())
		if err != nil {
			return nil, "", ErrPeerDelegation
		}
		parentGrant, found, err := gs.GrantInTx(ctx, tx, org, pg)
		if err != nil {
			return nil, "", err
		}
		if !found {
			return nil, "", ErrPeerDelegation
		}
		bounds = bounds.Intersect(parentGrant.Bounds)
	}
	var limits gdomain.Limits
	if raw := pin.Config.GetPeerScope().GetLimits(); len(raw) > 0 {
		if limits, err = gdomain.DecodeLimits(raw); err != nil {
			return nil, "", ErrPeerDelegation
		}
	}
	g, err := p.Grants.DelegateTx(ctx, tx, grantsapp.Workload{Org: org, InstanceID: instance, RunID: txn}, grantsapp.DelegateRequest{
		ChildRunID: child.ID, TaskRef: child.TaskRef, Bounds: bounds, Limits: limits,
	})
	if err != nil {
		return nil, "", pcerr.Wrap(err, pcerr.FailedPrecondition, "DELEGATION_NOT_ALLOWED", "the requester's grant cannot be delegated")
	}
	if err := a2astore.InsertPeerRun(ctx, q, org, txn, conn, "", a2astore.PeerRun{Run: child.ID, Grant: g.ID.UUID()}); err != nil {
		return nil, "", err
	}
	return &child.ID, audience, nil
}
