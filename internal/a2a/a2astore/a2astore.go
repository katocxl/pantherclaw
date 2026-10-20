// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package a2astore keeps a2a connections' pins and the peer runs created
// for them (G0 M14 D30, D33, D64, D85; migration 00154). A pin is
// proposed with the connection and serves once a person holding
// connection.manage confirms it with a fresh step-up (D92); the pin it
// replaces serves until then. Every function runs in the caller's tenant
// transaction.
package a2astore

import (
	"context"
	"errors"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Pin states.
const (
	StateProposed   = "PROPOSED"
	StateActive     = "ACTIVE"
	StateSuperseded = "SUPERSEDED"
	StateVoided     = "VOIDED"
)

// Errors.
var (
	// ErrNotFound: the connection has no pin in that state.
	ErrNotFound = errors.New("a2astore: no such a2a pin")
	// ErrUnpinned: the configuration carries no pinned card and digest;
	// nothing is stored unpinned.
	ErrUnpinned = errors.New("a2astore: the card is not pinned")
	// ErrShape: the configuration lacks its interface, or a peer agent
	// id is not a UUID.
	ErrShape = errors.New("a2astore: configuration incomplete")
)

// Pin is one stored pin.
type Pin struct {
	ID         ids.UUID
	Connection ids.UUID
	State      string
	Config     *pb.A2AConfig
	ProposedBy string
	ProposedAt time.Time
	// ConfirmedBy and ConfirmedAt are set once the pin was confirmed.
	ConfirmedBy  *ids.UUID
	ConfirmedKey *ids.UUID
	ConfirmedAt  *time.Time
	// DriftedAt and Observed are set once a re-read found another card.
	DriftedAt *time.Time
	Observed  []byte
}

type row struct {
	cardURL, binding, url string
	card, digest, keys    []byte
	skills                []string
	peer                  *ids.UUID
	bounds, limits        []byte
	maxAnswer, maxStream  int32
}

func toRow(c *pb.A2AConfig) (row, error) {
	if len(c.GetPinnedCard()) == 0 || len(c.GetCardDigest()) != 32 {
		return row{}, ErrUnpinned
	}
	if c.GetInterface() == nil {
		return row{}, ErrShape
	}
	r := row{
		cardURL: c.GetCardUrl(), binding: c.GetInterface().GetProtocol(), url: c.GetInterface().GetUrl(),
		card: c.GetPinnedCard(), digest: c.GetCardDigest(), keys: nilIfEmpty(c.GetCardKeys()), skills: c.GetSkills(),
		maxAnswer: c.GetMaxAnswerBytes(), maxStream: c.GetMaxStreamSeconds(),
	}
	if r.skills == nil {
		r.skills = []string{}
	}
	if s := c.GetPeerAgentId(); s != "" {
		id, err := ids.ParseUUID(s)
		if err != nil || c.GetPeerScope() == nil {
			return row{}, ErrShape
		}
		r.peer, r.bounds, r.limits = &id, c.GetPeerScope().GetBounds(), nilIfEmpty(c.GetPeerScope().GetLimits())
	}
	return r, nil
}

func nilIfEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// Propose stores a pinned configuration as the connection's proposal,
// voiding an older one. The ACTIVE pin, if any, keeps serving.
func Propose(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, c *pb.A2AConfig, by string) (ids.UUID, error) {
	r, err := toRow(c)
	if err != nil {
		return ids.UUID{}, err
	}
	if _, err := q.VoidA2AProposals(ctx, org, conn); err != nil {
		return ids.UUID{}, err
	}
	id := ids.NewV7()
	return id, q.InsertA2APin(ctx, dbq.InsertA2APinParams{
		OrgID: org, ID: id, ConnectionID: conn, CardUrl: r.cardURL, Binding: r.binding, InterfaceUrl: r.url, PinnedCard: r.card,
		CardDigest: r.digest, CardKeys: r.keys, Skills: r.skills, PeerAgentID: r.peer, PeerBounds: r.bounds,
		PeerLimits: r.limits, MaxAnswerBytes: r.maxAnswer, MaxStreamSeconds: r.maxStream, ProposedBy: by,
	})
}

// Get returns the connection's pin in state (ACTIVE or PROPOSED).
func Get(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, state string) (Pin, error) {
	r, err := q.GetA2APin(ctx, org, conn, state)
	if db.IsNoRows(err) {
		return Pin{}, ErrNotFound
	}
	if err != nil {
		return Pin{}, err
	}
	return pinOf(r), nil
}

func pinOf(r dbq.PcA2aPin) Pin {
	c := &pb.A2AConfig{
		CardUrl: r.CardUrl, PinnedCard: r.PinnedCard, CardDigest: r.CardDigest, CardKeys: r.CardKeys, Skills: r.Skills,
		Interface:      &pb.A2AInterface{Protocol: r.Binding, Url: r.InterfaceUrl},
		MaxAnswerBytes: r.MaxAnswerBytes, MaxStreamSeconds: r.MaxStreamSeconds,
	}
	if r.PeerAgentID != nil {
		c.PeerAgentId = r.PeerAgentID.String()
		c.PeerScope = &pb.A2APeerScope{Bounds: r.PeerBounds, Limits: r.PeerLimits}
	}
	return Pin{
		ID: r.ID, Connection: r.ConnectionID, State: r.State, Config: c, ProposedBy: r.ProposedBy, ProposedAt: r.ProposedAt,
		ConfirmedBy: r.ConfirmedBy, ConfirmedKey: r.ConfirmedCredential, ConfirmedAt: r.ConfirmedAt,
		DriftedAt: r.DriftedAt, Observed: r.ObservedDigest,
	}
}

// Activate makes the proposal pin the connection's ACTIVE pin, the
// previous one SUPERSEDED, for the person who confirmed it with key. The
// proposal is locked first; ErrNotFound when it is no longer the
// connection's proposal.
func Activate(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn, pin, by, key ids.UUID) (Pin, error) {
	r, err := q.LockA2AProposal(ctx, org, conn, pin)
	if db.IsNoRows(err) {
		return Pin{}, ErrNotFound
	}
	if err != nil {
		return Pin{}, err
	}
	if _, err := q.SupersedeA2APin(ctx, org, conn); err != nil {
		return Pin{}, err
	}
	n, err := q.ActivateA2APin(ctx, dbq.ActivateA2APinParams{OrgID: org, ID: r.ID, ConfirmedBy: &by, ConfirmedCredential: &key})
	if err != nil {
		return Pin{}, err
	}
	if n != 1 {
		return Pin{}, ErrNotFound
	}
	return Get(ctx, q, org, conn, StateActive)
}

// MarkDrift records that a re-read found observed instead of the ACTIVE
// pin's digest. It reports false when the pin changed meanwhile or drift
// was already recorded (the report is then stale or a repeat).
func MarkDrift(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, pinned, observed []byte) (bool, error) {
	n, err := q.MarkA2ADrift(ctx, dbq.MarkA2ADriftParams{OrgID: org, ConnectionID: conn, PinnedDigest: pinned, ObservedDigest: observed})
	return n == 1, err
}

// PeerRun is the child run (and delegated grant) of a requester's run for
// a peer agent in one A2A context (D33).
type PeerRun struct {
	Run, Grant ids.UUID
	Created    time.Time
}

// GetPeerRun returns the newest active peer run of (requester run,
// connection, context).
func GetPeerRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, requester, conn ids.UUID, contextID string) (PeerRun, bool, error) {
	r, err := q.GetA2APeerRun(ctx, dbq.GetA2APeerRunParams{OrgID: org, RequesterRunID: requester, ConnectionID: conn, ContextID: contextID})
	if db.IsNoRows(err) {
		return PeerRun{}, false, nil
	}
	if err != nil {
		return PeerRun{}, false, err
	}
	return PeerRun{Run: r.ChildRunID, Grant: r.ChildGrantID, Created: r.CreatedAt}, true, nil
}

// InsertPeerRun records a peer run. The caller holds the requester run's
// row lock, so no other BeginDispatch creates one for the same key meanwhile.
func InsertPeerRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, requester, conn ids.UUID, contextID string, p PeerRun) error {
	return q.InsertA2APeerRun(ctx, dbq.InsertA2APeerRunParams{
		OrgID: org, RequesterRunID: requester, ConnectionID: conn, ContextID: contextID, ChildRunID: p.Run, ChildGrantID: p.Grant,
	})
}

// ActivateAsOperator makes the proposal pin the connection's ACTIVE pin
// for dev seed's operator, without a person or a security key; the
// database accepts it only for a simulated connection (HR-221).
// DEVELOPMENT ONLY: the API and the confirm page never call it.
func ActivateAsOperator(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn, pin ids.UUID, operator string) (Pin, error) {
	if _, err := q.LockA2AProposal(ctx, org, conn, pin); db.IsNoRows(err) {
		return Pin{}, ErrNotFound
	} else if err != nil {
		return Pin{}, err
	}
	if _, err := q.SupersedeA2APin(ctx, org, conn); err != nil {
		return Pin{}, err
	}
	if n, err := q.ActivateA2APinAsOperator(ctx, &operator, org, pin); err != nil {
		return Pin{}, err
	} else if n != 1 {
		return Pin{}, ErrNotFound
	}
	return Get(ctx, q, org, conn, StateActive)
}
