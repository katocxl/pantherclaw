// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package a2astore keeps a2a connections' pinned configuration and the
// peer runs created for them (G0 M14 D30, D33, D64; migration 00154).
// Every function runs in the caller's tenant transaction.
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

// Errors.
var (
	// ErrNotFound: the connection has no a2a configuration.
	ErrNotFound = errors.New("a2astore: no a2a configuration")
	// ErrUnpinned: the configuration carries no pinned card and digest;
	// nothing is stored unpinned.
	ErrUnpinned = errors.New("a2astore: the card is not pinned")
	// ErrShape: the configuration lacks its interface, or a peer agent
	// id is not a UUID.
	ErrShape = errors.New("a2astore: configuration incomplete")
)

// Pin is a stored configuration with when and by whom it was pinned and
// any drift seen since.
type Pin struct {
	Config   *pb.A2AConfig
	PinnedBy string
	PinnedAt time.Time
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

// Insert stores a new connection's pinned configuration.
func Insert(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, c *pb.A2AConfig, by string) error {
	r, err := toRow(c)
	if err != nil {
		return err
	}
	return q.InsertA2AConnection(ctx, dbq.InsertA2AConnectionParams{
		OrgID: org, ConnectionID: conn, CardUrl: r.cardURL, Binding: r.binding, InterfaceUrl: r.url, PinnedCard: r.card,
		CardDigest: r.digest, CardKeys: r.keys, Skills: r.skills, PeerAgentID: r.peer, PeerBounds: r.bounds,
		PeerLimits: r.limits, MaxAnswerBytes: r.maxAnswer, MaxStreamSeconds: r.maxStream, PinnedBy: by,
	})
}

// Replace stores a refreshed pin (or a changed configuration, pinned
// again), clearing recorded drift.
func Replace(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, c *pb.A2AConfig, by string) error {
	r, err := toRow(c)
	if err != nil {
		return err
	}
	n, err := q.UpdateA2AConnection(ctx, dbq.UpdateA2AConnectionParams{
		OrgID: org, ConnectionID: conn, CardUrl: r.cardURL, Binding: r.binding, InterfaceUrl: r.url, PinnedCard: r.card,
		CardDigest: r.digest, CardKeys: r.keys, Skills: r.skills, PeerAgentID: r.peer, PeerBounds: r.bounds,
		PeerLimits: r.limits, MaxAnswerBytes: r.maxAnswer, MaxStreamSeconds: r.maxStream, PinnedBy: by,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Load returns a connection's pinned configuration.
func Load(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID) (Pin, error) {
	r, err := q.GetA2AConnection(ctx, org, conn)
	if db.IsNoRows(err) {
		return Pin{}, ErrNotFound
	}
	if err != nil {
		return Pin{}, err
	}
	c := &pb.A2AConfig{
		CardUrl: r.CardUrl, PinnedCard: r.PinnedCard, CardDigest: r.CardDigest, CardKeys: r.CardKeys, Skills: r.Skills,
		Interface:      &pb.A2AInterface{Protocol: r.Binding, Url: r.InterfaceUrl},
		MaxAnswerBytes: r.MaxAnswerBytes, MaxStreamSeconds: r.MaxStreamSeconds,
	}
	if r.PeerAgentID != nil {
		c.PeerAgentId = r.PeerAgentID.String()
		c.PeerScope = &pb.A2APeerScope{Bounds: r.PeerBounds, Limits: r.PeerLimits}
	}
	return Pin{Config: c, PinnedBy: r.PinnedBy, PinnedAt: r.PinnedAt, DriftedAt: r.DriftedAt, Observed: r.ObservedDigest}, nil
}

// MarkDrift records that a re-read found observed instead of the pinned
// digest. It reports false when the pin changed meanwhile or drift was
// already recorded (the report is then stale or a repeat).
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

// GetPeerRun returns the peer run of (requester run, connection, context).
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

// InsertPeerRun records a peer run; false when one already exists for the
// key (a concurrent BeginDispatch won), and the caller reads that one.
func InsertPeerRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, requester, conn ids.UUID, contextID string, p PeerRun) (bool, error) {
	n, err := q.InsertA2APeerRun(ctx, dbq.InsertA2APeerRunParams{
		OrgID: org, RequesterRunID: requester, ConnectionID: conn, ContextID: contextID, ChildRunID: p.Run, ChildGrantID: p.Grant,
	})
	return n == 1, err
}
