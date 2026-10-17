// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fetchTimeout bounds one card read.
const fetchTimeout = 10 * time.Second

// Errors a pin answers with: nothing is stored.
var (
	ErrCardFetch = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_UNREACHABLE",
		"the agent card could not be read from its URL")
	ErrCardInvalid = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_INVALID",
		"the agent card is not a valid A2A 1.0 card")
	ErrCardSignature = pcerr.New(pcerr.FailedPrecondition, "A2A_CARD_SIGNATURE",
		"the agent card's signature does not verify with the pinned keys (a signed card needs pinned keys, and pinned keys need a signed card)")
	ErrCardKeys = pcerr.New(pcerr.InvalidArgument, "A2A_CARD_KEYS_INVALID",
		"card keys must be a JWKS of Ed25519 or P-256 keys with distinct key ids")
	ErrCardInterface = pcerr.New(pcerr.FailedPrecondition, "A2A_INTERFACE_NOT_DECLARED",
		"the interface is not a JSONRPC or HTTP+JSON interface of version 1.0 that the card declares")
	ErrCardSkill = pcerr.New(pcerr.FailedPrecondition, "A2A_SKILL_NOT_DECLARED",
		"an allowed skill is not one of the card's skills")
)

// Pinner reads and checks a card before its configuration is stored
// (D30). Public reaches public addresses only; Simulated also reaches a
// loopback or private address, for a connection marked simulated (HR-221).
type Pinner struct {
	Public, Simulated *http.Client
}

// NewPinner returns a Pinner with egress clients (HR-070..074).
func NewPinner() *Pinner {
	private := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	}
	return &Pinner{
		Public:    httpx.NewEgressClient(httpx.EgressConfig{Timeout: fetchTimeout}),
		Simulated: httpx.NewEgressClient(httpx.EgressConfig{Timeout: fetchTimeout, AllowedPrefixes: private}),
	}
}

// Pin fetches the card at cfg's card URL and checks it against cfg, and
// returns cfg with the card as fetched and its digest. Whatever pinned
// card or digest cfg carried is ignored: only a read the server made is
// pinned.
func (p *Pinner) Pin(ctx context.Context, cfg *pb.A2AConfig, simulated bool) (*pb.A2AConfig, error) {
	client := p.Public
	if simulated {
		client = p.Simulated
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	got, err := wire.Pin(ctx, client, wire.PinRequest{
		CardURL: cfg.GetCardUrl(), Binding: cfg.GetInterface().GetProtocol(), URL: cfg.GetInterface().GetUrl(),
		Keys: cfg.GetCardKeys(), Skills: cfg.GetSkills(),
	})
	if err != nil {
		return nil, pinError(err)
	}
	out := proto.CloneOf(cfg)
	out.PinnedCard, out.CardDigest = got.Card, got.Digest[:]
	out.Skills = slices.Clone(cfg.GetSkills())
	return out, nil
}

func pinError(err error) error {
	switch {
	case errors.Is(err, wire.ErrFetch):
		return ErrCardFetch
	case errors.Is(err, wire.ErrKeysInvalid):
		return ErrCardKeys
	case errors.Is(err, wire.ErrCardSignature), errors.Is(err, wire.ErrCardUnsigned), errors.Is(err, wire.ErrCardKeysRequired):
		return ErrCardSignature
	case errors.Is(err, wire.ErrInterface):
		return ErrCardInterface
	case errors.Is(err, wire.ErrSkill):
		return ErrCardSkill
	}
	return ErrCardInvalid
}

// Adapter is the a2a kind's configuration adapter (D64): the connection
// service calls it in the transaction that creates or updates an a2a
// connection, and the configuration service to load what a gateway gets.
type Adapter struct {
	Pinner *Pinner
}

// Create pins and stores a new connection's configuration.
func (a *Adapter) Create(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, cfg *pb.A2AConfig, simulated bool, by string) (*pb.A2AConfig, error) {
	pinned, err := a.Pinner.Pin(ctx, cfg, simulated)
	if err != nil {
		return nil, err
	}
	return pinned, Insert(ctx, q, org, conn, pinned, by)
}

// Update pins the card again and replaces the configuration: every change
// of an a2a connection reads the card anew (a refresh of the pin is an
// update with the same configuration).
func (a *Adapter) Update(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID, cfg *pb.A2AConfig, simulated bool, by string) (*pb.A2AConfig, error) {
	pinned, err := a.Pinner.Pin(ctx, cfg, simulated)
	if err != nil {
		return nil, err
	}
	return pinned, Replace(ctx, q, org, conn, pinned, by)
}

// Load returns the configuration a gateway serves.
func (a *Adapter) Load(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID) (*pb.A2AConfig, error) {
	p, err := Load(ctx, q, org, conn)
	if err != nil {
		return nil, err
	}
	return p.Config, nil
}
