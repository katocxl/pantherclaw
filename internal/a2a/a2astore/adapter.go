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
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
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

// Adapter is the a2a kind's configuration store (D64, ports.KindConfig):
// the connection service calls Save in the transaction that creates or
// updates an a2a connection, and the gateway configuration Load. Every
// save reads the card anew and pins what it read.
type Adapter struct {
	Pinner *Pinner
}

var _ ports.KindConfig = (*Adapter)(nil)

// Save pins the card and proposes the configuration (a validated
// *capp.A2AConfig) of the connection just written in tx. The connection's
// simulated flag picks the egress client, and its writer is the pin's.
func (a *Adapter) Save(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID, _ int32, cfg any) (string, error) {
	in, ok := cfg.(*capp.A2AConfig)
	if !ok || in == nil {
		return "", ErrShape
	}
	q := dbq.New(tx)
	w, err := q.GetA2AConnectionWriter(ctx, org, conn)
	if err != nil {
		return "", err
	}
	pinned, err := a.Pinner.Pin(ctx, ToProto(in), w.Simulated)
	if err != nil {
		return "", err
	}
	// A proposal: it serves once an Org Admin confirms it (D85). The
	// interface URL is the connection's base URL.
	if _, err := Propose(ctx, q, org, conn, pinned, w.UpdatedBy); err != nil {
		return "", err
	}
	return in.Interface.URL, nil
}

// Load returns the configuration a gateway serves (*pb.A2AConfig).
func (a *Adapter) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID) (proto.Message, error) {
	p, err := Get(ctx, dbq.New(tx), org, conn, StateActive)
	if errors.Is(err, ErrNotFound) {
		// Nothing confirmed yet: the gateway gets no configuration and
		// refuses the connection (KIND_CONFIG_MISSING).
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p.Config, nil
}

// ToProto is a validated configuration as the gateway gets it, before the
// card is pinned.
func ToProto(c *capp.A2AConfig) *pb.A2AConfig {
	out := &pb.A2AConfig{
		CardUrl: c.CardURL, CardKeys: c.CardKeys, Skills: slices.Clone(c.Skills),
		Interface:      &pb.A2AInterface{Protocol: c.Interface.Protocol, Url: c.Interface.URL},
		MaxAnswerBytes: c.MaxAnswerBytes, MaxStreamSeconds: c.MaxStreamSeconds,
	}
	if c.PeerAgent != nil && c.PeerScope != nil {
		out.PeerAgentId = c.PeerAgent.String()
		out.PeerScope = &pb.A2APeerScope{Bounds: c.PeerScope.Bounds, Limits: c.PeerScope.Limits}
	}
	return out
}
