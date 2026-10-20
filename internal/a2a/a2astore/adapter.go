// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2astore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
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
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
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
// (D30). Public reaches public addresses only; Simulated reaches loopback
// only (D96), for a connection marked simulated (HR-221), and only after
// the simulator answered the handshake.
type Pinner struct {
	Public, Simulated *http.Client
}

// NewPinner returns a Pinner with egress clients (HR-070..074).
func NewPinner() *Pinner {
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	return &Pinner{
		Public:    httpx.NewEgressClient(httpx.EgressConfig{Timeout: fetchTimeout}),
		Simulated: httpx.NewEgressClient(httpx.EgressConfig{Timeout: fetchTimeout, AllowedPrefixes: loopback}),
	}
}

// ErrSimulatedCardURL refuses a simulated connection's card URL that is
// not a loopback literal of the interface URL's origin, or whose origin is
// not a simulator (D96, HR-221): nothing is fetched.
var ErrSimulatedCardURL = pcerr.New(pcerr.FailedPrecondition, "A2A_SIMULATED_CARD_URL",
	"a simulated connection's card URL must be a loopback address of the interface URL's origin, answered by a simulator")

// Pin fetches the card at cfg's card URL and checks it against cfg, and
// returns cfg with the card as fetched and its digest. Whatever pinned
// card or digest cfg carried is ignored: only a read the server made is
// pinned. For a simulated connection the card URL must be a loopback
// literal of the interface URL's origin, and that origin must answer the
// simulator handshake before the card is read.
func (p *Pinner) Pin(ctx context.Context, cfg *pb.A2AConfig, simulated bool) (*pb.A2AConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	client := p.Public
	if simulated {
		origin, ok := simulatedOrigin(cfg.GetCardUrl(), cfg.GetInterface().GetUrl())
		if !ok {
			return nil, ErrSimulatedCardURL
		}
		client = p.Simulated
		if err := simHandshake(ctx, client, origin); err != nil {
			return nil, ErrSimulatedCardURL
		}
	}
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

// simulatedOrigin is the origin of a simulated connection's card URL: a
// loopback address literal, the same scheme, host and port as the
// interface URL's.
func simulatedOrigin(cardURL, iface string) (string, bool) {
	c, err1 := url.Parse(cardURL)
	i, err2 := url.Parse(iface)
	if err1 != nil || err2 != nil || c.Scheme != i.Scheme || c.Host != i.Host || c.User != nil {
		return "", false
	}
	a, err := netip.ParseAddr(c.Hostname())
	if err != nil || !a.Unmap().IsLoopback() {
		return "", false
	}
	return c.Scheme + "://" + c.Host, true
}

// simHandshake asks origin whether it is a PantherClaw a2a simulator
// (HR-221): GET /.well-known/pantherclaw-sim with a fresh nonce must
// answer that simulator, kind a2a, and the nonce.
func simHandshake(ctx context.Context, client *http.Client, origin string) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	nonce := hex.EncodeToString(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+handshake.Path+"?nonce="+nonce, nil)
	if err != nil {
		return err
	}
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var a handshake.Answer
	if resp.StatusCode != http.StatusOK || json.UnmarshalRead(io.LimitReader(resp.Body, 4096), &a) != nil ||
		a.Simulator != handshake.Simulator || a.Kind != "a2a" || a.Nonce != nonce {
		return errors.New("a2astore: not an a2a simulator")
	}
	return nil
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
	active, err := Get(ctx, q, org, conn, StateActive)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return "", err
	case origin(active.Config.GetInterface().GetUrl()) != origin(in.Interface.URL):
		// A re-pin keeps the peer: the base URL (and its simulator
		// handshake) stays the confirmed interface's origin (D96 L3).
		return "", ErrInterfaceOrigin
	}
	pinned, err := a.Pinner.Pin(ctx, ToProto(in), w.Simulated)
	if err != nil {
		return "", err
	}
	// A proposal: it serves once a person holding connection.manage
	// confirms it (D85, D92). The base URL is the interface URL that serves:
	// the confirmed one while there is one (D96 L3).
	if _, err := Propose(ctx, q, org, conn, pinned, w.UpdatedBy); err != nil {
		return "", err
	}
	if active.Config != nil {
		return active.Config.GetInterface().GetUrl(), nil
	}
	return in.Interface.URL, nil
}

// ErrInterfaceOrigin refuses a re-pin to another scheme, host or port: a
// new peer is a new connection.
var ErrInterfaceOrigin = pcerr.New(pcerr.FailedPrecondition, "A2A_INTERFACE_ORIGIN",
	"a re-pin keeps the interface's scheme, host and port; create another connection for another peer")

// origin is a URL's scheme, host and port, or "".
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Load returns the configuration a gateway serves (*pb.A2AConfig).
func (a *Adapter) Load(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID) (proto.Message, error) {
	p, err := Get(ctx, dbq.New(tx), org, conn, StateActive)
	if errors.Is(err, ErrNotFound) || (err == nil && p.DriftedAt != nil) {
		// Nothing confirmed, or the confirmed card drifted (D96 L1): the
		// gateway gets no configuration and refuses the connection
		// (KIND_CONFIG_MISSING) until a new pin is confirmed.
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

// DriftHook records a reported card drift on the connection's ACTIVE pin
// (ports.KindDrift, D86): the server calls it in the transaction that
// quarantines the connection. A report against a digest that is no longer
// the pinned one is stale and refused; a repeat is accepted.
type DriftHook struct{}

var _ ports.KindDrift = DriftHook{}

// ErrStaleDrift refuses a drift report about a pin that is no longer the
// connection's.
var ErrStaleDrift = pcerr.New(pcerr.FailedPrecondition, "A2A_DRIFT_STALE",
	"the reported digest is not the connection's pinned card")

// Drift implements ports.KindDrift: expected and observed are the pinned
// and the observed card digests in hex (or a word for an unreadable or
// invalid card).
func (DriftHook) Drift(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID, expected, observed string) error {
	pinned, err := hex.DecodeString(expected)
	if err != nil || len(pinned) != 32 {
		return ErrStaleDrift
	}
	q := dbq.New(tx)
	p, err := Get(ctx, q, org, conn, StateActive)
	if err != nil || !bytes.Equal(p.Config.GetCardDigest(), pinned) {
		return ErrStaleDrift
	}
	if p.DriftedAt != nil {
		return nil
	}
	obs, err := hex.DecodeString(observed)
	if err != nil || len(obs) != 32 {
		// Not a digest ("invalid", "unreadable", "signature"): recorded as
		// the digest of the word, so the pin still reads as drifted.
		sum := sha256.Sum256([]byte(observed))
		obs = sum[:]
	}
	_, err = MarkDrift(ctx, q, org, conn, pinned, obs)
	return err
}
