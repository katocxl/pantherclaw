// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/connections/ports"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The M14 connection kinds (G0 M14 D4). Both are held by PantherClaw only:
// the gateway holds the credential and builds every request itself.
const (
	// KindPostgres is a Postgres database the gateway queries with
	// structured, read-only queries built from the reviewed manifest (D15).
	KindPostgres = "postgres"
	// KindA2A is a peer agent reached over the A2A protocol, its agent card
	// pinned (D30).
	KindA2A = "a2a"
)

// Postgres connection defaults and limits (D15).
const (
	DefaultPostgresPort           = 5432
	DefaultPostgresMaxRows        = 200
	MaxPostgresMaxRows            = 1000
	DefaultPostgresTimeoutMs      = 5000
	MaxPostgresTimeoutMs          = 30_000
	DefaultPostgresMaxResultBytes = 1 << 20
	MaxPostgresMaxResultBytes     = 4 << 20
	DefaultPostgresMinGroupSize   = 5
	MinPostgresMinGroupSize       = 2
	maxPostgresTables             = 64
	maxPostgresColumns            = 128
	maxPostgresCA                 = 16384
)

// A2A connection defaults and limits (D30).
const (
	DefaultA2AMaxAnswerBytes = 1 << 20
	MaxA2AMaxAnswerBytes     = 8 << 20
	DefaultA2AStreamSeconds  = 300
	MaxA2AStreamSeconds      = 3600
	maxA2ACard               = 256 << 10
	maxA2AKeys               = 64 << 10
	maxA2ASkills             = 64
	maxA2ASkill              = 128
	maxA2AScope              = 64 << 10
	maxA2AURL                = 2048
)

// Postgres sslmodes, column types and data classes (D15).
const (
	SSLVerifyFull = "verify-full"
	SSLRequire    = "require"
)

// PostgresTypes are the column types a manifest may name: no json, jsonb,
// bytea or arrays (D15).
var PostgresTypes = []string{"text", "int", "bigint", "numeric", "bool", "date", "timestamptz", "uuid"}

// DataClasses are the data classes of a column or answer field, from the
// most open to the most closed (D9, D15).
var DataClasses = []string{"public", "internal", "pii", "secret"}

// A2A interface protocols; gRPC is refused (D30).
const (
	A2AJSONRPC  = "JSONRPC"
	A2AHTTPJSON = "HTTP+JSON"
)

// Errors of the M14 kinds.
var (
	// ErrKindNotImplemented: the kind is defined, but this build cannot
	// serve it yet; nothing is created (fail closed, D4).
	ErrKindNotImplemented = pcerr.New(pcerr.FailedPrecondition, "KIND_NOT_IMPLEMENTED",
		"this kind of connection is not available yet")
	ErrPostgresConfig = pcerr.New(pcerr.InvalidArgument, "POSTGRES_CONFIG_INVALID",
		"a postgres connection needs a host, a database and user, sslmode verify-full (require only for an internal "+
			"database with a pinned CA), 1 to 64 tables of 1 to 128 typed, classified columns with lower-case names, "+
			"and limits in range")
	ErrA2AConfig = pcerr.New(pcerr.InvalidArgument, "A2A_CONFIG_INVALID",
		"an a2a connection needs an https agent card URL, a JSONRPC or HTTP+JSON interface, distinct skill ids, "+
			"a peer scope exactly when it names a peer agent, and limits in range")
	// ErrA2AKeyPrivate refuses card keys that carry private key material,
	// which a pin must never store. A stored pin holding such a key stays as
	// it is and cannot be saved again.
	ErrA2AKeyPrivate = pcerr.New(pcerr.InvalidArgument, "A2A_CARD_KEY_PRIVATE",
		"card keys must be public keys: remove the private members from the JWKS")
	// ErrA2ANotPinned: the connection has no pin to change.
	ErrA2ANotPinned = pcerr.New(pcerr.FailedPrecondition, "A2A_NOT_PINNED",
		"this a2a connection has no pin to change")
	// ErrA2AURLUnchanged: the public URL is already the one asked for, so
	// nothing is fetched, held or proposed.
	ErrA2AURLUnchanged = pcerr.New(pcerr.FailedPrecondition, "A2A_URL_UNCHANGED",
		"the public URL is already set to that value")
)

// identRE is a manifest identifier: lower case, never quoted (D15).
var identRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// PostgresConfig is a postgres connection's configuration and manifest.
// Zero limits take the defaults.
type PostgresConfig struct {
	Host     string          `json:"host"`
	Port     int32           `json:"port"`
	Database string          `json:"database"`
	User     string          `json:"user"`
	SSLMode  string          `json:"sslmode"`
	CAPEM    string          `json:"ca_pem,omitempty"`
	Internal bool            `json:"internal,omitempty"`
	Tables   []PostgresTable `json:"tables"`
	// MaxRows, StatementTimeoutMs, MaxResultBytes and MinGroupSize bound
	// every query.
	MaxRows            int32 `json:"max_rows"`
	StatementTimeoutMs int32 `json:"statement_timeout_ms"`
	MaxResultBytes     int32 `json:"max_result_bytes"`
	MinGroupSize       int32 `json:"min_group_size"`
}

// PostgresTable is one manifest table.
type PostgresTable struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	// ScopeKey and ScopeColumn name the record scope the table answers to
	// (D20); both or neither.
	ScopeKey    string           `json:"scope_key,omitempty"`
	ScopeColumn string           `json:"scope_column,omitempty"`
	MaxRows     int32            `json:"max_rows,omitempty"`
	Columns     []PostgresColumn `json:"columns"`
}

// PostgresColumn is one manifest column.
type PostgresColumn struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

// Check checks a postgres configuration and fills its defaults. It does
// not reach the database: the connection test does (D18).
func (c PostgresConfig) Check() (PostgresConfig, error) {
	c.Port = orDefault(c.Port, DefaultPostgresPort)
	c.MaxRows = orDefault(c.MaxRows, DefaultPostgresMaxRows)
	c.StatementTimeoutMs = orDefault(c.StatementTimeoutMs, DefaultPostgresTimeoutMs)
	c.MaxResultBytes = orDefault(c.MaxResultBytes, DefaultPostgresMaxResultBytes)
	c.MinGroupSize = orDefault(c.MinGroupSize, DefaultPostgresMinGroupSize)
	switch {
	case !validHost(c.Host), c.Port < 1 || c.Port > 65535,
		!identRE.MatchString(c.Database), !identRE.MatchString(c.User),
		c.MaxRows < 1 || c.MaxRows > MaxPostgresMaxRows,
		c.StatementTimeoutMs < 1 || c.StatementTimeoutMs > MaxPostgresTimeoutMs,
		c.MaxResultBytes < 1024 || c.MaxResultBytes > MaxPostgresMaxResultBytes,
		c.MinGroupSize < MinPostgresMinGroupSize,
		len(c.Tables) == 0 || len(c.Tables) > maxPostgresTables,
		len(c.CAPEM) > maxPostgresCA:
		return PostgresConfig{}, ErrPostgresConfig
	}
	switch c.SSLMode {
	case SSLVerifyFull:
	case SSLRequire:
		// Without hostname checks, only a pinned CA on a private network.
		if !c.Internal || c.CAPEM == "" {
			return PostgresConfig{}, ErrPostgresConfig
		}
	default:
		return PostgresConfig{}, ErrPostgresConfig
	}
	if c.CAPEM != "" && !validCA(c.CAPEM) {
		return PostgresConfig{}, ErrPostgresConfig
	}
	if a, err := netip.ParseAddr(strings.Trim(c.Host, "[]")); err == nil && !c.Internal && !publicAddr(a) {
		// A private address only with internal (set with a step-up).
		return PostgresConfig{}, ErrPostgresConfig
	}
	tables := make([]PostgresTable, len(c.Tables))
	seen := map[string]bool{}
	for i, t := range c.Tables {
		key := t.Schema + "." + t.Name
		if !identRE.MatchString(t.Schema) || !identRE.MatchString(t.Name) || seen[key] ||
			t.MaxRows < 0 || t.MaxRows > MaxPostgresMaxRows ||
			len(t.Columns) == 0 || len(t.Columns) > maxPostgresColumns ||
			(t.ScopeKey == "") != (t.ScopeColumn == "") ||
			(t.ScopeKey != "" && !identRE.MatchString(t.ScopeKey)) {
			return PostgresConfig{}, ErrPostgresConfig
		}
		seen[key] = true
		cols := map[string]bool{}
		for _, col := range t.Columns {
			if !identRE.MatchString(col.Name) || cols[col.Name] ||
				!slices.Contains(PostgresTypes, col.Type) || !slices.Contains(DataClasses, col.Class) {
				return PostgresConfig{}, ErrPostgresConfig
			}
			cols[col.Name] = true
		}
		if t.ScopeColumn != "" && !cols[t.ScopeColumn] {
			return PostgresConfig{}, ErrPostgresConfig
		}
		t.Columns = slices.Clone(t.Columns)
		tables[i] = t
	}
	c.Tables = tables
	return c, nil
}

// A2AConfig is an a2a connection's configuration. Zero limits take the
// defaults. CardDigest is set by the server, never taken from a caller.
type A2AConfig struct {
	CardURL    string        `json:"card_url"`
	PinnedCard []byte        `json:"pinned_card,omitempty"`
	CardDigest []byte        `json:"card_digest,omitempty"`
	Interface  A2AInterface  `json:"interface"`
	CardKeys   []byte        `json:"card_keys,omitempty"`
	Skills     []string      `json:"skills,omitempty"`
	PeerAgent  *ids.UUID     `json:"peer_agent_id,omitempty"`
	PeerScope  *A2APeerScope `json:"peer_scope,omitempty"`
	// MaxAnswerBytes and MaxStreamSeconds cap what is relayed (D31).
	MaxAnswerBytes   int32 `json:"max_answer_bytes"`
	MaxStreamSeconds int32 `json:"max_stream_seconds"`
	// PublicURL is the only URL the server signs this connection's card for
	// (G0 M24 D247); empty leaves the card unsigned.
	PublicURL string `json:"public_url,omitempty"`
}

// A2AInterface is the card interface the gateway calls.
type A2AInterface struct {
	Protocol string `json:"protocol"`
	URL      string `json:"url"`
}

// A2APeerScope bounds what a peer agent may do for a requester (D33):
// grant bounds and limits documents.
type A2APeerScope struct {
	Bounds []byte `json:"bounds"`
	Limits []byte `json:"limits,omitempty"`
}

// A2A pin states, as a read shows them.
const (
	A2APinProposed = "PROPOSED"
	A2APinActive   = "ACTIVE"
	A2APinDrifted  = "DRIFTED"
)

// A2AStatus is what a read shows of an a2a connection's pin; the public URL
// may not be serving yet. The card and its keys stay out of it.
type A2AStatus struct {
	PublicURL, PinState string
}

// jwkPrivateMembers are the JWK members that hold private or symmetric key
// material (RFC 7518 section 6).
var jwkPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// hasPrivateKey reports a JWKS with private key material in any of its keys.
// A document that is no JWKS is left to the card key check at the pin.
func hasPrivateKey(jwks []byte) bool {
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if json.Unmarshal(jwks, &set) != nil {
		return false
	}
	return slices.ContainsFunc(set.Keys, func(key map[string]any) bool {
		return slices.ContainsFunc(jwkPrivateMembers, func(m string) bool {
			_, ok := key[m]
			return ok
		})
	})
}

// Check checks an a2a configuration and fills its defaults. simulated
// allows http on a loopback or private address literal (a simulator,
// HR-221); otherwise both URLs are https. What depends on the card itself
// (the interface and skills it declares, its signatures) is checked when
// the card is fetched and pinned (D30).
func (c A2AConfig) Check(simulated bool) (A2AConfig, error) {
	c.MaxAnswerBytes = orDefault(c.MaxAnswerBytes, DefaultA2AMaxAnswerBytes)
	c.MaxStreamSeconds = orDefault(c.MaxStreamSeconds, DefaultA2AStreamSeconds)
	c.CardDigest = nil
	switch {
	case !a2aURL(c.CardURL, simulated), !a2aURL(c.Interface.URL, simulated),
		c.PublicURL != "" && !a2aURL(c.PublicURL, simulated),
		c.Interface.Protocol != A2AJSONRPC && c.Interface.Protocol != A2AHTTPJSON,
		len(c.PinnedCard) > maxA2ACard, len(c.PinnedCard) > 0 && !jsonObject(c.PinnedCard),
		len(c.CardKeys) > maxA2AKeys, len(c.CardKeys) > 0 && !jsonObject(c.CardKeys),
		len(c.Skills) > maxA2ASkills,
		c.MaxAnswerBytes < 1024 || c.MaxAnswerBytes > MaxA2AMaxAnswerBytes,
		c.MaxStreamSeconds < 1 || c.MaxStreamSeconds > MaxA2AStreamSeconds,
		(c.PeerAgent == nil) != (c.PeerScope == nil):
		return A2AConfig{}, ErrA2AConfig
	}
	if hasPrivateKey(c.CardKeys) {
		return A2AConfig{}, ErrA2AKeyPrivate
	}
	for i, s := range c.Skills {
		if s == "" || len(s) > maxA2ASkill || strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) ||
			slices.Contains(c.Skills[:i], s) {
			return A2AConfig{}, ErrA2AConfig
		}
	}
	if c.PeerScope != nil {
		p := c.PeerScope
		if len(p.Bounds) < 2 || len(p.Bounds) > maxA2AScope || !jsonObject(p.Bounds) ||
			len(p.Limits) > maxA2AScope || (len(p.Limits) > 0 && !jsonObject(p.Limits)) {
			return A2AConfig{}, ErrA2AConfig
		}
	}
	c.Skills = slices.Clone(c.Skills)
	return c, nil
}

// a2aURL is an https URL with a host and no credentials, or, for a
// simulated connection, http on a loopback or private address literal.
func a2aURL(raw string, simulated bool) bool {
	if raw == "" || len(raw) > maxA2AURL {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		a, err := netip.ParseAddr(u.Hostname())
		return simulated && err == nil && !publicAddr(a)
	}
	return false
}

// jsonObject reports whether b is one JSON object.
func jsonObject(b []byte) bool {
	var m map[string]any
	return json.Unmarshal(b, &m) == nil && m != nil
}

// validHost is a DNS name or an address literal.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return true
	}
	return hostRE.MatchString(h)
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validCA is one or more PEM certificates and nothing else.
func validCA(s string) bool {
	rest := []byte(s)
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return false
		}
		n++
	}
	return n > 0 && strings.TrimSpace(string(rest)) == ""
}

// publicAddr reports whether a is a public address: one the egress
// classifier lets clients reach without an allowed prefix (HR-071), so
// configuration time and dial time agree (G0 M14 D61).
func publicAddr(a netip.Addr) bool { return !httpx.DeniedAddr(a, nil) }

// WithKindConfigs sets the stores of the M14 kinds' configurations
// (G0 M14 D64): a postgres or a2a connection can be created only when its
// kind has one, and its configuration is saved in the same transaction.
func (s *Service) WithKindConfigs(k *ports.KindConfigs) *Service {
	s.kinds = k
	return s
}

// SetA2APublicURL changes only an a2a connection's public URL, at the revision
// the caller read: a weakening update like any change of its configuration,
// saved as a new proposal that serves once a person confirms it. Empty leaves
// the card unsigned. The save reads the peer's card again, so the proposal pins
// the card as read now. The URL already set is refused before any of that.
func (s *Service) SetA2APublicURL(ctx context.Context, id ids.UUID, publicURL string, revision int32) (Connection, error) {
	return s.Update(ctx, UpdateInput{ID: id, Revision: revision, A2APublicURL: &publicURL})
}

// currentA2A is the a2a configuration an edit starts from and its pin state:
// nil without a pin.
func (s *Service) currentA2A(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID) (*A2AConfig, string, error) {
	store, ok := s.kinds.Get(KindA2A)
	if !ok {
		return nil, "", ErrKindNotImplemented
	}
	pinned, ok := store.(ports.KindPinned)
	if !ok {
		return nil, "", ErrKindNotImplemented
	}
	cfg, state, err := pinned.CurrentPin(ctx, tx, org, conn)
	if err != nil {
		return nil, "", err
	}
	peer, _ := cfg.(*A2AConfig)
	return peer, state, nil
}

// a2aStatus is what a read shows of conn's pin: nil for another kind, without
// a pin, or without a store that can tell.
func (s *Service) a2aStatus(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn dbq.PcConnection) (*A2AStatus, error) {
	if conn.Kind != KindA2A {
		return nil, nil
	}
	peer, state, err := s.currentA2A(ctx, tx, org, conn.ID)
	if errors.Is(err, ErrKindNotImplemented) {
		return nil, nil
	}
	if err != nil || peer == nil {
		return nil, err
	}
	return &A2AStatus{PublicURL: peer.PublicURL, PinState: state}, nil
}

// kindConfig is a validated M14 configuration and the store it goes to.
type kindConfig struct {
	cfg   any
	store ports.KindConfig
}

// checkM14Kind checks a new connection's M14 configuration: a postgres or
// a2a connection carries its own configuration and is held by PantherClaw;
// no other kind carries one. A kind whose configuration store is not
// registered is refused with ErrKindNotImplemented and nothing is created
// (G0 M14 D4, D64: fail closed). It returns nil for the other kinds.
func (s *Service) checkM14Kind(in *CreateInput) (*kindConfig, error) {
	if in.Kind != KindPostgres && in.Kind != KindA2A && in.Kind != KindModel && in.Kind != KindVectorstore {
		if in.Postgres != nil || in.A2A != nil || in.Model != nil || in.Vectorstore != nil {
			return nil, ErrShape
		}
		return nil, nil
	}
	cfg, err := checkKindConfig(in.Kind, in.Simulated, in.Postgres, in.A2A, in.Model, in.Vectorstore)
	if err != nil {
		return nil, err
	}
	if in.AccessMode != AccessHeld {
		return nil, ErrShape
	}
	store, ok := s.kinds.Get(in.Kind)
	if !ok {
		return nil, ErrKindNotImplemented
	}
	return &kindConfig{cfg: cfg, store: store}, nil
}

// checkKindConfig validates the configuration a kind carries: exactly its
// own, checked and with its defaults.
func checkKindConfig(kind string, simulated bool, pg *PostgresConfig, peer *A2AConfig, model *ModelConfig, vs *VectorstoreConfig) (any, error) {
	if vs != nil && kind != KindVectorstore {
		return nil, ErrShape
	}
	switch kind {
	case KindVectorstore:
		// G0 M30 D922, D925a.
		if vs == nil || pg != nil || peer != nil || model != nil {
			return nil, ErrShape
		}
		cfg, err := vs.Check()
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	case KindModel:
		// G0 M29 D811.
		if model == nil || pg != nil || peer != nil {
			return nil, ErrShape
		}
		cfg, err := model.Check()
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	case KindPostgres:
		if pg == nil || peer != nil || model != nil {
			return nil, ErrShape
		}
		cfg, err := pg.Check()
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	case KindA2A:
		if peer == nil || pg != nil || model != nil {
			return nil, ErrShape
		}
		cfg, err := peer.Check(simulated)
		if err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	return nil, ErrShape
}

// m14Shape is the base URL and hosts of an M14 kind (D64): a postgres
// connection has none (its host is in its manifest, and its password
// goes in no header); an a2a connection's base URL is its interface URL,
// and its credential, when the card's security scheme needs one, goes in a
// header like an http connection's.
func (s *Service) m14Shape(kind string, simulated bool, in *CreateInput) (*string, []string, error) {
	switch kind {
	case KindModel:
		return s.modelShape(in.BaseURL, in.AllowedHosts, simulated, in.CredentialScheme, in.CredentialHeader)
	case KindPostgres, KindVectorstore:
		// A vectorstore connection's host is in its settings and its
		// password goes in no header, as a postgres connection's (G0 M30
		// D925a).
		if in.BaseURL != "" || len(in.AllowedHosts) > 0 || in.CredentialHeader != "" || in.CredentialScheme != "" || len(in.AgentHosts) > 0 {
			return nil, nil, ErrShape
		}
		return nil, []string{}, nil
	case KindA2A:
		if in.BaseURL != "" && in.BaseURL != in.A2A.Interface.URL {
			return nil, nil, ErrShape
		}
		if len(in.AgentHosts) > 0 || (in.CredentialScheme != "" && in.CredentialHeader == "") {
			return nil, nil, ErrShape
		}
		norm, ep, err := checkBaseURL(in.A2A.Interface.URL, s.own)
		if err != nil {
			return nil, nil, err
		}
		hosts, err := checkAllowedHosts(in.AllowedHosts, ep, norm, s.own)
		if err != nil {
			return nil, nil, err
		}
		if simulated {
			if err := checkSimulated(&norm, hosts); err != nil {
				return nil, nil, err
			}
		}
		return &norm, hosts, nil
	}
	return nil, nil, ErrShape
}

// checkKindGateway asks the store of a postgres or a2a connection's kind to
// validate the configuration for the gateway it moves to, in the move's
// transaction (G0 M14 D105, D115): without a store the kind is not
// implemented, and a store without a gateway check cannot validate the
// move, so it is refused too (fail closed). Other kinds are not asked.
func (s *Service) checkKindGateway(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn dbq.PcConnection, gateway ids.UUID) error {
	if conn.Kind != KindPostgres && conn.Kind != KindA2A && conn.Kind != KindVectorstore {
		return nil // a model connection may move: its settings depend on no gateway (G0 M29 D811)
	}
	store, ok := s.kinds.Get(conn.Kind)
	if !ok {
		return ErrKindNotImplemented
	}
	check, ok := store.(ports.KindGatewayCheck)
	if !ok {
		return ErrKindGatewayUnchecked
	}
	return check.CheckGateway(ctx, tx, org, conn.ID, gateway)
}

// ErrKindGatewayUnchecked: the kind's store cannot validate a move to
// another gateway, so the connection stays where it is (D115).
var ErrKindGatewayUnchecked = pcerr.New(pcerr.FailedPrecondition, "KIND_GATEWAY_UNCHECKED",
	"this kind of connection cannot be moved to another gateway in this build")
