// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"net/url"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// KindSnowflake is a Snowflake account the gateway reads over the
// Snowflake SQL API with statements it builds itself from the reviewed
// manifest, as for postgres (G0 M31 D962): backed only by pc.snowflake,
// held by PantherClaw only, its credential a snowflake_keypair from which
// the gateway signs a key-pair JWT per call (HR-726).
const KindSnowflake = "snowflake"

// SnowflakePackage is the package that backs snowflake connections, and
// backs nothing else (D962).
const SnowflakePackage = "pc.snowflake"

// Snowflake connection defaults and limits (D962): the SQL API's statement
// timeout is at most 60 s.
const (
	DefaultSnowflakeTimeoutMs = 30_000
	MaxSnowflakeTimeoutMs     = 60_000
)

// Errors of the snowflake kind.
var (
	ErrSnowflakeConfig = pcerr.New(pcerr.InvalidArgument, "SNOWFLAKE_CONFIG_INVALID",
		"a snowflake connection needs an account identifier, a lower-case warehouse, database and schema, an https base URL "+
			"on the account's host (ACCOUNT.snowflakecomputing.com or ACCOUNT.privatelink.snowflakecomputing.com), the "+
			"credential in Authorization: Bearer, 1 to 64 tables of 1 to 128 typed, classified columns with lower-case "+
			"names, and limits in range (statement timeout at most 60000 ms)")
	// ErrSnowflakeEndpointImmutable: the account, warehouse, database and
	// schema are fixed once the connection exists.
	ErrSnowflakeEndpointImmutable = pcerr.New(pcerr.FailedPrecondition, "SNOWFLAKE_ENDPOINT_IMMUTABLE",
		"a snowflake connection's account, warehouse, database and schema cannot change: create a new connection")
)

var snowflakeAccountRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}(\.[A-Za-z0-9_-]{1,64}){0,2}$`)

// SnowflakeConfig is a snowflake connection's configuration and manifest
// (D962). Zero limits take the defaults. The tables are a postgres
// manifest's: lower-case identifiers, typed and classified columns.
type SnowflakeConfig struct {
	Account   string          `json:"account"`
	Warehouse string          `json:"warehouse"`
	Database  string          `json:"database"`
	Schema    string          `json:"schema"`
	Tables    []PostgresTable `json:"tables"`
	// MaxRows, StatementTimeoutMs, MaxResultBytes and MinGroupSize bound
	// every query.
	MaxRows            int32 `json:"max_rows"`
	StatementTimeoutMs int32 `json:"statement_timeout_ms"`
	MaxResultBytes     int32 `json:"max_result_bytes"`
	MinGroupSize       int32 `json:"min_group_size"`
}

// Check checks a snowflake configuration and fills its defaults: the
// manifest exactly as a postgres manifest is checked. It does not reach
// Snowflake.
func (c SnowflakeConfig) Check() (SnowflakeConfig, error) {
	c.StatementTimeoutMs = orDefault(c.StatementTimeoutMs, DefaultSnowflakeTimeoutMs)
	if !snowflakeAccountRE.MatchString(c.Account) || !identRE.MatchString(c.Warehouse) || !identRE.MatchString(c.Database) ||
		!identRE.MatchString(c.Schema) || c.StatementTimeoutMs < 1 || c.StatementTimeoutMs > MaxSnowflakeTimeoutMs {
		return SnowflakeConfig{}, ErrSnowflakeConfig
	}
	// The manifest and the other limits are checked as a postgres one's; the
	// endpoint fields there are placeholders that pass.
	pg, err := PostgresConfig{
		Host: "snowflake.invalid", Database: c.Database, User: c.Warehouse, SSLMode: SSLVerifyFull, Tables: c.Tables,
		MaxRows: c.MaxRows, StatementTimeoutMs: 1, MaxResultBytes: c.MaxResultBytes, MinGroupSize: c.MinGroupSize,
	}.Check()
	if err != nil {
		return SnowflakeConfig{}, ErrSnowflakeConfig
	}
	c.Tables, c.MaxRows, c.MaxResultBytes, c.MinGroupSize = pg.Tables, pg.MaxRows, pg.MaxResultBytes, pg.MinGroupSize
	return c, nil
}

// SameEndpoint reports whether two configurations name the same account,
// warehouse, database and schema (D962).
func (c SnowflakeConfig) SameEndpoint(o SnowflakeConfig) bool {
	return c.Account == o.Account && c.Warehouse == o.Warehouse && c.Database == o.Database && c.Schema == o.Schema
}

// SnowflakeHosts are the hosts an account's base URL may name: its own,
// or its private link host, lower case.
func SnowflakeHosts(account string) []string {
	a := strings.ToLower(account)
	return []string{a + ".snowflakecomputing.com", a + ".privatelink.snowflakecomputing.com"}
}

// checkSnowflakeCreate checks what a snowflake connection's creation needs
// before the defaults apply (D962): pc.snowflake, held access, its
// configuration. Another kind never uses pc.snowflake.
func checkSnowflakeCreate(in *CreateInput) error {
	switch {
	case (in.Package == SnowflakePackage) != (in.Kind == KindSnowflake):
		return ErrShape
	case in.Kind != KindSnowflake:
		if in.Snowflake != nil {
			return ErrShape
		}
		return nil
	case in.Snowflake == nil, in.AccessMode != AccessHeld, in.ModelRelay:
		return ErrShape
	}
	if in.CredentialHeader == "" && in.CredentialScheme == "" {
		in.CredentialHeader, in.CredentialScheme = "Authorization", "Bearer"
	}
	return nil
}

// snowflakeShape is a snowflake connection's base URL and hosts (D962): an
// https URL with no path on the account's host (a loopback or private
// literal over http when simulated), the credential in Authorization:
// Bearer and sent to that host only, and no agent hosts (its reads are
// served natively, as a postgres connection's).
func (s *Service) snowflakeShape(simulated bool, in *CreateInput) (*string, []string, error) {
	if in.Snowflake == nil || in.CredentialHeader != "Authorization" || in.CredentialScheme != "Bearer" || len(in.AgentHosts) > 0 {
		return nil, nil, ErrShape
	}
	norm, ep, err := checkBaseURL(in.BaseURL, s.own)
	if err != nil {
		return nil, nil, err
	}
	u, _ := url.Parse(norm)
	if u == nil || (u.Path != "" && u.Path != "/") {
		return nil, nil, ErrSnowflakeConfig
	}
	if !simulated {
		host := strings.ToLower(u.Hostname())
		if u.Scheme != "https" || u.Port() != "" || (host != SnowflakeHosts(in.Snowflake.Account)[0] && host != SnowflakeHosts(in.Snowflake.Account)[1]) {
			return nil, nil, ErrSnowflakeConfig
		}
	}
	hosts, err := checkAllowedHosts(nil, ep, norm, s.own)
	if err != nil {
		return nil, nil, err
	}
	if len(in.AllowedHosts) > 0 && (len(in.AllowedHosts) != len(hosts) || in.AllowedHosts[0] != hosts[0]) {
		return nil, nil, ErrShape
	}
	if simulated {
		if err := checkSimulated(&norm, hosts); err != nil {
			return nil, nil, err
		}
	}
	return &norm, hosts, nil
}

// loadSnowflake reads a snowflake connection's configuration as a read
// shows it: the one serving, else the one proposed; nil for another kind.
func loadSnowflake(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection) (*SnowflakeConfig, error) {
	if conn.Kind != KindSnowflake {
		return nil, nil
	}
	row, err := q.GetSnowflakeConnection(ctx, conn.OrgID, conn.ID)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	raw := row.Config
	if raw == nil {
		raw = row.Proposed
	}
	return DecodeSnowflake(raw)
}

// DecodeSnowflake decodes a stored snowflake configuration; nil for none.
func DecodeSnowflake(raw []byte) (*SnowflakeConfig, error) {
	if raw == nil {
		return nil, nil
	}
	var c SnowflakeConfig
	if err := json.Unmarshal(raw, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	return &c, nil
}
