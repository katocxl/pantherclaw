// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// KindMCPContainer is a third-party stdio MCP server that a customer-hosted
// gateway runs in a hardened container (G0 M9 track C; HR-084, HR-216).
// It has no base URL and holds no credential: its egress goes through an
// edge to the gateway, which places the egress connection's credential.
const KindMCPContainer = "mcp_container"

// Connector defaults and limits (00093).
const (
	DefaultConnectorMemoryMiB = 512
	DefaultConnectorMilliCPUs = 1000
	DefaultConnectorPIDs      = 256
	maxConnectorEnv           = 64
	maxConnectorPlaceholders  = 16
	maxConnectorArgs          = 32
	maxConnectorValue         = 1024
	// maxConnectorEnvBytes is 00093's bound on the environment as the
	// database writes it out (jsonb text, a space after each colon and
	// comma).
	maxConnectorEnvBytes = 65536
)

// Connector errors.
var (
	ErrConnector = pcerr.New(pcerr.InvalidArgument, "CONNECTOR_INVALID",
		"a connector needs an image pinned by digest, a command of 1 to 32 arguments, non-secret environment values, "+
			"limits in range, and egress only through an active http connection of the same gateway")
	ErrHostedGateway = pcerr.New(pcerr.FailedPrecondition, "CONNECTOR_ON_HOSTED_GATEWAY",
		"connectors run only on customer-hosted gateways (HR-084)")
)

// ConnectorSpec is a connector's container. Zero limits take the defaults.
type ConnectorSpec struct {
	// Image is pinned by digest: repo@sha256:<hex>, or a local image id.
	Image string
	// Command is the program and its arguments, run as given.
	Command []string
	// Environment holds non-secret values only.
	Environment map[string]string
	// CredentialPlaceholders are names the gateway sets to a placeholder;
	// the credential is placed on the mediated egress (design decision 18).
	CredentialPlaceholders []string
	// EgressConnection is the http connection that mediates its egress;
	// nil means no egress at all.
	EgressConnection           *ids.UUID
	MemoryMiB, MilliCPUs, PIDs int32
}

var (
	connectorImageRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._/:-]{0,254}@)?sha256:[0-9a-f]{64}$`)
	connectorEnvRE   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	// secretPrefixes are the well-known prefixes of credentials, which an
	// environment value may never carry (HR-061, HR-216).
	secretPrefixes = []string{
		"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "sk_live_", "sk_test_", "rk_live_", "rk_test_", "sk-", "xoxb-", "xoxp-",
		"xapp-", "npm_", "AIza", "AKIA", "ASIA", "eyJ", "-----BEGIN",
	}
)

// check checks a spec and fills its defaults.
func (c ConnectorSpec) check() (ConnectorSpec, error) {
	c.MemoryMiB = orDefault(c.MemoryMiB, DefaultConnectorMemoryMiB)
	c.MilliCPUs = orDefault(c.MilliCPUs, DefaultConnectorMilliCPUs)
	c.PIDs = orDefault(c.PIDs, DefaultConnectorPIDs)
	switch {
	case !connectorImageRE.MatchString(c.Image),
		len(c.Command) == 0 || len(c.Command) > maxConnectorArgs,
		len(c.Environment) > maxConnectorEnv || len(c.CredentialPlaceholders) > maxConnectorPlaceholders,
		c.MemoryMiB < 64 || c.MemoryMiB > 8192 || c.MilliCPUs < 100 || c.MilliCPUs > 8000 || c.PIDs < 32 || c.PIDs > 4096:
		return ConnectorSpec{}, ErrConnector
	}
	for _, a := range c.Command {
		if a == "" || len(a) > maxConnectorValue || strings.ContainsRune(a, 0) || secretLike(a) {
			return ConnectorSpec{}, ErrConnector
		}
	}
	for name, v := range c.Environment {
		if !connectorEnvRE.MatchString(name) || len(v) > maxConnectorValue || strings.ContainsAny(v, "\x00\r\n") || secretLike(v) {
			return ConnectorSpec{}, ErrConnector
		}
	}
	if b, err := json.Marshal(c.Environment); err != nil || len(b)+2*len(c.Environment) > maxConnectorEnvBytes {
		return ConnectorSpec{}, ErrConnector
	}
	for i, name := range c.CredentialPlaceholders {
		if _, literal := c.Environment[name]; literal || !connectorEnvRE.MatchString(name) || slices.Contains(c.CredentialPlaceholders[:i], name) {
			return ConnectorSpec{}, ErrConnector
		}
	}
	c.Command = slices.Clone(c.Command)
	c.Environment = maps.Clone(c.Environment)
	c.CredentialPlaceholders = slices.Clone(c.CredentialPlaceholders)
	return c, nil
}

// secretLike reports a value with a token that starts like a credential.
func secretLike(v string) bool {
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune(" \t=:,;\"'", r) }) {
		for _, p := range secretPrefixes {
			if strings.HasPrefix(tok, p) {
				return true
			}
		}
	}
	return false
}

// WithPantherClawHosted names the gateways PantherClaw hosts. It comes from
// the server's configuration only, never from a tenant or a gateway; no
// connector is created on, moved to or delivered to them (HR-084).
func (s *Service) WithPantherClawHosted(gateways []ids.UUID) *Service {
	s.hosted = map[ids.UUID]bool{}
	for _, g := range gateways {
		s.hosted[g] = true
	}
	return s
}

// PantherClawHosted reports whether the server's configuration names a
// gateway as PantherClaw-hosted (the fallback list, kept for one release,
// G0 M19 D203).
func (s *Service) PantherClawHosted(gateway ids.UUID) bool { return s.hosted[gateway] }

// hostedIn reports, in the caller's transaction, whether PantherClaw hosts
// a gateway: the configured list, or a hosted gateway record that names it
// (migration 00229, G0 M19 D203), whatever its state (HR-084).
func (s *Service) hostedIn(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateway ids.UUID) (bool, error) {
	if s.hosted[gateway] {
		return true, nil
	}
	return q.IsHostedGateway(ctx, org, gateway)
}

// putConnector stores a connector connection's spec at the connection's
// revision, after checking its egress connection: an active http
// connection of the same org and gateway.
func putConnector(ctx context.Context, q *dbq.Queries, c actor, conn dbq.PcConnection, spec ConnectorSpec) (dbq.PcConnectorSpec, error) {
	if e := spec.EgressConnection; e != nil {
		egress, err := q.GetConnection(ctx, c.Org, *e)
		if db.IsNoRows(err) {
			return dbq.PcConnectorSpec{}, ErrConnector
		} else if err != nil {
			return dbq.PcConnectorSpec{}, err
		}
		if egress.Kind != KindHTTP || egress.State != StateActive || egress.GatewayID != conn.GatewayID || egress.ID == conn.ID {
			return dbq.PcConnectorSpec{}, ErrConnector
		}
	}
	env, err := json.Marshal(spec.Environment)
	if err != nil {
		return dbq.PcConnectorSpec{}, err
	}
	if spec.Environment == nil {
		env = []byte("{}")
	}
	return q.InsertConnectorSpec(ctx, dbq.InsertConnectorSpecParams{
		OrgID: c.Org, ConnectionID: conn.ID, Revision: conn.Revision, Image: spec.Image, Command: spec.Command,
		Environment: env, CredentialPlaceholders: orEmpty(spec.CredentialPlaceholders), EgressConnectionID: spec.EgressConnection,
		MemoryMib: spec.MemoryMiB, MilliCpus: spec.MilliCPUs, Pids: spec.PIDs, CreatedBy: c.By,
	})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// connectorSummary is how a spec appears in a change's old and new values
// (specView).
func connectorSummary(s *dbq.PcConnectorSpec) string {
	if s == nil {
		return ""
	}
	var env map[string]string
	_ = json.Unmarshal(s.Environment, &env)
	return specView(ConnectorSpec{
		Image: s.Image, Command: s.Command, Environment: env, CredentialPlaceholders: s.CredentialPlaceholders,
		EgressConnection: s.EgressConnectionID, MemoryMiB: s.MemoryMib, MilliCPUs: s.MilliCpus, PIDs: s.Pids,
	})
}

// specView is how a spec appears in a change's old and new values: what it
// runs and may reach, the names of its environment, placeholders and its
// limits, and the SHA-256 of the whole spec, values included, so that any
// change to it (NODE_OPTIONS or LD_PRELOAD change what runs as much as the
// command does) is a weakening change whose audit shows it. An
// environment value never appears (HR-183).
func specView(s ConnectorSpec) string {
	if s.Environment == nil {
		s.Environment = map[string]string{}
	}
	e := ""
	if s.EgressConnection != nil {
		e = s.EgressConnection.String()
	}
	canon, _ := json.Marshal(struct {
		Image        string            `json:"image"`
		Command      []string          `json:"command"`
		Environment  map[string]string `json:"environment"`
		Placeholders []string          `json:"placeholders"`
		Egress       string            `json:"egress"`
		Limits       [3]int32          `json:"limits"`
	}{s.Image, s.Command, s.Environment, slices.Sorted(slices.Values(s.CredentialPlaceholders)), e, [3]int32{s.MemoryMiB, s.MilliCPUs, s.PIDs}},
		json.Deterministic(true))
	sum := sha256.Sum256(canon)
	return fmt.Sprintf("%s %s egress=%s env=%s placeholders=%s limits=%d/%d/%d sha256=%x", s.Image, strings.Join(s.Command, " "), e,
		strings.Join(slices.Sorted(maps.Keys(s.Environment)), ","), strings.Join(slices.Sorted(slices.Values(s.CredentialPlaceholders)), ","),
		s.MemoryMiB, s.MilliCPUs, s.PIDs, sum)
}
