// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
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
		"github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "glpat-", "sk_live_", "sk-", "xoxb-", "xoxp-", "AKIA", "-----BEGIN",
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
		if a == "" || len(a) > maxConnectorValue || strings.ContainsRune(a, 0) {
			return ConnectorSpec{}, ErrConnector
		}
	}
	for name, v := range c.Environment {
		if !connectorEnvRE.MatchString(name) || len(v) > maxConnectorValue || strings.ContainsAny(v, "\x00\r\n") || secretLike(v) {
			return ConnectorSpec{}, ErrConnector
		}
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

// PantherClawHosted reports whether PantherClaw hosts a gateway.
func (s *Service) PantherClawHosted(gateway ids.UUID) bool { return s.hosted[gateway] }

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

// connectorSummary is how a spec appears in a change's old and new values:
// its image, command and egress connection, never its environment.
func connectorSummary(s *dbq.PcConnectorSpec) string {
	if s == nil {
		return ""
	}
	return summary(s.Image, s.Command, s.EgressConnectionID)
}

func specSummary(s ConnectorSpec) string { return summary(s.Image, s.Command, s.EgressConnection) }

func summary(image string, command []string, egress *ids.UUID) string {
	e := ""
	if egress != nil {
		e = egress.String()
	}
	return image + " " + strings.Join(command, " ") + " egress=" + e
}
