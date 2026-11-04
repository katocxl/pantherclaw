// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"strings"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/connections/sfmanifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// wireM31Snowflake registers the snowflake kind's configuration store (G0
// M31 D962): snowflake connections can then be created, their manifest
// proposed in the creating transaction, and gateways get the confirmed one
// with the connection.
func wireM31Snowflake(core *m14Core) {
	if core == nil {
		return
	}
	core.kinds.Register(capp.KindSnowflake, sfmanifest.Store{})
}

// manifestsByKind is the manifest confirm path for postgres and snowflake
// connections (G0 M31 D962a): a snowflake connection's manifest is read and
// confirmed by sfmanifest, everything else by pgmanifest, so the step-up
// is checked once, by the store of the connection's own kind. Until the
// console's snowflake page (M40), a snowflake manifest is shown in the
// postgres page's terms: the account host, database and schema, and the
// warehouse in the role's place.
type manifestsByKind struct {
	pg *pgmanifest.Service
	sf *sfmanifest.Service
}

// sfErrors are sfmanifest's errors as the page knows them.
var sfErrors = map[error]error{
	sfmanifest.ErrNotFound: pgmanifest.ErrNotFound, sfmanifest.ErrNothing: pgmanifest.ErrNothing,
	sfmanifest.ErrHuman: pgmanifest.ErrHuman, sfmanifest.ErrChanged: pgmanifest.ErrChanged,
}

func pageErr(err error) error {
	for from, to := range sfErrors {
		if errors.Is(err, from) {
			return to
		}
	}
	return err
}

func (m manifestsByKind) Get(ctx context.Context, id ids.UUID) (pgmanifest.Manifest, error) {
	if ok, err := m.sf.Serves(ctx, id); err != nil || !ok {
		if err != nil {
			return pgmanifest.Manifest{}, err
		}
		return m.pg.Get(ctx, id)
	}
	s, err := m.sf.Get(ctx, id)
	if err != nil {
		return pgmanifest.Manifest{}, pageErr(err)
	}
	return pgmanifest.Manifest{
		Connection: s.Connection, Name: s.Name, State: s.State, Current: pgView(s.Current), Proposed: pgView(s.Proposed),
		ProposedAt: s.ProposedAt, ConfirmedAt: s.ConfirmedAt, Widening: s.Widening, Digest: s.Digest,
	}, nil
}

func (m manifestsByKind) Confirm(ctx context.Context, id ids.UUID, digest string, su *stepup.StepUp) error {
	ok, err := m.sf.Serves(ctx, id)
	switch {
	case err != nil:
		return err
	case ok:
		return pageErr(m.sf.Confirm(ctx, id, digest, su))
	}
	return m.pg.Confirm(ctx, id, digest, su)
}

// pgView is a snowflake configuration in the postgres page's fields.
func pgView(c *capp.SnowflakeConfig) *capp.PostgresConfig {
	if c == nil {
		return nil
	}
	return &capp.PostgresConfig{
		Host: capp.SnowflakeHosts(c.Account)[0], Port: 443, Database: c.Database + "/" + c.Schema, User: "warehouse " + strings.ToUpper(c.Warehouse),
		SSLMode: "https", Tables: c.Tables, MaxRows: c.MaxRows, StatementTimeoutMs: c.StatementTimeoutMs,
		MaxResultBytes: c.MaxResultBytes, MinGroupSize: c.MinGroupSize,
	}
}
