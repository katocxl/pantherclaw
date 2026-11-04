// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// KindVectorstore is a pgvector retrieval index the gateway reads and
// writes with statements it builds itself (G0 M30 D922): backed only by
// pc.vectorstore, held by PantherClaw only, with no base URL. Each record
// carries the run, agent and transaction that wrote it, from the permit
// (HR-704), and a write by an agent not on the writer list is held for a
// person (HR-705).
const KindVectorstore = "vectorstore"

// VectorstorePackage is the package that backs vectorstore connections,
// and backs nothing else (D922).
const VectorstorePackage = "pc.vectorstore"

// Vectorstore limits (D922, D924, D925).
const (
	MaxVectorstoreDimensions = 16000
	maxVectorstoreWriters    = 64
)

// Distance metrics of a vectorstore table (D923).
var VectorstoreDistances = []string{"cosine", "l2", "inner_product"}

// Errors of the vectorstore kind.
var (
	ErrVectorstoreConfig = pcerr.New(pcerr.InvalidArgument, "VECTORSTORE_CONFIG_INVALID",
		"a vectorstore connection needs a host, a database and user, sslmode verify-full (require only for an internal "+
			"database with a pinned CA), a lower-case schema and table, 1 to 16000 dimensions, a distance of cosine, l2 "+
			"or inner_product, and at most 64 distinct writer agents")
	// ErrVectorstoreEndpointImmutable: the endpoint is fixed once the
	// connection exists; a store that moves is a new connection (D925a).
	ErrVectorstoreEndpointImmutable = pcerr.New(pcerr.FailedPrecondition, "VECTORSTORE_ENDPOINT_IMMUTABLE",
		"a vectorstore connection's host, port, database, user, sslmode, CA and internal setting cannot change: "+
			"create a new connection for the moved store")
)

// VectorstoreConfig is a vectorstore connection's settings (D922-D925a).
// A zero port takes the default.
type VectorstoreConfig struct {
	Host     string `json:"host"`
	Port     int32  `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	SSLMode  string `json:"sslmode"`
	CAPEM    string `json:"ca_pem,omitempty"`
	Internal bool   `json:"internal,omitempty"`
	// Schema and Table name the one table, created from the printed DDL.
	Schema     string `json:"schema_name"`
	Table      string `json:"table_name"`
	Dimensions int32  `json:"dimensions"`
	Distance   string `json:"distance"`
	// Writers are the agents that may write without a person (D924).
	Writers []ids.UUID `json:"writer_agent_ids"`
}

// Check checks a vectorstore configuration and fills its defaults, the
// endpoint exactly as a postgres connection's (D925a). It does not reach
// the database: the connection test does.
func (c VectorstoreConfig) Check() (VectorstoreConfig, error) {
	c.Port = orDefault(c.Port, DefaultPostgresPort)
	switch {
	case !validHost(c.Host), c.Port < 1 || c.Port > 65535,
		!identRE.MatchString(c.Database), !identRE.MatchString(c.User),
		len(c.CAPEM) > maxPostgresCA,
		!identRE.MatchString(c.Schema), !identRE.MatchString(c.Table),
		c.Dimensions < 1 || c.Dimensions > MaxVectorstoreDimensions,
		!slices.Contains(VectorstoreDistances, c.Distance),
		len(c.Writers) > maxVectorstoreWriters:
		return VectorstoreConfig{}, ErrVectorstoreConfig
	}
	switch c.SSLMode {
	case SSLVerifyFull:
	case SSLRequire:
		// Without hostname checks, only a pinned CA on a private network.
		if !c.Internal || c.CAPEM == "" {
			return VectorstoreConfig{}, ErrVectorstoreConfig
		}
	default:
		return VectorstoreConfig{}, ErrVectorstoreConfig
	}
	if c.CAPEM != "" && !validCA(c.CAPEM) {
		return VectorstoreConfig{}, ErrVectorstoreConfig
	}
	if a, err := netip.ParseAddr(strings.Trim(c.Host, "[]")); err == nil && !c.Internal && !publicAddr(a) {
		// A private address only with internal.
		return VectorstoreConfig{}, ErrVectorstoreConfig
	}
	writers := make([]ids.UUID, 0, len(c.Writers))
	for _, w := range c.Writers {
		if w.IsZero() || slices.Contains(writers, w) {
			return VectorstoreConfig{}, ErrVectorstoreConfig
		}
		writers = append(writers, w)
	}
	slices.SortFunc(writers, func(a, b ids.UUID) int { return strings.Compare(a.String(), b.String()) })
	c.Writers = writers
	return c, nil
}

// sameEndpoint reports whether two configurations name the same database
// the same way (D925a).
func (c VectorstoreConfig) sameEndpoint(o VectorstoreConfig) bool {
	return c.Host == o.Host && c.Port == o.Port && c.Database == o.Database && c.User == o.User &&
		c.SSLMode == o.SSLMode && c.CAPEM == o.CAPEM && c.Internal == o.Internal
}

// checkVectorstoreCreate checks what a vectorstore connection's creation
// needs before the defaults apply (D922): pc.vectorstore, held access, no
// base URL, hosts or credential header (its password goes in no header, as
// a postgres connection's). Another kind never uses pc.vectorstore.
func checkVectorstoreCreate(in *CreateInput) error {
	switch {
	case (in.Package == VectorstorePackage) != (in.Kind == KindVectorstore):
		return ErrShape
	case in.Kind != KindVectorstore:
		if in.Vectorstore != nil {
			return ErrShape
		}
		return nil
	case in.Vectorstore == nil, in.AccessMode != AccessHeld, in.ModelRelay:
		return ErrShape
	}
	return nil
}

// loadVectorstore reads a vectorstore connection's settings; nil for
// another kind.
func loadVectorstore(ctx context.Context, q *dbq.Queries, conn dbq.PcConnection) (*VectorstoreConfig, error) {
	if conn.Kind != KindVectorstore {
		return nil, nil
	}
	row, err := q.GetVectorstoreConnection(ctx, conn.OrgID, conn.ID)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return VectorstoreConfigFromRow(row), nil
}

// VectorstoreConfigFromRow is a stored vectorstore configuration.
func VectorstoreConfigFromRow(row dbq.GetVectorstoreConnectionRow) *VectorstoreConfig {
	return &VectorstoreConfig{
		Host: row.Host, Port: row.Port, Database: row.Database, User: row.DbUser, SSLMode: row.Sslmode,
		CAPEM: deref(row.CaPem), Internal: row.Internal, Schema: row.SchemaName, Table: row.TableName,
		Dimensions: row.Dimensions, Distance: row.Distance, Writers: slices.Clone(row.WriterAgentIds),
	}
}

// SaveVectorstore writes a checked vectorstore configuration (the
// vectorstore kind store's Save, G0 M30 D925). A stored endpoint never
// changes: a different one is refused here too, and the statement never
// updates it.
func SaveVectorstore(ctx context.Context, tx db.TenantTx, org ids.OrgID, conn ids.UUID, c *VectorstoreConfig) error {
	q := dbq.New(tx)
	if cur, err := q.GetVectorstoreConnection(ctx, org, conn); err == nil {
		if !VectorstoreConfigFromRow(cur).sameEndpoint(*c) {
			return ErrVectorstoreEndpointImmutable
		}
	} else if !db.IsNoRows(err) {
		return err
	}
	p := dbq.PutVectorstoreConnectionParams{
		OrgID: org, ConnectionID: conn, Host: c.Host, Port: c.Port, Database: c.Database, DbUser: c.User,
		Sslmode: c.SSLMode, Internal: c.Internal, SchemaName: c.Schema, TableName: c.Table,
		Dimensions: c.Dimensions, Distance: c.Distance, WriterAgentIds: c.Writers,
	}
	if c.CAPEM != "" {
		ca := c.CAPEM
		p.CaPem = &ca
	}
	if p.WriterAgentIds == nil {
		p.WriterAgentIds = []ids.UUID{}
	}
	return q.PutVectorstoreConnection(ctx, p)
}

// vectorstoreWeakens reports whether a new configuration widens what the
// connection lets through (HR-183): a newly listed writer, or another
// table.
func vectorstoreWeakens(before, after *VectorstoreConfig) bool {
	if before == nil || before.Schema != after.Schema || before.Table != after.Table {
		return true
	}
	for _, w := range after.Writers {
		if !slices.Contains(before.Writers, w) {
			return true
		}
	}
	return false
}

// vectorstoreSummary is a vectorstore configuration in an audit record:
// the table, its shape and how many writers, never the CA.
func vectorstoreSummary(c *VectorstoreConfig) string {
	if c == nil {
		return ""
	}
	return "table=" + c.Schema + "." + c.Table + " dimensions=" + strconv.Itoa(int(c.Dimensions)) +
		" distance=" + c.Distance + " writers=" + strconv.Itoa(len(c.Writers))
}
