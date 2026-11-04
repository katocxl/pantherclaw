// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgdispatch

import (
	json "encoding/json/v2"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The retrieval-index statements of a vectorstore connection (G0 M30 D922,
// D923): one pgvector table the admin created from the printed DDL, which
// the gateway never runs. Like every statement here, the SQL holds only the
// connection's identifiers, fixed keywords and $n placeholders; the
// embedding, the content, the metadata and the filter are parameters. The
// provenance columns are filled from the permit, never from the agent's
// params (HR-704), and every reader sees them.

// Distance is a vectorstore connection's distance metric.
type Distance string

// Distance metrics.
const (
	DistanceCosine       Distance = "cosine"
	DistanceL2           Distance = "l2"
	DistanceInnerProduct Distance = "inner_product"
)

// distanceOp is the pgvector operator of each metric.
var distanceOp = map[Distance]string{
	DistanceCosine:       "<=>",
	DistanceL2:           "<->",
	DistanceInnerProduct: "<#>",
}

// Vector limits (D922, D922a, D922b).
const (
	MaxDimensions    = 16000
	DefaultTopK      = 10
	MaxTopK          = 100
	MaxFilterKeys    = 16
	MaxMetadataKeys  = 32
	MaxMetadataValue = 1 << 10
	MaxVectorID      = 256
	MaxVectorContent = 8 << 10
)

// metadataKeyRe is a metadata or filter key (D922b), as the string_map
// param type reads it.
var metadataKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

// VectorTable is a vectorstore connection's table and its shape.
type VectorTable struct {
	Schema     string
	Name       string
	Dimensions int
	Distance   Distance
}

func (t VectorTable) check() error {
	switch {
	case !ValidIdentifier(t.Schema) || !ValidIdentifier(t.Name):
		return &Error{Code: CodeManifestInvalid, Detail: "the vector table's schema and name must be lower-case identifiers"}
	case t.Dimensions < 1 || t.Dimensions > MaxDimensions:
		return &Error{Code: CodeManifestInvalid, Detail: fmt.Sprintf("dimensions must be 1..%d", MaxDimensions)}
	case distanceOp[t.Distance] == "":
		return &Error{Code: CodeManifestInvalid, Detail: fmt.Sprintf("unknown distance %q", t.Distance)}
	}
	return nil
}

func (t VectorTable) ref() string { return quote(t.Schema, t.Name) }

// Provenance is who wrote a record, from the permit (D923, HR-704).
type Provenance struct {
	RunID         string
	AgentID       string
	TransactionID string
}

func (p Provenance) check() error {
	for _, id := range []string{p.RunID, p.AgentID, p.TransactionID} {
		if !uuidRe.MatchString(id) {
			return queryErr("the permit's run, agent and transaction ids must be uuids")
		}
	}
	return nil
}

// VectorQuery is a vector_query: the TopK records nearest Embedding whose
// metadata holds every Filter pair.
type VectorQuery struct {
	Table     VectorTable
	Embedding []float64
	TopK      int // 0: DefaultTopK
	Filter    map[string]string
}

// VectorUpsert is a vector_upsert: one record written or replaced by id.
type VectorUpsert struct {
	Table      VectorTable
	ID         string
	Content    string
	Embedding  []float64
	Metadata   map[string]string
	Provenance Provenance
}

// VectorDelete is a vector_delete: one record removed by id.
type VectorDelete struct {
	Table VectorTable
	ID    string
}

// VectorQueryColumns are the columns a vector_query answers with: the
// record, its distance and its provenance (D923).
var VectorQueryColumns = []Output{
	{Name: "id", Type: TypeText},
	{Name: "content", Type: TypeText},
	{Name: "metadata", Type: TypeText},
	{Name: "distance", Type: TypeNumeric},
	{Name: "pc_run_id", Type: TypeUUID},
	{Name: "pc_agent_id", Type: TypeUUID},
	{Name: "pc_written_at", Type: TypeTimestamptz},
}

// BuildVectorQuery builds a vector_query statement, ordered by distance
// with the connection's metric.
func BuildVectorQuery(q VectorQuery) (*Statement, error) {
	if err := q.Table.check(); err != nil {
		return nil, err
	}
	topK := q.TopK
	if topK == 0 {
		topK = DefaultTopK
	}
	if topK < 1 || topK > MaxTopK {
		return nil, queryErr("top_k must be 1..%d", MaxTopK)
	}
	vec, err := vectorText(q.Table, q.Embedding)
	if err != nil {
		return nil, err
	}
	if len(q.Filter) > MaxFilterKeys {
		return nil, queryErr("a filter holds at most %d keys", MaxFilterKeys)
	}
	if err := checkMetadata(q.Filter); err != nil {
		return nil, err
	}
	b := &builder{}
	dist := fmt.Sprintf("(%s %s %s::vector)", quote("embedding"), distanceOp[q.Table.Distance], b.arg(vec))
	sel := []string{
		selected(quote("id")),
		selected(quote("content")),
		selected(quote("metadata")),
		selected(dist),
		selected(quote("pc_run_id")),
		selected(quote("pc_agent_id")),
		selected(quote("pc_written_at")),
	}
	if len(q.Filter) > 0 {
		raw, err := json.Marshal(q.Filter, json.Deterministic(true))
		if err != nil {
			return nil, queryErr("filter: %v", err)
		}
		b.where = append(b.where, fmt.Sprintf("%s @> %s::jsonb", quote("metadata"), b.arg(string(raw))))
	}
	st := &Statement{Output: slices.Clone(VectorQueryColumns), Limit: topK}
	st.SQL = "SELECT " + strings.Join(sel, ", ") + " FROM ONLY " + q.Table.ref() + b.whereSQL() +
		" ORDER BY " + dist + " LIMIT " + strconv.Itoa(topK+1)
	st.Args = b.args
	return st, nil
}

// BuildVectorUpsert builds a vector_upsert statement. It returns no rows;
// the pc_* columns come from the permit and pc_written_at from the
// database clock.
func BuildVectorUpsert(q VectorUpsert) (*Statement, error) {
	if err := q.Table.check(); err != nil {
		return nil, err
	}
	if err := checkVectorID(q.ID); err != nil {
		return nil, err
	}
	if !utf8.ValidString(q.Content) || strings.ContainsRune(q.Content, 0) || len(q.Content) > MaxVectorContent {
		return nil, queryErr("content must be valid text of at most %d bytes", MaxVectorContent)
	}
	vec, err := vectorText(q.Table, q.Embedding)
	if err != nil {
		return nil, err
	}
	if len(q.Metadata) > MaxMetadataKeys {
		return nil, queryErr("metadata holds at most %d keys", MaxMetadataKeys)
	}
	if err := checkMetadata(q.Metadata); err != nil {
		return nil, err
	}
	if err := q.Provenance.check(); err != nil {
		return nil, err
	}
	meta := q.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	raw, err := json.Marshal(meta, json.Deterministic(true))
	if err != nil {
		return nil, queryErr("metadata: %v", err)
	}
	b := &builder{}
	cols := []string{"id", "content", "embedding", "metadata", "pc_run_id", "pc_agent_id", "pc_transaction_id"}
	vals := []string{
		b.arg(q.ID) + "::text",
		b.arg(q.Content) + "::text",
		b.arg(vec) + "::vector",
		b.arg(string(raw)) + "::jsonb",
		b.arg(q.Provenance.RunID) + "::uuid",
		b.arg(q.Provenance.AgentID) + "::uuid",
		b.arg(q.Provenance.TransactionID) + "::uuid",
	}
	quoted := make([]string, len(cols))
	set := make([]string, 0, len(cols))
	for i, c := range cols {
		quoted[i] = quote(c)
		if c != "id" {
			set = append(set, quote(c)+" = EXCLUDED."+quote(c))
		}
	}
	set = append(set, quote("pc_written_at")+" = now()")
	st := &Statement{}
	st.SQL = "INSERT INTO " + q.Table.ref() + " (" + strings.Join(quoted, ", ") + ") VALUES (" + strings.Join(vals, ", ") +
		") ON CONFLICT (" + quote("id") + ") DO UPDATE SET " + strings.Join(set, ", ")
	st.Args = b.args
	return st, nil
}

// BuildVectorDelete builds a vector_delete statement. It returns no rows.
func BuildVectorDelete(q VectorDelete) (*Statement, error) {
	if err := q.Table.check(); err != nil {
		return nil, err
	}
	if err := checkVectorID(q.ID); err != nil {
		return nil, err
	}
	b := &builder{}
	st := &Statement{}
	st.SQL = "DELETE FROM ONLY " + q.Table.ref() + " WHERE " + quote("id") + " = " + b.arg(q.ID) + "::text"
	st.Args = b.args
	return st, nil
}

// VectorDDL is the table and extension the admin runs for a vectorstore
// connection (D923); the gateway never runs it.
func VectorDDL(t VectorTable) (string, error) {
	if err := t.check(); err != nil {
		return "", err
	}
	return "CREATE EXTENSION IF NOT EXISTS vector;\n" +
		"CREATE TABLE " + t.ref() + " (\n" +
		"  id text PRIMARY KEY,\n" +
		"  content text NOT NULL,\n" +
		"  embedding vector(" + strconv.Itoa(t.Dimensions) + ") NOT NULL,\n" +
		"  metadata jsonb NOT NULL DEFAULT '{}',\n" +
		"  pc_run_id uuid NOT NULL,\n" +
		"  pc_agent_id uuid NOT NULL,\n" +
		"  pc_transaction_id uuid NOT NULL,\n" +
		"  pc_written_at timestamptz NOT NULL DEFAULT now()\n" +
		");\n", nil
}

// vectorText is the embedding as pgvector's text form, [v1,v2,…], bound as
// a parameter and cast to vector (D927).
func vectorText(t VectorTable, v []float64) (string, error) {
	if len(v) != t.Dimensions {
		return "", queryErr("the embedding has %d values, the table %d", len(v), t.Dimensions)
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, f := range v {
		if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > math.MaxFloat32 {
			return "", queryErr("the embedding must hold finite numbers")
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(f, 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String(), nil
}

func checkVectorID(id string) error {
	if id == "" || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || len(id) > MaxVectorID {
		return queryErr("id must be valid text of 1..%d bytes", MaxVectorID)
	}
	return nil
}

// checkMetadata checks a flat string map's keys and values.
func checkMetadata(m map[string]string) error {
	for _, k := range slices.Sorted(maps.Keys(m)) {
		v := m[k]
		if !metadataKeyRe.MatchString(k) {
			return queryErr("metadata key %q is not a name", k)
		}
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) || len(v) > MaxMetadataValue {
			return queryErr("metadata value of %q must be valid text of at most %d bytes", k, MaxMetadataValue)
		}
	}
	return nil
}
