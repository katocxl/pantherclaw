// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/intel/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Matching at discovery and drift (G0 M38 D1104; HR-819, HR-822). What an
// upstream server lists is matched against the current indicators, in the
// caller's transaction, when the org consumes the feed: its reported name
// and version and its package reference (mcp_server), each tool's listed
// description (tool_description), and that description's shingles
// (injection_text). A match is recorded once per object and indicator, in
// pc.intel_matches and as audit intel.matched, which the built-in detection
// pc.intel.match alerts on. Holding is the decision path's (HR-819): nothing
// here refuses, quarantines or changes what is served.

// Object types of a match.
const (
	ObjectConnection    = "connection"
	ObjectInventoryItem = "inventory_item"
	ObjectRun           = "run"
	ObjectTransaction   = "transaction"
)

// Matcher matches at discovery, drift and in content scans.
type Matcher struct {
	// Ents gates consuming; nil matches nothing.
	Ents Editions
}

// ServerInfo is an upstream server's serverInfo as stored on the
// connection: its UNTRUSTED word (HR-822).
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Bounds of a stored serverInfo, as the gateway's report allows.
const (
	maxServerName    = 256
	maxServerVersion = 128
)

// Valid reports whether the info may be stored: printable UTF-8 within the
// bounds, and a name.
func (s ServerInfo) Valid() bool {
	ok := func(v string, n int) bool {
		return utf8.ValidString(v) && len(v) <= n && !strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f })
	}
	return s.Name != "" && ok(s.Name, maxServerName) && ok(s.Version, maxServerVersion)
}

// ParseServerInfo reads a stored serverInfo; nil or unreadable is none.
func ParseServerInfo(raw []byte) (ServerInfo, bool) {
	if len(raw) == 0 {
		return ServerInfo{}, false
	}
	var s ServerInfo
	if json.Unmarshal(raw, &s) != nil || !s.Valid() {
		return ServerInfo{}, false
	}
	return s, true
}

// EncodeServerInfo is the stored form of s.
func EncodeServerInfo(s ServerInfo) ([]byte, error) { return json.Marshal(s, json.Deterministic(true)) }

// mode reads whether org consumes, and the edition still allows it.
func (m *Matcher) mode(ctx context.Context, q *dbq.Queries, org ids.OrgID) (domain.Mode, error) {
	if m == nil || m.Ents == nil {
		return domain.ModeOff, nil
	}
	st, err := ReadSettings(ctx, q, org)
	if err != nil || !st.Consume.Consumes() {
		return domain.ModeOff, err
	}
	e, err := m.Ents.Current(ctx)
	if err != nil {
		return domain.ModeOff, errEditionUnknown
	}
	if !e.IntelConsume() {
		return domain.ModeOff, nil
	}
	return st.Consume, nil
}

// ServerHits are the mcp_server indicators a connection's upstream server
// matches: its reported name and version, and its pinned package reference
// and version. Read in any transaction.
func ServerHits(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn ids.UUID) ([]domain.Hit, error) {
	row, err := q.IntelSourceConnection(ctx, org, conn)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var hashes []string
	if info, ok := ParseServerInfo(row.UpstreamServerInfo); ok {
		hashes = append(hashes, domain.ServerHash(info.Name, info.Version))
	}
	if row.PinnedVersion != nil {
		hashes = append(hashes, domain.PackageHash(row.Package, *row.PinnedVersion))
	}
	return hashHits(ctx, q, domain.KindMCPServer, hashes)
}

// DescriptionHits are the tool_description indicators a description
// matches.
func DescriptionHits(ctx context.Context, q *dbq.Queries, text string) ([]domain.Hit, error) {
	return hashHits(ctx, q, domain.KindToolDescription, []string{domain.DescriptionHash(text)})
}

func hashHits(ctx context.Context, q *dbq.Queries, k domain.Kind, hashes []string) ([]domain.Hit, error) {
	var want []string
	for _, h := range hashes {
		if h != "" {
			want = append(want, h)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	rows, err := q.IntelHashHits(ctx, string(k), want)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Hit, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.Hit{ID: r.ID, Kind: domain.Kind(r.Kind), Severity: domain.Severity(r.Severity)})
	}
	return out, nil
}

// TextHits are the injection_text indicators a text matches: each holding
// at least min(3, n) of the text's shingles.
func TextHits(ctx context.Context, q *dbq.Queries, text string) ([]domain.Hit, error) {
	sh := domain.Shingles(text)
	if len(sh) == 0 {
		return nil, nil
	}
	rows, err := q.IntelShingleCandidates(ctx, sh)
	if err != nil {
		return nil, err
	}
	in := make([]domain.Indicator, 0, len(rows))
	for _, r := range rows {
		in = append(in, domain.Indicator{ID: r.ID, Kind: domain.KindInjectionText, Shingles: r.Shingles, Severity: domain.Severity(r.Severity)})
	}
	return domain.NewSet(in).Text(sh), nil
}

// target is what a match is about.
type target struct {
	objectType, objectRef string
	conn                  *ids.UUID
	tool                  *string
}

// record writes each hit once per object, with its audit event.
func record(ctx context.Context, tx db.TenantTx, org ids.OrgID, mode domain.Mode, by evdomain.Actor, t target, hits []domain.Hit) error {
	q := dbq.New(tx)
	for _, h := range hits {
		seen, err := q.IntelMatchSeen(ctx, dbq.IntelMatchSeenParams{
			OrgID: org, IndicatorID: h.ID, ObjectType: t.objectType, ObjectRef: t.objectRef,
		})
		if err != nil {
			return err
		}
		if seen {
			continue
		}
		id := ids.NewV7()
		if err := q.InsertIntelMatch(ctx, dbq.InsertIntelMatchParams{
			OrgID: org, ID: id, IndicatorID: h.ID, Kind: string(h.Kind), ObjectType: t.objectType, ObjectRef: t.objectRef,
			ConnectionID: t.conn, Tool: t.tool, Mode: string(mode),
		}); err != nil {
			return err
		}
		details := map[string]string{
			"match_id": id.String(), "indicator_id": h.ID, "kind": string(h.Kind), "severity": string(h.Severity),
			"mode": string(mode), "object_type": t.objectType, "object_ref": t.objectRef,
		}
		if t.conn != nil {
			details["connection_id"] = t.conn.String()
		}
		if t.tool != nil {
			details["tool"] = *t.tool
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.IntelMatched, Actor: by, Outcome: audit.Success,
			Object: &audit.Object{Type: t.objectType, ID: t.objectRef}, Details: details,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Server records the connection's upstream server's word, when the gateway
// learned it, and matches the server (D1104). A report without one, or with
// one out of bounds, keeps what was stored.
func (m *Matcher) Server(ctx context.Context, tx db.TenantTx, conn ids.UUID, name, version string, by evdomain.Actor) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	if info := (ServerInfo{Name: name, Version: version}); info.Valid() {
		raw, err := EncodeServerInfo(info)
		if err != nil {
			return err
		}
		if err := q.SetConnectionServerInfo(ctx, raw, org, conn); err != nil {
			return err
		}
	}
	mode, err := m.mode(ctx, q, org)
	if err != nil || !mode.Consumes() {
		return err
	}
	hits, err := ServerHits(ctx, q, org, conn)
	if err != nil || len(hits) == 0 {
		return err
	}
	return record(ctx, tx, org, mode, by, target{objectType: ObjectConnection, objectRef: conn.String(), conn: &conn}, hits)
}

// Tool matches one tool's listed description: its hash and its shingles.
// item is the inventory item, or zero for a drift report (the connection is
// then the object).
func (m *Matcher) Tool(ctx context.Context, tx db.TenantTx, conn, item ids.UUID, tool, description string, by evdomain.Actor) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	mode, err := m.mode(ctx, q, org)
	if err != nil || !mode.Consumes() || description == "" {
		return err
	}
	hits, err := DescriptionHits(ctx, q, description)
	if err != nil {
		return err
	}
	text, err := TextHits(ctx, q, description)
	if err != nil {
		return err
	}
	hits = append(hits, text...)
	if len(hits) == 0 {
		return nil
	}
	t := target{objectType: ObjectConnection, objectRef: conn.String() + "/" + tool, conn: &conn, tool: &tool}
	if !item.IsZero() {
		t.objectType, t.objectRef = ObjectInventoryItem, item.String()
	}
	return record(ctx, tx, org, mode, by, t, hits)
}

// Content records the injection_text matches a gateway's content scan found
// on a run's body (D1104): the indicator ids it named, those still current.
// object is the run, or the transaction when the run is not known.
func (m *Matcher) Content(ctx context.Context, tx db.TenantTx, run, txn ids.UUID, indicators []string, by evdomain.Actor) error {
	q := dbq.New(tx)
	org := tx.OrgID()
	mode, err := m.mode(ctx, q, org)
	if err != nil || !mode.Consumes() || len(indicators) == 0 {
		return err
	}
	var hits []domain.Hit
	for _, id := range indicators {
		row, err := q.GetIntelIndicator(ctx, id)
		if db.IsNoRows(err) {
			continue
		} else if err != nil {
			return err
		}
		if domain.Kind(row.Kind) == domain.KindInjectionText {
			hits = append(hits, domain.Hit{ID: row.ID, Kind: domain.KindInjectionText, Severity: domain.Severity(row.Severity)})
		}
	}
	if len(hits) == 0 {
		return nil
	}
	t := target{objectType: ObjectRun, objectRef: run.String()}
	if run.IsZero() {
		t = target{objectType: ObjectTransaction, objectRef: txn.String()}
	}
	return record(ctx, tx, org, mode, by, t, hits)
}
