// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json/v2"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Search actions (G0 M11 part 2 D46, D48; F305, F318, F321, HR-295,
// HR-296): ask a question and run what it reads as, open a case from chosen
// results, and export results. Each re-runs its search under the caller's
// own permissions, so neither carries anything the caller could not read.

// CaseOpener opens a case in the caller's transaction (reflexports
// CaseOpener; the Team edition).
type CaseOpener interface {
	Open(ctx context.Context, tx pgx.Tx, seed reflexdomain.CaseSeed) (ids.UUID, error)
}

// Answer is a question's interpretation and, unless it needs
// clarification, the first page of its results.
type Answer struct {
	Interpretation Interpretation
	Result         *Result
}

// Ask reads a question and runs it under the caller's permissions (D46).
// Nothing runs when the question needs clarification.
func (s *Service) Ask(ctx context.Context, question, timezone string, pr page.Request) (Answer, error) {
	in, err := s.Interpret(ctx, question, timezone)
	if err != nil {
		return Answer{}, err
	}
	out := Answer{Interpretation: in}
	if in.NeedsClarification {
		return out, nil
	}
	var r Result
	if in.Query != nil {
		r, err = s.Search(ctx, *in.Query, pr)
	} else {
		r, err = s.RunBuiltin(ctx, *in.Builtin, pr)
	}
	if err != nil {
		return Answer{}, err
	}
	out.Result = &r
	return out, nil
}

// Source names the search an action works on: exactly one structured
// query, built-in query or saved query.
type Source struct {
	Query   *Query
	Builtin *BuiltinQuery
	Saved   *ids.UUID
}

// spec resolves src to its query, reading a saved query the caller may see.
func (s *Service) spec(ctx context.Context, src Source) (Spec, error) {
	n := 0
	for _, set := range []bool{src.Query != nil, src.Builtin != nil, src.Saved != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return Spec{}, ErrInvalidQuery("name one query, built-in query or saved query")
	}
	if src.Saved != nil {
		q, err := s.Get(ctx, *src.Saved)
		if err != nil {
			return Spec{}, err
		}
		return q.Spec, nil
	}
	sp := Spec{Query: src.Query, Builtin: src.Builtin}
	return sp, sp.Validate()
}

// runSpec runs one page of sp in tx under c, narrowed to where c also
// holds also (none: no narrowing).
func (s *Service) runSpec(ctx context.Context, c tenancy.Caller, tx db.TenantTx, sp Spec, pr page.Request, also td.Permission) (Result, error) {
	if sp.Query != nil {
		return s.runAlso(ctx, c, tx, *sp.Query, pr, also)
	}
	if exposureBuiltin(sp.Builtin.Name) {
		if also != "" && !c.Can(also, td.OrgPath(c.Org)) {
			return Result{}, td.ErrPermissionDenied(also)
		}
		return s.runExposure(ctx, *sp.Builtin, pr)
	}
	if sp.Builtin.Name == BuiltinIncidentCorrelation {
		if also != "" && !c.Can(also, td.OrgPath(c.Org)) {
			return Result{}, td.ErrPermissionDenied(also)
		}
		return s.runCorrelation(ctx, c, *sp.Builtin, pr)
	}
	q, notes, err := sp.Builtin.expand(s.now())
	if err != nil {
		return Result{}, err
	}
	if err := q.Validate(); err != nil {
		return Result{}, err
	}
	out, err := s.runAlso(ctx, c, tx, q, pr, also)
	if err != nil {
		return Result{}, err
	}
	out.Omissions = append(out.Omissions, notes...)
	return out, nil
}

// Export limits (HR-296).
const (
	// MaxExportRows caps an export; more rows are left out and the export
	// says so.
	MaxExportRows = 10000
	// MaxCaseItems caps the results a case is opened from.
	MaxCaseItems = 50
)

// Export formats.
const (
	FormatJSON = "JSON"
	FormatCSV  = "CSV"
)

// Export is an exported result set.
type Export struct {
	Format      string
	ContentType string
	Data        []byte
	Rows        int
	Truncated   bool
	Scope       Scope
	Omissions   []Omission
	AsOf        time.Time
	// AuditID is the ledger entry that records the export.
	AuditID ids.UUID
}

// ErrExportRestricted reports an export of an entity the caller may not
// read or export anywhere.
func errExportRestricted(p td.Permission) error { return td.ErrPermissionDenied(p) }

// ExportResults exports up to 10 000 rows of a search the caller may read
// and export, and records the export with the query in the audit ledger
// (D48, HR-296).
func (s *Service) ExportResults(ctx context.Context, src Source, format string) (Export, error) {
	c, err := searcher(ctx)
	if err != nil {
		return Export{}, err
	}
	if !c.CanAnywhere(td.PermEvidenceExport) {
		return Export{}, td.ErrPermissionDenied(td.PermEvidenceExport)
	}
	if format != FormatJSON && format != FormatCSV {
		return Export{}, ErrInvalidQuery("format must be JSON or CSV")
	}
	sp, err := s.spec(ctx, src)
	if err != nil {
		return Export{}, err
	}
	var out Export
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var items []Item
		pr := page.Request{Size: page.Max}
		for {
			r, err := s.runSpec(ctx, c, tx, sp, pr, td.PermEvidenceExport)
			if err != nil {
				return err
			}
			if r.Scope.Restricted {
				return errExportRestricted(r.Scope.Permission)
			}
			if pr.After.IsZero() {
				out.Scope, out.Omissions, out.AsOf = r.Scope, r.Omissions, r.AsOf
			}
			items = append(items, r.Items...)
			if len(items) >= MaxExportRows {
				out.Truncated = len(items) > MaxExportRows || r.Next != ""
				items = items[:MaxExportRows]
				break
			}
			if r.Next == "" {
				break
			}
			if pr, err = page.Parse(page.Max, r.Next); err != nil {
				return err
			}
		}
		out.Rows, out.Format = len(items), format
		var err error
		if out.Data, out.ContentType, err = encode(items, format); err != nil {
			return err
		}
		e, err := audit.Record(ctx, tx, audit.Event{
			Name: "search.exported", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "search", ID: sourceID(src)}, Details: exportDetails(sp, out),
		})
		out.AuditID = e.ID
		return err
	})
	if err != nil {
		return Export{}, err
	}
	if out.Truncated {
		out.Omissions = append(out.Omissions, Omission{Code: "TRUNCATED", Detail: "the export stops at 10000 rows"})
	}
	return out, nil
}

func sourceID(src Source) string {
	if src.Saved != nil {
		return src.Saved.String()
	}
	return "adhoc"
}

// exportDetails records the query (in full when it fits, else its digest
// with its entity or built-in name) and the export's size.
func exportDetails(sp Spec, e Export) map[string]string {
	b, _ := json.Marshal(sp)
	sum := sha256.Sum256(b)
	d := map[string]string{
		"format": e.Format, "rows": strconv.Itoa(e.Rows), "truncated": strconv.FormatBool(e.Truncated),
		"query_sha256": hex.EncodeToString(sum[:]), "scope_whole": strconv.FormatBool(e.Scope.All),
	}
	if len(b) <= 512 {
		d["query"] = string(b)
	}
	if sp.Query != nil {
		d["entity"] = string(sp.Query.Entity)
	} else {
		d["builtin"] = string(sp.Builtin.Name)
	}
	return d
}

// exportItem is one exported row.
type exportItem struct {
	Entity   string            `json:"entity"`
	ID       string            `json:"id"`
	Time     *time.Time        `json:"time,omitempty"`
	Label    string            `json:"label"`
	Fields   map[string]string `json:"fields"`
	Evidence []string          `json:"evidence"`
}

// encode renders items as JSON (an array) or CSV (entity, id, time, label,
// one column per field, evidence). A CSV cell that a spreadsheet would read
// as a formula is prefixed with an apostrophe.
func encode(items []Item, format string) ([]byte, string, error) {
	if format == FormatJSON {
		rows := make([]exportItem, 0, len(items))
		for _, i := range items {
			e := exportItem{Entity: string(i.Entity), ID: i.ID, Label: i.Label, Fields: i.Fields, Evidence: i.Evidence}
			if !i.Time.IsZero() {
				t := i.Time.UTC()
				e.Time = &t
			}
			rows = append(rows, e)
		}
		b, err := json.Marshal(rows)
		return b, "application/json", err
	}
	keys := map[string]bool{}
	for _, i := range items {
		for k := range i.Fields {
			keys[k] = true
		}
	}
	cols := slices.Sorted(maps.Keys(keys))
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(slices.Concat([]string{"entity", "id", "time", "label"}, cols, []string{"evidence"}))
	for _, i := range items {
		t := ""
		if !i.Time.IsZero() {
			t = i.Time.UTC().Format(time.RFC3339Nano)
		}
		row := []string{string(i.Entity), i.ID, t, cell(i.Label)}
		for _, k := range cols {
			row = append(row, cell(i.Fields[k]))
		}
		row = append(row, cell(strings.Join(i.Evidence, " ")))
		_ = w.Write(row)
	}
	w.Flush()
	return buf.Bytes(), "text/csv", w.Error()
}

func cell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// OpenCaseRequest opens a case from chosen results of a search.
type OpenCaseRequest struct {
	Source Source
	Items  []string
	Title  string
}

// ErrItemsNotFound reports chosen items the search no longer returns to
// the caller (gone, changed, or outside the caller's permissions).
var ErrItemsNotFound = pcerr.New(pcerr.NotFound, "SEARCH_ITEMS_NOT_FOUND",
	"some chosen results are not in this search's results")

// errTooManyRefs reports a selection whose evidence exceeds a case seed.
var errTooManyRefs = ErrInvalidQuery("the chosen results link too much evidence for one case: choose fewer")

// OpenCaseFromResults opens a case (Team, case.manage) carrying only the
// chosen results' evidence: the search is re-run under the caller's
// permissions and only the items it returns are used (D48, HR-296).
func (s *Service) OpenCaseFromResults(ctx context.Context, r OpenCaseRequest) (ids.UUID, error) {
	c, err := searcher(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if !c.CanAnywhere(td.PermCaseManage) {
		return ids.UUID{}, td.ErrPermissionDenied(td.PermCaseManage)
	}
	title := strings.TrimSpace(r.Title)
	switch {
	case title == "" || utf8.RuneCountInString(title) > 200:
		return ids.UUID{}, ErrInvalidQuery("title must be 1 to 200 characters")
	case len(r.Items) == 0 || len(r.Items) > MaxCaseItems:
		return ids.UUID{}, ErrInvalidQuery("choose 1 to 50 results")
	case s.Cases == nil:
		return ids.UUID{}, ErrCasesUnavailable
	}
	want := map[string]bool{}
	for _, id := range r.Items {
		if id == "" || len(id) > 200 {
			return ids.UUID{}, ErrInvalidQuery("result id is malformed")
		}
		want[id] = true
	}
	sp, err := s.spec(ctx, r.Source)
	if err != nil {
		return ids.UUID{}, err
	}
	var out ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		chosen, err := s.chosen(ctx, c, tx, sp, want)
		if err != nil {
			return err
		}
		seed, agents, err := caseSeed(c, title, chosen)
		if err != nil {
			return err
		}
		if err := canManageCase(ctx, c, dbq.New(tx), agents); err != nil {
			return err
		}
		out, err = s.Cases.Open(ctx, tx.Pgx(), seed)
		return err
	})
	return out, err
}

// ErrCasesUnavailable reports a server without cases wired.
var ErrCasesUnavailable = pcerr.New(pcerr.FailedPrecondition, "NOT_AVAILABLE", "cases are not available on this server")

// chosen pages sp (at most MaxExportRows rows) and returns the items whose
// ids are wanted; any wanted id it does not return is refused.
func (s *Service) chosen(ctx context.Context, c tenancy.Caller, tx db.TenantTx, sp Spec, want map[string]bool) ([]Item, error) {
	var out []Item
	seen := 0
	pr := page.Request{Size: page.Max}
	for {
		r, err := s.runSpec(ctx, c, tx, sp, pr, "")
		if err != nil {
			return nil, err
		}
		for _, i := range r.Items {
			if want[i.ID] {
				out = append(out, i)
				delete(want, i.ID)
			}
		}
		seen += len(r.Items)
		if len(want) == 0 || r.Next == "" || seen >= MaxExportRows {
			break
		}
		if pr, err = page.Parse(page.Max, r.Next); err != nil {
			return nil, err
		}
	}
	if len(want) > 0 {
		return nil, ErrItemsNotFound
	}
	return out, nil
}

// caseSeed turns the chosen items' evidence links into a case seed:
// transactions, runs and ledger entries become evidence, other records
// subjects. It returns the agents the items are about.
func caseSeed(c tenancy.Caller, title string, items []Item) (reflexdomain.CaseSeed, []ids.UUID, error) {
	opener := reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: c.Principal.ID.String()}
	if c.Principal.Kind == td.KindServiceAccount {
		opener.Type = reflexdomain.SubjectServiceAccount
	}
	seed := reflexdomain.CaseSeed{Org: c.Org, Title: title, Source: "manual", Opener: opener}
	evKinds := map[string]bool{
		reflexdomain.EvidenceTransaction: true, reflexdomain.EvidenceRun: true, reflexdomain.EvidenceLedger: true,
	}
	seenRef := map[string]bool{}
	agentSet := map[ids.UUID]bool{}
	for _, i := range items {
		for _, k := range []string{"agent"} {
			if a, err := ids.ParseUUID(i.Fields[k]); err == nil {
				agentSet[a] = true
			}
		}
		for _, a := range strings.Split(i.Fields["agents"], ",") {
			if id, err := ids.ParseUUID(a); err == nil {
				agentSet[id] = true
			}
		}
		if i.Entity == EntityAgents {
			if id, err := ids.ParseUUID(i.ID); err == nil {
				agentSet[id] = true
			}
		}
		for _, ev := range i.Evidence {
			kind, id, ok := strings.Cut(ev, ":")
			if !ok || seenRef[ev] {
				continue
			}
			u, err := ids.ParseUUID(id)
			if err != nil {
				continue // a definition digest names no record
			}
			seenRef[ev] = true
			switch {
			case evKinds[kind]:
				seed.Evidence = append(seed.Evidence, reflexdomain.EvidenceRef{Kind: kind, ID: u})
			case reflexdomain.SubjectType(kind).Valid():
				seed.Subjects = append(seed.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectType(kind), ID: u.String()})
			}
		}
	}
	if len(seed.Evidence) > reflexdomain.MaxEvidence || len(seed.Subjects) > reflexdomain.MaxSubjects {
		return reflexdomain.CaseSeed{}, nil, errTooManyRefs
	}
	agents := slices.SortedFunc(maps.Keys(agentSet), func(a, b ids.UUID) int { return slices.Compare(a[:], b[:]) })
	return seed, agents, nil
}

// canManageCase checks case.manage over every agent the case is about, or
// at the org when it is about none.
func canManageCase(ctx context.Context, c tenancy.Caller, q *dbq.Queries, agents []ids.UUID) error {
	if c.Can(td.PermCaseManage, td.OrgPath(c.Org)) {
		return nil
	}
	if len(agents) == 0 {
		return td.ErrPermissionDenied(td.PermCaseManage)
	}
	sc, err := AgentScope(ctx, c, q, td.PermCaseManage)
	if err != nil {
		return err
	}
	for _, a := range agents {
		if !sc.All && !slices.Contains(sc.Agents, a) {
			return td.ErrPermissionDenied(td.PermCaseManage)
		}
	}
	return nil
}
