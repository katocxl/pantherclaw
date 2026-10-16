// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Quick find (G0 M11 part 2 D45; F304, F320, HR-295): one box that finds a
// record by its id, an id prefix of at least 8 hex digits, or a name or
// title. Each kind is matched under the viewer's own permission and scope
// for it, in the database, before the limit and the count, so a hidden
// record never shows in matches, counts or suggestions. A kind the viewer
// may not read at all is listed as an omission ("outside your
// permissions"), never as empty.

// FindKind is a kind of record quick find matches.
type FindKind string

// Quick-find kinds. Named kinds match names and titles as well as ids.
const (
	FindAgents          FindKind = "agents"
	FindConnections     FindKind = "connections"
	FindCases           FindKind = "cases"
	FindIncidents       FindKind = "incidents"
	FindAlerts          FindKind = "alerts"
	FindPackages        FindKind = "packages"
	FindGateways        FindKind = "gateways"
	FindServiceAccounts FindKind = "service_accounts"
	FindPeople          FindKind = "people"
	FindRuns            FindKind = "runs"
	FindTransactions    FindKind = "transactions"
	FindGrants          FindKind = "grants"
	FindApprovals       FindKind = "approvals"
	FindFindings        FindKind = "findings"
	FindPolicyVersions  FindKind = "policy_versions"
	FindAudit           FindKind = "audit"
	FindAutomations     FindKind = "automations"
	FindExecutions      FindKind = "automation_executions"
)

// How a match was made.
const (
	MatchedID           = "ID"
	MatchedIDPrefix     = "ID_PREFIX"
	MatchedNameExact    = "NAME_EXACT"
	MatchedNamePrefix   = "NAME_PREFIX"
	MatchedNameContains = "NAME_CONTAINS"
)

// Limits on quick find.
const (
	minFindText      = 2
	maxFindText      = 100
	minIDPrefix      = 8
	defaultFindLimit = 5
	maxFindLimit     = 10
)

// findRow is the shape every quick-find query returns.
type findRow struct {
	ID    ids.UUID
	Label string
	State string
	At    time.Time
	Total int64
}

// findArgs are a quick find's match arguments: an id range (nil when the
// text is no id or id prefix) and the escaped name pattern ("" when the
// text matches no names).
type findArgs struct {
	lo, hi   *ids.UUID
	contains string
	lowered  string
	limit    int32
}

// finder matches one kind. org: the permission is read at the org (all or
// nothing), else at the agents' places. named: the kind matches names.
type finder struct {
	perm  td.Permission
	org   bool
	named bool
	// evidence is the evidence kind of a match ("agent" → "agent:<id>").
	evidence string
	run      func(context.Context, *dbq.Queries, tenancy.Caller, Scope, findArgs) ([]findRow, error)
}

// finders lists the kinds in the order results show them.
var findOrder = []FindKind{
	FindAgents, FindConnections, FindCases, FindIncidents, FindAlerts, FindPackages, FindGateways,
	FindServiceAccounts, FindPeople, FindRuns, FindTransactions, FindGrants, FindApprovals, FindFindings,
	FindPolicyVersions, FindAudit, FindAutomations, FindExecutions,
}

var finders = map[FindKind]finder{
	FindAgents: {td.PermAgentRead, false, true, "agent", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindAgents(ctx, dbq.FindAgentsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: a.lo, IDHi: a.hi, Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindAgentsRow) findRow { return findRow(r) }), err
	}},
	FindConnections: {td.PermConnectionRead, true, true, "connection", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindConnections(ctx, dbq.FindConnectionsParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindConnectionsRow) findRow { return findRow(r) }), err
	}},
	FindCases: {td.PermCaseRead, false, true, "case", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindCases(ctx, dbq.FindCasesParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: a.lo, IDHi: a.hi, Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindCasesRow) findRow { return findRow(r) }), err
	}},
	FindIncidents: {td.PermIncidentRead, false, true, "incident", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindIncidents(ctx, dbq.FindIncidentsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: a.lo, IDHi: a.hi, Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindIncidentsRow) findRow { return findRow(r) }), err
	}},
	FindAlerts: {td.PermIncidentRead, false, true, "alert", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindAlerts(ctx, dbq.FindAlertsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: a.lo, IDHi: a.hi, Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindAlertsRow) findRow { return findRow(r) }), err
	}},
	FindPackages: {td.PermPackageRead, true, true, "package", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindPackages(ctx, dbq.FindPackagesParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindPackagesRow) findRow { return findRow(r) }), err
	}},
	FindGateways: {td.PermGatewayRead, true, true, "gateway", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindGateways(ctx, dbq.FindGatewaysParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindGatewaysRow) findRow { return findRow(r) }), err
	}},
	FindServiceAccounts: {td.PermServiceAccountRead, true, true, "service_account", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindServiceAccounts(ctx, dbq.FindServiceAccountsParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindServiceAccountsRow) findRow { return findRow(r) }), err
	}},
	// People only with the member read permission at the org (D45).
	FindPeople: {td.PermUserRead, true, true, "user", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindPeople(ctx, dbq.FindPeopleParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindPeopleRow) findRow { return findRow(r) }), err
	}},
	FindRuns: {td.PermRunRead, false, false, "run", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindRuns(ctx, dbq.FindRunsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindRunsRow) findRow { return findRow(r) }), err
	}},
	FindTransactions: {td.PermEvidenceRead, false, false, "transaction", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindTransactions(ctx, dbq.FindTransactionsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindTransactionsRow) findRow { return findRow(r) }), err
	}},
	FindGrants: {td.PermGrantRead, false, false, "grant", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindGrants(ctx, dbq.FindGrantsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindGrantsRow) findRow { return findRow(r) }), err
	}},
	FindApprovals: {td.PermApprovalRead, false, false, "approval", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindApprovals(ctx, dbq.FindApprovalsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindApprovalsRow) findRow { return findRow(r) }), err
	}},
	FindFindings: {td.PermPostureRead, false, false, "finding", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindFindings(ctx, dbq.FindFindingsParams{
			OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(),
			IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindFindingsRow) findRow { return findRow(r) }), err
	}},
	FindPolicyVersions: {td.PermPolicyRead, true, false, "policy_version", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindPolicyVersions(ctx, dbq.FindPolicyVersionsParams{OrgID: c.Org, IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit})
		return convert(rows, func(r dbq.FindPolicyVersionsRow) findRow { return findRow(r) }), err
	}},
	FindAutomations: {td.PermAutomationRead, true, true, "automation", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindAutomations(ctx, dbq.FindAutomationsParams{
			OrgID: c.Org, IDLo: a.lo, IDHi: a.hi,
			Contains: a.contains, Lowered: a.lowered, PageLimit: a.limit,
		})
		return convert(rows, func(r dbq.FindAutomationsRow) findRow { return findRow(r) }), err
	}},
	FindExecutions: {td.PermAutomationRead, true, false, "automation_execution", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindAutomationExecutions(ctx, dbq.FindAutomationExecutionsParams{OrgID: c.Org, IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit})
		return convert(rows, func(r dbq.FindAutomationExecutionsRow) findRow { return findRow(r) }), err
	}},
	FindAudit: {td.PermAuditRead, true, false, "ledger", func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, a findArgs) ([]findRow, error) {
		rows, err := q.FindAudit(ctx, dbq.FindAuditParams{OrgID: c.Org, IDLo: *a.lo, IDHi: *a.hi, PageLimit: a.limit})
		return convert(rows, func(r dbq.FindAuditRow) findRow { return findRow(r) }), err
	}},
}

func convert[R any](rows []R, f func(R) findRow) []findRow {
	out := make([]findRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, f(r))
	}
	return out
}

// FindKinds lists the quick-find kinds in result order.
func FindKinds() []FindKind { return slices.Clone(findOrder) }

// Match is one record quick find matched, with the evidence it links to.
type Match struct {
	Kind      FindKind
	ID        string
	Label     string
	State     string
	Time      time.Time
	MatchedBy string
	Evidence  []string
}

// KindResult is one kind's matches: Count is how many records in the
// viewer's scope match (at most MaxCount, Capped above it).
type KindResult struct {
	Kind    FindKind
	Matches []Match
	Count   int
	Capped  bool
	// PrefixOnly: names starting with the text filled the limit, so Count
	// covers those only; names containing it elsewhere were not counted
	// (D79 S3, D86 Q4).
	PrefixOnly bool
	Scope      Scope
}

// FindResult is a quick find's answer. Omissions name the kinds the viewer
// may not read ("outside your permissions") or reads only in part.
type FindResult struct {
	Text      string
	Kinds     []KindResult
	Omissions []Omission
	AsOf      time.Time
}

// FindRequest is a quick find: text 2..100 characters, the kinds to match
// (none: all) and at most Limit matches per kind (default 5, at most 10).
type FindRequest struct {
	Text  string
	Kinds []FindKind
	Limit int
}

func (r FindRequest) validate() (string, error) {
	t := strings.TrimSpace(r.Text)
	switch n := utf8.RuneCountInString(t); {
	case n < minFindText || n > maxFindText:
		return "", ErrInvalidQuery("text must be 2 to 100 characters")
	case !printable(t) || !utf8.ValidString(t):
		return "", ErrInvalidQuery("text is malformed")
	case r.Limit < 0 || r.Limit > maxFindLimit:
		return "", ErrInvalidQuery("limit must be at most 10")
	case len(r.Kinds) > len(findOrder):
		return "", ErrInvalidQuery("too many kinds")
	}
	for _, k := range r.Kinds {
		if _, ok := finders[k]; !ok {
			return "", ErrInvalidQuery("unknown kind " + string(k))
		}
	}
	return t, nil
}

// idRange returns the ids text names: one id for a full id, the ids that
// start with it for 8 to 31 hex digits (hyphens ignored), else nil.
func idRange(text string) (lo, hi *ids.UUID, exact bool) {
	if u, err := ids.ParseUUID(text); err == nil {
		return &u, &u, true
	}
	h := strings.ToLower(strings.ReplaceAll(text, "-", ""))
	if len(h) < minIDPrefix || len(h) > 32 {
		return nil, nil, false
	}
	var l, u ids.UUID
	for i := range 32 {
		var lv, hv byte = 0, 0xf
		if i < len(h) {
			c := h[i]
			switch {
			case c >= '0' && c <= '9':
				lv = c - '0'
			case c >= 'a' && c <= 'f':
				lv = c - 'a' + 10
			default:
				return nil, nil, false
			}
			hv = lv
		}
		shift := 4 * (1 - i%2)
		l[i/2] |= lv << shift
		u[i/2] |= hv << shift
	}
	return &l, &u, len(h) == 32
}

// likeContains returns the LIKE pattern matching s anywhere, with LIKE's
// own characters escaped: what a person types never becomes a pattern.
func likeContains(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

// matchedBy says how row r matched text.
func matchedBy(r findRow, a findArgs, exact bool) string {
	if a.lo != nil && slices.Compare(r.ID[:], a.lo[:]) >= 0 && slices.Compare(r.ID[:], a.hi[:]) <= 0 {
		if exact {
			return MatchedID
		}
		return MatchedIDPrefix
	}
	l := strings.ToLower(r.Label)
	switch {
	case l == a.lowered:
		return MatchedNameExact
	case strings.HasPrefix(l, a.lowered):
		return MatchedNamePrefix
	default:
		return MatchedNameContains
	}
}

// Find runs a quick find under the caller's permissions (HR-295).
func (s *Service) Find(ctx context.Context, r FindRequest) (FindResult, error) {
	c, err := searcher(ctx)
	if err != nil {
		return FindResult{}, err
	}
	text, err := r.validate()
	if err != nil {
		return FindResult{}, err
	}
	var out FindResult
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.find(ctx, c, dbq.New(tx), text, r.Kinds, r.Limit)
		return err
	}, db.ReadOnly())
	return out, err
}

// find matches text in q; kinds empty means every kind.
func (s *Service) find(ctx context.Context, c tenancy.Caller, q *dbq.Queries, text string, kinds []FindKind, limit int) (FindResult, error) {
	if limit == 0 {
		limit = defaultFindLimit
	}
	lo, hi, exact := idRange(text)
	lowered := strings.ToLower(text)
	args := findArgs{lo: lo, hi: hi, lowered: lowered, contains: likeContains(lowered), limit: int32(limit)}
	out := FindResult{Text: text, AsOf: s.now()}
	for _, k := range findOrder {
		if len(kinds) > 0 && !slices.Contains(kinds, k) {
			continue
		}
		f := finders[k]
		if !f.named && lo == nil {
			continue // the text is no id: nothing of this kind can match
		}
		var sc Scope
		var err error
		if f.org {
			sc = orgScope(c, f.perm)
		} else if sc, err = AgentScope(ctx, c, q, f.perm); err != nil {
			return FindResult{}, err
		}
		switch {
		case sc.Restricted:
			out.Omissions = append(out.Omissions, Omission{
				Code: omissionRestricted, Detail: string(k) + ": outside your permissions (" + string(f.perm) + ")",
			})
			continue
		case !sc.All:
			out.Omissions = append(out.Omissions, Omission{
				Code: omissionScopeLimited, Detail: string(k) + ": only the agents where you hold " + string(f.perm),
			})
		}
		rows, total, prefixOnly, err := findKind(ctx, k, f, q, c, sc, args)
		if err != nil {
			return FindResult{}, err
		}
		kr := KindResult{
			Kind: k, Scope: sc, Matches: []Match{}, Count: int(min(total, MaxCount)), Capped: total > MaxCount,
			PrefixOnly: prefixOnly,
		}
		a := args
		for _, r := range rows {
			kr.Matches = append(kr.Matches, Match{
				Kind: k, ID: r.ID.String(), Label: r.Label, State: r.State, Time: r.At, MatchedBy: matchedBy(r, a, exact),
				Evidence: []string{f.evidence + ":" + r.ID.String()},
			})
		}
		out.Kinds = append(out.Kinds, kr)
	}
	return out, nil
}

// exactMatches returns the records of kinds that phrase names exactly (by
// id, or by the whole name, ignoring case) under c's permissions in tx.
func exactMatches(ctx context.Context, s *Service, c tenancy.Caller, tx db.TenantTx, phrase string, kinds []FindKind) ([]Match, error) {
	if utf8.RuneCountInString(phrase) < minFindText || utf8.RuneCountInString(phrase) > maxFindText {
		return nil, nil
	}
	r, err := s.find(ctx, c, dbq.New(tx), phrase, kinds, maxFindLimit)
	if err != nil {
		return nil, err
	}
	var out []Match
	for _, k := range r.Kinds {
		for _, m := range k.Matches {
			if m.MatchedBy == MatchedID || m.MatchedBy == MatchedNameExact {
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// findKind matches kind k. For a text that is no id, names starting with it
// come first, through their own index-served query (D86 Q4); only when
// they leave the limit unfilled does the query matching ids and names
// containing the text run, which scans the kind's rows in the viewer's
// scope and ranks exact and prefix names first, so its page and count
// stand alone. prefixOnly says the count covers name prefixes only.
func findKind(ctx context.Context, k FindKind, f finder, q *dbq.Queries, c tenancy.Caller, sc Scope, args findArgs,
) (rows []findRow, n int64, prefixOnly bool, err error) {
	a := args
	if !f.named {
		a.contains = ""
		rows, err = f.run(ctx, q, c, sc, a)
		return rows, total(rows), false, err
	}
	if args.lo == nil {
		pre, err := prefixFinders[k](ctx, q, c, sc, args.lowered, args.lowered+string(utf8.MaxRune), args.limit)
		if err != nil || len(pre) >= int(args.limit) {
			return pre, total(pre), err == nil, err
		}
	}
	rows, err = f.run(ctx, q, c, sc, a)
	return rows, total(rows), false, err
}

func total(rows []findRow) int64 {
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Total
}

type prefixFinder func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, lo, hi string, limit int32) ([]findRow, error)

// prefixFinders are the name-prefix queries of the named kinds.
var prefixFinders = map[FindKind]prefixFinder{
	FindAgents: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindAgentsByPrefix(ctx, dbq.FindAgentsByPrefixParams{OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindAgentsByPrefixRow) findRow { return findRow(r) }), err
	},
	FindConnections: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindConnectionsByPrefix(ctx, dbq.FindConnectionsByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindConnectionsByPrefixRow) findRow { return findRow(r) }), err
	},
	FindCases: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindCasesByPrefix(ctx, dbq.FindCasesByPrefixParams{OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindCasesByPrefixRow) findRow { return findRow(r) }), err
	},
	FindIncidents: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindIncidentsByPrefix(ctx, dbq.FindIncidentsByPrefixParams{OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindIncidentsByPrefixRow) findRow { return findRow(r) }), err
	},
	FindAlerts: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, sc Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindAlertsByPrefix(ctx, dbq.FindAlertsByPrefixParams{OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindAlertsByPrefixRow) findRow { return findRow(r) }), err
	},
	FindPackages: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindPackagesByPrefix(ctx, dbq.FindPackagesByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindPackagesByPrefixRow) findRow { return findRow(r) }), err
	},
	FindGateways: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindGatewaysByPrefix(ctx, dbq.FindGatewaysByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindGatewaysByPrefixRow) findRow { return findRow(r) }), err
	},
	FindServiceAccounts: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindServiceAccountsByPrefix(ctx, dbq.FindServiceAccountsByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindServiceAccountsByPrefixRow) findRow { return findRow(r) }), err
	},
	FindPeople: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindPeopleByPrefix(ctx, dbq.FindPeopleByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindPeopleByPrefixRow) findRow { return findRow(r) }), err
	},
	FindAutomations: func(ctx context.Context, q *dbq.Queries, c tenancy.Caller, _ Scope, lo, hi string, limit int32) ([]findRow, error) {
		rows, err := q.FindAutomationsByPrefix(ctx, dbq.FindAutomationsByPrefixParams{OrgID: c.Org, NameLo: lo, NameHi: hi, PageLimit: limit})
		return convert(rows, func(r dbq.FindAutomationsByPrefixRow) findRow { return findRow(r) }), err
	},
}
