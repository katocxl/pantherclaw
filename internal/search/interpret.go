// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // the zone database on every platform, so "today" means the same everywhere
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Plain-language questions (G0 M11 part 2 D46; F305, F321, HR-295, founder
// decision F5). A question is read by a fixed tokenizer and lexicon, never a
// model, and nothing leaves the server. The answer shows the query it
// produced, the range and its time zone, what the rows mean (attempts,
// confirmed effects, decisions or effects) and every phrase it understood.
// It never guesses: words it does not know, names that match no record the
// viewer may read, and names that match more than one are returned, and
// then it asks for clarification instead of running anything. Names are
// resolved with quick find under the viewer's own permissions, so a record
// the viewer may not read reads exactly like one that does not exist.

// EventMeaning says what the rows of a transaction answer mean.
type EventMeaning string

// Event meanings.
const (
	// MeaningAttempts: actions an agent attempted and how each was decided.
	MeaningAttempts EventMeaning = "ATTEMPTS"
	// MeaningConfirmed: actions whose effect was confirmed at the target.
	MeaningConfirmed EventMeaning = "CONFIRMED"
	// MeaningDecisions: the decisions themselves (denied, held).
	MeaningDecisions EventMeaning = "DECISIONS"
	// MeaningEffects: what is known of the effects (failed, unknown).
	MeaningEffects EventMeaning = "EFFECTS"
)

// Ambiguity is a phrase that names more than one record the viewer may
// read.
type Ambiguity struct {
	Phrase     string
	Candidates []Match
}

// Interpretation is how a question was read.
type Interpretation struct {
	Question string
	// Exactly one of Query and Builtin is set unless NeedsClarification.
	Query   *Query
	Builtin *BuiltinQuery
	// Entity is the entity searched (a built-in query's own entity name
	// otherwise).
	Entity      string
	Filters     []string
	Environment string
	Start, End  *time.Time
	Timezone    string
	Meaning     EventMeaning
	// Matched lists each phrase understood and what it became.
	Matched            []string
	UnknownWords       []string
	Ambiguities        []Ambiguity
	NeedsClarification bool
	// Clarifications say what to add or change.
	Clarifications []string
}

// Limits on questions.
const (
	maxQuestion     = 300
	maxQuestionDays = 366
)

// nameResolver finds the records a phrase names exactly, among the kinds
// given, under the viewer's permissions.
type nameResolver func(ctx context.Context, phrase string, kinds []FindKind) ([]Match, error)

// stopwords carry no meaning in a question.
var stopwords = map[string]bool{
	"a": true, "an": true, "the": true, "of": true, "in": true, "on": true, "at": true, "to": true, "with": true,
	"which": true, "what": true, "were": true, "was": true, "are": true, "is": true, "did": true, "do": true,
	"does": true, "that": true, "my": true, "any": true, "there": true, "been": true, "have": true, "has": true,
	"show": true, "me": true, "list": true, "find": true, "get": true, "give": true, "please": true, "all": true,
	"and": true, "or": true, "from": true, "by": true, "for": true, "who": true, "where": true, "when": true,
	"made": true, "taken": true, "done": true, "happened": true, "recent": true, "every": true, "each": true,
	"named": true, "called": true, "about": true, "into": true, "via": true, "through": true, "using": true,
	"it": true, "how": true, "many": true, "used": true, "use": true, "uses": true, "touched": true,
}

// entityWords map an entity word to its entity.
var entityWords = map[string]Entity{
	"transaction": EntityTransactions, "transactions": EntityTransactions, "action": EntityTransactions,
	"actions": EntityTransactions, "call": EntityTransactions, "calls": EntityTransactions,
	"decision": EntityTransactions, "decisions": EntityTransactions, "attempt": EntityTransactions,
	"attempts": EntityTransactions,
	"run":      EntityRuns, "runs": EntityRuns, "session": EntityRuns, "sessions": EntityRuns,
	"agent": EntityAgents, "agents": EntityAgents,
	"grant": EntityGrants, "grants": EntityGrants,
	"connection": EntityConnections, "connections": EntityConnections,
	"approval": EntityApprovals, "approvals": EntityApprovals,
	"audit":     EntityAudit,
	"operation": EntityOperations, "operations": EntityOperations,
	"alert": EntityAlerts, "alerts": EntityAlerts,
	"incident": EntityIncidents, "incidents": EntityIncidents,
	"case": EntityCases, "cases": EntityCases,
	"finding": EntityFindings, "findings": EntityFindings,
	"policies": EntityPolicyVersions, "policy": EntityPolicyVersions,
	"package": EntityPackages, "packages": EntityPackages,
	"gateway": EntityGateways, "gateways": EntityGateways,
	"automation": EntityAutomations, "automations": EntityAutomations,
	"execution": EntityExecutions, "executions": EntityExecutions,
}

// multiEntity are entity phrases of more than one word, longest first.
var multiEntity = []struct {
	words  []string
	entity Entity
}{
	{[]string{"policy", "versions"}, EntityPolicyVersions},
	{[]string{"policy", "version"}, EntityPolicyVersions},
	{[]string{"grant", "changes"}, EntityGrantChanges},
	{[]string{"audit", "events"}, EntityAudit},
	{[]string{"audit", "log"}, EntityAudit},
	{[]string{"tool", "packages"}, EntityPackages},
}

// outcome is what an outcome word filters transactions by.
type outcome struct {
	decisions []string
	effects   []string
	meaning   EventMeaning
}

var outcomes = map[string]outcome{
	"denied":    {decisions: []string{"DENY", "CANNOT_AUTHORIZE"}, meaning: MeaningDecisions},
	"blocked":   {decisions: []string{"DENY", "CANNOT_AUTHORIZE"}, meaning: MeaningDecisions},
	"refused":   {decisions: []string{"DENY", "CANNOT_AUTHORIZE"}, meaning: MeaningDecisions},
	"held":      {decisions: []string{"REQUIRE_APPROVAL", "REQUIRE_STEP_UP"}, meaning: MeaningDecisions},
	"waiting":   {decisions: []string{"REQUIRE_APPROVAL", "REQUIRE_STEP_UP"}, meaning: MeaningDecisions},
	"allowed":   {decisions: []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS"}, meaning: MeaningAttempts},
	"permitted": {decisions: []string{"ALLOW", "ALLOW_WITH_OBLIGATIONS"}, meaning: MeaningAttempts},
	"confirmed": {effects: []string{"CONFIRMED"}, meaning: MeaningConfirmed},
	"succeeded": {effects: []string{"CONFIRMED"}, meaning: MeaningConfirmed},
	"failed":    {effects: []string{"NONE_CONFIRMED", "PARTIAL"}, meaning: MeaningEffects},
	"unknown":   {effects: []string{"UNKNOWN"}, meaning: MeaningEffects},
}

// environments map an environment word to its kind.
var environments = map[string]string{
	"production": "PRODUCTION", "prod": "PRODUCTION", "staging": "STAGING", "stage": "STAGING",
	"development": "DEVELOPMENT", "dev": "DEVELOPMENT",
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	numRe  = regexp.MustCompile(`^\d{1,4}$`)
	wordRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N}._@+-]*$`)
)

// token is one word of a question, or a quoted phrase (always a name).
type token struct {
	text   string
	quoted bool
}

// tokenize lowercases q and splits it into words and quoted phrases,
// trimming punctuation around words.
func tokenize(q string) ([]token, error) {
	var out []token
	rest := q
	for {
		rest = strings.TrimLeft(rest, " \t\r\n")
		if rest == "" {
			return out, nil
		}
		if c := rest[0]; c == '"' || c == '\'' && strings.Count(rest, "'") >= 2 {
			end := strings.IndexByte(rest[1:], c)
			if end < 0 {
				return nil, ErrInvalidQuery("unterminated quote")
			}
			if p := strings.TrimSpace(rest[1 : end+1]); p != "" {
				out = append(out, token{text: strings.ToLower(p), quoted: true})
			}
			rest = rest[end+2:]
			continue
		}
		i := strings.IndexAny(rest, " \t\r\n")
		if i < 0 {
			i = len(rest)
		}
		w := strings.Trim(strings.ToLower(rest[:i]), ",.?!;:()[]")
		w = strings.TrimSuffix(w, "'s")
		if w != "" {
			out = append(out, token{text: w})
		}
		rest = rest[i:]
	}
}

// parser reads one question.
type parser struct {
	toks    []token
	used    []bool
	in      Interpretation
	loc     *time.Location
	now     time.Time
	resolve nameResolver
	// ops is the operation catalog the viewer may read (sorted, unique).
	ops []string
	// resource is the resource group of who_can_write.
	resource string
}

func (p *parser) word(i int) string {
	if i < 0 || i >= len(p.toks) || p.used[i] || p.toks[i].quoted {
		return ""
	}
	return p.toks[i].text
}

// seq reports whether the unused words at i are ws.
func (p *parser) seq(i int, ws ...string) bool {
	for k, w := range ws {
		if p.word(i+k) != w {
			return false
		}
	}
	return true
}

// find returns the first index where ws start, or -1.
func (p *parser) find(ws ...string) int {
	for i := range p.toks {
		if p.seq(i, ws...) {
			return i
		}
	}
	return -1
}

func (p *parser) take(i, n int, became string) {
	parts := make([]string, 0, n)
	for k := i; k < i+n; k++ {
		p.used[k] = true
		parts = append(parts, p.toks[k].text)
	}
	p.in.Matched = append(p.in.Matched, strings.Join(parts, " ")+" → "+became)
}

func (p *parser) clarify(msg string) {
	p.in.NeedsClarification = true
	p.in.Clarifications = append(p.in.Clarifications, msg)
}

// Interpret reads a question without running it.
func (s *Service) Interpret(ctx context.Context, question, timezone string) (Interpretation, error) {
	c, err := searcher(ctx)
	if err != nil {
		return Interpretation{}, err
	}
	var out Interpretation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		res := func(ctx context.Context, phrase string, kinds []FindKind) ([]Match, error) {
			return exactMatches(ctx, s, c, tx, phrase, kinds)
		}
		ops, err := s.visibleOperations(ctx, c, tx)
		if err != nil {
			return err
		}
		out, err = interpret(ctx, question, timezone, s.now(), res, ops)
		return err
	}, db.ReadOnly())
	return out, err
}

// interpret is Interpret with its clock, resolver and the viewer-visible
// operation catalog (nil: none visible) given.
func interpret(ctx context.Context, question, timezone string, now time.Time, resolve nameResolver, ops []string) (Interpretation, error) {
	q := strings.TrimSpace(question)
	switch {
	case q == "" || utf8.RuneCountInString(q) > maxQuestion:
		return Interpretation{}, ErrInvalidQuery("question must be 1 to 300 characters")
	case !printable(q) || !utf8.ValidString(q):
		return Interpretation{}, ErrInvalidQuery("question is malformed")
	}
	if timezone == "" {
		timezone = "UTC"
	}
	loc, err := time.LoadLocation(timezone)
	if err != nil || timezone == "Local" {
		return Interpretation{}, ErrInvalidQuery("timezone must be an IANA time zone name")
	}
	toks, err := tokenize(q)
	if err != nil {
		return Interpretation{}, err
	}
	p := &parser{
		toks: toks, used: make([]bool, len(toks)), loc: loc, now: now.In(loc), resolve: resolve, ops: ops,
		in: Interpretation{Question: q, Timezone: timezone},
	}
	if err := p.parse(ctx); err != nil {
		return Interpretation{}, err
	}
	return p.in, nil
}

func (p *parser) parse(ctx context.Context) error {
	if err := p.timePhrases(); err != nil {
		return err
	}
	b := p.builtinPhrase()
	env := p.environment()
	var ent Entity
	if b == "" {
		ent = p.entity()
	}
	oc := p.outcomes()
	refs, err := p.names(ctx, b)
	if err != nil {
		return err
	}
	if b == BuiltinWhoCanWrite {
		p.resourceGroup(refs)
	}
	for i, t := range p.toks {
		if !p.used[i] && !t.quoted && !stopwords[t.text] {
			p.in.UnknownWords = append(p.in.UnknownWords, t.text)
		}
	}
	if len(p.in.UnknownWords) > 0 {
		p.clarify("rephrase or remove the words not understood: " + strings.Join(p.in.UnknownWords, ", "))
	}
	if len(p.in.Ambiguities) > 0 {
		p.clarify("name one record: use its id or a more exact name")
	}
	if b != "" {
		p.builtin(b, env, oc, refs)
	} else {
		p.query(ent, env, oc, refs)
	}
	return nil
}

// timePhrases reads today, yesterday, this week, last|past N
// hours|days|weeks, since <date>, between <date> and <date>, on <date>.
func (p *parser) timePhrases() error {
	day := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, p.loc) }
	set := func(start, end *time.Time) error {
		if p.in.Start != nil || p.in.End != nil {
			p.clarify("give one time range")
			return nil
		}
		if start != nil && end != nil && !end.After(*start) {
			return ErrInvalidQuery("the range ends before it starts")
		}
		if start != nil && p.now.Sub(*start) > maxQuestionDays*24*time.Hour {
			return ErrInvalidQuery("the range starts more than a year ago")
		}
		p.in.Start, p.in.End = utc(start), utc(end)
		return nil
	}
	date := func(s string) (time.Time, bool) {
		t, err := time.ParseInLocation("2006-01-02", s, p.loc)
		return t, err == nil
	}
	for i := range p.toks {
		today := day(p.now)
		switch w := p.word(i); {
		case w == "today":
			p.take(i, 1, "from "+today.Format(time.RFC3339))
			if err := set(&today, nil); err != nil {
				return err
			}
		case w == "yesterday":
			y := today.AddDate(0, 0, -1)
			p.take(i, 1, "from "+y.Format(time.RFC3339)+" to "+today.Format(time.RFC3339))
			if err := set(&y, &today); err != nil {
				return err
			}
		case w == "this" && p.word(i+1) == "week":
			wd := (int(today.Weekday()) + 6) % 7 // Monday starts the week
			m := today.AddDate(0, 0, -wd)
			p.take(i, 2, "from "+m.Format(time.RFC3339))
			if err := set(&m, nil); err != nil {
				return err
			}
		case w == "last" || w == "past":
			n, k := 1, i+1
			if numRe.MatchString(p.word(k)) {
				n, _ = strconv.Atoi(p.word(k))
				k++
			}
			unit := map[string]time.Duration{
				"hour": time.Hour, "hours": time.Hour, "day": 24 * time.Hour,
				"days": 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour,
			}[p.word(k)]
			if unit == 0 || n < 1 {
				continue
			}
			s := p.now.Add(-time.Duration(n) * unit)
			p.take(i, k-i+1, "from "+s.Format(time.RFC3339))
			if err := set(&s, nil); err != nil {
				return err
			}
		case w == "since" && dateRe.MatchString(p.word(i+1)):
			s, ok := date(p.word(i + 1))
			if !ok {
				return ErrInvalidQuery("not a date: " + p.word(i+1))
			}
			p.take(i, 2, "from "+s.Format(time.RFC3339))
			if err := set(&s, nil); err != nil {
				return err
			}
		case w == "on" && dateRe.MatchString(p.word(i+1)):
			s, ok := date(p.word(i + 1))
			if !ok {
				return ErrInvalidQuery("not a date: " + p.word(i+1))
			}
			e := s.AddDate(0, 0, 1)
			p.take(i, 2, "from "+s.Format(time.RFC3339)+" to "+e.Format(time.RFC3339))
			if err := set(&s, &e); err != nil {
				return err
			}
		case w == "between" && dateRe.MatchString(p.word(i+1)) && p.word(i+2) == "and" && dateRe.MatchString(p.word(i+3)):
			s, ok1 := date(p.word(i + 1))
			e, ok2 := date(p.word(i + 3))
			if !ok1 || !ok2 {
				return ErrInvalidQuery("not a date")
			}
			e = e.AddDate(0, 0, 1) // the end date is included
			p.take(i, 4, "from "+s.Format(time.RFC3339)+" to "+e.Format(time.RFC3339))
			if err := set(&s, &e); err != nil {
				return err
			}
		}
	}
	return nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func (p *parser) environment() string {
	for i := range p.toks {
		if k, ok := environments[p.word(i)]; ok {
			if p.in.Environment != "" && p.in.Environment != k {
				p.clarify("name one environment")
			}
			p.in.Environment = k
			p.take(i, 1, "environment "+k)
		}
	}
	return p.in.Environment
}

// builtinPhrase recognizes a built-in query's phrasing.
func (p *parser) builtinPhrase() Builtin {
	phrases := []struct {
		words []string
		b     Builtin
	}{
		{[]string{"why", "was"}, BuiltinWhyAllowed},
		{[]string{"who", "can", "write", "to"}, BuiltinWhoCanWrite},
		{[]string{"who", "can", "write"}, BuiltinWhoCanWrite},
		{[]string{"unused", "grants"}, BuiltinUnusedGrants},
		{[]string{"recent", "authority", "changes"}, BuiltinRecentAuthorityChange},
		{[]string{"authority", "changes"}, BuiltinRecentAuthorityChange},
		{[]string{"payment-capable", "tools"}, BuiltinToolCapability},
		{[]string{"payment", "capable", "tools"}, BuiltinToolCapability},
		{[]string{"tools", "that", "can", "move", "money"}, BuiltinToolCapability},
		{[]string{"actions", "on", "behalf", "of"}, BuiltinActionsForPrincipal},
		{[]string{"actions", "for"}, BuiltinActionsForPrincipal},
		{[]string{"what", "depends", "on"}, BuiltinConnectionDependents},
		{[]string{"who", "depends", "on"}, BuiltinConnectionDependents},
		{[]string{"widest", "exposure"}, BuiltinWidestExposure},
		{[]string{"most", "exposed"}, BuiltinWidestExposure},
		{[]string{"production", "access"}, BuiltinProductionAccess},
	}
	for _, ph := range phrases {
		i := p.find(ph.words...)
		if i < 0 {
			continue
		}
		if ph.b == BuiltinWhyAllowed {
			// "why was <transaction> allowed"
			j := p.find("allowed")
			if j < 0 {
				continue
			}
			p.take(j, 1, "built-in "+string(ph.b))
		}
		p.take(i, len(ph.words), "built-in "+string(ph.b))
		return ph.b
	}
	return ""
}

func (p *parser) entity() Entity {
	var ent Entity
	add := func(e Entity) {
		if ent != "" && ent != e {
			p.clarify("ask about one kind of record: " + string(ent) + " or " + string(e))
		}
		ent = e
	}
	for i := range p.toks {
		for _, m := range multiEntity {
			if p.seq(i, m.words...) {
				p.take(i, len(m.words), "entity "+string(m.entity))
				add(m.entity)
			}
		}
	}
	for i := range p.toks {
		w := p.word(i)
		if w == "agent" && i+1 < len(p.toks) {
			continue // "agent <name>" names an agent, read with the names
		}
		if e, ok := entityWords[w]; ok {
			p.take(i, 1, "entity "+string(e))
			add(e)
		}
	}
	return ent
}

func (p *parser) outcomes() []outcome {
	var out []outcome
	for i := range p.toks {
		if o, ok := outcomes[p.word(i)]; ok {
			label := strings.Join(slices.Concat(o.decisions, o.effects), "|")
			p.take(i, 1, "outcome "+label)
			out = append(out, o)
		}
	}
	return out
}

// ref is a record a question names.
type ref struct {
	phrase string
	match  Match
}

// nameKinds are the kinds a bare name may name; a preceding "agent" or
// "connection" narrows it.
var nameKinds = []FindKind{FindAgents, FindConnections, FindAutomations}

// names resolves the remaining words that name records: quoted phrases,
// ids, and words after "agent", "connection", "for" or "on". Every other
// remaining word is tried as an agent or connection name.
func (p *parser) names(ctx context.Context, b Builtin) ([]ref, error) {
	var out []ref
	kindsFor := func(i int) []FindKind {
		switch {
		case p.word(i-1) == "agent":
			return []FindKind{FindAgents}
		case p.word(i-1) == "connection":
			return []FindKind{FindConnections}
		case b == BuiltinActionsForPrincipal:
			return []FindKind{FindPeople, FindServiceAccounts}
		case b == BuiltinConnectionDependents || b == BuiltinWhoCanWrite:
			return []FindKind{FindConnections}
		}
		return nameKinds
	}
	for i, t := range p.toks {
		if p.used[i] || (!t.quoted && (stopwords[t.text] || (t.text == "agent" || t.text == "connection") && i+1 < len(p.toks))) {
			continue
		}
		if !t.quoted && !wordRe.MatchString(t.text) {
			continue
		}
		kinds := kindsFor(i)
		if uuidRe.MatchString(t.text) {
			kinds = FindKinds()
		}
		ms, err := p.resolve(ctx, t.text, kinds)
		if err != nil {
			return nil, err
		}
		// "agent X" and "connection X" name only that kind (D86 Q3).
		if !uuidRe.MatchString(t.text) && p.word(i-1) != "agent" && p.word(i-1) != "connection" {
			ms = append(ms, p.operationsNamed(t.text)...)
		}
		switch len(ms) {
		case 0:
			if t.quoted {
				p.in.UnknownWords = append(p.in.UnknownWords, t.text)
				p.used[i] = true
			}
			continue // an unknown word, reported with the rest
		case 1:
			out = append(out, ref{phrase: t.text, match: ms[0]})
			for _, k := range []string{"agent", "connection"} {
				if p.word(i-1) == k {
					p.used[i-1] = true
				}
			}
			p.take(i, 1, strings.TrimSuffix(string(ms[0].Kind), "s")+" "+ms[0].ID)
		default:
			p.used[i] = true
			p.in.Ambiguities = append(p.in.Ambiguities, Ambiguity{Phrase: t.text, Candidates: ms})
		}
	}
	return out, nil
}

// query builds the structured query.
func (p *parser) query(ent Entity, env string, ocs []outcome, refs []ref) {
	if ent == "" && len(ocs) > 0 {
		ent = EntityTransactions
		p.in.Matched = append(p.in.Matched, "an outcome word → entity transactions")
	}
	if ent == "" {
		p.clarify("say what to search for, for example actions, runs, agents, grants, alerts or cases")
		return
	}
	f := Filters{Start: p.in.Start, End: p.in.End}
	if env != "" {
		f.EnvKinds = []string{env}
		p.in.Filters = append(p.in.Filters, "environment is "+env)
	}
	if len(ocs) > 0 && ent != EntityTransactions {
		p.clarify("outcome words (denied, held, allowed, failed, unknown) apply to actions only")
		return
	}
	if slices.ContainsFunc(ocs, func(o outcome) bool { return len(o.decisions) > 0 }) &&
		slices.ContainsFunc(ocs, func(o outcome) bool { return len(o.effects) > 0 }) {
		// "allowed or failed" is a union of a decision and an effect, which
		// one query cannot say: ask instead of reading "or" as "and".
		p.clarify("choose decisions (denied, held, allowed) or effects (confirmed, failed, unknown), not both")
		return
	}
	for _, o := range ocs {
		f.Decisions = appendNew(f.Decisions, o.decisions...)
		f.EffectStates = appendNew(f.EffectStates, o.effects...)
	}
	if ent == EntityTransactions {
		p.in.Meaning = meaningOf(ocs)
	}
	if len(f.Decisions) > 0 {
		p.in.Filters = append(p.in.Filters, "decision is one of "+strings.Join(f.Decisions, ", "))
	}
	if len(f.EffectStates) > 0 {
		p.in.Filters = append(p.in.Filters, "effect is one of "+strings.Join(f.EffectStates, ", "))
	}
	if n := len(slices.DeleteFunc(slices.Clone(refs), func(r ref) bool { return r.match.Kind != FindOperations })); n > 1 {
		// Two operation words cannot both filter one query (D86 Q1).
		p.clarify("name one operation")
		return
	}
	for _, r := range refs {
		if !p.applyRef(ent, &f, r) {
			p.clarify(r.phrase + " is a " + strings.TrimSuffix(string(r.match.Kind), "s") + ", which does not filter " + string(ent))
			return
		}
	}
	q := Query{Entity: ent, Filters: f}
	if err := q.Validate(); err != nil {
		p.clarify(err.Error())
		return
	}
	p.in.Entity = string(ent)
	if !p.in.NeedsClarification {
		p.in.Query = &q
	}
}

// applyRef sets the filter a named record becomes for ent.
func (p *parser) applyRef(ent Entity, f *Filters, r ref) bool {
	if r.match.Kind == FindOperations {
		switch {
		case r.match.MatchedBy == MatchedOperation:
			f.Operation = r.match.ID
			p.in.Filters = append(p.in.Filters, "operation is "+r.match.ID)
		case ent == EntityApprovals:
			return false // approvals filter by one exact operation
		default:
			f.OperationPrefix = r.match.ID
			p.in.Filters = append(p.in.Filters, "operation starts with "+r.match.ID)
		}
		return true
	}
	id, err := ids.ParseUUID(r.match.ID)
	if err != nil {
		return false
	}
	desc := fmt.Sprintf("%s is %s (%s)", strings.TrimSuffix(string(r.match.Kind), "s"), r.match.Label, r.match.Evidence[0])
	slot := map[FindKind]**ids.UUID{
		FindAgents: &f.Agent, FindRuns: &f.Run, FindGrants: &f.Grant, FindConnections: &f.Connection,
		FindGateways: &f.Gateway, FindAlerts: &f.Alert, FindIncidents: &f.Incident, FindAutomations: &f.Automation,
	}
	if (r.match.Kind == FindKind(ent)) || (ent == EntityTransactions && r.match.Kind == FindTransactions) {
		f.ID = &id
		p.in.Filters = append(p.in.Filters, "id is "+r.match.ID)
		return true
	}
	if r.match.Kind == FindConnections && ent == EntityAgents {
		f.UsedConnection = &id
		p.in.Filters = append(p.in.Filters, "used connection "+r.match.Label+" ("+r.match.Evidence[0]+")")
		return true
	}
	if r.match.Kind == FindPeople {
		f.PrincipalUser = &id
	} else if r.match.Kind == FindServiceAccounts {
		f.PrincipalSA = &id
	} else if s, ok := slot[r.match.Kind]; ok {
		*s = &id
	} else {
		return false
	}
	p.in.Filters = append(p.in.Filters, desc)
	return true
}

// builtin builds the built-in query.
func (p *parser) builtin(b Builtin, env string, ocs []outcome, refs []ref) {
	p.in.Entity = string(b)
	bq := BuiltinQuery{Name: b, Params: Params{Start: p.in.Start, End: p.in.End}}
	if len(ocs) > 0 {
		p.clarify("outcome words do not apply to " + string(b))
		return
	}
	if env != "" {
		p.clarify("an environment does not apply to " + string(b))
		return
	}
	for _, r := range refs {
		id, _ := ids.ParseUUID(r.match.ID)
		//exhaustive:ignore // only these kinds are parameters of a built-in query; the rest ask for clarification
		switch r.match.Kind {
		case FindTransactions:
			bq.Params.Transaction = &id
		case FindAgents:
			bq.Params.Agent = &id
		case FindConnections:
			bq.Params.Connection = &id
		case FindPeople:
			bq.Params.PrincipalUser = &id
		case FindServiceAccounts:
			bq.Params.PrincipalSA = &id
		default:
			p.clarify(r.phrase + " does not apply to " + string(b))
			return
		}
		p.in.Filters = append(p.in.Filters, fmt.Sprintf("%s is %s (%s)", strings.TrimSuffix(string(r.match.Kind), "s"), r.match.Label, r.match.Evidence[0]))
	}
	//exhaustive:ignore // only these built-in queries take parameters the question does not name
	switch b {
	case BuiltinToolCapability:
		bq.Params.Effect = "funds."
		p.in.Filters = append(p.in.Filters, "effect starts with funds.")
	case BuiltinProductionAccess:
		p.in.Meaning = MeaningAttempts
	case BuiltinWhoCanWrite:
		if p.resource != "" {
			bq.Params.Resource = p.resource
			p.in.Filters = append(p.in.Filters, "resource group is "+p.resource)
		}
	}
	var err error
	if exposureBuiltin(b) {
		err = bq.validateExposure()
	} else {
		var q Query
		q, _, err = bq.expand(p.now)
		if err == nil {
			err = q.Validate()
		}
	}
	if err != nil {
		p.clarify(err.Error())
		return
	}
	if !p.in.NeedsClarification {
		p.in.Builtin = &bq
	}
}

func meaningOf(ocs []outcome) EventMeaning {
	m := MeaningAttempts
	for _, o := range ocs {
		switch {
		case o.meaning == MeaningDecisions && m == MeaningAttempts:
			m = MeaningDecisions
		case o.meaning == MeaningConfirmed || o.meaning == MeaningEffects:
			m = o.meaning
		}
	}
	return m
}

func appendNew(dst []string, vs ...string) []string {
	for _, v := range vs {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// resourceGroup takes the one word left after "who can write" as the
// resource group, literally, unless a connection was named. More than one
// word left is not a resource group: those words stay unknown.
func (p *parser) resourceGroup(refs []ref) {
	for _, r := range refs {
		if r.match.Kind == FindConnections {
			return
		}
	}
	left := -1
	for i, t := range p.toks {
		if p.used[i] || (!t.quoted && stopwords[t.text]) {
			continue
		}
		if left >= 0 {
			return
		}
		left = i
	}
	if left >= 0 && len(p.toks[left].text) <= maxTextLen {
		p.resource = p.toks[left].text
		p.take(left, 1, "resource group "+p.resource)
	}
}

// FindOperations is the kind of an operation a question names: it is read
// from the operation catalog, not by quick find.
const FindOperations FindKind = "operations"

// How a question's word names operations.
const (
	MatchedOperation       = "OPERATION"
	MatchedOperationPrefix = "OPERATION_PREFIX"
)

// visibleOperations returns the org's active operations when c may read
// the catalog (package.read at the org, as the operations entity), else
// nil: an operation word then reads like any unknown word.
func (s *Service) visibleOperations(ctx context.Context, c tenancy.Caller, tx db.TenantTx) ([]string, error) {
	if s.Defs == nil || !c.Can(entityPerm[EntityOperations], td.OrgPath(c.Org)) {
		return nil, nil
	}
	defs, err := s.operations(ctx, c, tx, Filters{})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.Operation)
	}
	return out, nil
}

// nounForms returns w and its singular forms (refunds → refund,
// batches → batch, policies → policy).
func nounForms(w string) []string {
	out := []string{w}
	switch {
	case strings.HasSuffix(w, "ies") && len(w) > 3:
		out = append(out, w[:len(w)-3]+"y")
	case strings.HasSuffix(w, "es") && len(w) > 2:
		out = append(out, w[:len(w)-2], w[:len(w)-1])
	case strings.HasSuffix(w, "s") && len(w) > 1:
		out = append(out, w[:len(w)-1])
	}
	return out
}

// operationsNamed returns the operations word names in the viewer-visible
// catalog: the operations with a segment equal to the word or its
// singular, grouped by the path up to that segment. One group is one
// candidate (its single operation, or every operation under its prefix);
// several groups are an ambiguity, never a guess.
func (p *parser) operationsNamed(word string) []Match {
	forms := nounForms(word)
	groups := map[string][]string{}
	var order []string
	for _, op := range p.ops {
		segs := strings.Split(op, ".")
		for j, s := range segs {
			if !slices.Contains(forms, s) {
				continue
			}
			g := strings.Join(segs[:j+1], ".")
			if _, ok := groups[g]; !ok {
				order = append(order, g)
			}
			groups[g] = append(groups[g], op)
			break
		}
	}
	out := make([]Match, 0, len(order))
	for _, g := range order {
		ops := groups[g]
		if len(ops) > 1 && slices.Contains(ops, g) {
			// The group is itself an operation with others under it: the word
			// names that operation or all of them, which a prefix alone would
			// not say (it leaves the root out). Both are offered (D86 Q2).
			out = append(out, Match{
				Kind: FindOperations, ID: g, Label: g, MatchedBy: MatchedOperation,
				Evidence: []string{"operation:" + g},
			})
		}
		m := Match{Kind: FindOperations, ID: ops[0], Label: ops[0], MatchedBy: MatchedOperation}
		if len(ops) > 1 {
			m.ID, m.Label, m.MatchedBy = g+".", g+".*", MatchedOperationPrefix
		}
		m.Evidence = []string{"operation:" + m.ID}
		out = append(out, m)
	}
	return out
}
