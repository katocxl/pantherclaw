// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

var (
	idPattern     = regexp.MustCompile(`^(RT-[0-9]{3}|CX-[0-9]{3,5})$`)
	stepIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	attackerRE    = regexp.MustCompile(`^A([1-9]|1[0-2])$`)
	threatRE      = regexp.MustCompile(`^T-[0-9]{3}$`)
	ruleRE        = regexp.MustCompile(`^HR-[0-9]{3}$`)
	fileNameRE    = regexp.MustCompile(`^(RT-[0-9]{3}|CX-[0-9]{3,5})-[a-z0-9]+(-[a-z0-9]+)*\.yaml$`)
	roleRE        = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	toolRE        = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,120}$`)
	tokenRE       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	saveNameRE    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	categories    = []string{"functional", "boundary", "recovery", "explanation"}
	suites        = []string{"coding-agent", "platform"}
	tiers         = []string{"community", "business"}
	// M14 capabilities and faces: G0 M14 D46.
	capabilities = []string{
		"github", "payments", "mcp", "sandbox", "person", "second_org",
		"stripe.refund", "stripe.transfer", "stripe.key_swap", "pg.query", "pg.role_swap", "slack.post",
		"slack.interaction_post", "authzen.evaluate", "a2a.send", "a2a.card_swap",
		// G0 UI: a signed-in browser session of a person (RT-060, RT-061).
		"browser",
		// G0 M20 D254: an agent commenting through pc.jira and merging through
		// pc.gitlab.
		"jira.comment", "gitlab.merge", "gitlab.deploy",
		// G0 M20 D286: an agent deploying through pc.aws.ecs. Harness only: on
		// a live range it would be a real deploy.
		"aws.ecs.deploy",
	}
	faces       = []string{"mcp", "http", "sdk", "hook", "a2a", "authzen"}
	methods     = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
	instances   = []string{"primary", "other"}
	credentials = []string{"none", "found_pat"}
	widenings   = []string{"destinations", "amount", "operations", "lifetime"}
	stealModes  = []string{"token_without_key", "proof_replay", "stale_nonce", "other_instance"}
	probes      = []string{"dns_docker_resolver", "dns_external", "ipv6", "icmp", "metadata", "host_gateway", "docker_socket", "direct_https", "ssh_push", "planted_pat_push", "raw_curl_merge"}
	sims        = []string{"github", "mcp", "payments", "stripe", "postgres", "slack", "a2a"}
	simChanges  = []string{"push_commit", "tool_description", "fault", "reaction", "reply", "interaction_post"}
	// slackChanges are valid only with sim: slack (G0 M14 D91).
	slackChanges   = []string{"reaction", "reply", "interaction_post"}
	personRoles    = []string{"approver", "launcher", "developer"}
	readObjects    = []string{"transaction", "approval", "run"}
	waitFor        = []string{"effect_confirmed", "effect_unknown", "downstream_read"}
	receiptHas     = []string{"grant", "policy_version", "package_version", "facts", "simulated"}
	kindsNeedingEx = map[string]bool{
		"agent.call": true, "agent.direct": true, "agent.child": true, "agent.steal": true,
		"sandbox.probe": true, "server.read": true, "target.replay": true, "wait": true,
		"person.approve": true, "person.decline": true, "check.receipt": true, "browser.call": true,
	}
)

// harnessOnlyKinds do what a range never does to real state: only
// harness-only scenarios use them.
var harnessOnlyKinds = []string{"operator.kill_switch"}

// StepKinds is the closed `do` catalog.
var StepKinds = []string{
	"agent.call", "agent.direct", "agent.child", "agent.steal", "sandbox.probe",
	"sim.mutate", "person.approve", "person.decline", "operator.revoke_grant",
	"operator.kill_switch", "server.read", "target.replay", "wait", "check.receipt", "browser.call",
}

// Per-kind `with` shapes. Decoding is strict: an unknown field is an error.
type (
	callWith struct {
		Face       string         `json:"face"`
		Connection string         `json:"connection"`
		Tool       string         `json:"tool,omitempty"`
		Method     string         `json:"method,omitempty"`
		Path       string         `json:"path,omitempty"`
		Args       jsontext.Value `json:"args,omitempty"`
		Body       jsontext.Value `json:"body,omitempty"`
		Instance   string         `json:"instance,omitempty"`
		Concurrent int            `json:"concurrent,omitempty"`
		ActionOf   string         `json:"action_of,omitempty"`
		Fault      string         `json:"fault,omitempty"`
	}
	directWith struct {
		Connection string         `json:"connection"`
		Method     string         `json:"method"`
		Path       string         `json:"path"`
		Body       jsontext.Value `json:"body,omitempty"`
		Credential string         `json:"credential,omitempty"`
	}
	childWith struct {
		Grant struct {
			Widen []string `json:"widen"`
		} `json:"grant"`
		Then callWith `json:"then"`
	}
	stealWith struct {
		Mode string   `json:"mode"`
		Call callWith `json:"call"`
	}
	probeWith struct {
		Probe string `json:"probe"`
	}
	mutateWith struct {
		Sim    string         `json:"sim"`
		Change string         `json:"change"`
		Args   jsontext.Value `json:"args,omitempty"`
	}
	personWith struct {
		Step string `json:"step"`
		As   string `json:"as"`
	}
	readWith struct {
		Object string `json:"object"`
		Org    string `json:"org,omitempty"`
	}
	replayWith struct {
		Of string `json:"of"`
	}
	waitWith struct {
		For        string `json:"for"`
		Of         string `json:"of"`
		MaxSeconds int    `json:"max_seconds"`
	}
	receiptWith struct {
		Of  string   `json:"of"`
		Has []string `json:"has"`
	}
	emptyWith struct{}
	// browserWith is one request a page sends with the person's session
	// cookie (G0 UI, RT-060, RT-061): to the Connect API or the live
	// operations stream, from a page whose origin the step names, with or
	// without the PC-CSRF header, the bearer token as well, a method and a
	// body type. Never a host or URL.
	browserWith struct {
		Target string `json:"target"`
		Origin string `json:"origin"`
		CSRF   bool   `json:"csrf,omitzero"`
		Bearer bool   `json:"bearer,omitzero"`
		Method string `json:"method"`
		Body   string `json:"body"`
	}
)

// browser.call allow-lists.
var (
	browserTargets = []string{"api", "ops_stream"}
	// same_origin: Sec-Fetch-Site same-origin and the public Origin;
	// origin_only: no Fetch Metadata, the public Origin; the rest are
	// another site's page, a sibling subdomain, a typed URL, another
	// Origin without Fetch Metadata, and no proof at all.
	browserOrigins = []string{"same_origin", "origin_only", "cross_site", "same_site", "typed_url", "other_origin", "no_proof"}
	browserMethods = []string{"POST", "GET"}
	browserBodies  = []string{"json", "proto", "form", "text"}
)

// CustomerStepKinds are the step kinds a customer (CX-###) scenario may
// use: the kinds the live driver runs, none with harness powers (G0 M17
// D126). internal/redteam/adapters/live tests that the two agree.
var CustomerStepKinds = []string{
	"agent.call", "agent.child", "agent.steal", "target.replay", "wait", "check.receipt", "person.approve", "person.decline",
}

// CustomerCapabilities are the requires a customer scenario may name: what
// a live range can set up. Sandbox probes, a second org, a browser session
// and the simulator swaps belong to the harness.
var CustomerCapabilities = []string{
	"github", "payments", "mcp", "person", "stripe.refund", "stripe.transfer", "pg.query", "slack.post",
	"authzen.evaluate", "a2a.send", "jira.comment", "gitlab.merge", "gitlab.deploy",
}

// KnownCapabilities returns every capability a scenario may require.
func KnownCapabilities() []string { return slices.Clone(capabilities) }

// validateCustomer applies the limits of a customer scenario (D126): it is
// business-tier, never harness-only, uses only live-driver step kinds and
// requires only what a live range provides.
func (s *Scenario) validateCustomer() error {
	switch {
	case s.Tier != "business":
		return invalid("a customer scenario (CX-###) is tier business")
	case s.HarnessOnly:
		return invalid("a customer scenario (CX-###) cannot be harness_only")
	}
	for _, r := range s.Requires {
		if !slices.Contains(CustomerCapabilities, r) {
			return invalid("a customer scenario (CX-###) requires only %v, not %q", CustomerCapabilities, r)
		}
	}
	for i, st := range s.Steps {
		if !slices.Contains(CustomerStepKinds, st.Do) {
			return invalid("step %d (%s): a customer scenario (CX-###) uses only %v, not %q", i+1, st.ID, CustomerStepKinds, st.Do)
		}
	}
	return nil
}

// CheckFileName checks that a file named <id>-<slug>.yaml carries this scenario's id.
func (s *Scenario) CheckFileName(base string) error {
	m := fileNameRE.FindStringSubmatch(base)
	if m == nil || m[1] != s.ID {
		return invalid("%s: the filename must be %s-<slug>.yaml", base, s.ID)
	}
	return nil
}

// Validate checks a decoded scenario against the format rules (D9).
func (s *Scenario) Validate() error {
	switch {
	case s.APIVersion != APIVersion:
		return invalid("apiVersion must be %s", APIVersion)
	case !idPattern.MatchString(s.ID):
		return invalid("id %q must match RT-### or CX-###", s.ID)
	case s.Title == "" || len(s.Title) > MaxTitleLen:
		return invalid("title must be 1..%d bytes", MaxTitleLen)
	case hasUnsafeRune(s.Title):
		return invalid("title must not hold control or bidirectional-control characters")
	case !slices.Contains(categories, s.Category):
		return invalid("category must be one of %v", categories)
	case !slices.Contains(suites, s.Suite):
		return invalid("suite must be one of %v", suites)
	case !slices.Contains(tiers, s.Tier):
		return invalid("tier must be one of %v", tiers)
	case !attackerRE.MatchString(s.Attacker):
		return invalid("attacker must be A1..A12")
	case len(s.Steps) == 0 || len(s.Steps) > MaxSteps:
		return invalid("a scenario has 1..%d steps", MaxSteps)
	}
	customer := OriginOf(s.ID) == OriginCustomer
	if customer {
		if err := s.validateCustomer(); err != nil {
			return err
		}
	}
	// A customer scenario may leave threats and rules out; any it names are
	// real T-### and HR-### ids (D126).
	if err := listOf("threats", s.Threats, threatRE, !customer); err != nil {
		return err
	}
	if err := listOf("rules", s.Rules, ruleRE, !customer); err != nil {
		return err
	}
	for _, r := range s.Requires {
		if !slices.Contains(capabilities, r) {
			return invalid("requires %q must be one of %v", r, capabilities)
		}
	}
	if err := unique("requires", s.Requires); err != nil {
		return err
	}

	earlier := map[string]bool{} // step ids seen so far
	known := map[string]bool{}   // saved value names defined by earlier steps
	for i := range s.Steps {
		st := &s.Steps[i]
		at := fmt.Sprintf("step %d (%s)", i+1, st.ID)
		if !stepIDPattern.MatchString(st.ID) {
			return invalid("step %d: id %q must match [a-z0-9-]{1,40}", i+1, st.ID)
		}
		if earlier[st.ID] {
			return invalid("%s: duplicate step id", at)
		}
		if !slices.Contains(StepKinds, st.Do) {
			return invalid("%s: unknown step kind %q", at, st.Do)
		}
		if slices.Contains(harnessOnlyKinds, st.Do) && !s.HarnessOnly {
			return invalid("%s: %s needs harness_only: true", at, st.Do)
		}
		if st.Do == "browser.call" && !slices.Contains(s.Requires, "browser") {
			return invalid("%s: browser.call needs requires: [browser]", at)
		}
		with, err := st.withJSON()
		if err != nil {
			return invalid("%s: %v", at, err)
		}
		if err := checkWith(st.Do, with, earlier); err != nil {
			return invalid("%s: %v", at, err)
		}
		refs, err := References(with)
		if err != nil {
			return invalid("%s: %v", at, err)
		}
		concurrent := 0
		if st.Do == "agent.call" {
			var cw callWith
			_ = json.Unmarshal(with, &cw)
			concurrent = cw.Concurrent
		}
		for _, r := range refs {
			if r == "n" && concurrent > 0 {
				continue
			}
			if !strings.HasPrefix(r, "fixture.") && !known[r] {
				return invalid("%s: ${%s} is not a value saved by an earlier step", at, r)
			}
		}
		if err := st.Expect.validate(st.Do, earlier, concurrent); err != nil {
			return invalid("%s: %v", at, err)
		}
		for name, ptr := range st.Save {
			if !saveNameRE.MatchString(name) || known[name] || name == "n" {
				return invalid("%s: save name %q must match [a-z][a-z0-9_]{0,31} and be new", at, name)
			}
			if !validPointer(ptr) {
				return invalid("%s: save %q: %q is not an RFC 6901 pointer", at, name, ptr)
			}
		}
		if len(st.Save) > 8 {
			return invalid("%s: at most 8 saves", at)
		}
		for name := range st.Save {
			known[name] = true
		}
		earlier[st.ID] = true
	}
	return nil
}

func (st *Step) withJSON() (jsontext.Value, error) {
	if len(st.With) == 0 {
		return jsontext.Value("{}"), nil
	}
	if st.With.Kind() != '{' {
		return nil, fmt.Errorf("with must be a mapping")
	}
	return st.With, nil
}

// CheckResolvedWith re-validates a step's `with` after substitution, so a
// saved value cannot smuggle a host, URL or unknown field in (T-092).
func CheckResolvedWith(kind string, with []byte, earlier map[string]bool) error {
	return checkWith(kind, with, earlier)
}

func checkWith(kind string, with []byte, earlier map[string]bool) error {
	strict := func(v any) error {
		if err := json.Unmarshal(with, v, json.RejectUnknownMembers(true)); err != nil {
			return err
		}
		return nil
	}
	switch kind {
	case "agent.call":
		var w callWith
		if err := strict(&w); err != nil {
			return err
		}
		return w.validate(true, earlier)
	case "agent.direct":
		var w directWith
		if err := strict(&w); err != nil {
			return err
		}
		if !roleRE.MatchString(w.Connection) {
			return fmt.Errorf("connection must be a role name, not an address")
		}
		if !slices.Contains(methods, w.Method) {
			return fmt.Errorf("method must be one of %v", methods)
		}
		if err := checkPath(w.Path); err != nil {
			return err
		}
		if w.Credential != "" && !slices.Contains(credentials, w.Credential) {
			return fmt.Errorf("credential must be one of %v", credentials)
		}
		return checkDepth("body", w.Body)
	case "agent.child":
		var w childWith
		if err := strict(&w); err != nil {
			return err
		}
		if len(w.Grant.Widen) == 0 {
			return fmt.Errorf("grant.widen needs at least one of %v", widenings)
		}
		for _, x := range w.Grant.Widen {
			if !slices.Contains(widenings, x) {
				return fmt.Errorf("grant.widen %q must be one of %v", x, widenings)
			}
		}
		if err := unique("grant.widen", w.Grant.Widen); err != nil {
			return err
		}
		return w.Then.validate(false, earlier)
	case "agent.steal":
		var w stealWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(stealModes, w.Mode) {
			return fmt.Errorf("mode must be one of %v", stealModes)
		}
		return w.Call.validate(false, earlier)
	case "sandbox.probe":
		var w probeWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(probes, w.Probe) {
			return fmt.Errorf("probe must be one of %v", probes)
		}
	case "sim.mutate":
		var w mutateWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(sims, w.Sim) || !slices.Contains(simChanges, w.Change) {
			return fmt.Errorf("sim must be one of %v and change one of %v", sims, simChanges)
		}
		if slices.Contains(slackChanges, w.Change) && w.Sim != "slack" {
			return fmt.Errorf("change %s is only for sim slack", w.Change)
		}
		return checkDepth("args", w.Args)
	case "person.approve", "person.decline":
		var w personWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(personRoles, w.As) {
			return fmt.Errorf("as must be one of %v", personRoles)
		}
		return needEarlier("step", w.Step, earlier)
	case "operator.revoke_grant", "operator.kill_switch":
		var w emptyWith
		return strict(&w)
	case "server.read":
		var w readWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(readObjects, w.Object) || (w.Org != "" && w.Org != "other") {
			return fmt.Errorf("object must be one of %v and org empty or \"other\"", readObjects)
		}
	case "target.replay":
		var w replayWith
		if err := strict(&w); err != nil {
			return err
		}
		return needEarlier("of", w.Of, earlier)
	case "wait":
		var w waitWith
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(waitFor, w.For) || w.MaxSeconds < 1 || w.MaxSeconds > MaxWaitSecond {
			return fmt.Errorf("for must be one of %v and max_seconds 1..%d", waitFor, MaxWaitSecond)
		}
		return needEarlier("of", w.Of, earlier)
	case "check.receipt":
		var w receiptWith
		if err := strict(&w); err != nil {
			return err
		}
		if len(w.Has) == 0 {
			return fmt.Errorf("has needs at least one of %v", receiptHas)
		}
		for _, h := range w.Has {
			if !slices.Contains(receiptHas, h) {
				return fmt.Errorf("has %q must be one of %v", h, receiptHas)
			}
		}
		if err := unique("has", w.Has); err != nil {
			return err
		}
		return needEarlier("of", w.Of, earlier)
	case "browser.call":
		var w browserWith
		if err := strict(&w); err != nil {
			return err
		}
		switch {
		case !slices.Contains(browserTargets, w.Target):
			return fmt.Errorf("target must be one of %v", browserTargets)
		case !slices.Contains(browserOrigins, w.Origin):
			return fmt.Errorf("origin must be one of %v", browserOrigins)
		case !slices.Contains(browserMethods, w.Method):
			return fmt.Errorf("method must be one of %v", browserMethods)
		case !slices.Contains(browserBodies, w.Body):
			return fmt.Errorf("body must be one of %v", browserBodies)
		}
	default:
		if kind == "support.probe" {
			return supportStep(strict)
		}
		if ui, ok := uiStepKinds[kind]; ok {
			return ui(strict)
		}
		if m13, ok := m13StepKinds[kind]; ok {
			return m13(strict)
		}
		return fmt.Errorf("unknown step kind %q", kind)
	}
	return nil
}

// validate checks one call. Steps never name a host or URL: targets are
// connection roles the driver binds to simulated connections.
func (w *callWith) validate(top bool, earlier map[string]bool) error {
	if !top && (w.Concurrent != 0 || w.ActionOf != "" || w.Fault != "") {
		return fmt.Errorf("concurrent, action_of and fault belong to a top-level agent.call")
	}
	if w.Concurrent != 0 && (w.Concurrent < 2 || w.Concurrent > MaxConcurrent) {
		return fmt.Errorf("concurrent must be 2..%d", MaxConcurrent)
	}
	if w.ActionOf != "" {
		if err := needEarlier("action_of", w.ActionOf, earlier); err != nil {
			return err
		}
	}
	if w.Fault != "" && (w.Fault != "gateway_unreachable" || w.Face != "hook") {
		return fmt.Errorf("fault must be gateway_unreachable and only with face hook")
	}
	if !slices.Contains(faces, w.Face) {
		return fmt.Errorf("face must be one of %v", faces)
	}
	if !roleRE.MatchString(w.Connection) {
		return fmt.Errorf("connection must be a role name, not an address")
	}
	if w.Instance != "" && !slices.Contains(instances, w.Instance) {
		return fmt.Errorf("instance must be one of %v", instances)
	}
	byTool := w.Tool != ""
	byPath := w.Method != "" || w.Path != ""
	switch {
	case byTool && byPath:
		return fmt.Errorf("a call names a tool or a method and path, not both")
	case w.Face == "http" && !byPath, (w.Face == "mcp" || w.Face == "hook") && !byTool:
		return fmt.Errorf("face %s needs %s", w.Face, map[bool]string{true: "method and path", false: "tool"}[w.Face == "http"])
	case w.Face == "sdk" && !byTool && !byPath:
		return fmt.Errorf("face sdk needs a tool or a method and path")
	case (w.Face == "mcp" || w.Face == "hook") && byPath, w.Face == "http" && byTool:
		return fmt.Errorf("face %s does not take that form", w.Face)
	}
	if byTool {
		if !toolRE.MatchString(w.Tool) {
			return fmt.Errorf("tool %q has characters outside [A-Za-z0-9_.:/-]", w.Tool)
		}
		if len(w.Body) > 0 {
			return fmt.Errorf("body goes with method and path; use args with a tool")
		}
		if len(w.Args) > 0 && w.Args.Kind() != '{' {
			return fmt.Errorf("args must be a mapping")
		}
		return checkDepth("args", w.Args)
	}
	if !slices.Contains(methods, w.Method) {
		return fmt.Errorf("method must be one of %v", methods)
	}
	if err := checkPath(w.Path); err != nil {
		return err
	}
	if len(w.Args) > 0 {
		return fmt.Errorf("args goes with a tool; use body with method and path")
	}
	return checkDepth("body", w.Body)
}

func checkPath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "://"):
		return fmt.Errorf("path %q must be a path starting with a single /, never a URL", truncate(p))
	case strings.ContainsAny(p, "\\@ \t\r\n") || len(p) > 2048:
		return fmt.Errorf("path %q has characters a path cannot hold", truncate(p))
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("path %q has a .. segment", truncate(p))
		}
	}
	return nil
}

func checkDepth(what string, v jsontext.Value) error {
	if len(v) == 0 {
		return nil
	}
	d, err := jsonDepth(v)
	if err != nil {
		return err
	}
	if d > MaxArgsDepth {
		return fmt.Errorf("%s nests deeper than %d", what, MaxArgsDepth)
	}
	return nil
}

func needEarlier(field, id string, earlier map[string]bool) error {
	if !earlier[id] {
		return fmt.Errorf("%s %q must name an earlier step", field, id)
	}
	return nil
}

func (e Expect) validate(kind string, earlier map[string]bool, concurrent int) error {
	if e.MaxAllow != nil && (concurrent == 0 || *e.MaxAllow < 0 || *e.MaxAllow > concurrent) {
		return fmt.Errorf("expect.max_allow needs a concurrent call and a value 0..concurrent")
	}
	if e.Outcome == "" && kindsNeedingEx[kind] && (kind != "agent.call" || concurrent == 0 || e.MaxAllow == nil) {
		return fmt.Errorf("expect.outcome is required for %s", kind)
	}
	if e.Outcome != "" && !e.Outcome.Valid() {
		return fmt.Errorf("expect.outcome %q is not an outcome", e.Outcome)
	}
	for _, f := range []struct{ name, v string }{{"reason", e.Reason}, {"code", e.Code}, {"decisive_control", e.DecisiveControl}} {
		if f.v != "" && !tokenRE.MatchString(f.v) {
			return fmt.Errorf("expect.%s %q has characters outside [A-Za-z0-9_.:-]", f.name, f.v)
		}
	}
	if e.SameDecisionAs != "" {
		return needEarlier("expect.same_decision_as", e.SameDecisionAs, earlier)
	}
	return nil
}

// validPointer reports an RFC 6901 pointer that names a value (not the document).
func validPointer(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' && (i+1 >= len(p) || (p[i+1] != '0' && p[i+1] != '1')) {
			return false
		}
	}
	return true
}

func listOf(name string, v []string, re *regexp.Regexp, required bool) error {
	if required && len(v) == 0 {
		return invalid("%s needs at least one entry", name)
	}
	for _, x := range v {
		if !re.MatchString(x) {
			return invalid("%s: %q does not match %s", name, x, re)
		}
	}
	return unique(name, v)
}

func unique(name string, v []string) error {
	seen := map[string]bool{}
	for _, x := range v {
		if seen[x] {
			return invalid("%s: duplicate %q", name, x)
		}
		seen[x] = true
	}
	return nil
}

// hasUnsafeRune reports a control character (C0, C1, DEL) or a Unicode
// bidirectional control, which could make a title read differently from
// what it is.
func hasUnsafeRune(s string) bool {
	for _, r := range s {
		switch {
		case unicode.IsControl(r), r == 0x061C, r == 0x200E, r == 0x200F,
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			return true
		}
	}
	return false
}
