// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Bounds of a v2 graph (D301). MaxNodes keeps step_index inside its CHECK.
const (
	MaxNodes     = 40
	MaxPaths     = 64
	MaxPathDepth = 20
)

// guardStepRef finds the steps a guard reads. A guard that reaches them
// another way fails closed at run time.
var guardStepRef = regexp.MustCompile(`\bsteps\s*\.\s*([a-z][a-z0-9_-]{0,62})\b`)

// Paths lists every path from the entry to where it ends, as node ids. ok
// is false on a cycle, or past limit paths.
func (f *Flow) Paths(limit int) ([][]string, bool) {
	var out [][]string
	on := map[string]bool{}
	var walk func(id string, path []string) bool
	walk = func(id string, path []string) bool {
		if on[id] {
			return false
		}
		path = append(slices.Clip(path), id)
		n := f.Node(id)
		var edges []Edge
		if n != nil {
			edges = n.Edges()
		}
		if len(edges) == 0 {
			out = append(out, path)
			return len(out) <= limit
		}
		on[id] = true
		defer delete(on, id)
		for _, e := range edges {
			if !walk(e.To, path) {
				return false
			}
		}
		return true
	}
	if f.Entry == "" {
		return nil, true
	}
	if !walk(f.Entry, nil) {
		return nil, false
	}
	return out, true
}

// Before lists, per node, the nodes that precede it on every path that
// reaches it (D301 NOT_ON_ALL_PATHS).
func Before(paths [][]string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, p := range paths {
		for i, id := range p {
			prior := make(map[string]bool, i)
			for _, x := range p[:i] {
				prior[x] = true
			}
			have, seen := out[id]
			if !seen {
				out[id] = prior
				continue
			}
			for x := range have {
				if !prior[x] {
					delete(have, x)
				}
			}
		}
	}
	return out
}

// analyze prepares what the node checks share. It reports nothing: with a
// cycle or too many paths the path-wise checks are skipped, and nodes()
// refuses the graph itself.
func (v *validator) analyze() {
	v.flow = v.d.Flow()
	v.nodeAt = make(map[string]string, len(v.flow.Nodes))
	for i := range v.flow.Nodes {
		if _, dup := v.nodeAt[v.flow.Nodes[i].ID]; !dup {
			v.nodeAt[v.flow.Nodes[i].ID] = "/nodes/" + strconv.Itoa(i)
		}
	}
	v.before = map[string]bool{}
	if len(v.flow.Nodes) > MaxNodes {
		return
	}
	if paths, ok := v.flow.Paths(MaxPaths); ok {
		v.paths, v.pathsKnown = paths, true
		v.beforeNode = Before(paths)
	}
}

// precedes reports whether id runs before the node being checked on every
// path. A graph already refused does not repeat the finding.
func (v *validator) precedes(id string) bool { return !v.pathsKnown || v.before[id] }

// earlierStep checks a reference to an earlier step of a kind: on v2 it
// must precede its user on every path.
func (v *validator) earlierStep(at string, seen map[string]int, id, kind, msg string) {
	switch {
	case !v.d.IsV2():
		if !earlier(seen, id) || v.stepKind(id) != kind {
			v.err(CodeLimitRange, at, "%s", msg)
		}
	case v.stepKind(id) != kind:
		v.err(CodeLimitRange, at, "%s", msg)
	case !v.precedes(id):
		v.err(CodeNotOnAllPaths, at, "%q does not run before this on every path", id)
	}
}

// guard checks a branch, case or step guard: the `when` grammar, and steps
// it reads precede it on every path.
func (v *validator) guard(at, src string) {
	v.expr(at, src)
	if err := CompileGuard(src); err != nil {
		v.err(CodeLimitRange, at, "not a guard expression: %v", err)
		return
	}
	for _, m := range guardStepRef.FindAllStringSubmatch(src, -1) {
		if !v.precedes(m[1]) {
			v.err(CodeNotOnAllPaths, at, "step %q does not run before this on every path", m[1])
		}
	}
}

// nodes checks a v2 graph (D301, HR-531): every error has its own code.
func (v *validator) nodes() {
	f := v.flow
	switch n := len(f.Nodes); {
	case n < 1:
		v.err(CodeLimitRange, "/nodes", "declare at least one node")
		return
	case n > MaxNodes:
		v.err(CodeLimitRange, "/nodes", "at most %d nodes", MaxNodes)
		return
	}
	seen := map[string]int{}
	for i := range f.Nodes {
		n := &f.Nodes[i]
		at := "/nodes/" + strconv.Itoa(i)
		v.before = v.beforeNode[n.ID]
		switch n.Kind() {
		case NodeKindStep:
			v.step(at, n.Spec(), seen, false)
			if n.When != "" {
				v.guard(at+"/when", n.When)
			}
		case NodeKindBranch, NodeKindSwitch, NodeKindJoin, NodeKindTerminal:
			v.nodeID(at, n.ID, seen)
		}
		seen[n.ID] = i
		v.targets(at, n)
		switch n.Kind() {
		case NodeKindBranch:
			v.guard(at+"/branch/when", n.Branch.When)
		case NodeKindSwitch:
			v.switchNode(at, n.Switch)
		case NodeKindJoin:
			v.joinNode(at, n)
		case NodeKindTerminal:
			v.terminalNode(at, n)
		case NodeKindStep:
		}
	}
	v.before = map[string]bool{}
	v.reachable()
	v.cycles()
	if len(f.Nodes) <= MaxNodes && !v.pathsKnown && !v.hasCycle {
		v.err(CodeLimitRange, "/nodes", "at most %d paths", MaxPaths)
	}
	for _, p := range v.paths {
		if len(p)-1 > MaxPathDepth {
			v.err(CodeLimitRange, "/nodes", "a path has %d nodes; at most %d", len(p)-1, MaxPathDepth)
			break
		}
	}
}

func (v *validator) nodeID(at, id string, seen map[string]int) {
	if !stepIDFormat.MatchString(id) {
		v.err(CodeLimitRange, at+"/id", "a node id is a lowercase slug")
	} else if _, dup := seen[id]; dup {
		v.err(CodeLimitRange, at+"/id", "node id %q is used twice", id)
	}
}

// targets checks every way out of a node leads to a node.
func (v *validator) targets(at string, n *NodeSpec) {
	check := func(p, to string) {
		switch {
		case to == "":
			v.err(CodePathNotTerminated, at+p, "this path ends here without a terminal node")
		case v.flow.Node(to) == nil:
			v.err(CodePathNotTerminated, at+p, "node %q does not exist", to)
		}
	}
	switch n.Kind() {
	case NodeKindStep, NodeKindJoin:
		check("/next", n.Next)
	case NodeKindBranch:
		check("/branch/then", n.Branch.Then)
		check("/branch/else", n.Branch.Else)
	case NodeKindSwitch:
		for i, c := range n.Switch.Cases {
			check("/switch/cases/"+strconv.Itoa(i)+"/next", c.Next)
		}
		if n.Switch.Default != "" {
			check("/switch/default", n.Switch.Default)
		}
	case NodeKindTerminal:
	}
}

func (v *validator) switchNode(at string, s *SwitchSpec) {
	if s.Default == "" {
		v.err(CodeSwitchNoDefault, at+"/switch/default", "a switch needs a default")
	}
	if len(s.Cases) == 0 {
		v.err(CodeSwitchNoDefault, at+"/switch/cases", "a switch needs at least one case")
	}
	guards := map[string]bool{}
	for i, c := range s.Cases {
		p := at + "/switch/cases/" + strconv.Itoa(i) + "/when"
		if guards[c.When] {
			v.err(CodeSwitchNoDefault, p, "this case repeats an earlier one")
		}
		guards[c.When] = true
		v.guard(p, c.When)
	}
}

// joinNode: From is exactly the direct predecessors, and ALL of two or more
// could never hold, since paths are exclusive (D307).
func (v *validator) joinNode(at string, n *NodeSpec) {
	var preds []string
	for i := range v.flow.Nodes {
		for _, e := range v.flow.Nodes[i].Edges() {
			if e.To == n.ID && !slices.Contains(preds, v.flow.Nodes[i].ID) {
				preds = append(preds, v.flow.Nodes[i].ID)
			}
		}
	}
	from := slices.Sorted(slices.Values(n.Join.From))
	slices.Sort(preds)
	switch {
	case n.Join.Mode != JoinAny && n.Join.Mode != JoinAll:
		v.err(CodeJoinInvalid, at+"/join/mode", "mode is ANY or ALL")
	case len(from) == 0:
		v.err(CodeJoinInvalid, at+"/join/from", "a join needs a node that leads to it")
	case !slices.Equal(from, preds):
		v.err(CodeJoinInvalid, at+"/join/from", "from lists exactly the nodes that lead here: %s", strings.Join(preds, ", "))
	case n.Join.Mode == JoinAll && len(from) > 1:
		v.err(CodeJoinInvalid, at+"/join/mode", "paths are mutually exclusive, so ALL of %d nodes could never hold: use ANY", len(from))
	}
}

func (v *validator) terminalNode(at string, n *NodeSpec) {
	if !n.Outcome.Valid() {
		v.err(CodeTerminalMissing, at+"/outcome", "outcome is SUCCEEDED, PARTIALLY_COMPLETED or FAILED")
	}
	if len(n.FinishWhen) == 0 {
		v.err(CodeTerminalMissing, at+"/finish_when", "say what proves this path is done (finish_when)")
	}
	for i, f := range n.FinishWhen {
		p := at + "/finish_when/" + strconv.Itoa(i)
		if v.finishEntry(p, f) && !v.precedes(f.Step) {
			v.err(CodeNotOnAllPaths, p+"/step", "%q does not run before this terminal on every path", f.Step)
		}
	}
}

// reachable: every node can be reached from the entry (HR-531).
func (v *validator) reachable() {
	seen := map[string]bool{}
	var walk func(id string)
	walk = func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		if n := v.flow.Node(id); n != nil {
			for _, e := range n.Edges() {
				walk(e.To)
			}
		}
	}
	walk(v.flow.Entry)
	for i := range v.flow.Nodes {
		if !seen[v.flow.Nodes[i].ID] {
			v.err(CodeUnreachableNode, "/nodes/"+strconv.Itoa(i), "nothing leads to node %q", v.flow.Nodes[i].ID)
		}
	}
}

// cycles refuses every loop, reachable or not (HR-531): retry is the only
// repetition.
func (v *validator) cycles() {
	const (
		visiting = 1
		finished = 2
	)
	state := map[string]int{}
	var walk func(id string)
	walk = func(id string) {
		state[id] = visiting
		if n := v.flow.Node(id); n != nil {
			for _, e := range n.Edges() {
				switch state[e.To] {
				case visiting:
					v.hasCycle = true
					v.err(CodeCycle, v.nodeAt[id], "%q leads back to %q: loops are not allowed, retry is the only repetition", id, e.To)
				case 0:
					walk(e.To)
				}
			}
		}
		state[id] = finished
	}
	for i := range v.flow.Nodes {
		if id := v.flow.Nodes[i].ID; state[id] == 0 {
			walk(id)
		}
	}
}

// compensation checks a v2 entry's link to the node it answers (D307): it
// reads what preceded that node, and that node.
func (v *validator) compensation(at string, s StepSpec) {
	n := v.flow.Node(s.Compensates)
	switch {
	case s.Compensates == "":
		v.err(CodeLimitRange, at+"/compensates", "name the step node this compensates")
	case n == nil || n.Kind() != NodeKindStep:
		v.err(CodeLimitRange, at+"/compensates", "%q is not a step node", s.Compensates)
	case !Catalog[n.Step].Effectful:
		v.err(CodeLimitRange, at+"/compensates", "%s changes nothing to compensate", n.Step)
	}
	v.before = map[string]bool{s.Compensates: true}
	for x := range v.beforeNode[s.Compensates] {
		v.before[x] = true
	}
	if s.When != "" {
		v.guard(at+"/when", s.When)
	}
}

// pathChecks hold the authority rules per path (HR-532, T-230). Each path is
// checked alone, and the whole-definition checks stay: the stricter applies.
func (v *validator) pathChecks() {
	reported := map[string]bool{}
	once := func(code, at, msg string, args ...any) {
		if k := code + "\x00" + at + "\x00" + args[0].(string); !reported[k] { //nolint:forcetypeassert // always a string here
			reported[k] = true
			v.err(code, at, msg, args...)
		}
	}
	for _, p := range v.paths {
		launches := 0
		for i, id := range p {
			n := v.flow.Node(id)
			if n == nil || n.Kind() != NodeKindStep {
				continue
			}
			at := v.nodeAt[id]
			if k, ok := Catalog[n.Step]; ok && k.NeedsPlatformScope() {
				if _, declared := v.platformScopes(n.Step); !declared {
					once(CodePathOutsideCeiling, at+"/step", "%s runs on the path %s without being listed under authority.platform", n.Step, pathText(p))
				}
			}
			if n.Step != KindLaunchRun {
				continue
			}
			launches++
			w, err := n.Spec().DecodeWith()
			lw, ok := w.(*LaunchRunWith)
			if err != nil || !ok {
				continue
			}
			v.launchOnPath(at, n, lw, p, once)
			v.waitsOnPath(at, n, lw, p, p[i+1:], once)
		}
		if c := v.d.Authority.Ceiling; c != nil && launches > c.PerDay.Grants {
			once(CodePathOutsideCeiling, "/authority/ceiling/per_day/grants", "%s launches %d runs; the ceiling allows %d grants a day", pathText(p), launches, c.PerDay.Grants)
		}
	}
}

func (v *validator) launchOnPath(at string, n *NodeSpec, lw *LaunchRunWith, p []string, once func(code, at, msg string, args ...any)) {
	c := v.d.Authority.Ceiling
	if c == nil {
		once(CodePathOutsideCeiling, at, "%s launches on the path %s without a ceiling", n.ID, pathText(p))
		return
	}
	if !slices.Contains(c.Agents, lw.Agent) {
		once(CodePathOutsideCeiling, at+"/with/agent", "%s launches an agent outside the ceiling on the path %s", n.ID, pathText(p))
	}
	if lw.Grant.Operations != nil && c.Bounds.Operations != nil {
		if op, ok := lw.Grant.Operations.Within(*c.Bounds.Operations); !ok {
			once(CodePathOutsideCeiling, at+"/with/grant/operations", "%s may run %s outside the ceiling on the path %s", n.ID, op, pathText(p))
		}
	}
}

// waitsOnPath: every irreversible operation a launch may perform needs a
// wait_effect on it after the launch, on this same path. A guarded wait may
// be skipped, so it does not count.
func (v *validator) waitsOnPath(at string, n *NodeSpec, lw *LaunchRunWith, p, rest []string, once func(code, at, msg string, args ...any)) {
	for _, op := range v.ops {
		info, ok := v.infos[op]
		if !ok || !info.Irreversible {
			continue
		}
		if lw.Grant.Operations != nil && !lw.Grant.Operations.Matches(op) {
			continue
		}
		covered := slices.ContainsFunc(rest, func(id string) bool {
			x := v.flow.Node(id)
			if x == nil || x.Step != KindWaitEffect || x.When != "" {
				return false
			}
			w, err := x.Spec().DecodeWith()
			we, isWait := w.(*WaitEffectWith)
			return err == nil && isWait && we.Step == n.ID && (gdomain.Ops{op}.Matches(we.Operation) || we.Operation == op)
		})
		if !covered {
			once(CodeIrreversibleUnwaitedOnPath, at, "%s cannot be undone: the path %s needs a wait_effect on it after %s", op, pathText(p), n.ID)
		}
	}
}

func pathText(p []string) string { return strings.Join(p, " > ") }
