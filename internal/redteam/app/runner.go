// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app runs range scenarios (HR-223) against a Driver: ordered steps,
// substitution of saved values, no retries, stop on the first mismatch.
package app

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// Capability is something a driver can offer a scenario.
type Capability string

// The capabilities. "requires" in a scenario names the first six; Harness
// marks a driver allowed to run harness_only scenarios.
const (
	CapGitHub    Capability = "github"
	CapPayments  Capability = "payments"
	CapMCP       Capability = "mcp"
	CapSandbox   Capability = "sandbox"
	CapPerson    Capability = "person"
	CapSecondOrg Capability = "second_org"
	CapHarness   Capability = "harness"
)

// Fixture is the driver's per-scenario values, referenced as ${fixture.<name>}.
type Fixture map[string]string

// Driver executes steps against simulators. Targets are connection roles the
// driver binds itself; a step never names a host.
type Driver interface {
	// Supports reports whether the driver can run a step kind. A scenario with
	// a step the driver lacks is SKIPPED before Setup, never ERROR.
	Supports(kind string) bool
	Capabilities() map[Capability]bool
	Setup(ctx context.Context, s domain.Scenario) (Fixture, error)
	Do(ctx context.Context, s domain.Scenario, st domain.Step, vars map[string]string) (domain.Observation, error)
	Teardown(ctx context.Context, s domain.Scenario) error
}

// DefaultTimeout is the per-scenario limit.
const DefaultTimeout = 60 * time.Second

const teardownTimeout = 10 * time.Second

// Runner runs scenarios over a Driver.
type Runner struct {
	Driver  Driver
	Timeout time.Duration // 0 = DefaultTimeout
}

// Run runs one scenario. It never retries a step.
func (r *Runner) Run(ctx context.Context, s domain.Scenario) (res domain.Result) {
	res = domain.Result{ScenarioID: s.ID}
	// A scenario is validated here too: a Scenario built in code, not parsed,
	// never reaches the driver unchecked.
	if err := s.Validate(); err != nil {
		res.Verdict, res.Detail = domain.VerdictError, err.Error()
		return res
	}
	digest, err := domain.Digest(&s)
	if err != nil {
		res.Verdict, res.Detail = domain.VerdictError, err.Error()
		return res
	}
	res.Digest = digest
	if why := r.skipReason(s); why != "" {
		res.Verdict, res.Detail = domain.VerdictSkipped, why
		return res
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	fixture, err := r.Driver.Setup(ctx, s)
	// Teardown always runs, even after a failed Setup or a timeout.
	defer func() {
		tctx, tcancel := context.WithTimeout(context.WithoutCancel(ctx), teardownTimeout)
		defer tcancel()
		if err := r.Driver.Teardown(tctx, s); err != nil && res.Verdict == domain.VerdictPass {
			res.Verdict, res.Detail = domain.VerdictError, "teardown: "+err.Error()
		}
	}()
	if err != nil {
		res.Verdict, res.Detail = domain.VerdictError, "setup: "+err.Error()
		return res
	}

	vars := map[string]string{}
	for k, v := range fixture {
		vars["fixture."+k] = v
	}
	seen := map[string]domain.Observation{}
	ids := map[string]bool{}
	for _, st := range s.Steps {
		sr, verdict, detail := r.step(ctx, s, st, vars, seen, ids)
		res.Steps = append(res.Steps, sr)
		if verdict != "" {
			res.Verdict, res.Detail = verdict, fmt.Sprintf("step %s: %s", st.ID, detail)
			return res
		}
		seen[st.ID] = sr.Observed
		ids[st.ID] = true
	}
	res.Verdict = domain.VerdictPass
	return res
}

// RunAll runs the scenarios in order and returns their results.
func (r *Runner) RunAll(ctx context.Context, set []Loaded) []domain.Result {
	out := make([]domain.Result, 0, len(set))
	for _, l := range set {
		out = append(out, r.Run(ctx, l.Scenario))
	}
	return out
}

// Entries converts results to baseline entries.
func Entries(results []domain.Result) []domain.Entry {
	out := make([]domain.Entry, len(results))
	for i, r := range results {
		out[i] = domain.Entry{ID: r.ScenarioID, Digest: r.Digest, Verdict: r.Verdict}
	}
	return out
}

func (r *Runner) skipReason(s domain.Scenario) string {
	caps := r.Driver.Capabilities()
	for _, need := range s.Requires {
		if !caps[Capability(need)] {
			return "driver lacks capability " + need
		}
	}
	if s.HarnessOnly && !caps[CapHarness] {
		return "harness_only scenario under a non-harness driver"
	}
	for _, st := range s.Steps {
		if !r.Driver.Supports(st.Do) {
			return "driver lacks " + st.Do
		}
	}
	for _, st := range s.Steps {
		if strings.HasPrefix(st.Do, "person.") && !caps[CapPerson] {
			return "person step without an interactive operator"
		}
	}
	return ""
}

// step runs one step. A non-empty verdict ends the scenario.
func (r *Runner) step(ctx context.Context, s domain.Scenario, st domain.Step, vars map[string]string, seen map[string]domain.Observation, ids map[string]bool) (domain.StepResult, domain.Verdict, string) {
	sr := domain.StepResult{StepID: st.ID, Expect: st.Expect}
	if len(st.With) > 0 {
		subst := make(map[string]string, len(vars)+1)
		for k, v := range vars {
			subst[k] = v
		}
		subst["n"] = "${n}" // the driver fills n per concurrent call
		with, err := domain.Substitute(st.With, subst)
		if err == nil {
			err = domain.CheckResolvedWith(st.Do, with, ids)
		}
		if err != nil {
			return sr, domain.VerdictError, err.Error()
		}
		st.With = with
	}
	obs, err := r.Driver.Do(ctx, s, st, vars)
	if errors.Is(err, ErrUnsupported) {
		return sr, domain.VerdictSkipped, err.Error()
	}
	if err != nil {
		return sr, domain.VerdictError, err.Error()
	}
	if ctx.Err() != nil {
		return sr, domain.VerdictError, ctx.Err().Error()
	}
	if len(obs.Response) > domain.MaxResponseBytes {
		return sr, domain.VerdictError, "driver response over 64 KiB"
	}
	if st.Do == "agent.call" {
		var c struct {
			Concurrent int `json:"concurrent"`
		}
		_ = json.Unmarshal(st.With, &c)
		if len(obs.Each) != c.Concurrent && (c.Concurrent > 0 || len(obs.Each) > 0) {
			return sr, domain.VerdictError, fmt.Sprintf("driver returned %d observations for %d concurrent calls", len(obs.Each), c.Concurrent)
		}
	}
	sr.Observed = obs
	if len(obs.Missing) > 0 {
		sr.Mismatch = "the receipt lacks " + strings.Join(obs.Missing, ", ")
		return sr, domain.VerdictFail, sr.Mismatch
	}
	if why := mismatch(st.Expect, obs, seen); why != "" {
		sr.Mismatch = why
		return sr, domain.VerdictFail, why
	}
	for name, ptr := range st.Save {
		v, err := extract(obs.Response, ptr)
		if err != nil {
			sr.Mismatch = fmt.Sprintf("save %s: %v", name, err)
			return sr, domain.VerdictFail, sr.Mismatch
		}
		vars[name] = v
	}
	sr.Matched = true
	return sr, "", ""
}

func mismatch(e domain.Expect, o domain.Observation, seen map[string]domain.Observation) string {
	if len(o.Each) > 0 {
		return mismatchEach(e, o, seen)
	}
	if e.MaxAllow != nil {
		return "max_allow needs a concurrent step"
	}
	var bad []string
	if e.Outcome != "" && o.Outcome != e.Outcome {
		bad = append(bad, fmt.Sprintf("outcome %s, want %s", o.Outcome, e.Outcome))
	}
	if e.Reason != "" && o.Reason != e.Reason && !slices.Contains(o.Reasons, e.Reason) {
		bad = append(bad, fmt.Sprintf("reason %q, want %q", o.Reason, e.Reason))
	}
	if e.Code != "" && o.Code != e.Code {
		bad = append(bad, fmt.Sprintf("code %q, want %q", o.Code, e.Code))
	}
	if e.SameDecisionAs != "" {
		p := seen[e.SameDecisionAs]
		if p.Outcome != o.Outcome || p.Reason != o.Reason || p.Code != o.Code {
			bad = append(bad, fmt.Sprintf("decision %s/%s/%s differs from step %s (%s/%s/%s)",
				o.Outcome, o.Reason, o.Code, e.SameDecisionAs, p.Outcome, p.Reason, p.Code))
		}
	}
	return strings.Join(bad, "; ")
}

// extract resolves an RFC 6901 pointer into a JSON response and returns the
// scalar it names as text.
func extract(resp []byte, ptr string) (string, error) {
	if len(resp) == 0 {
		return "", errors.New("no response to read")
	}
	cur := jsontext.Value(resp)
	if !cur.IsValid() {
		return "", errors.New("response is not JSON")
	}
	for _, raw := range strings.Split(ptr[1:], "/") {
		tok := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch cur.Kind() { //nolint:exhaustive // the other kinds are not containers or scalars we save
		case '{':
			var m map[string]jsontext.Value
			if err := json.Unmarshal(cur, &m); err != nil {
				return "", fmt.Errorf("%s: %w", ptr, err)
			}
			v, ok := m[tok]
			if !ok {
				return "", fmt.Errorf("%s: no member %q", ptr, tok)
			}
			cur = v
		case '[':
			var a []jsontext.Value
			if err := json.Unmarshal(cur, &a); err != nil {
				return "", fmt.Errorf("%s: %w", ptr, err)
			}
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(a) || strconv.Itoa(i) != tok {
				return "", fmt.Errorf("%s: no element %q", ptr, tok)
			}
			cur = a[i]
		default:
			return "", fmt.Errorf("%s: cannot descend into a scalar at %q", ptr, tok)
		}
	}
	switch cur.Kind() { //nolint:exhaustive // the other kinds are not containers or scalars we save
	case '"':
		var s string
		if err := json.Unmarshal(cur, &s); err != nil {
			return "", err
		}
		return s, nil
	case '0', 't', 'f':
		return string(cur), nil
	}
	return "", fmt.Errorf("%s names a non-scalar value", ptr)
}

// Loaded is a scenario file read from disk.
type Loaded struct {
	File     string
	Scenario domain.Scenario
	Digest   string
}

// LoadDir loads every *.yaml scenario in dir, sorted by id. A bad file, a
// filename that does not carry its id, or a repeated id is an error.
func LoadDir(dir string) ([]Loaded, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var out []Loaded
	ids := map[string]string{}
	for _, f := range files {
		info, err := os.Lstat(f)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s: a scenario file is a regular file (no links, no directories)", filepath.Base(f))
		}
		if info.Size() > domain.MaxFileBytes {
			return nil, fmt.Errorf("%s: larger than %d bytes", filepath.Base(f), domain.MaxFileBytes)
		}
		raw, err := os.ReadFile(f) //nolint:gosec // G304: operator-chosen scenario directory
		if err != nil {
			return nil, err
		}
		s, err := domain.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if err := s.CheckFileName(filepath.Base(f)); err != nil {
			return nil, err
		}
		if prev, dup := ids[s.ID]; dup {
			return nil, fmt.Errorf("%s: id %s is also in %s", filepath.Base(f), s.ID, prev)
		}
		ids[s.ID] = filepath.Base(f)
		d, err := domain.Digest(s)
		if err != nil {
			return nil, err
		}
		out = append(out, Loaded{File: f, Scenario: *s, Digest: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scenario.ID < out[j].Scenario.ID })
	return out, nil
}

var blocking = map[domain.Outcome]bool{domain.OutcomeDeny: true, domain.OutcomeHold: true, domain.OutcomeCannotAuthorize: true, domain.OutcomeRefused: true}

// mismatchEach judges a concurrent step (D22): at most max_allow observations
// may be ALLOW, and every other one must match outcome, reason and code.
func mismatchEach(e domain.Expect, o domain.Observation, seen map[string]domain.Observation) string {
	allowed := 0
	for i, each := range o.Each {
		if each.Outcome == domain.OutcomeAllow && e.MaxAllow != nil {
			allowed++
			if why := mismatch(domain.Expect{SameDecisionAs: e.SameDecisionAs}, each, seen); why != "" {
				return fmt.Sprintf("call %d: %s", i+1, why)
			}
			continue
		}
		if e.Outcome == "" && e.MaxAllow != nil {
			if !blocking[each.Outcome] {
				return fmt.Sprintf("call %d: outcome %s is not a blocking outcome", i+1, each.Outcome)
			}
			continue
		}
		one := e
		one.MaxAllow = nil
		if why := mismatch(one, each, seen); why != "" {
			return fmt.Sprintf("call %d: %s", i+1, why)
		}
	}
	if e.MaxAllow != nil && allowed > *e.MaxAllow {
		return fmt.Sprintf("%d calls were ALLOW, at most %d allowed", allowed, *e.MaxAllow)
	}
	return ""
}

// ErrUnsupported is what a driver returns for a step it cannot perform; the
// runner marks the scenario SKIPPED instead of ERROR.
var ErrUnsupported = errors.New("redteam: step not supported by this driver")
