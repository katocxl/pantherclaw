// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Names resolves ids to display names for the summary (agents, sources,
// destinations, people); an id it cannot name is shown as the id.
type Names map[string]string

func (n Names) of(id fmt.Stringer) string {
	if s, ok := n[id.String()]; ok && s != "" {
		return s
	}
	return id.String()
}

// Summary is the plain-language description of a version (F681), made of
// deterministic sentences in the outline order: When, If, Under
// authority, Do, Wait when, If work fails, Finish when. It is generated
// once, when the version is validated, and stored with it.
func Summary(d *Definition, names Names) string {
	var b strings.Builder
	line := func(label, text string) {
		b.WriteString(label)
		b.WriteString(": ")
		b.WriteString(text)
		b.WriteString("\n")
	}
	line("When", whenText(d, names))
	if len(d.If) > 0 {
		line("If", "all of: "+strings.Join(d.If, "; ")+".")
	}
	line("Under authority", authorityText(d, names))
	var waits []string
	for _, s := range d.Do {
		text := stepText(d, s, names)
		if Catalog[s.Step].Wait {
			waits = append(waits, text)
		}
		line("Do", text)
	}
	if len(waits) > 0 {
		line("Wait when", strings.Join(waits, "; ")+".")
	}
	fails := "stop"
	if d.IfFails != nil && d.IfFails.Default == OnFailureEscalate {
		fails = "stop and escalate to the owner"
	}
	if d.IfFails != nil && len(d.IfFails.Compensate) > 0 {
		var cs []string
		for _, s := range d.IfFails.Compensate {
			cs = append(cs, stepText(d, s, names))
		}
		fails += ", then run compensation (never reported as an undo): " + strings.Join(cs, "; ")
	}
	line("If work fails", fails+".")
	var fin []string
	for _, f := range d.Finish {
		fin = append(fin, "step "+f.Step+" shows "+strings.ToLower(strings.ReplaceAll(string(f.Condition), "_", " ")))
	}
	line("Finish when", strings.Join(fin, " and ")+", within "+human(d.Limits.DeadlineOrDefault())+".")
	return b.String()
}

func human(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	}
	return d.String()
}

func whenText(d *Definition, names Names) string {
	w := d.When
	params := ""
	if ps := w.Params(); len(ps) > 0 {
		params = " with parameters " + strings.Join(sortedKeys(ps), ", ")
	}
	switch {
	case w.Schedule != nil:
		return fmt.Sprintf("on schedule %q in %s%s.", w.Schedule.Cron, w.Schedule.Timezone, params)
	case w.Event != nil:
		return fmt.Sprintf("a platform %s event occurs%s.", w.Event.On, params)
	case w.Inbound != nil:
		return fmt.Sprintf("a signed %s event arrives from source %s%s.", w.Inbound.Type, names.of(w.Inbound.Source), params)
	case w.Condition != nil:
		return fmt.Sprintf("%s holds for %s%s.", w.Condition.Probe, human(w.Condition.For.D()), params)
	case w.Threshold != nil:
		return fmt.Sprintf("at least %d %s events occur within %s.", w.Threshold.AtLeast, w.Threshold.On, human(w.Threshold.Over.D()))
	case w.Manual != nil:
		s := "a person starts it"
		if w.Manual.StepUp {
			s += " with a security-key step-up"
		}
		return s + params + "."
	}
	return "never."
}

func authorityText(d *Definition, names Names) string {
	a := d.Authority
	who := "its own identity"
	if u, ok := a.PrincipalUser(); ok {
		who = "person " + names.of(u)
	}
	c := a.Ceiling
	if c == nil {
		return "acting as " + who + ", with no grants."
	}
	var agents []string
	for _, x := range c.Agents {
		agents = append(agents, names.of(x))
	}
	ops := "no operations"
	if c.Bounds.Operations != nil {
		ops = strings.Join(*c.Bounds.Operations, ", ")
	}
	s := fmt.Sprintf("acting for %s, grants of at most %s to %s for %s; at most %d grants and %d runs a day",
		who, human(c.PerGrant.TTL.D()), strings.Join(agents, ", "), ops, c.PerDay.Grants, c.PerDay.Runs)
	var budgets []string
	for _, m := range c.PerDay.Budget {
		budgets = append(budgets, m.Currency+" "+m.Amount)
	}
	if len(budgets) > 0 {
		s += ", spending at most " + strings.Join(budgets, ", ") + " a day"
	}
	return s + "."
}

func stepText(_ *Definition, s StepSpec, names Names) string {
	w, err := s.DecodeWith()
	if err != nil {
		return s.ID + ": " + s.Step
	}
	var t string
	switch x := w.(type) {
	case *LaunchRunWith:
		t = "launch " + names.of(x.Agent)
		if x.TaskRef != "" {
			t += " for " + x.TaskRef
		}
		if x.Grant.Operations != nil {
			t += ", allowed only " + strings.Join(*x.Grant.Operations, ", ")
		}
		if len(x.Calls) > 0 {
			t += fmt.Sprintf(", making %d declared tool calls through the gateway", len(x.Calls))
		}
	case *WaitRunWith:
		t = "wait until the run of " + x.Step + " ends"
	case *WaitEffectWith:
		t = "wait until " + x.Operation + " is confirmed in the run of " + x.Step
	case *GateWith:
		t = fmt.Sprintf("wait for %d approval(s) with a security key, at most %s", max(x.MinApprovals, 1), human(x.Deadline.D()))
	case *RevokeGrantWith:
		t = "revoke grants (" + strings.ToLower(x.Scope) + ")"
	case *NotifyWith:
		to := slices.Clone(x.To)
		if x.Destination != nil {
			to = append(to, names.of(*x.Destination))
		}
		t = fmt.Sprintf("notify %s: %q", strings.Join(to, ", "), x.Message.Title)
	case *DeliverWith:
		t = "deliver the digest of " + x.From + " to " + names.of(x.Destination)
	case *WaitWith:
		t = "wait " + human(x.Duration.D())
	case *ContainWith:
		t = "contain the triggering " + strings.ToLower(strings.TrimPrefix(x.Subject, "TRIGGER_")) + " (" + strings.ToLower(x.Action) + ")"
	case *OpenCaseWith:
		t = fmt.Sprintf("open a case %q", x.Title)
	default:
		t = strings.ReplaceAll(s.Step, "_", " ")
	}
	return s.ID + ": " + t
}
