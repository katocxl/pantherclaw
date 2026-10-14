// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
)

// With the sandbox tag the driver runs `pclaw sandbox run` in real Docker
// containers, as the M9 exit does.
const sandboxBuilt = true

// sandboxRig is the M9 stack a sandbox scenario runs in.
type sandboxRig struct {
	m *m9
	// revoked is set once the seeded workload instance is revoked, which
	// the agent's runs in the sandbox need (coverage counts an agent
	// sandboxed only when every active instance is).
	revoked bool
	// closure is the probe report of the sandbox's own run, once it ran.
	closure string
}

// sandboxStart starts the stack of a sandbox scenario: the M9 exit's.
func sandboxStart(d *rangeDriver) *stack {
	m := startM9(d.t)
	d.extra.sandbox = &sandboxRig{m: m}
	return m.stack
}

func sandboxSetup(*rangeDriver) error { return nil }

// run starts the sandbox with the agent's arguments, once the seeded
// instance is out of the way, and returns its output.
func (r *sandboxRig) run(d *rangeDriver, agentArgs ...string) (int, string, string) {
	if !r.revoked {
		r.m.revokeSeeded(d.t)
		r.revoked = true
	}
	return r.m.sandbox(d.t, pclaw.Options{}, agentArgs...)
}

func sandboxProbe(d *rangeDriver, st domain.Step, vars map[string]string) (domain.Observation, error) {
	var w struct {
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	r := d.extra.sandbox
	if r == nil {
		return domain.Observation{}, fmt.Errorf("the scenario has no sandbox")
	}
	switch w.Probe {
	case "raw_curl_merge":
		code, out, errs := r.run(d, "merge", ghRepo, vars["pr"], vars["head"])
		if code != 0 || !closurePassed.MatchString(out) {
			return domain.Observation{}, fmt.Errorf("sandbox run: %d\n%s\n%s", code, out, errs)
		}
		line := lineOf(out, "merge ")
		status, body, _ := strings.Cut(strings.TrimPrefix(line, "merge "), " ")
		if status == "200" {
			return domain.Observation{Outcome: domain.OutcomeAllow, Detail: line}, nil
		}
		return observeREST(403, nil, []byte(body)), nil
	case "planted_pat_push":
		code, out, errs := r.run(d, "push", ghRepo)
		if code != 0 || !closurePassed.MatchString(out) {
			return domain.Observation{}, fmt.Errorf("sandbox run: %d\n%s\n%s", code, out, errs)
		}
		l := lineOf(out, "https-push ")
		if strings.HasPrefix(l, "https-push error") || strings.HasPrefix(l, "https-push 403") {
			// github.com is no mapped host: the edge refuses it and says so; a
			// range's routes are not recorded as coverage (HR-222).
			if !refusedRoutes.MatchString(errs) {
				return domain.Observation{}, fmt.Errorf("the edge reported no refused route:\n%s", errs)
			}
			if n := d.s.row(d.t, "SELECT count(*)::text FROM pc.coverage_routes WHERE connection_id = $1", d.s.gh.conn); n != "0" {
				return domain.Observation{}, fmt.Errorf("%s routes of a range's sandbox were recorded as coverage", n)
			}
			return domain.Observation{Outcome: domain.OutcomeRefused, Reason: "CANNOT_AUTHORIZE", Code: "unmapped_destination", Detail: l}, nil
		}
		return domain.Observation{Outcome: domain.OutcomeAllow, Detail: l}, nil
	}
	// The rest are probes of the closure every sandbox run starts with.
	if r.closure == "" {
		code, out, errs := r.run(d, "push", ghRepo)
		if code != 0 || !closurePassed.MatchString(out) {
			return domain.Observation{}, fmt.Errorf("sandbox run: %d\n%s\n%s", code, out, errs)
		}
		r.closure = "done"
	}
	var id, jws string
	d.s.query(d.t, "SELECT id::text, report FROM pc.probe_runs WHERE kind = 'SANDBOX' ORDER BY received_at DESC LIMIT 1", nil, &id, &jws)
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return domain.Observation{}, fmt.Errorf("no sandbox probe report")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return domain.Observation{}, err
	}
	var rep report.Report
	if err := json.Unmarshal(payload, &rep, json.RejectUnknownMembers(false)); err != nil {
		return domain.Observation{}, err
	}
	for _, x := range rep.Results {
		if x.Name == w.Probe && x.Role == report.RoleProbe {
			if x.Observed == report.Blocked {
				return domain.Observation{Outcome: domain.OutcomeBlocked, ProbeReportID: id, Detail: x.Detail}, nil
			}
			return domain.Observation{Outcome: domain.OutcomeAllow, ProbeReportID: id, Detail: x.Observed + " " + x.Detail}, nil
		}
	}
	return domain.Observation{}, fmt.Errorf("the probe report has no %s result", w.Probe)
}
